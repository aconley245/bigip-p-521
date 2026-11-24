#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9, !=3.9.0, !=3.9.1"
# dependencies = [
#     "cryptography>=50.0.2",
#     "pyopenssl>=26.4.0",
# ]
#
# [tool.uv]
# exclude-newer = "2026-11-24T00:00:00Z"
# ///
"""
F5 BIG-IP Backend Pool Member TLS Certificate Chain Auditor
Scans bigip.conf, connects to backend members, and flags any pool members
whose certificate chain (leaf, self-signed, or intermediate/root CA) utilizes
a P-521 (secp521r1) key. Fully compatible with NGINX, Apache, and microservices.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
import sys
from typing import Dict, List, Optional, Set, Tuple

# Cryptographic libraries for full certificate chain and curve inspection
try:
    from OpenSSL import SSL, crypto
    try:
        from OpenSSL._util import ffi, lib
        CFFI_OPENSSL_AVAILABLE = True
    except ImportError:
        CFFI_OPENSSL_AVAILABLE = False
    PYOPENSSL_AVAILABLE = True
except ImportError:
    PYOPENSSL_AVAILABLE = False
    CFFI_OPENSSL_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


# Known service port mappings for common F5 configurations
SERVICE_PORTS = {
    "https": 443,
    "http": 80,
    "ssl": 443,
    "webcache": 8080,
    "alt-https": 8443,
}

P521_CURVE_NAMES = {
    "secp521r1",
    "nistp521",
    "p-521",
    "p521",
    "prime521v1",
    "1.3.132.0.35",
}

# Explicitly prioritize ECDSA and standard suites to ensure ECC certificates are selected
CIPHER_LIST = (
    b"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:"
    b"ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:"
    b"ECDHE-RSA-AES128-GCM-SHA256:HIGH:ALL:!aNULL:!eNULL:!MD5:!RC4:!3DES"
)


class BigIPConfigParser:
    """Parses bigip.conf blocks to extract pools and backend members."""

    def __init__(self, config_content: str):
        self.config_content = config_content

    def extract_pools(self) -> Dict[str, List[Tuple[str, int]]]:
        """
        Extracts pools and member tuples (ip_or_host, port) from bigip.conf.
        Handles TMOS hierarchical blocks, partition paths, and port notations.
        """
        pools: Dict[str, List[Tuple[str, int]]] = {}

        # Regex to locate 'ltm pool <name> { ... }' blocks
        pool_pattern = re.compile(
            r'ltm\s+pool\s+([^\s{]+)\s*\{', re.MULTILINE
        )

        for match in pool_pattern.finditer(self.config_content):
            pool_name = match.group(1)
            start_idx = match.end() - 1
            block = self._extract_block(self.config_content, start_idx)

            members = self._extract_members_from_block(block)
            if members:
                pools[pool_name] = members

        return pools

    def _extract_block(self, content: str, start_index: int) -> str:
        """Balanced brace extraction for TMOS nested stanzas."""
        brace_count = 0
        end_index = start_index

        for i in range(start_index, len(content)):
            char = content[i]
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_index = i + 1
                    break

        return content[start_index:end_index]

    def _extract_members_from_block(self, pool_block: str) -> List[Tuple[str, int]]:
        """Parses the 'members { ... }' stanza within a pool definition."""
        members: List[Tuple[str, int]] = []
        members_match = re.search(r'\bmembers\s*\{', pool_block)
        if not members_match:
            return members

        start_idx = members_match.end() - 1
        members_block = self._extract_block(pool_block, start_idx)

        # Match member entries like '/Common/10.10.10.50:443 {' or 'node1:https {'
        member_pattern = re.compile(r'([^\s{]+):([^\s{]+)\s*\{')
        for match in member_pattern.finditer(members_block):
            raw_node = match.group(1).strip()
            raw_port = match.group(2).strip()

            # Clean TMOS partition prefix (e.g., /Common/10.1.1.1 -> 10.1.1.1)
            host = raw_node.split('/')[-1]

            # Resolve port names or numbers
            port = SERVICE_PORTS.get(raw_port.lower())
            if port is None:
                try:
                    port = int(raw_port)
                except ValueError:
                    continue

            members.append((host, port))

        return members


class CertChainValidator:
    """Connects to pool members via TLS and analyzes certificate chains for P-521 keys."""

    def __init__(self, timeout: float = 4.0, sni_hostname: Optional[str] = None, verbose: bool = False):
        self.timeout = timeout
        self.sni_hostname = sni_hostname
        self.verbose = verbose

    @staticmethod
    def _is_ip_address(host: str) -> bool:
        """Determines if a target host string is an IPv4 or IPv6 literal."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @staticmethod
    def _format_ssl_error(exc: Exception) -> str:
        """Extracts clear, descriptive error details from nested OpenSSL exception tuples."""
        if PYOPENSSL_AVAILABLE and isinstance(exc, SSL.Error):
            if exc.args and isinstance(exc.args, (list, tuple)) and exc.args[0]:
                formatted_errors = []
                for entry in exc.args[0]:
                    if isinstance(entry, tuple) and len(entry) >= 3:
                        formatted_errors.append(f"{entry[1]}: {entry[2]}")
                    else:
                        formatted_errors.append(str(entry))
                return " | ".join(formatted_errors)
        err_str = str(exc).strip()
        return err_str if err_str else repr(exc)

    def audit_endpoint(self, host: str, port: int) -> Dict:
        """
        Performs TLS connection, downloads certificate chain (including self-signed certs),
        and checks whether the leaf or any CA in the chain utilizes P-521 keys.
        """
        result = {
            "host": host,
            "port": port,
            "connected": False,
            "flagged": False,
            "has_p521_leaf": False,
            "has_p521_ca": False,
            "is_self_signed": False,
            "p521_leaf": None,
            "p521_cas": [],
            "inspected_certs": [],
            "error": None,
            "chain_length": 0,
        }

        # Skip obvious non-SSL/plaintext HTTP ports
        if port == 80:
            result["error"] = "Skipped port 80 (plaintext HTTP)"
            return result

        try:
            chain = self._fetch_cert_chain(host, port)
            result["connected"] = True
            result["chain_length"] = len(chain)

            # Analyze certificates in the presented chain
            for idx, cert in enumerate(chain):
                is_ca, is_self_signed, curve_name, key_size, key_type, subject, issuer = self._inspect_cert(cert)

                # Record inspected cert overview for diagnostics
                cert_summary = {
                    "depth": idx,
                    "subject": subject,
                    "issuer": issuer,
                    "key_type": key_type,
                    "key_size": key_size,
                    "curve": curve_name,
                    "is_ca": is_ca,
                    "is_self_signed": is_self_signed,
                }
                result["inspected_certs"].append(cert_summary)

                # Record self-signed attribute on the leaf certificate
                if idx == 0 and is_self_signed:
                    result["is_self_signed"] = True

                # Evaluate P-521 curve presence by curve name OR explicit 521-bit key length
                is_p521 = (
                    (curve_name and curve_name.lower() in P521_CURVE_NAMES) or
                    (key_type == "EC" and key_size == 521)
                )

                if is_p521:
                    resolved_curve = curve_name if curve_name else "secp521r1 (521-bit EC)"
                    cert_data = {
                        "depth": idx,
                        "subject": subject,
                        "issuer": issuer,
                        "curve": resolved_curve,
                        "key_size": key_size,
                        "is_ca": is_ca,
                        "is_self_signed": is_self_signed,
                    }

                    # Leaf certificate evaluation (depth 0)
                    if idx == 0:
                        result["has_p521_leaf"] = True
                        result["p521_leaf"] = cert_data
                        # If a self-signed cert acts as its own root/CA, flag CA status as well
                        if is_ca or is_self_signed:
                            result["has_p521_ca"] = True
                            result["p521_cas"].append(cert_data)
                    else:
                        # Intermediate or root CA certificates in the chain
                        result["has_p521_ca"] = True
                        result["p521_cas"].append(cert_data)

            # Overall flagged condition: either leaf or CA uses P-521
            if result["has_p521_leaf"] or result["has_p521_ca"]:
                result["flagged"] = True

        except Exception as e:
            result["error"] = self._format_ssl_error(e)

        return result

    def _fetch_cert_chain(self, host: str, port: int) -> List:
        """
        Attempts pyOpenSSL with explicit P-521 curve advertisement first.
        Falls back to standard library ssl module if pyOpenSSL encounters negotiation errors.
        """
        errors = []

        if PYOPENSSL_AVAILABLE:
            try:
                return self._fetch_cert_chain_pyopenssl(host, port)
            except Exception as e:
                errors.append(f"pyOpenSSL: {self._format_ssl_error(e)}")

        if CRYPTOGRAPHY_AVAILABLE:
            try:
                return self._fetch_cert_chain_stdlib(host, port)
            except Exception as e:
                errors.append(f"stdlib ssl: {self._format_ssl_error(e)}")

        if not PYOPENSSL_AVAILABLE and not CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError(
                "pyOpenSSL or cryptography is required. Run with `uv run big-ip-pool-member-p512-cert.py` "
                "or install with: pip install pyOpenSSL cryptography"
            )

        raise RuntimeError(" | ".join(errors) if errors else "Connection failed")

    def _fetch_cert_chain_pyopenssl(self, host: str, port: int) -> List:
        """
        pyOpenSSL TLS connection with explicit P-521 curve advertisement,
        ECDSA prioritization, and permissive certificate verification for self-signed roots.
        """
        try:
            ctx = SSL.Context(SSL.TLS_METHOD)
        except AttributeError:
            ctx = SSL.Context(SSL.SSLv23_METHOD)

        ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)

        # Force OpenSSL to advertise P-521 in ClientHello supported_groups extension
        if CFFI_OPENSSL_AVAILABLE and hasattr(ctx, "_context"):
            try:
                # Set supported elliptic curves / groups explicitly
                lib.SSL_CTX_set1_curves_list(
                    ctx._context,
                    b"P-521:secp521r1:prime521v1:P-384:secp384r1:P-256:secp256r1:X25519"
                )
            except Exception:
                pass

            try:
                # Advertise compatible signature algorithms (SHA-512 with ECDSA)
                lib.SSL_CTX_set1_sigalgs_list(
                    ctx._context,
                    b"ECDSA+SHA512:ECDSA+SHA384:ECDSA+SHA256:RSA+SHA512:RSA+SHA384:RSA+SHA256"
                )
            except Exception:
                pass

        # Set cipher list
        try:
            ctx.set_cipher_list(CIPHER_LIST)
        except Exception:
            pass

        # Disable verification failures to allow self-signed and untrusted internal chains
        def verify_callback(conn, cert, errnum, depth, ok):
            return True

        ctx.set_verify(SSL.VERIFY_NONE, verify_callback)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        ssl_conn = SSL.Connection(ctx, sock)

        # RFC 6066: Send SNI if explicitly passed or if host is a DNS name
        if self.sni_hostname:
            ssl_conn.set_tlsext_host_name(self.sni_hostname.encode("utf-8"))
        elif not self._is_ip_address(host):
            ssl_conn.set_tlsext_host_name(host.encode("utf-8"))

        ssl_conn.connect((host, port))
        ssl_conn.do_handshake()

        # Retrieve peer certificate chain
        chain = ssl_conn.get_peer_cert_chain()

        # Fallback for standalone self-signed servers that do not populate chain list
        if not chain:
            peer_cert = ssl_conn.get_peer_certificate()
            if peer_cert:
                chain = [peer_cert]

        ssl_conn.close()
        sock.close()

        if not chain:
            raise ValueError("No certificates returned by server in TLS handshake.")

        return chain

    def _fetch_cert_chain_stdlib(self, host: str, port: int) -> List:
        """Standard library fallback probe with permissive security level and TLS 1.3 support."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Lower security level to accept all legacy or custom curves
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0:ALL")
        except Exception:
            pass

        server_hostname = None
        if self.sni_hostname:
            server_hostname = self.sni_hostname
        elif not self._is_ip_address(host):
            server_hostname = host

        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssl_sock:
                der_cert = ssl_sock.getpeercert(binary_form=True)
                if not der_cert:
                    raise ValueError("No certificate presented by peer.")
                cert = x509.load_der_x509_certificate(der_cert)
                return [cert]

    def _inspect_cert(self, cert) -> Tuple[bool, bool, Optional[str], Optional[int], str, str, str]:
        """
        Inspects an X.509 certificate for CA status, self-signed status, ECC curve name, and key size.
        Returns: (is_ca, is_self_signed, curve_name, key_size, key_type, subject_str, issuer_str)
        """
        is_ca = False
        is_self_signed = False
        curve_name = None
        key_size = None
        key_type = "UNKNOWN"

        if CRYPTOGRAPHY_AVAILABLE:
            crypto_cert = cert.to_cryptography() if hasattr(cert, "to_cryptography") else cert
            subject_str = crypto_cert.subject.rfc4514_string()
            issuer_str = crypto_cert.issuer.rfc4514_string()

            # Determine self-signed condition (subject == issuer)
            if crypto_cert.subject == crypto_cert.issuer:
                is_self_signed = True

            # Check Basic Constraints extension for CA flag
            try:
                bc_ext = crypto_cert.extensions.get_extension_for_oid(
                    x509.ExtensionOID.BASIC_CONSTRAINTS
                )
                is_ca = bc_ext.value.ca
            except x509.ExtensionNotFound:
                is_ca = False

            # Inspect public key
            pub_key = crypto_cert.public_key()
            if isinstance(pub_key, ec.EllipticCurvePublicKey):
                key_type = "EC"
                key_size = pub_key.key_size
                curve_name = pub_key.curve.name.lower()
            else:
                key_type = pub_key.__class__.__name__
                if hasattr(pub_key, "key_size"):
                    key_size = pub_key.key_size
        else:
            # Fallback using native pyOpenSSL methods
            subject_str = "/" + "/".join(
                [f"{k.decode()}={v.decode()}" for k, v in cert.get_subject().get_components()]
            )
            issuer_str = "/" + "/".join(
                [f"{k.decode()}={v.decode()}" for k, v in cert.get_issuer().get_components()]
            )

            if cert.get_subject().der() == cert.get_issuer().der():
                is_self_signed = True

            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                if ext.get_short_name() == b"basicConstraints":
                    if b"CA:TRUE" in str(ext).encode():
                        is_ca = True

            pkey = cert.get_pubkey()
            key_size = pkey.bits()
            if pkey.type() == crypto.TYPE_EC:
                key_type = "EC"
                if key_size == 521:
                    curve_name = "secp521r1"
            elif pkey.type() == crypto.TYPE_RSA:
                key_type = "RSA"

        return is_ca, is_self_signed, curve_name, key_size, key_type, subject_str, issuer_str


def main():
    parser = argparse.ArgumentParser(
        description="Audit BIG-IP backend pool members for P-521 leaf, self-signed, and CA certificates."
    )
    parser.add_argument(
        "-f", "--file", required=True, help="Path to bigip.conf file."
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=4.0, help="Socket timeout in seconds (default: 4.0)."
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=10, help="Concurrent worker threads (default: 10)."
    )
    parser.add_argument(
        "--sni", default=None, help="Explicit SNI hostname for TLS ClientHello (vital for NGINX vhosts)."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Display diagnostic details for every inspected member."
    )
    parser.add_argument(
        "--json", action="store_true", help="Output results in JSON format."
    )
    args = parser.parse_args()

    # Read configuration file
    try:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        print(f"[!] Error reading file '{args.file}': {e}", file=sys.stderr)
        sys.exit(1)

    if not args.json:
        print(f"[*] Parsing BIG-IP configuration: {args.file}...")
    config_parser = BigIPConfigParser(content)
    pools = config_parser.extract_pools()

    total_pools = len(pools)
    unique_endpoints: Set[Tuple[str, int]] = set()
    for members in pools.values():
        for m in members:
            unique_endpoints.add(m)

    if not args.json:
        print(f"[*] Identified {total_pools} pools with {len(unique_endpoints)} unique backend endpoints.")

    if not unique_endpoints:
        if args.json:
            print("[]")
        else:
            print("[!] No pool members found. Exiting.")
        sys.exit(0)

    # Perform concurrent TLS auditing
    validator = CertChainValidator(timeout=args.timeout, sni_hostname=args.sni, verbose=args.verbose)
    endpoint_results: Dict[Tuple[str, int], Dict] = {}

    if not args.json:
        print(f"[*] Auditing TLS endpoints with {args.workers} threads (P-521 curve negotiation enabled)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {
            executor.submit(validator.audit_endpoint, host, port): (host, port)
            for host, port in unique_endpoints
        }
        for future in concurrent.futures.as_completed(future_map):
            ep = future_map[future]
            try:
                endpoint_results[ep] = future.result()
            except Exception as e:
                endpoint_results[ep] = {
                    "host": ep[0],
                    "port": ep[1],
                    "connected": False,
                    "flagged": False,
                    "has_p521_leaf": False,
                    "has_p521_ca": False,
                    "is_self_signed": False,
                    "p521_leaf": None,
                    "p521_cas": [],
                    "inspected_certs": [],
                    "error": str(e),
                    "chain_length": 0,
                }

    # Aggregate by pool
    summary = []
    affected_pools_count = 0
    error_pools_count = 0

    for pool_name, members in pools.items():
        pool_flagged = False
        pool_has_error = False
        member_reports = []

        for m in members:
            audit = endpoint_results.get(m, {})
            if audit.get("flagged"):
                pool_flagged = True
            if not audit.get("connected"):
                pool_has_error = True
            member_reports.append(audit)

        if pool_flagged:
            affected_pools_count += 1
        elif pool_has_error:
            error_pools_count += 1

        summary.append({
            "pool": pool_name,
            "flagged": pool_flagged,
            "has_error": pool_has_error,
            "members": member_reports,
        })

    # Render output
    if args.json:
        print(json.dumps(summary, indent=2))
        return

    # Formatted terminal display
    print("\n" + "=" * 95)
    print(
        f"AUDIT SUMMARY: {affected_pools_count}/{total_pools} pools flagged with P-521 certificates | "
        f"{error_pools_count} unverified pools with connection/handshake errors"
    )
    print("=" * 95)

    for item in summary:
        if item["flagged"]:
            print(f"\nPool: {item['pool']} [CRITICAL - P-521 DETECTED]")
            for m in item["members"]:
                host_str = f"{m['host']}:{m['port']}"
                cert_type_tag = "[SELF-SIGNED]" if m.get("is_self_signed") else "[CA-SIGNED]"
                if m.get("flagged"):
                    print(f"  --> Member: {host_str} {cert_type_tag} - VULNERABLE")
                    if m.get("has_p521_leaf") and m.get("p521_leaf"):
                        leaf = m["p521_leaf"]
                        print(f"      [LEAF CERT] Subject:  {leaf['subject']}")
                        print(f"      [LEAF CERT] Curve:    {leaf['curve']} ({leaf.get('key_size')} bits)")
                        print(f"      [LEAF CERT] Type:     Self-Signed: {leaf['is_self_signed']}")
                    for ca in m.get("p521_cas", []):
                        if ca.get("depth") == 0 and m.get("has_p521_leaf"):
                            continue  # Avoid duplicate printing if already output as leaf
                        print(f"      [CA/INTERMEDIATE] Depth {ca['depth']} Issuer:  {ca['issuer']}")
                        print(f"      [CA/INTERMEDIATE] Depth {ca['depth']} Subject: {ca['subject']}")
                        print(f"      [CA/INTERMEDIATE] Curve: {ca['curve']} ({ca.get('key_size')} bits)")
                elif m.get("connected"):
                    print(f"  --> Member: {host_str} {cert_type_tag} - Secure (No P-521)")
                else:
                    print(f"  --> Member: {host_str} - Error: {m.get('error')}")

        elif item.get("has_error"):
            # Flag pools where members could not complete TLS handshake as UNVERIFIED
            print(f"\nPool: {item['pool']} [WARNING - UNVERIFIED / HANDSHAKE ERROR]")
            for m in item["members"]:
                host_str = f"{m['host']}:{m['port']}"
                if not m.get("connected"):
                    print(f"  --> Member: {host_str} - Handshake/Connection Failed: {m.get('error')}")
                elif args.verbose:
                    cert_info = m["inspected_certs"][0] if m.get("inspected_certs") else {}
                    print(f"  --> Member: {host_str} [OK] - Key: {cert_info.get('key_type')} {cert_info.get('key_size')}b, Curve: {cert_info.get('curve')}")

        elif args.verbose:
            print(f"\nPool: {item['pool']} [OK]")
            for m in item["members"]:
                host_str = f"{m['host']}:{m['port']}"
                if m.get("connected"):
                    cert_info = m["inspected_certs"][0] if m.get("inspected_certs") else {}
                    print(f"  --> Member: {host_str} [OK] - Key: {cert_info.get('key_type')} {cert_info.get('key_size')}b, Curve: {cert_info.get('curve')}")
                else:
                    print(f"  --> Member: {host_str} - Error: {m.get('error')}")

    if affected_pools_count == 0 and error_pools_count == 0:
        print("\n[✓] All backend pool members were successfully verified: No P-521 certificates detected.")
    elif affected_pools_count == 0 and error_pools_count > 0:
        print("\n[!] No P-521 certificates were confirmed, but some pool members failed to connect or negotiate TLS. Check the warnings above.")


if __name__ == "__main__":
    main()