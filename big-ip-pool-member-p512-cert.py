#!/usr/bin/env python3
"""
F5 BIG-IP Backend Pool Member TLS Certificate Chain Auditor
Scans bigip.conf, connects to backend members, and flags any pool members
whose certificate chain includes a CA/Intermediate CA with a P-521 (secp521r1) key.
"""

import argparse
import concurrent.futures
import json
import re
import socket
import ssl
import sys
from typing import Dict, List, Optional, Set, Tuple

# Try importing cryptography and pyOpenSSL for comprehensive chain retrieval
try:
    from OpenSSL import SSL, crypto
    PYOPENSSL_AVAILABLE = True
except ImportError:
    PYOPENSSL_AVAILABLE = False

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
    "prime521v1",
    "1.3.132.0.35",
}


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
    """Connects to pool members via TLS and analyzes certificate chains for P-521 CAs."""

    def __init__(self, timeout: float = 4.0, sni_hostname: Optional[str] = None):
        self.timeout = timeout
        self.sni_hostname = sni_hostname

    def audit_endpoint(self, host: str, port: int) -> Dict:
        """
        Performs TLS connection, downloads certificate chain, and checks for P-521 CAs.
        """
        result = {
            "host": host,
            "port": port,
            "connected": False,
            "has_p521_ca": False,
            "p521_cas": [],
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

            # Analyze certificates: index 0 is typically leaf, index > 0 are intermediate/root CAs
            for idx, cert in enumerate(chain):
                is_ca, curve_name, subject, issuer = self._inspect_cert(cert)

                # Flag if this is a CA / Intermediate CA (or non-leaf cert) using P-521
                if curve_name in P521_CURVE_NAMES:
                    if is_ca or idx > 0:
                        result["has_p521_ca"] = True
                        result["p521_cas"].append({
                            "depth": idx,
                            "subject": subject,
                            "issuer": issuer,
                            "curve": curve_name,
                            "is_ca_extension": is_ca,
                        })

        except Exception as e:
            result["error"] = str(e)

        return result

    def _fetch_cert_chain(self, host: str, port: int) -> List:
        """Retrieves peer certificate chain using pyOpenSSL."""
        if not PYOPENSSL_AVAILABLE:
            raise RuntimeError(
                "pyOpenSSL is required to retrieve the full unverified intermediate certificate chain. "
                "Install with: pip install pyOpenSSL cryptography"
            )

        # Set up SSL Context (allowing unverified retrieval to inspect backend self-signed or internal CAs)
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        ssl_conn = SSL.Connection(ctx, sock)
        if self.sni_hostname:
            ssl_conn.set_tlsext_host_name(self.sni_hostname.encode("utf-8"))
        else:
            ssl_conn.set_tlsext_host_name(host.encode("utf-8"))

        ssl_conn.connect((host, port))
        ssl_conn.do_handshake()

        chain = ssl_conn.get_peer_cert_chain()
        ssl_conn.close()
        sock.close()

        if not chain:
            raise ValueError("No certificates returned by server in TLS handshake.")

        return chain

    def _inspect_cert(self, cert) -> Tuple[bool, Optional[str], str, str]:
        """
        Inspects an X.509 certificate for CA status and ECC curve name.
        Returns: (is_ca, curve_name, subject_str, issuer_str)
        """
        # Convert pyOpenSSL X509 to cryptography X509 if available
        is_ca = False
        curve_name = None

        if CRYPTOGRAPHY_AVAILABLE:
            crypto_cert = cert.to_cryptography()
            subject_str = crypto_cert.subject.rfc4514_string()
            issuer_str = crypto_cert.issuer.rfc4514_string()

            # Check Basic Constraints
            try:
                bc_ext = crypto_cert.extensions.get_extension_for_oid(
                    x509.ExtensionOID.BASIC_CONSTRAINTS
                )
                is_ca = bc_ext.value.ca
            except x509.ExtensionNotFound:
                is_ca = False

            # Check Public Key Curve
            pub_key = crypto_cert.public_key()
            if isinstance(pub_key, ec.EllipticCurvePublicKey):
                curve_name = pub_key.curve.name.lower()
        else:
            # Fallback using pyOpenSSL inspect methods
            subject_str = "/" + "/".join(
                [f"{k.decode()}={v.decode()}" for k, v in cert.get_subject().get_components()]
            )
            issuer_str = "/" + "/".join(
                [f"{k.decode()}={v.decode()}" for k, v in cert.get_issuer().get_components()]
            )

            # Check extensions for basicConstraints
            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                if ext.get_short_name() == b"basicConstraints":
                    if b"CA:TRUE" in str(ext).encode():
                        is_ca = True

            # OpenSSL key inspection
            pkey = cert.get_pubkey()
            if pkey.type() == crypto.TYPE_EC:
                # pyOpenSSL doesn't directly expose curve names on legacy bindings
                key_text = crypto.dump_publickey(crypto.FILETYPE_PEM, pkey).decode("utf-8")
                if "secp521r1" in key_text or "P-521" in key_text:
                    curve_name = "secp521r1"

        return is_ca, curve_name, subject_str, issuer_str


def main():
    parser = argparse.ArgumentParser(
        description="Audit BIG-IP backend pool members for P-521 CA certificates."
    )
    parser.add_argument(
        "-f", "--file", required=True, help="Path to bigip.conf file."
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=3.5, help="Socket timeout in seconds (default: 3.5)."
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=10, help="Concurrent worker threads (default: 10)."
    )
    parser.add_argument(
        "--sni", default=None, help="Optional SNI server name to send in ClientHello."
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

    print(f"[*] Parsing BIG-IP configuration: {args.file}...")
    config_parser = BigIPConfigParser(content)
    pools = config_parser.extract_pools()

    total_pools = len(pools)
    unique_endpoints: Set[Tuple[str, int]] = set()
    for members in pools.values():
        for m in members:
            unique_endpoints.add(m)

    print(f"[*] Identified {total_pools} pools with {len(unique_endpoints)} unique backend endpoints.")

    if not unique_endpoints:
        print("[!] No pool members found. Exiting.")
        sys.exit(0)

    # Perform concurrent TLS auditing
    validator = CertChainValidator(timeout=args.timeout, sni_hostname=args.sni)
    endpoint_results: Dict[Tuple[str, int], Dict] = {}

    print(f"[*] Auditing TLS endpoints with {args.workers} threads...")
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
                    "has_p521_ca": False,
                    "error": str(e),
                }

    # Aggregate by pool
    summary = []
    affected_pools_count = 0

    for pool_name, members in pools.items():
        pool_flagged = False
        member_reports = []

        for m in members:
            audit = endpoint_results.get(m, {})
            if audit.get("has_p521_ca"):
                pool_flagged = True
            member_reports.append(audit)

        if pool_flagged:
            affected_pools_count += 1

        summary.append({
            "pool": pool_name,
            "flagged": pool_flagged,
            "members": member_reports,
        })

    # Render output
    if args.json:
        print(json.dumps(summary, indent=2))
        return

    # Formatted terminal display
    print("\n" + "=" * 90)
    print(f"AUDIT SUMMARY: {affected_pools_count}/{total_pools} pools contain members using P-521 CAs")
    print("=" * 90)

    for item in summary:
        status_marker = "[CRITICAL - P-521 CA DETECTED]" if item["flagged"] else "[OK]"
        if item["flagged"]:
            print(f"\nPool: {item['pool']} {status_marker}")
            for m in item["members"]:
                host_str = f"{m['host']}:{m['port']}"
                if m.get("has_p521_ca"):
                    print(f"  --> Member: {host_str} - VULNERABLE")
                    for ca in m.get("p521_cas", []):
                        print(f"      Depth {ca['depth']} Issuer:  {ca['issuer']}")
                        print(f"      Depth {ca['depth']} Subject: {ca['subject']}")
                        print(f"      Curve: {ca['curve']} (CA Flag: {ca['is_ca_extension']})")
                elif m.get("connected"):
                    print(f"  --> Member: {host_str} - Secure (No P-521 CAs)")
                else:
                    print(f"  --> Member: {host_str} - Could not connect ({m.get('error')})")

    if affected_pools_count == 0:
        print("\n[✓] No backend pool members were found using P-521 CA or intermediate certificates.")


if __name__ == "__main__":
    main()
