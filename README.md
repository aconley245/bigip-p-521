# F5 BIG-IP Pool Member P-521 Certificate Auditor

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![F5 TMOS](https://img.shields.io/badge/TMOS-v13%20--%20v17%2B-red.svg)](https://www.f5.com/)
[![OpenSSL](https://img.shields.io/badge/Cryptography-pyOpenSSL%20%2B%20cryptography-orange.svg)](https://github.com/pyca/cryptography)

A high-performance security auditing and troubleshooting utility for F5 BIG-IP environments. This tool parses TMOS `bigip.conf` configurations, extracts all backend `ltm pool` members across all partitions, and inspects their TLS certificate chains in parallel to identify any services running **NIST P-521** (`secp521r1` / OID `1.3.132.0.35`) keys.

---

## Background & Problem Statement

In enterprise BIG-IP architectures, TLS hardware acceleration cards (such as Cavium/Nitrox and Intel Coleto Creek chipsets) are optimized for RSA (2048/4096-bit) and standard Elliptic Curve Cryptography (ECC) curves—predominantly **NIST P-256** (`secp256r1`) and **NIST P-384** (`secp384r1`).

When backend pool members (NGINX, Apache, Envoy, or internal microservices) present certificates or intermediate CAs generated on the **NIST P-521** curve:

1. **Hardware Offload Incompatibility**: Many hardware platforms cannot offload 521-bit elliptic curves, forcing TMOS into software crypto fallback (TMM high CPU) or silently dropping handshakes.
2. **Server-Side SSL Profile Failures**: If the assigned F5 `serverssl` profile is not explicitly configured with compatible curve parameters or cipher suites, the BIG-IP will log `SSL Handshake failed` or reset the backend connection with `TCP RST`.
3. **Silent Client Hello Rejections**: Standard TLS clients that omit `secp521r1` from their TLS `supported_groups` extension fail to establish connections with servers enforcing P-521 ECDSA suites, resulting in intermittent pool member flapping.

This tool proactively uncovers these vulnerabilities across entire fleets of backend servers before cutovers, migrations, or platform upgrades.

---

## What's New in This Version

- **Leaf Certificate Auditing (Depth 0)**: Evaluates the server's end-entity (leaf) certificate independently from issuing authorities.
- **Full Self-Signed Support**: Automatically detects and handles self-signed server certificates (`Subject == Issuer`), ensuring internal nodes and dev environments are fully audited without verification aborts.
- **Explicit P-521 Curve Negotiation**: Injects `secp521r1` / `P-521` directly into the OpenSSL `supported_groups` extension via CFFI bindings. This eliminates `tlsv1 alert handshake failure` errors on strict servers like NGINX.
- **Dual-Stack Probe Engine**: Employs `pyOpenSSL` with an automatic, resilient fallback to Python standard library `ssl` with relaxed `@SECLEVEL=0` to ensure connectivity across diverse TLS 1.2 and TLS 1.3 servers.
- **Unmasked Error Logging**: Unpacks nested OpenSSL error queues, eliminating empty `Error:` strings and displaying exact reason codes (e.g., handshake alerts, connection timeouts, or TCP resets).
- **False Negative Prevention**: Unreachable or non-negotiating endpoints are flagged with `[WARNING - UNVERIFIED / HANDSHAKE ERROR]` rather than marked as healthy.
- **SNI Sanitation & Override (`--sni`)**: Strips IP literals from SNI fields (RFC 6066 compliance) and provides an explicit `--sni` parameter to target specific NGINX `server_name` virtual hosts.

---

## Architecture Overview

```
 ┌───────────────┐
 │  bigip.conf   │
 └───────┬───────┘
         │ (Balanced-brace TMOS Parser)
         ▼
 ┌────────────────────────────────────────────────────────┐
 │ Unique Endpoint Extraction & Partition Normalization   │
 └───────┬────────────────────────────────────────────────┘
         │
         ▼  (Concurrent ThreadPoolExecutor)
 ┌────────────────────────────────────────────────────────┐
 │ Dual-Stack TLS Probe Engine                            │
 │  ├─ pyOpenSSL (P-521 supported_groups + ECDSA ciphers) │
 │  └─ Python ssl fallback (@SECLEVEL=0)                  │
 └───────┬────────────────────────────────────────────────┘
         │
         ▼
 ┌────────────────────────────────────────────────────────┐
 │ X.509 Cryptographic Chain Analyzer                     │
 │  ├─ Leaf Verification (Depth 0, BasicConstraints)      │
 │  ├─ Intermediate & Root CA Inspection (Depth > 0)      │
 │  ├─ Self-Signed Detection (Subject == Issuer)          │
 │  └─ Curve Match: secp521r1 / prime521v1 / 521-bit EC   │
 └───────┬────────────────────────────────────────────────┘
         │
         ▼
 ┌────────────────────────────────────────────────────────┐
 │ Output Formatter: Terminal Dashboard or JSON Schema    │
 └────────────────────────────────────────────────────────┘
```

---

## Prerequisites & Installation

### Requirements

- Python 3.9+ (excluding 3.9.0 / 3.9.1)
- OpenSSL 1.1.1 or 3.0+
- [`uv`](https://docs.astral.sh/uv/) (recommended for zero-setup execution using PEP 723 inline script metadata)

### Running with `uv` (Recommended)

`big-ip-pool-member-p512-cert.py` embeds [PEP 723](https://peps.python.org/pep-0723/) inline script metadata (with `[tool.uv]` settings), so `uv` provisions the Python environment and dependencies (`cryptography`, `pyOpenSSL`) automatically:

```bash
uv run big-ip-pool-member-p512-cert.py -f /path/to/bigip.conf
```

Or execute it directly via the `#!/usr/bin/env -S uv run --script` shebang:

```bash
./big-ip-pool-member-p512-cert.py -f /path/to/bigip.conf
```

You can also inspect or lock the inline script dependencies with `uv`:

```bash
uv tree --script big-ip-pool-member-p512-cert.py
uv lock --script big-ip-pool-member-p512-cert.py
```

### Manual Installation (`pip`)

If you prefer running with a standard Python environment, install the required cryptographic modules:

```bash
pip install -r requirements.txt
# or:
pip install pyOpenSSL cryptography
```

---

## Usage Guide

### Basic Scan

Run an audit against a local `bigip.conf` file:

```bash
uv run big-ip-pool-member-p512-cert.py -f /path/to/bigip.conf
# or with a pre-configured environment:
python3 big-ip-pool-member-p512-cert.py -f /path/to/bigip.conf
```

### Advanced Scan with SNI & Verbose Diagnostics

When pool members are listening behind an NGINX virtual host or require explicit Server Name Indication:

```bash
uv run big-ip-pool-member-p512-cert.py -f bigip.conf --sni api.corp.internal -v -t 5.0 -w 20
```

### JSON Export for CI/CD & Automation

Export detailed findings for ingestion into SIEM or compliance dashboards:

```bash
uv run big-ip-pool-member-p512-cert.py -f bigip.conf --json > p521_audit_report.json
```

---

## Command-Line Arguments

| Flag | Long Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| `-f` | `--file` | *Required* | Path to the BIG-IP configuration file (`bigip.conf`). |
| `-t` | `--timeout` | `4.0` | Socket and TLS handshake timeout in seconds. |
| `-w` | `--workers` | `10` | Number of concurrent worker threads. |
| | `--sni` | `None` | Explicit hostname sent in the TLS `server_name` ClientHello extension. |
| `-v` | `--verbose` | `False` | Displays key type, bit-size, and curve for every clean member inspected. |
| | `--json` | `False` | Outputs raw scan results in formatted JSON. |

---

## Sample Outputs

### 1. Terminal Output with Detected Vulnerabilities

```text
[*] Parsing BIG-IP configuration: bigip.conf...
[*] Identified 14 pools with 38 unique backend endpoints.
[*] Auditing TLS endpoints with 10 threads (P-521 curve negotiation enabled)...

===============================================================================================
AUDIT SUMMARY: 1/14 pools flagged with P-521 certificates | 1 unverified pools with connection/handshake errors
===============================================================================================

Pool: /Common/api-ecommerce-pool [CRITICAL - P-521 DETECTED]
  --> Member: 10.0.200.105:443 [CA-SIGNED] - VULNERABLE
      [LEAF CERT] Subject:  CN=api.ecommerce.internal,O=Finance Corp,C=US
      [LEAF CERT] Curve:    secp521r1 (521 bits)
      [LEAF CERT] Type:     Self-Signed: False
      [CA/INTERMEDIATE] Depth 1 Issuer:  CN=Corp Root CA G2,O=Finance Corp,C=US
      [CA/INTERMEDIATE] Depth 1 Subject: CN=Corp Intermediate ECC CA,O=Finance Corp,C=US
      [CA/INTERMEDIATE] Curve: secp521r1 (521 bits)
  --> Member: 10.0.200.106:443 [CA-SIGNED] - Secure (No P-521)

Pool: /Common/legacy-app-pool [WARNING - UNVERIFIED / HANDSHAKE ERROR]
  --> Member: 10.0.10.25:8443 - Handshake/Connection Failed: [('SSL routines', 'ssl3_read_bytes', 'tlsv1 alert handshake failure')]

Pool: /Common/web-frontend-pool [OK]
  --> Member: 10.0.100.10:443 [OK] - Key: EC 256b, Curve: prime256v1
  --> Member: 10.0.100.11:443 [OK] - Key: RSA 2048b, Curve: None
```

### 2. JSON Output Schema

```json
[
  {
    "pool": "/Common/api-ecommerce-pool",
    "flagged": true,
    "has_error": false,
    "members": [
      {
        "host": "10.0.200.105",
        "port": 443,
        "connected": true,
        "flagged": true,
        "has_p521_leaf": true,
        "has_p521_ca": true,
        "is_self_signed": false,
        "p521_leaf": {
          "depth": 0,
          "subject": "CN=api.ecommerce.internal,O=Finance Corp,C=US",
          "issuer": "CN=Corp Intermediate ECC CA,O=Finance Corp,C=US",
          "curve": "secp521r1",
          "key_size": 521,
          "is_ca": false,
          "is_self_signed": false
        },
        "p521_cas": [
          {
            "depth": 1,
            "subject": "CN=Corp Intermediate ECC CA,O=Finance Corp,C=US",
            "issuer": "CN=Corp Root CA G2,O=Finance Corp,C=US",
            "curve": "secp521r1",
            "key_size": 521,
            "is_ca": true,
            "is_self_signed": false
          }
        ],
        "inspected_certs": [],
        "error": null,
        "chain_length": 2
      }
    ]
  }
]
```

---

## Troubleshooting Guide

### NGINX Handshake Failure (`tlsv1 alert handshake failure`)

If an NGINX backend server using a P-521 certificate reports a handshake failure:

1. **Virtual Host & SNI Routing**:
   If NGINX has `ssl_reject_handshake on;` or name-based `server_name` blocks, connecting by raw IP triggers an immediate rejection. Use `--sni`:
   ```bash
   uv run big-ip-pool-member-p512-cert.py -f bigip.conf --sni myapp.example.com -v
   ```

2. **Verify NGINX Curve Support**:
   Confirm that your `nginx.conf` allows the P-521 curve:
   ```nginx
   ssl_ecdh_curve secp521r1:secp384r1:prime256v1:X25519;
   ```

3. **Direct OpenSSL Verification**:
   Verify the endpoint directly using `openssl s_client`:
   ```bash
   openssl s_client -connect <IP>:443 -curves P-521:secp521r1 -servername myapp.example.com
   ```

---

## License

This project is distributed under the MIT License. See [LICENSE](LICENSE) for details.