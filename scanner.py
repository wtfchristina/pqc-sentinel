import asyncio
"""
PQC Sentinel: TLS 1.3 Post-Quantum Compliance & Audit Scanner
Supports single targets or batch audits from a text file, exporting to CSV.
"""

import csv
import socket
import struct
import sys
from datetime import datetime, timezone

# IANA TLS Named Groups
GROUPS = {
    0x11EC: "X25519MLKEM768 (Post-Quantum Hybrid - NIST FIPS 203)",
    0x11EB: "SecP256r1MLKEM768 (Post-Quantum Hybrid)",
    0x11ED: "SecP384r1MLKEM1024 (Post-Quantum Hybrid)",
    0x001D: "X25519 (Classical ECDHE - Quantum Vulnerable)",
    0x0017: "secp256r1 (Classical ECDHE - Quantum Vulnerable)",
}

PQC_GROUPS = {0x11EC, 0x11EB, 0x11ED}


def build_probe(hostname: str) -> bytes:
    client_random = b"\x5a" * 32

    ciphers = (
        b"\x13\x01"  # TLS_AES_128_GCM_SHA256
        b"\x13\x02"  # TLS_AES_256_GCM_SHA384
        b"\x13\x03"  # TLS_CHACHA20_POLY1305_SHA256
        b"\xc0\x2b"  # ECDHE-ECDSA-AES128-GCM-SHA256
        b"\xc0\x2f"  # ECDHE-RSA-AES128-GCM-SHA256
    )
    cipher_suites = struct.pack("!H", len(ciphers)) + ciphers
    compression = b"\x01\x00"

    # SNI Extension
    host_bytes = hostname.encode("utf-8")
    sni_content = (
        struct.pack("!H", len(host_bytes) + 3)
        + b"\x00"
        + struct.pack("!H", len(host_bytes))
        + host_bytes
    )
    ext_sni = struct.pack("!HH", 0x0000, len(sni_content)) + sni_content

    # Supported Versions (TLS 1.3 + TLS 1.2)
    versions_content = b"\x04\x03\x04\x03\x03"
    ext_versions = struct.pack("!HH", 0x002B, len(versions_content)) + versions_content

    # Supported Groups (PQC + Classical)
    groups_list = struct.pack("!HHHHH", 0x11EC, 0x11EB, 0x11ED, 0x001D, 0x0017)
    groups_content = struct.pack("!H", len(groups_list)) + groups_list
    ext_groups = struct.pack("!HH", 0x000A, len(groups_content)) + groups_content

    # Signature Algorithms
    sig_algs = struct.pack("!HHHH", 0x0403, 0x0804, 0x0401, 0x0501)
    sig_content = struct.pack("!H", len(sig_algs)) + sig_algs
    ext_sig = struct.pack("!HH", 0x000D, len(sig_content)) + sig_content

    # Key Shares (X25519 fallback + ML-KEM-768)
    share_x25519 = struct.pack("!HH", 0x001D, 32) + (b"\x07" * 32)
    share_mlkem = struct.pack("!HH", 0x11EC, 1216) + (b"\x08" * 1216)
    key_shares_payload = share_x25519 + share_mlkem
    key_shares_content = struct.pack("!H", len(key_shares_payload)) + key_shares_payload
    ext_key_shares = struct.pack("!HH", 0x0033, len(key_shares_content)) + key_shares_content

    all_extensions = ext_sni + ext_versions + ext_groups + ext_sig + ext_key_shares
    extensions_block = struct.pack("!H", len(all_extensions)) + all_extensions

    body = (
        b"\x03\x03"
        + client_random
        + b"\x00"
        + cipher_suites
        + compression
        + extensions_block
    )

    handshake_msg = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake_msg)) + handshake_msg


def audit_host(hostname: str, port: int = 443, timeout: float = 4.0) -> dict:
    packet = build_probe(hostname)
    result = {
        "domain": hostname,
        "port": port,
        "status": "ERROR",
        "group": "None",
        "posture": "UNKNOWN",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            sock.sendall(packet)
            response = sock.recv(4096)
    except Exception as err:
        result["status"] = "FAILED"
        result["posture"] = f"Connection error: {err}"
        return result

    if len(response) < 5 or response[0] != 0x16:
        result["status"] = "REJECTED"
        result["posture"] = "No TLS Handshake record returned"
        return result

    idx = response.find(b"\x00\x33")
    if idx == -1:
        result["status"] = "VULNERABLE"
        result["group"] = "Legacy / Non-PQC"
        result["posture"] = "Classical exchange only (Harvest Now, Decrypt Later)"
        return result

    group_id = struct.unpack("!H", response[idx + 4 : idx + 6])[0]
    group_name = GROUPS.get(group_id, f"0x{group_id:04x}")
    result["group"] = group_name

    if group_id in PQC_GROUPS:
        result["status"] = "SECURE"
        result["posture"] = "Active Post-Quantum Protection (FIPS 203)"
    else:
        result["status"] = "VULNERABLE"
        result["posture"] = "Classical key exchange in use (Vulnerable)"

    return result



async def audit_host_async(hostname: str, port: int = 443, timeout: float = 4.0) -> dict:
    return await asyncio.to_thread(audit_host, hostname, port, timeout)

async def audit_hosts_concurrent(domains: list[str]) -> list[dict]:
    tasks = [audit_host_async(domain) for domain in domains]
    return await asyncio.gather(*tasks)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py <domain_or_file> [--csv output.csv]")
        sys.exit(1)

    arg = sys.argv[1]
    csv_file = sys.argv[3] if len(sys.argv) > 3 and sys.argv[2] == "--csv" else "pqc_audit_report.csv"

    # Check if target is a file or single hostname
    targets = []
    if arg.endswith(".txt"):
        try:
            with open(arg, "r") as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception as e:
            print(f"[-] Could not read targets file: {e}")
            sys.exit(1)
    else:
        targets = [arg]

    print(f"\n[+] Running Post-Quantum TLS Audit on {len(targets)} target(s)...")
    results = []

    print("-" * 75)
    print(f"{'DOMAIN':<30} | {'STATUS':<12} | {'KEY EXCHANGE GROUP'}")
    print("-" * 75)

    for domain in targets:
        res = audit_host(domain)
        results.append(res)
        print(f"{res['domain']:<30} | {res['status']:<12} | {res['group']}")

    print("-" * 75)

    # Save to CSV
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "port", "status", "group", "posture", "timestamp"])
        writer.writeheader()
        writer.writerows(results)

    print(f"[+] Audit complete. Report saved to: {csv_file}\n")


if __name__ == "__main__":
    main()
