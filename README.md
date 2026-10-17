# PQC-Sentinel

Post-Quantum Cryptographic compliance auditor and line-rate telemetry block sealer adhering to NIST FIPS 203/204/205 and NSA CNSA 2.0 standards.

## Capabilities

* **AST & Binary Scanner:** Automated static discovery of deprecated public-key cryptography (RSA, ECDSA, ECDH) and legacy hash functions across enterprise repositories.
* **FIPS 204 Block Sealer:** Digital signature encapsulation using module-lattice-based algorithms with HMAC-SHA3-512 authentication.
* **Zeroization Harness:** Assembly-level verification ensuring ephemeral secret keys and intermediate states are completely scrubbed from memory after sealing.

## Verification & Auditing

Run the standalone compliance scan:
```bash
python3 tools/audit/pqc_scanner.py . --output audit_report.json
```

Run cryptographic tests:
```bash
python3 -m unittest discover -s tests -p "test_*.py"
```
