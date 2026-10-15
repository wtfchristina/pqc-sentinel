import re

class PQCScanner:
    CLASSICAL_PATTERNS = [
        (r"rsa\.generate_private_key", "RSA", "CRITICAL", "Deprecated under CNSA 2.0 timeline."),
        (r"SECP256R1|SECP384R1|SECP521R1", "ECDSA/SECP256R1", "CRITICAL", "Classical curve non-quantum-safe."),
        (r"hazmat\.primitives\.asymmetric\.dsa", "DSA", "CRITICAL", "Classical signature vulnerable to Shor's algorithm.")
    ]

    FIPS_PATTERNS = [
        (r"ML-KEM-768|ML-KEM-1024", "FIPS_203", "COMPLIANT", "NIST FIPS 203 Approved KEM parameter set."),
        (r"ML-DSA-65|ML-DSA-87", "FIPS_204", "COMPLIANT", "NIST FIPS 204 Approved signature standard."),
        (r"SLH-DSA-SHA2-128s|SLH-DSA-SHAKE-128s", "FIPS_205", "COMPLIANT", "NIST FIPS 205 Stateless Hash-Based Signatures.")
    ]

    def scan_source(self, code_str: str) -> list[dict]:
        findings = []

        for pattern, algo, severity, desc in self.CLASSICAL_PATTERNS:
            if re.search(pattern, code_str):
                findings.append({
                    "algorithm": algo,
                    "severity": severity,
                    "description": desc,
                    "status": "NON_COMPLIANT"
                })

        for pattern, standard, status, desc in self.FIPS_PATTERNS:
            if re.search(pattern, code_str):
                findings.append({
                    "standard": standard,
                    "status": status,
                    "description": desc
                })

        if re.search(r"sk_bytes|private_key|secret_key", code_str):
            if not re.search(r"zeroize|memset_s|explicit_bzero|\.fill\(0\)", code_str):
                findings.append({
                    "rule": "MISSING_ZEROIZATION",
                    "severity": "HIGH",
                    "status": "NON_COMPLIANT",
                    "description": "Sensitive key buffer detected without verifiable memory zeroization."
                })

        return findings
