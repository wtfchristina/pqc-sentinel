import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.audit.pqc_scanner import PQCScanner

class TestPQCScannerInvariants(unittest.TestCase):
    def setUp(self):
        self.scanner = PQCScanner()

    def test_cnsa_2_0_timeline_enforcement(self):
        legacy_code = """
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ec_key = ec.generate_private_key(ec.SECP256R1())
        """
        results = self.scanner.scan_source(legacy_code)
        vuln_types = [r["algorithm"] for r in results if r["severity"] == "CRITICAL"]
        self.assertIn("RSA", vuln_types, "Failed to flag legacy RSA under CNSA 2.0")
        self.assertIn("ECDSA/SECP256R1", vuln_types, "Failed to flag non-quantum-safe curve SECP256R1")

    def test_fips_203_ml_kem_detection(self):
        valid_pqc_code = """
        import oqs
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        public_key = kem.generate_keypair()
        """
        results = self.scanner.scan_source(valid_pqc_code)
        compliant = [r for r in results if r.get("status") == "COMPLIANT"]
        self.assertTrue(len(compliant) > 0, "Failed to identify compliant ML-KEM-768 instantiation")

    def test_zeroization_after_decapsulation(self):
        leaky_code = """
        def process_secret(sk_bytes):
            token = sk_bytes[:32]
            return token
        """
        results = self.scanner.scan_source(leaky_code)
        issues = [r["rule"] for r in results]
        self.assertIn("MISSING_ZEROIZATION", issues, "Failed to flag unzeroized sensitive key buffer")

if __name__ == "__main__":
    unittest.main()
