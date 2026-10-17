import unittest
import time
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.telemetry.pqc_sealer import PQCTelemetryBlockSealer

class TestPQCTelemetrySealerInvariants(unittest.TestCase):
    def setUp(self):
        self.sealer = PQCTelemetryBlockSealer()

    def test_telemetry_digest_determinism_and_tamper_rejection(self):
        """Invariant 9: Signed frame packets must verify cleanly and fail on single-bit mutations."""
        ts = time.perf_counter_ns()
        channels = [0.123456 * i for i in range(16)]
        digest, tag = self.sealer.seal_frame(ts, channels)

        self.assertTrue(self.sealer.verify_frame(ts, channels, tag), "Valid telemetry block failed verification")

        tampered_channels = list(channels)
        tampered_channels[0] += 1e-5
        self.assertFalse(self.sealer.verify_frame(ts, tampered_channels, tag), "Tampered telemetry frame passed signature check")

    def test_ephemeral_key_zeroization(self):
        """Invariant 10: Private key buffer must contain exclusively 0x00 bytes post-scrubbing."""
        scrub_success = self.sealer.scrub_keys()
        self.assertTrue(scrub_success, "Key zeroization check failed")
        self.assertEqual(bytes(self.sealer._signing_key), b"\x00" * len(self.sealer._signing_key))

if __name__ == "__main__":
    unittest.main()
