
import unittest
from datetime import datetime, timedelta

from detection import detect_brute_force


class TestBruteForceDetection(unittest.TestCase):

    def test_rapid_failed_logins(self):
        start = datetime(2026, 10, 11, 10, 0, 0)

        attempts = {
            "192.0.2.10": [
                start,
                start + timedelta(seconds=5),
                start + timedelta(seconds=10)
            ]
        }

        result = detect_brute_force(attempts)
        self.assertIn("192.0.2.10", result)

    def test_spread_out_failed_logins(self):
        start = datetime(2026, 10, 11, 10, 0, 0)

        attempts = {
            "192.0.2.10": [
                start,
                start + timedelta(minutes=5),
                start + timedelta(minutes=10)
            ]
        }

        result = detect_brute_force(attempts)
        self.assertNotIn("192.0.2.10", result)

    def test_below_threshold(self):
        start = datetime(2026, 10, 11, 10, 0, 0)

        attempts = {
            "198.51.100.15": [
                start,
                start + timedelta(seconds=10)
            ]
        }

        result = detect_brute_force(attempts)
        self.assertEqual(len(result), 0)


if __name__ == "__main__":
    unittest.main()
