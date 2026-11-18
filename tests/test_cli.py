import unittest
from authtrail.cli import analyze

class AnalyzeTests(unittest.TestCase):
    def test_groups_failures_and_reports_successes(self):
        lines = [
            "Nov 18 10:00:00 host sshd[10]: Failed password for invalid user demo from 192.0.2.8 port 22 ssh2",
            "Nov 18 10:01:00 host sshd[11]: Failed password for demo from 192.0.2.8 port 22 ssh2",
            "Nov 18 10:02:00 host sshd[12]: Accepted publickey for alice from 192.0.2.9 port 22 ssh2",
        ]
        result = analyze(lines, threshold=2)
        self.assertEqual(result["failure_events"], 2)
        self.assertEqual(result["successful_events"], 1)
        self.assertEqual(result["sources_at_or_above_threshold"], [{"source": "192.0.2.8", "failed_attempts": 2}])

    def test_threshold_is_validated(self):
        with self.assertRaises(ValueError):
            analyze([], threshold=0)

if __name__ == "__main__":
    unittest.main()
