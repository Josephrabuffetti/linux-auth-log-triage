import unittest
from datetime import datetime

from auth_log_triage import AuthEvent, analyze, parse_line, parse_lines


class ParseTests(unittest.TestCase):
    def test_parses_failed_invalid_user(self):
        event = parse_line(
            "Oct  1 09:14:02 lab-vm sshd[2041]: Failed password for invalid user admin from 203.0.113.44 port 50101 ssh2",
            2026,
        )
        self.assertEqual(event, AuthEvent(datetime(2026, 10, 1, 9, 14, 2), "admin", "203.0.113.44", "failed"))

    def test_parses_success_and_ipv6(self):
        event = parse_line(
            "2026-10-01T09:19:20Z lab-vm sshd[2046]: Accepted publickey for labuser from 2001:db8::10 port 50106 ssh2",
            1999,
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.outcome, "accepted")
        self.assertEqual(event.source_ip, "2001:db8::10")

    def test_ignores_unrelated_records(self):
        self.assertIsNone(parse_line("Oct  1 10:05:44 lab-vm sshd[2105]: session opened for user analyst", 2026))

    def test_counts_unparsed_lines(self):
        events, skipped = parse_lines(["not a log line\n", "Oct  1 09:14:02 lab sshd[1]: Failed password for x from 192.0.2.1 port 2 ssh2\n"], 2026)
        self.assertEqual(len(events), 1)
        self.assertEqual(skipped, 1)


class DetectionTests(unittest.TestCase):
    @staticmethod
    def event(minute: int, outcome: str = "failed", ip: str = "203.0.113.44", user: str = "student"):
        return AuthEvent(datetime(2026, 10, 1, 9, minute), user, ip, outcome)

    def test_flags_repeated_failures_from_one_ip(self):
        events = [self.event(minute) for minute in range(10, 15)]
        report = analyze(events)
        self.assertEqual(report["alerts"][0]["type"], "repeated_failed_logins")
        self.assertEqual(report["alerts"][0]["failed_attempts"], 5)

    def test_does_not_flag_below_threshold_or_across_ips(self):
        events = [self.event(10 + i, ip=f"192.0.2.{i}") for i in range(5)]
        self.assertEqual(analyze(events)["alerts"], [])

    def test_flags_success_after_prior_failures_from_same_ip(self):
        events = [self.event(minute) for minute in (10, 11, 12)]
        events.append(self.event(14, outcome="accepted", user="labuser"))
        report = analyze(events)
        self.assertTrue(any(alert["type"] == "successful_login_after_repeated_failures" for alert in report["alerts"]))

    def test_does_not_correlate_failures_after_success(self):
        events = [self.event(10, outcome="accepted")] + [self.event(minute) for minute in (11, 12, 13)]
        report = analyze(events)
        self.assertFalse(any(alert["type"] == "successful_login_after_repeated_failures" for alert in report["alerts"]))

    def test_validates_thresholds(self):
        with self.assertRaises(ValueError):
            analyze([], threshold=1)


if __name__ == "__main__":
    unittest.main()
