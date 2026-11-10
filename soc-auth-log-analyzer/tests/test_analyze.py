import unittest

from src.analyze import analyze_events


def event(timestamp, source, status, username="user"):
    return {
        "timestamp": timestamp,
        "source_ip": source,
        "username": username,
        "status": status,
    }


class AnalyzeEventsTests(unittest.TestCase):
    def test_detects_success_after_failure_threshold(self):
        events = [
            event("2026-11-01T09:00:00Z", "192.0.2.10", "failure"),
            event("2026-11-01T09:00:08Z", "192.0.2.10", "failure"),
            event("2026-11-01T09:00:15Z", "192.0.2.10", "failure"),
            event("2026-11-01T09:00:30Z", "192.0.2.10", "success"),
        ]
        report = analyze_events(events)
        self.assertEqual(report["events_processed"], 4)
        self.assertEqual(report["findings"][0]["severity"], "review")
        self.assertTrue(report["findings"][0]["successful_login_after_threshold"])

    def test_does_not_flag_below_threshold(self):
        events = [
            event("2026-11-01T09:00:00Z", "192.0.2.10", "failure"),
            event("2026-11-01T09:00:30Z", "192.0.2.10", "success"),
        ]
        self.assertEqual(analyze_events(events)["findings"], [])

    def test_rejects_invalid_threshold(self):
        with self.assertRaises(ValueError):
            analyze_events([], threshold=0)

    def test_rejects_unknown_status(self):
        with self.assertRaises(ValueError):
            analyze_events([event("2026-11-01T09:00:00Z", "192.0.2.10", "unknown")])


if __name__ == "__main__":
    unittest.main()
