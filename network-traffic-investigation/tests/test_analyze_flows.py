import unittest
from src.analyze_flows import analyze


def row(port, src="192.0.2.1", dst="192.0.2.2"):
    return {"timestamp": "2026-11-02T10:00:00Z", "src_ip": src, "dst_ip": dst,
            "src_port": "50000", "dst_port": str(port), "protocol": "TCP",
            "bytes": "100", "direction": "internal"}


class FlowAnalyzerTests(unittest.TestCase):
    def test_flags_port_fanout(self):
        report = analyze([row(p) for p in (22, 80, 443, 445)])
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["unique_destination_ports"], 4)

    def test_does_not_flag_below_threshold(self):
        self.assertEqual(analyze([row(443)])["findings"], [])

    def test_rejects_invalid_threshold(self):
        with self.assertRaises(ValueError):
            analyze([], 1)

    def test_rejects_invalid_bytes(self):
        item = row(443)
        item["bytes"] = "-5"
        with self.assertRaises(ValueError):
            analyze([item])


if __name__ == "__main__":
    unittest.main()
