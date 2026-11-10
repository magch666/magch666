from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DesignConsistencyTests(unittest.TestCase):
    def test_all_documented_vlans_exist_in_config(self):
        config = (ROOT / "configs/access-switch.txt").read_text()
        for vlan in ("10", "20", "30", "40", "999"):
            self.assertIn(f"vlan {vlan}", config)

    def test_guest_is_denied_internal_access_in_matrix(self):
        readme = (ROOT / "README.md").read_text()
        self.assertIn("| Guest | Internal VLANs | Deny |", readme)

    def test_unused_ports_are_disabled(self):
        config = (ROOT / "configs/access-switch.txt").read_text()
        self.assertIn("interface range GigabitEthernet0/3-23", config)
        self.assertIn(" shutdown", config)


if __name__ == "__main__":
    unittest.main()
