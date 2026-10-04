import json
import os
import tempfile
import unittest

from config import ScanConfig
from models import PortResult, PortState, ProbeResult
from state import ScanState


class V11Tests(unittest.TestCase):
    def test_toml_config(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "cadeur.toml")
            with open(path, "w", encoding="utf-8") as f:
                f.write('profile = "fast"\nworkers = 111\ncheckpoint_every = 25\n[service]\nworkers = 7\n')
            cfg = ScanConfig.from_toml(path)
        self.assertEqual(cfg.profile, "fast")
        self.assertEqual(cfg.workers, 111)
        self.assertEqual(cfg.checkpoint_every, 25)
        self.assertEqual(cfg.service_workers, 7)

    def test_state_round_trip(self):
        result = PortResult(
            "127.0.0.1",
            8080,
            PortState.OPEN,
            1.2,
            [ProbeResult(1, PortState.OPEN, 1.2)],
            address="127.0.0.1",
            family="IPv4",
            target_id="127.0.0.1",
        )
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "scan.json")
            state = ScanState(path)
            state.save_results(
                "127.0.0.1",
                [result],
                host="127.0.0.1",
                address="127.0.0.1",
                family="IPv4",
                ports_signature="80,8080",
            )
            loaded = state.load_results("127.0.0.1", "80,8080")
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].port, 8080)
            self.assertEqual(loaded[0].state, PortState.OPEN)
            state.mark_complete()
            with open(path, encoding="utf-8") as f:
                payload = json.load(f)
        self.assertTrue(payload["completed"])

    def test_state_signature_prevents_wrong_resume(self):
        result = PortResult("127.0.0.1", 80, PortState.OPEN, 1.0)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "scan.json")
            state = ScanState(path)
            state.save_results(
                "127.0.0.1", [result], host="127.0.0.1", address="127.0.0.1", family="IPv4", ports_signature="80"
            )
            self.assertEqual(state.load_results("127.0.0.1", "443"), [])


if __name__ == "__main__":
    unittest.main()
