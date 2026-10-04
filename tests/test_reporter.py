import json
import os
import tempfile
import unittest

from models import HostDiscoveryResult, HostReport, PortResult, PortState, ProbeResult, TargetSpec
from reporter import export_html, export_json


class ReporterTests(unittest.TestCase):
    def _report(self):
        result = PortResult("192.0.2.10", 443, PortState.OPEN, 2.5, [ProbeResult(1, PortState.OPEN, 2.5)])
        target = TargetSpec("192.0.2.10", "192.0.2.10", "IPv4", "192.0.2.10")
        discovery = HostDiscoveryResult("192.0.2.10", "192.0.2.10", True, "ASSUMED TARGET")
        return HostReport(target, discovery, [result])

    def test_json_export_schema_1(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "report.json")
            export_json(path, [self._report()])
            with open(path, encoding="utf-8") as f:
                payload = json.load(f)
        self.assertEqual(payload["schema_version"], "1.0")
        self.assertEqual(payload["summary"]["open"], 0)
        self.assertEqual(payload["hosts"][0]["results"][0]["port"], 443)

    def test_html_export(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "report.html")
            export_html(path, [self._report()])
            with open(path, encoding="utf-8") as f:
                content = f.read()
        self.assertIn("CADEUR v1.1", content)
        self.assertIn("443/tcp", content)


if __name__ == "__main__":
    unittest.main()
