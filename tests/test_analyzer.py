import unittest

from analyzer import analyze_results, build_patterns, format_port_ranges
from models import PortResult, PortState, ProbeResult


def timeout_result(port: int, attempts: int = 3) -> PortResult:
    probes = [ProbeResult(i, PortState.TIMEOUT, None, "timeout") for i in range(1, attempts + 1)]
    return PortResult("192.0.2.10", port, PortState.TIMEOUT, None, probes)


class AnalyzerTests(unittest.TestCase):
    def test_format_port_ranges(self):
        self.assertEqual(format_port_ranges([1, 2, 3, 5, 7, 8]), "1-3 5 7-8")

    def test_timeout_analysis_groups_patterns(self):
        results = [timeout_result(port) for port in range(1, 6)] + [
            PortResult("192.0.2.10", 6, PortState.CLOSED, 2.0)
        ]
        assessments = analyze_results(results)
        patterns = build_patterns(assessments)
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0].ports, [1, 2, 3, 4, 5])


if __name__ == "__main__":
    unittest.main()
