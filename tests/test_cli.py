import unittest

from cli import build_parser, parse_ports


class CLITests(unittest.TestCase):
    def test_port_parser(self):
        self.assertEqual(parse_ports("80,443,8000-8002"), [80, 443, 8000, 8001, 8002])

    def test_parser_retry_flag(self):
        args = build_parser().parse_args(["192.0.2.10", "-rt", "--fast"])
        self.assertTrue(args.retry_timeouts)
        self.assertEqual(args.profile, "fast")

    def test_parser_disable_retry_flag(self):
        args = build_parser().parse_args(["192.0.2.10", "--no-retry-timeouts"])
        self.assertFalse(args.retry_timeouts)


if __name__ == "__main__":
    unittest.main()
