import asyncio
import socket
import unittest

from models import PortState
from scanner import probe_port


class ScannerTests(unittest.TestCase):
    def test_probe_local_server(self):
        async def run():
            async def handler(reader, writer):
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            try:
                opened = await probe_port("127.0.0.1", port, 0.5, 1)
                self.assertEqual(opened.state, PortState.OPEN)
            finally:
                server.close()
                await server.wait_closed()

        asyncio.run(run())

    def test_probe_connection_refused_is_closed(self):
        from unittest.mock import patch

        async def fake_connect(*_args, **_kwargs):
            raise ConnectionRefusedError(10061, "connection refused")

        async def run():
            with patch("scanner._connect", new=fake_connect):
                result = await probe_port("127.0.0.1", 9, 0.2, 1)
            self.assertEqual(result.state, PortState.CLOSED)

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()

class RetryModeTests(unittest.TestCase):
    def test_retry_is_disabled_by_default(self):
        from config import ScanConfig
        from scanner import retry_timeouts
        from models import PortResult, PortState, ProbeResult

        result = PortResult(
            "192.0.2.10",
            12345,
            PortState.TIMEOUT,
            None,
            [ProbeResult(1, PortState.TIMEOUT, None, "timeout")],
        )
        updated, resolved = retry_timeouts([result], ScanConfig(timeout_sec=0.1, workers=2), "12345")
        self.assertEqual(resolved, 0)
        self.assertEqual(len(updated[0].attempts), 1)


if __name__ == "__main__":
    unittest.main()
