import asyncio
import unittest

from discovery import discover_host
from models import TargetSpec


class DiscoveryTests(unittest.TestCase):
    def test_tcp_fallback_marks_host_alive(self):
        async def run():
            async def handler(reader, writer):
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            target = TargetSpec("127.0.0.1", "127.0.0.1", "IPv4", "127.0.0.1")
            try:
                result = await discover_host(target, (port,), timeout_sec=0.2, use_icmp=False)
                self.assertTrue(result.alive)
                self.assertEqual(result.method, f"TCP/{port}")
            finally:
                server.close()
                await server.wait_closed()

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
