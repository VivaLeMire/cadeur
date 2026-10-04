import asyncio
import unittest

from models import PortResult, PortState
from service_detector import detect_service_async


class ServiceDetectorTests(unittest.TestCase):
    def test_detect_http_on_nonstandard_port(self):
        async def handler(reader, writer):
            try:
                await reader.read(1024)
                writer.write(b"HTTP/1.1 200 OK\r\nServer: test-server\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        async def run():
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            try:
                result = PortResult("127.0.0.1", port, PortState.OPEN, 1.0)
                service = await detect_service_async(result, 0.5)
                self.assertEqual(service.name, "HTTP")
                self.assertEqual(service.confidence, 99)
            finally:
                server.close()
                await server.wait_closed()
                await asyncio.sleep(0.05)

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
