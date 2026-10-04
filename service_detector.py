from __future__ import annotations

import asyncio
import re
import ssl
from typing import Awaitable, Callable, Sequence

from models import PortResult, PortState, ServiceInfo

Probe = Callable[[str, int, float], Awaitable[ServiceInfo | None]]


def _parse_http(data: bytes) -> tuple[str, str | None, str | None, dict]:
    text = data.decode("iso-8859-1", "replace")
    first = text.splitlines()[0] if text.splitlines() else "HTTP response"
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+(.*))?", first)
    status = match.group(1) if match else None
    headers = {}
    for line in text.split("\r\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:120] if title_match else None
    return first[:200], status, title, headers


async def _open(host: str, port: int, timeout: float, ssl_context: ssl.SSLContext | None = None):
    return await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ssl_context), timeout=timeout)


async def probe_http(host: str, port: int, timeout: float, secure: bool = False) -> ServiceInfo | None:
    context = None
    name = "HTTPS" if secure else "HTTP"
    method = "HTTPS request" if secure else "HTTP request"
    if secure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    writer = None
    try:
        reader, writer = await _open(host, port, timeout, context)
        request = f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        writer.write(request)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        ssl_obj = writer.get_extra_info("ssl_object")
        if not data.startswith(b"HTTP/"):
            return None
        first, status, title, headers = _parse_http(data)
        return ServiceInfo(
            host,
            port,
            name,
            99,
            first,
            method,
            first,
            headers.get("server"),
            None,
            {"status": status, "title": title, "server": headers.get("server"), "tls": bool(ssl_obj)},
        )
    except Exception:
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def probe_http_plain(host: str, port: int, timeout: float) -> ServiceInfo | None:
    return await probe_http(host, port, timeout, False)


async def probe_https(host: str, port: int, timeout: float) -> ServiceInfo | None:
    return await probe_http(host, port, timeout, True)


async def probe_banner(host: str, port: int, timeout: float) -> ServiceInfo | None:
    writer = None
    try:
        reader, writer = await _open(host, port, timeout)
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        text = data.decode("utf-8", "replace").strip()[:256]
        low = text.lower()
        checks = [
            ("SSH", 99, "ssh-", "SSH banner"),
            ("FTP", 95, "220 ", "FTP banner"),
            ("SMTP", 95, "220 ", "SMTP banner"),
            ("POP3", 95, "+ok", "POP3 banner"),
            ("IMAP", 95, "* ok", "IMAP banner"),
        ]
        for name, confidence, marker, probe_method in checks:
            if marker in low:
                return ServiceInfo(host, port, name, confidence, text, probe_method, text)
    except Exception:
        pass
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    return None


def _smb2_negotiate_request() -> bytes:
    dialects = b"\x02\x02\x10\x02\x00\x03\x02\x03\x11\x03"
    body = bytearray()
    body += (36).to_bytes(2, "little")
    body += (0).to_bytes(2, "little")
    body += (1).to_bytes(2, "little")
    body += (0).to_bytes(2, "little")
    body += b"\x00" * 16
    body += (0).to_bytes(4, "little")
    body += (0).to_bytes(8, "little")
    body += dialects
    header = bytearray()
    header += b"\xfeSMB"
    header += (64).to_bytes(2, "little")
    header += b"\x00\x00\x00\x00"
    header += (0).to_bytes(2, "little")
    header += (0).to_bytes(2, "little")
    header += (0).to_bytes(4, "little")
    header += (0).to_bytes(4, "little")
    header += (0).to_bytes(8, "little")
    header += (0).to_bytes(4, "little")
    header += (0).to_bytes(4, "little")
    header += (0).to_bytes(8, "little")
    header += (0).to_bytes(16, "little")
    payload = bytes(header) + bytes(body)
    return len(payload).to_bytes(4, "big") + payload


async def probe_smb(host: str, port: int, timeout: float) -> ServiceInfo | None:
    if port != 445:
        return None
    writer = None
    try:
        reader, writer = await _open(host, port, timeout)
        writer.write(_smb2_negotiate_request())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        if b"\xfeSMB" in data[:64]:
            return ServiceInfo(host, port, "SMB", 99, "SMB2 response", "SMB2 negotiate", "SMB2 protocol response")
    except Exception:
        pass
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    return None


async def probe_tls(host: str, port: int, timeout: float) -> ServiceInfo | None:
    writer = None
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        _reader, writer = await _open(host, port, timeout, context)
        ssl_obj = writer.get_extra_info("ssl_object")
        metadata = {}
        if ssl_obj is not None:
            metadata["cipher"] = ssl_obj.cipher()
            metadata["version"] = ssl_obj.version()
            metadata["peer_certificate"] = bool(ssl_obj.getpeercert())
        return ServiceInfo(host, port, "TLS", 80, None, "TLS handshake", "TLS handshake accepted", None, metadata.get("version"), metadata)
    except Exception:
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


PROBE_MAP: dict[str, Probe] = {
    "HTTP": probe_http_plain,
    "HTTPS": probe_https,
    "SSH/FTP/MAIL": probe_banner,
    "SMB": probe_smb,
    "TLS": probe_tls,
}

PORT_HINTS: dict[int, tuple[str, ...]] = {
    21: ("SSH/FTP/MAIL",),
    22: ("SSH/FTP/MAIL",),
    25: ("SSH/FTP/MAIL",),
    80: ("HTTP", "HTTPS"),
    110: ("SSH/FTP/MAIL",),
    143: ("SSH/FTP/MAIL",),
    443: ("HTTPS", "HTTP"),
    445: ("SMB",),
    3389: ("TLS",),
    8080: ("HTTP", "HTTPS"),
    8000: ("HTTP", "HTTPS"),
    8443: ("HTTPS", "HTTP"),
}


def get_probe_order(port: int) -> tuple[str, ...]:
    hinted = list(PORT_HINTS.get(port, ()))
    generic = ("SSH/FTP/MAIL", "HTTP", "HTTPS", "SMB", "TLS")
    for name in generic:
        if name not in hinted:
            hinted.append(name)
    return tuple(hinted)


async def detect_service_async(result: PortResult, timeout: float = 0.8) -> ServiceInfo:
    if result.state is not PortState.OPEN:
        raise ValueError("service detection requires an OPEN port")
    for probe_name in get_probe_order(result.port):
        info = await PROBE_MAP[probe_name](result.host, result.port, timeout)
        if info is not None:
            return info
    return ServiceInfo(result.host, result.port, "UNKNOWN", 0, None, "no positive probe", None)


async def detect_services_async(results: Sequence[PortResult], workers: int = 24, timeout: float = 0.8) -> list[ServiceInfo]:
    open_results = [result for result in results if result.state is PortState.OPEN]
    semaphore = asyncio.Semaphore(max(1, workers))

    async def one(result: PortResult) -> ServiceInfo:
        async with semaphore:
            return await detect_service_async(result, timeout)

    return await asyncio.gather(*(one(result) for result in open_results))


def detect_services(results: Sequence[PortResult], workers: int = 24, timeout: float = 0.8) -> list[ServiceInfo]:
    if not any(result.state is PortState.OPEN for result in results):
        return []
    return asyncio.run(detect_services_async(results, workers, timeout))


def detect_service(result: PortResult, timeout: float = 0.8) -> ServiceInfo:
    return asyncio.run(detect_service_async(result, timeout))
