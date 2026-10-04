from __future__ import annotations

import asyncio
import platform
import socket
import time

from models import HostDiscoveryResult, TargetSpec
from scanner import probe_resolved


async def _icmp_probe(address: str, timeout_sec: float) -> tuple[bool, float | None]:
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", str(max(1, int(timeout_sec * 1000))), address]
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, int(timeout_sec)) or 1), address]
    started = time.perf_counter()
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(process.wait(), timeout=max(timeout_sec + 0.5, 0.8))
    except (FileNotFoundError, asyncio.TimeoutError, OSError):
        return False, None
    latency = (time.perf_counter() - started) * 1000
    return process.returncode == 0, latency if process.returncode == 0 else None


async def _tcp_probe(address: str, family: int, port: int, timeout_sec: float) -> tuple[bool, float | None, str]:
    result = await probe_resolved(address, port, family, timeout_sec, 1)
    if result.state.value == "OPEN":
        return True, result.latency_ms, f"tcp/{port} open"
    if result.state.value == "CLOSED":
        return True, result.latency_ms, f"tcp/{port} refused"
    return False, result.latency_ms, f"tcp/{port} {result.state.value.lower()}"


async def discover_host(
    target: TargetSpec,
    ports: tuple[int, ...],
    timeout_sec: float = 0.35,
    use_icmp: bool = True,
    workers: int = 32,
) -> HostDiscoveryResult:
    family = socket.AF_INET6 if target.family == "IPv6" else socket.AF_INET
    probes: list[str] = []

    if use_icmp:
        alive, latency = await _icmp_probe(target.address, timeout_sec)
        probes.append("icmp")
        if alive:
            return HostDiscoveryResult(target.value, target.address, True, "ICMP", latency, "ICMP echo reply", probes)

    semaphore = asyncio.Semaphore(max(1, workers))

    async def one(port: int):
        async with semaphore:
            return port, await _tcp_probe(target.address, family, port, timeout_sec)

    results = await asyncio.gather(*(one(port) for port in ports))
    for port, (alive, latency, evidence) in results:
        probes.append(f"tcp/{port}")
        if alive:
            method = evidence.split()[0].upper() if evidence else f"TCP/{port}"
            return HostDiscoveryResult(target.value, target.address, True, method, latency, evidence, probes)

    return HostDiscoveryResult(target.value, target.address, False, "UNREACHABLE", None, "no discovery response", probes)


async def discover_targets_async(
    targets: list[TargetSpec],
    ports: tuple[int, ...],
    timeout_sec: float = 0.35,
    workers: int = 32,
    use_icmp: bool = True,
) -> list[HostDiscoveryResult]:
    semaphore = asyncio.Semaphore(max(1, workers))

    async def one(target: TargetSpec):
        async with semaphore:
            return await discover_host(target, ports, timeout_sec, use_icmp, workers=min(16, workers))

    return await asyncio.gather(*(one(target) for target in targets))


def discover_targets(
    targets: list[TargetSpec],
    ports: tuple[int, ...],
    timeout_sec: float = 0.35,
    workers: int = 32,
    use_icmp: bool = True,
) -> list[HostDiscoveryResult]:
    return asyncio.run(discover_targets_async(targets, ports, timeout_sec, workers, use_icmp))
