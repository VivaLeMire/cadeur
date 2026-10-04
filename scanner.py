from __future__ import annotations

import asyncio
import math
import os
import socket
import statistics
import time
from collections import Counter
from dataclasses import dataclass
from typing import Awaitable, Callable

from config import ScanConfig
from models import PortResult, PortState, ProbeResult, ScanSummary
from state import ScanState


@dataclass(slots=True)
class ScanProgress:
    phase: str
    completed: int
    total: int
    started_at: float
    states: Counter
    latest_open: list[int]


class AdaptiveTimeout:
    def __init__(self, initial: float, minimum: float, maximum: float):
        self.value = max(minimum, min(initial, maximum))
        self.minimum = minimum
        self.maximum = maximum
        self.samples: list[float] = []

    def observe(self, latency_ms: float | None) -> None:
        if latency_ms is None:
            return
        self.samples.append(latency_ms)
        if len(self.samples) < 6:
            return
        median_ms = statistics.median(self.samples[-24:])
        candidate = max(self.minimum, min(median_ms * 3 / 1000, self.maximum))
        self.value = self.value * 0.85 + candidate * 0.15


async def _connect(address: str, port: int, family: int, timeout: float) -> float:
    loop = asyncio.get_running_loop()
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setblocking(False)
    started = time.perf_counter()
    try:
        endpoint = (address, port) if family == socket.AF_INET else (address, port, 0, 0)
        await asyncio.wait_for(loop.sock_connect(sock, endpoint), timeout)
        return (time.perf_counter() - started) * 1000
    finally:
        sock.close()


def _is_closed(exc: OSError) -> bool:
    return (
        isinstance(exc, ConnectionRefusedError)
        or getattr(exc, "winerror", None) in {10061}
        or getattr(exc, "errno", None) in {111, 61, 10061}
    )


async def probe_resolved(address: str, port: int, family: int, timeout: float, attempt: int = 1) -> ProbeResult:
    started = time.perf_counter()
    try:
        latency = await _connect(address, port, family, timeout)
        return ProbeResult(attempt, PortState.OPEN, latency)
    except asyncio.TimeoutError:
        return ProbeResult(attempt, PortState.TIMEOUT, None, "connection timeout")
    except OSError as exc:
        latency = (time.perf_counter() - started) * 1000
        state = PortState.CLOSED if _is_closed(exc) else PortState.ERROR
        return ProbeResult(attempt, state, latency, str(exc))
    except Exception as exc:
        return ProbeResult(
            attempt,
            PortState.ERROR,
            (time.perf_counter() - started) * 1000,
            f"{type(exc).__name__}: {exc}",
        )


async def resolve_target(host: str) -> tuple[str, int]:
    infos = await asyncio.get_running_loop().getaddrinfo(
        host,
        None,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    family, _, _, _, sockaddr = infos[0]
    return sockaddr[0], family


async def probe_port(host: str, port: int, timeout: float, attempt_number: int = 1) -> ProbeResult:
    address, family = await resolve_target(host)
    return await probe_resolved(address, port, family, timeout, attempt_number)


def _clear() -> None:
    if os.name == "nt":
        os.system("cls")
        return
    if os.environ.get("TERM"):
        os.system("clear")
        return
    print("\033[2J\033[H", end="")


def _bar(completed: int, total: int, width: int = 36) -> str:
    ratio = min(1.0, completed / total) if total else 1.0
    filled = int(width * ratio)
    return "[" + "=" * filled + "." * (width - filled) + f"] {ratio * 100:6.2f}%"


def _eta(seconds: float) -> str:
    if not math.isfinite(seconds) or seconds < 0:
        return "--:--"
    seconds = int(seconds)
    return f"{seconds // 60:02d}:{seconds % 60:02d}"


def render_dashboard(
    progress: ScanProgress,
    host: str,
    range_text: str,
    timeout_value: float | None = None,
) -> None:
    elapsed = max(time.perf_counter() - progress.started_at, 0.001)
    speed = progress.completed / elapsed
    remaining = max(progress.total - progress.completed, 0)
    eta = remaining / speed if speed else math.inf
    states = progress.states
    _clear()
    print("CADEUR  •  ADAPTIVE NETWORK SCANNER")
    print("═" * 78)
    print(f"PHASE:       {progress.phase}\nTARGET:      {host}\nPORT RANGE:  {range_text}")
    if timeout_value is not None:
        print(f"TIMEOUT:     {timeout_value * 1000:.0f} ms")
    print("─" * 78)
    print(f"PROGRESS     {_bar(progress.completed, progress.total)}")
    print(f"SCANNED      {progress.completed:>6} / {progress.total:<6}   SPEED: {speed:>8.1f} ports/s")
    print(f"ELAPSED      {elapsed:>8.1f}s       ETA: {_eta(eta)}")
    print("─" * 78)
    print(
        f"OPEN: {states[PortState.OPEN]:<6} "
        f"CLOSED: {states[PortState.CLOSED]:<6} "
        f"TIMEOUT: {states[PortState.TIMEOUT]:<6} "
        f"ERROR: {states[PortState.ERROR]:<6}"
    )
    print(f"LATEST OPEN: {', '.join(map(str, progress.latest_open)) or '—'}")


CheckpointCallback = Callable[[PortResult, list[PortResult]], Awaitable[None] | None]


async def _run(
    items,
    worker,
    host: str,
    range_text: str,
    phase: str,
    workers: int,
    interval: float,
    timeout_value: float | None = None,
    on_result: CheckpointCallback | None = None,
):
    if not items:
        return []
    queue: asyncio.Queue = asyncio.Queue()
    for item in items:
        queue.put_nowait(item)
    for _ in range(min(workers, len(items))):
        queue.put_nowait(None)

    results: list[PortResult] = []
    states = Counter({state: 0 for state in PortState})
    progress = ScanProgress(phase, 0, len(items), time.perf_counter(), states, [])
    lock = asyncio.Lock()
    callback_lock = asyncio.Lock()

    async def worker_loop():
        while True:
            item = await queue.get()
            try:
                if item is None:
                    return
                result = await worker(item)
                results.append(result)
                async with lock:
                    progress.completed += 1
                    progress.states[result.state] += 1
                    if result.state is PortState.OPEN:
                        progress.latest_open = (progress.latest_open + [result.port])[-10:]
                if on_result is not None:
                    async with callback_lock:
                        callback_value = on_result(result, results)
                        if asyncio.iscoroutine(callback_value):
                            await callback_value
            finally:
                queue.task_done()

    tasks = [asyncio.create_task(worker_loop()) for _ in range(min(workers, len(items)))]
    last_render = 0.0
    try:
        while any(not task.done() for task in tasks):
            if time.perf_counter() - last_render >= interval:
                render_dashboard(progress, host, range_text, timeout_value)
                last_render = time.perf_counter()
            await asyncio.sleep(0.02)
        await asyncio.gather(*tasks)
    except (asyncio.CancelledError, KeyboardInterrupt):
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if on_result is not None and results:
            async with callback_lock:
                callback_value = on_result(results[-1], results)
                if asyncio.iscoroutine(callback_value):
                    await callback_value
        raise
    render_dashboard(progress, host, range_text, timeout_value)
    return results


async def scan_ports_async(
    host: str,
    ports: list[int],
    config: ScanConfig,
    range_text: str = "custom",
    address: str | None = None,
    family: int | None = None,
    target_id: str | None = None,
    resume_results: list[PortResult] | None = None,
    state_store: ScanState | None = None,
):
    cfg = config.normalized()
    started = time.perf_counter()
    if address is None or family is None:
        address, family = await resolve_target(host)
    timeout_model = AdaptiveTimeout(cfg.timeout_sec, cfg.min_timeout_sec, cfg.max_timeout_sec)
    target_key = target_id or host
    family_name = "IPv6" if family == socket.AF_INET6 else "IPv4"
    resume_by_port = {result.port: result for result in (resume_results or [])}
    remaining_ports = [port for port in ports if port not in resume_by_port]
    completed_since_checkpoint = 0

    async def checkpoint(result: PortResult, current_results: list[PortResult]) -> None:
        nonlocal completed_since_checkpoint
        if state_store is None:
            return
        resume_by_port[result.port] = result
        completed_since_checkpoint += 1
        if completed_since_checkpoint < cfg.checkpoint_every and len(resume_by_port) < len(ports):
            return
        completed_since_checkpoint = 0
        await asyncio.to_thread(
            state_store.save_results,
            target_key,
            list(resume_by_port.values()),
            host=host,
            address=address,
            family=family_name,
            ports_signature=','.join(map(str, ports)),
        )

    async def initial(port: int):
        result = await probe_resolved(address, port, family, timeout_model.value, 1)
        timeout_model.observe(result.latency_ms)
        return PortResult(
            host,
            port,
            result.state,
            result.latency_ms,
            [result],
            result.error,
            address,
            family_name,
            target_key,
        )

    try:
        initial_results = await _run(
            remaining_ports,
            initial,
            host,
            range_text,
            "INITIAL SCAN",
            cfg.workers,
            cfg.render_interval,
            timeout_model.value,
            checkpoint,
        )
        for result in initial_results:
            resume_by_port[result.port] = result
        initial_results = sorted(resume_by_port.values(), key=lambda result: result.port)

        if state_store is not None:
            await asyncio.to_thread(
                state_store.save_results,
                target_key,
                initial_results,
                host=host,
                address=address,
                family=family_name,
                ports_signature=','.join(map(str, ports)),
            )

        initial_timeouts = [result for result in initial_results if result.state is PortState.TIMEOUT]
        retry_resolved = 0

        if cfg.retry_timeouts and cfg.retry_count and initial_timeouts:
            async def retry(result: PortResult):
                nonlocal retry_resolved
                for attempt in range(2, cfg.retry_count + 2):
                    if cfg.retry_backoff_sec:
                        await asyncio.sleep(cfg.retry_backoff_sec)
                    probe = await probe_resolved(address, result.port, family, timeout_model.value, attempt)
                    result.attempts.append(probe)
                    if probe.latency_ms is not None:
                        result.latency_ms = probe.latency_ms
                        timeout_model.observe(probe.latency_ms)
                    result.state = probe.state
                    result.error = probe.error
                    if probe.state is not PortState.TIMEOUT:
                        retry_resolved += 1
                        break
                return result

            retried = await _run(
                initial_timeouts,
                retry,
                host,
                range_text,
                "RETRY TIMEOUT",
                cfg.workers,
                cfg.render_interval,
                timeout_model.value,
                checkpoint,
            )
            for result in retried:
                resume_by_port[result.port] = result

        final = sorted(resume_by_port.values(), key=lambda result: result.port)
        elapsed = time.perf_counter() - started
        summary = ScanSummary(
            host,
            address,
            len(final),
            sum(r.state is PortState.OPEN for r in final),
            sum(r.state is PortState.CLOSED for r in final),
            sum(r.state is PortState.TIMEOUT for r in final),
            sum(r.state is PortState.ERROR for r in final),
            elapsed,
            len(initial_timeouts),
            retry_resolved,
            time.strftime("%Y-%m-%dT%H:%M:%S"),
        )
        return final, summary
    except (asyncio.CancelledError, KeyboardInterrupt):
        if state_store is not None and resume_by_port:
            await asyncio.to_thread(
                state_store.save_results,
                target_key,
                list(resume_by_port.values()),
                host=host,
                address=address,
                family=family_name,
                ports_signature=','.join(map(str, ports)),
            )
        raise


def scan_ports(
    host: str,
    ports: list[int],
    config: ScanConfig,
    range_text: str = "custom",
    address: str | None = None,
    family: int | None = None,
    target_id: str | None = None,
    resume_results: list[PortResult] | None = None,
    state_store: ScanState | None = None,
):
    return asyncio.run(
        scan_ports_async(
            host,
            ports,
            config,
            range_text,
            address,
            family,
            target_id,
            resume_results,
            state_store,
        )
    )


def retry_timeouts(results: list[PortResult], config: ScanConfig, range_text: str = "custom"):
    """Explicit retry entry point; range_text is accepted for compatibility."""
    async def run():
        cfg = config.normalized()
        if not cfg.retry_timeouts or cfg.retry_count <= 0:
            return list(results), 0
        updated: list[PortResult] = []
        resolved = 0
        for result in results:
            if result.state is not PortState.TIMEOUT or not result.address:
                updated.append(result)
                continue
            family = socket.AF_INET6 if ":" in result.address else socket.AF_INET
            current = result
            for attempt in range(2, cfg.retry_count + 2):
                probe = await probe_resolved(result.address, result.port, family, cfg.timeout_sec, attempt)
                current.attempts.append(probe)
                current.state = probe.state
                current.error = probe.error
                if probe.latency_ms is not None:
                    current.latency_ms = probe.latency_ms
                if probe.state is not PortState.TIMEOUT:
                    resolved += 1
                    break
            updated.append(current)
        return updated, resolved

    return asyncio.run(run())
