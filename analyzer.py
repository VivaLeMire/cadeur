from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Sequence

from models import AnalysisPattern, AssessmentType, PortAssessment, PortResult, PortState


def get_latencies(result: PortResult) -> list[float]:
    return [p.latency_ms for p in result.attempts if p.latency_ms is not None]


def calculate_latency_stability(latencies: Sequence[float]) -> float:
    if len(latencies) < 2:
        return 1.0 if latencies else 0.0
    mean = statistics.mean(latencies)
    if mean <= 0:
        return 1.0
    return max(0.0, min(1.0, 1.0 - statistics.pstdev(latencies) / mean))


def get_neighbor_results(results: Sequence[PortResult], port: int, radius: int = 2) -> list[PortResult]:
    by_port = {result.port: result for result in results}
    return [by_port[p] for p in range(max(1, port - radius), port + radius + 1) if p != port and p in by_port]


def analyze_timeout(result: PortResult, all_results: Sequence[PortResult]) -> PortAssessment:
    attempts = len(result.attempts)
    timeout_attempts = sum(p.state is PortState.TIMEOUT for p in result.attempts)
    timeout_ratio = timeout_attempts / attempts if attempts else 1.0
    latencies = get_latencies(result)
    average_latency = statistics.mean(latencies) if latencies else None
    stability = calculate_latency_stability(latencies)
    if timeout_ratio == 1.0 and not latencies:
        stability = 1.0

    neighbors = get_neighbor_results(all_results, result.port)
    neighbor_timeout_ratio = (
        sum(r.state is PortState.TIMEOUT for r in neighbors) / len(neighbors) if neighbors else 0.0
    )

    if timeout_ratio >= 0.66 and stability >= 0.85 and neighbor_timeout_ratio >= 0.50:
        assessment = AssessmentType.POSSIBLE_FILTERING
        confidence = min(90, 50 + int(timeout_ratio * 20) + int(neighbor_timeout_ratio * 20))
        reason = "Repeated timeout responses with stable behavior and similar results on neighboring ports."
    elif timeout_ratio < 1.0:
        assessment = AssessmentType.UNSTABLE_RESPONSE
        confidence = min(85, 45 + int((1.0 - timeout_ratio) * 30))
        reason = "The port produced mixed outcomes across probe attempts."
    elif neighbors and neighbor_timeout_ratio < 0.50:
        assessment = AssessmentType.POSSIBLE_NETWORK_ISSUE
        confidence = min(80, 55 + int((1.0 - neighbor_timeout_ratio) * 20))
        reason = "The timeout is isolated while nearby ports behave differently."
    else:
        assessment = AssessmentType.INCONCLUSIVE
        confidence = 55
        reason = "Repeated timeouts were observed, but the evidence is insufficient for a stronger conclusion."

    return PortAssessment(
        result.host,
        result.port,
        assessment,
        confidence,
        attempts,
        timeout_attempts,
        average_latency,
        reason,
    )


def analyze_results(results: Sequence[PortResult]) -> list[PortAssessment]:
    return [analyze_timeout(r, results) for r in results if r.state is PortState.TIMEOUT]


def format_port_ranges(ports: Sequence[int]) -> str:
    if not ports:
        return "—"
    values = sorted(set(ports))
    ranges: list[str] = []
    start = prev = values[0]
    for value in values[1:]:
        if value == prev + 1:
            prev = value
            continue
        ranges.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = value
    ranges.append(str(start) if start == prev else f"{start}-{prev}")
    return " ".join(ranges)


def build_patterns(assessments: Sequence[PortAssessment]) -> list[AnalysisPattern]:
    grouped: dict[tuple[str, int, int, str, str], list[PortAssessment]] = defaultdict(list)
    for assessment in assessments:
        latency_bucket = "none" if assessment.average_latency_ms is None else str(int(assessment.average_latency_ms // 25))
        host = assessment.host
        grouped[(host, assessment.assessment.value, assessment.attempts, assessment.timeout_attempts, latency_bucket)].append(assessment)

    patterns: list[AnalysisPattern] = []
    for (host, assessment_name, attempts, timeout_attempts, _), items in grouped.items():
        avg = statistics.mean([i.average_latency_ms for i in items if i.average_latency_ms is not None]) if any(i.average_latency_ms is not None for i in items) else None
        confidence = round(statistics.mean(i.confidence for i in items))
        assessment = AssessmentType(assessment_name)
        stability = "HIGH" if all(i.timeout_attempts == i.attempts for i in items) else "MIXED"
        patterns.append(AnalysisPattern(assessment, sorted(i.port for i in items), confidence, attempts, timeout_attempts, avg, stability, items[0].reason, host))
    return sorted(patterns, key=lambda p: (p.host, p.ports[0] if p.ports else 0))
