from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PortState(str, Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


class AssessmentType(str, Enum):
    POSSIBLE_FILTERING = "POSSIBLE FILTERING"
    POSSIBLE_NETWORK_ISSUE = "POSSIBLE NETWORK ISSUE"
    UNSTABLE_RESPONSE = "UNSTABLE RESPONSE"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(slots=True)
class ProbeResult:
    attempt: int
    state: PortState
    latency_ms: float | None
    error: str | None = None


@dataclass(slots=True)
class PortResult:
    host: str
    port: int
    state: PortState
    latency_ms: float | None
    attempts: list[ProbeResult] = field(default_factory=list)
    error: str | None = None
    address: str | None = None
    family: str | None = None
    target_id: str | None = None

    @property
    def open(self) -> bool:
        return self.state is PortState.OPEN


@dataclass(slots=True)
class PortAssessment:
    host: str
    port: int
    assessment: AssessmentType
    confidence: int
    attempts: int
    timeout_attempts: int
    average_latency_ms: float | None
    reason: str


@dataclass(slots=True)
class AnalysisPattern:
    assessment: AssessmentType
    ports: list[int]
    confidence: int
    attempts: int
    timeout_attempts: int
    average_latency_ms: float | None
    stability: str
    reason: str
    host: str = ""


@dataclass(slots=True)
class ServiceInfo:
    host: str
    port: int
    name: str
    confidence: int
    banner: str | None = None
    method: str = "unknown"
    evidence: str | None = None
    product: str | None = None
    version: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScanSummary:
    host: str
    address: str | None
    total: int
    open_count: int
    closed_count: int
    timeout_count: int
    error_count: int
    elapsed_seconds: float
    initial_timeout_count: int
    retry_resolved_count: int
    started_at: str | None = None


@dataclass(slots=True)
class HostDiscoveryResult:
    host: str
    address: str
    alive: bool
    method: str
    latency_ms: float | None = None
    evidence: str | None = None
    probes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TargetSpec:
    value: str
    address: str
    family: str
    target_id: str


@dataclass(slots=True)
class HostReport:
    target: TargetSpec
    discovery: HostDiscoveryResult
    results: list[PortResult] = field(default_factory=list)
    summary: ScanSummary | None = None
    services: list[ServiceInfo] = field(default_factory=list)
    assessments: list[PortAssessment] = field(default_factory=list)
