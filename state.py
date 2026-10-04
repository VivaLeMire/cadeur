from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterable

from models import PortResult, PortState, ProbeResult

SCHEMA_VERSION = "1.1"


def result_to_dict(result: PortResult) -> dict:
    return {
        "host": result.host,
        "port": result.port,
        "state": result.state.value,
        "latency_ms": result.latency_ms,
        "error": result.error,
        "address": result.address,
        "family": result.family,
        "target_id": result.target_id,
        "attempts": [
            {
                "attempt": probe.attempt,
                "state": probe.state.value,
                "latency_ms": probe.latency_ms,
                "error": probe.error,
            }
            for probe in result.attempts
        ],
    }


def result_from_dict(data: dict) -> PortResult:
    attempts = [
        ProbeResult(
            int(item["attempt"]),
            PortState(item["state"]),
            item.get("latency_ms"),
            item.get("error"),
        )
        for item in data.get("attempts", [])
    ]
    return PortResult(
        host=str(data["host"]),
        port=int(data["port"]),
        state=PortState(data["state"]),
        latency_ms=data.get("latency_ms"),
        attempts=attempts,
        error=data.get("error"),
        address=data.get("address"),
        family=data.get("family"),
        target_id=data.get("target_id"),
    )


class ScanState:
    """Small JSON checkpoint store for interrupted scans."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.payload = {
            "schema_version": SCHEMA_VERSION,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "completed": False,
            "targets": {},
        }
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if data.get("schema_version") != SCHEMA_VERSION:
            return
        if isinstance(data.get("targets"), dict):
            self.payload = data

    def load_results(self, target_id: str, ports_signature: str | None = None) -> list[PortResult]:
        target = self.payload.get("targets", {}).get(target_id, {})
        if ports_signature is not None and target.get("ports_signature") != ports_signature:
            return []
        raw = target.get("results", {}) if isinstance(target, dict) else {}
        results: list[PortResult] = []
        for item in raw.values():
            try:
                results.append(result_from_dict(item))
            except (KeyError, TypeError, ValueError):
                continue
        return sorted(results, key=lambda item: item.port)

    def save_results(
        self,
        target_id: str,
        results: Iterable[PortResult],
        *,
        host: str,
        address: str,
        family: str,
        ports_signature: str,
    ) -> None:
        target = self.payload.setdefault("targets", {}).setdefault(target_id, {})
        target.update({"host": host, "address": address, "family": family, "ports_signature": ports_signature})
        target["results"] = {str(result.port): result_to_dict(result) for result in results}
        self.payload["completed"] = False
        self.payload["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._flush()

    def mark_complete(self) -> None:
        self.payload["completed"] = True
        self.payload["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._flush()

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)
