from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from errors import ConfigurationError

PROFILE_DEFAULTS = {
    "fast": dict(timeout_sec=0.10, workers=900, min_timeout_sec=0.06, max_timeout_sec=0.50),
    "normal": dict(timeout_sec=0.20, workers=600, min_timeout_sec=0.08, max_timeout_sec=0.80),
    "accurate": dict(timeout_sec=0.45, workers=450, min_timeout_sec=0.12, max_timeout_sec=1.50),
}


@dataclass(slots=True)
class ScanConfig:
    profile: str = "normal"
    timeout_sec: float = 0.20
    workers: int = 600
    retry_timeouts: bool = False
    retry_count: int = 2
    retry_backoff_sec: float = 0.0
    min_timeout_sec: float = 0.08
    max_timeout_sec: float = 0.80
    render_interval: float = 0.25
    service_workers: int = 32
    service_timeout_sec: float = 0.6
    discovery_workers: int = 128
    discovery_timeout_sec: float = 0.35
    discovery_ports: tuple[int, ...] = (22, 80, 443, 445, 3389, 8080, 8000)
    discovery: bool = True
    discover_single: bool = False
    json_path: str | None = None
    html_path: str | None = None
    max_targets: int = 256
    adaptive_workers: bool = True
    host_concurrency: int = 1
    checkpoint_every: int = 100

    def normalized(self) -> "ScanConfig":
        profile = self.profile.lower().strip()
        if profile not in PROFILE_DEFAULTS:
            raise ConfigurationError(f"unknown profile: {profile}")
        defaults = PROFILE_DEFAULTS[profile]
        minimum = max(0.03, min(float(self.min_timeout_sec), 5.0))
        maximum = max(minimum, min(float(self.max_timeout_sec), 5.0))
        timeout = max(minimum, min(float(self.timeout_sec), maximum))
        discovery_ports = tuple(sorted({int(p) for p in self.discovery_ports if 1 <= int(p) <= 65535}))
        return ScanConfig(
            profile=profile,
            timeout_sec=timeout,
            workers=max(1, min(int(self.workers), 2000)),
            retry_timeouts=bool(self.retry_timeouts),
            retry_count=max(0, min(int(self.retry_count), 5)),
            retry_backoff_sec=max(0.0, min(float(self.retry_backoff_sec), 2.0)),
            min_timeout_sec=minimum,
            max_timeout_sec=maximum,
            render_interval=max(0.05, min(float(self.render_interval), 2.0)),
            service_workers=max(1, min(int(self.service_workers), 200)),
            service_timeout_sec=max(0.1, min(float(self.service_timeout_sec), 10.0)),
            discovery_workers=max(1, min(int(self.discovery_workers), 500)),
            discovery_timeout_sec=max(0.05, min(float(self.discovery_timeout_sec), 5.0)),
            discovery_ports=discovery_ports or defaults.get("discovery_ports", (80, 443)),
            discovery=bool(self.discovery),
            discover_single=bool(self.discover_single),
            json_path=self.json_path,
            html_path=self.html_path,
            max_targets=max(1, min(int(self.max_targets), 4096)),
            adaptive_workers=bool(self.adaptive_workers),
            host_concurrency=max(1, min(int(self.host_concurrency), 16)),
            checkpoint_every=max(10, min(int(self.checkpoint_every), 5000)),
        )

    @classmethod
    def from_profile(cls, profile: str = "normal", **overrides) -> "ScanConfig":
        profile = profile.lower().strip()
        if profile not in PROFILE_DEFAULTS:
            raise ConfigurationError(f"unknown profile: {profile}")
        base = dict(PROFILE_DEFAULTS[profile])
        base.update({k: v for k, v in overrides.items() if v is not None})
        base["profile"] = profile
        return cls(**base).normalized()

    @classmethod
    def from_toml(cls, path: str | Path, profile: str | None = None, **overrides) -> "ScanConfig":
        path = Path(path)
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ConfigurationError(f"cannot read config '{path}': {exc}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise ConfigurationError(f"invalid TOML in '{path}': {exc}") from exc

        source: dict = {k: v for k, v in raw.items() if not isinstance(v, dict)}
        section_maps = {
            "scanner": {},
            "discovery": {"timeout_sec": "discovery_timeout_sec", "workers": "discovery_workers", "ports": "discovery_ports", "enabled": "discovery", "single": "discover_single"},
            "service": {"workers": "service_workers", "timeout_sec": "service_timeout_sec"},
            "output": {"json": "json_path", "html": "html_path"},
            "target": {"max_targets": "max_targets", "host_concurrency": "host_concurrency"},
        }
        for section, values in raw.items():
            if not isinstance(values, dict):
                continue
            mapping = section_maps.get(section, {})
            for key, value in values.items():
                destination = mapping.get(key, key if section == "scanner" else None)
                if destination is not None:
                    source[destination] = value

        source.update({k: v for k, v in overrides.items() if v is not None})
        selected_profile = profile or source.get("profile", "normal")
        source.pop("profile", None)
        valid = set(cls.__dataclass_fields__)
        source = {k: v for k, v in source.items() if k in valid}
        return cls.from_profile(selected_profile, **source)
