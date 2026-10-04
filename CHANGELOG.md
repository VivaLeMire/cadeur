## v1.1.1

- Added explicit `--no-retry-timeouts` override for local TOML configs.
- CLI now prints active profile and retry state before scanning.
- Reworked closed-port unit test to be deterministic across Windows network conditions.

# Changelog

## v1.1.0
- Added TOML configuration via `--config` and automatic `cadeur.toml` discovery.
- Added resumable scan checkpoints with `--state` and `--resume`.
- Added atomic checkpoint writes to avoid corrupting state files.
- Added graceful Ctrl+C exit code `130`.
- Added stable application exit codes for configuration, target, and runtime errors.
- Added scan checkpoint frequency control with `--checkpoint-every`.
- Preserved explicit timeout retry behavior: `-rt/--retry-timeouts` remains opt-in.
- Added tests for TOML configuration and checkpoint round-trips.

## v1.0.0
- Added host discovery pipeline with ICMP + TCP fallback.
- Added multi-host and CIDR scanning flow.
- Added explicit `--no-discovery` and `--discover-single` controls.
- Kept timeout retries opt-in with `-rt/--retry-timeouts`.
- Added SMB2 protocol evidence probe.
- Added HTTP/TLS metadata extraction.
- Added structured JSON schema `1.0`.
- Added standalone HTML reports.
- Stabilized CLI configuration and scan/report flow.
- Expanded automated test coverage.
