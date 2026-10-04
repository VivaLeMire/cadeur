# CADEUR

<p align="center">
  <strong>Adaptive Asynchronous Network Scanner</strong>
</p>

<p align="center">
  A modular network reconnaissance tool for authorized security testing, lab environments, and network analysis.
</p>

<p align="center">
  <a href="https://github.com/VivaLeMire/cadeur/actions/workflows/ci.yml">
    <img src="https://github.com/VivaLeMire/cadeur/actions/workflows/ci.yml/badge.svg" alt="CI">
  </a>
  <a href="https://github.com/VivaLeMire/cadeur/releases">
    <img src="https://img.shields.io/github/v/release/VivaLeMire/cadeur?display_name=tag&sort=semver" alt="Latest Release">
  </a>
  <a href="https://github.com/VivaLeMire/cadeur/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/VivaLeMire/cadeur" alt="License">
  </a>
  <img src="https://img.shields.io/badge/python-3.12%2B-blue" alt="Python">
</p>

---

## What is CADEUR?

CADEUR is an asynchronous network scanner designed to discover reachable hosts, identify open TCP services, analyze network behavior, and generate structured reports.

The project focuses on modular architecture, adaptive scanning, observable results, and a clear separation between raw network observations and security assessments.

```text
Target
  │
  ▼
Host Discovery
  │
  ▼
Async TCP Scanner
  │
  ├── Adaptive Timeout
  ├── Adaptive Concurrency
  └── Optional Retry
  │
  ▼
Open Ports
  │
  ▼
Service Detection
  │
  ▼
Behavioral Analysis
  │
  ▼
JSON / HTML Reports
```

## Features

* Async TCP scanning with bounded concurrency
* Host discovery and CIDR support
* Multiple targets
* Adaptive timeout and concurrency
* Explicit timeout retry mode
* Checkpoint and resume support
* Service detection with protocol-based evidence
* Behavioral timeout analysis
* JSON and HTML reporting
* TOML configuration
* Automated testing with GitHub Actions

> CADEUR is intended for systems you own or are explicitly authorized to test.

## v1.1.1

v1.1 focuses on making the v1.0 engine reliable for longer scans and repeatable workflows.

```text
CLI / CONFIG
     ↓
TARGET NORMALIZATION
     ↓
HOST DISCOVERY
     ↓
ASYNC TCP SCANNER
     ↓
CHECKPOINT / RESUME
     ↓
OPEN PORTS
     ↓
SERVICE DETECTION
     ↓
ANALYZER
     ↓
JSON / HTML
```

## What changed in v1.1

### TOML configuration

Pass a config explicitly:

```bash
python cli.py 192.0.2.10 --config cadeur.toml -p 1-1000
```

When no `--config` is supplied, CADEUR automatically loads `cadeur.toml` from the current directory when it exists.

An example is included as `cadeur.toml.example`.

### Checkpoint and resume

Use a state file for a long scan:

```bash
python cli.py 192.0.2.10 -p 1-65535 --state scan.json
```

After an interruption, continue only the unfinished ports:

```bash
python cli.py 192.0.2.10 -p 1-65535 --state scan.json --resume
```

The checkpoint contains the completed TCP observations for the exact target and port-set signature. A different port range will not accidentally reuse the old results.

Tune checkpoint frequency with:

```bash
python cli.py 192.0.2.10 -p 1-65535 --state scan.json --checkpoint-every 250
```

### Retry control

Timeout retries are disabled by default. If `cadeur.toml` enables them, you can explicitly override that setting with:

```bash
python cli.py 127.0.0.1 -p 1-1000 --no-retry-timeouts
```

Enable retries explicitly with `-rt`. The CLI prints the active profile and retry state before scanning.

### Exit codes

```text
0    success
2    configuration / CLI error
3    target / resolution error
4    runtime error
130  user interruption (Ctrl+C)
```

## CLI

```text
-u      OPEN only
-c      CLOSED only
-d      TIMEOUT only
-e      ERROR only
-fl     FULL output
-a      behavioral analysis
-r      retry history
-s      service detection
-p      port range
-tm     TCP timeout
-w      concurrency
-rc     retry count
-rt     retry TIMEOUT ports

--fast
--normal
--accurate
--config PATH
--state PATH
--resume
--checkpoint-every N
--no-discovery
--discover-single
--json PATH
--html PATH
```

Examples use TEST-NET addresses only. Scan real systems only when you own them or have explicit authorization.

```bash
python cli.py
python cli.py 192.0.2.10 -p 1-1000 -u
python cli.py 192.0.2.0/24 -p 1-1000 -s -a
python cli.py 192.0.2.10 -p 1-65535 --state scan.json
python cli.py 192.0.2.10 -p 1-65535 --state scan.json --resume
```

## Tests

```bash
python -m unittest discover -s tests -v
```

The test suite uses loopback services and local files only.

## Roadmap

- v1.2 — UDP engine with a separate result model and protocol probes.
- v1.3 — deeper service intelligence and richer version/product evidence.
- v1.4 — network-level aggregation and topology-oriented reporting.
- v1.5 — security observation and finding rules without automatic exploitation.
- v2.0 — optional high-performance packet engine (SYN/raw scanning where platform support is appropriate).
