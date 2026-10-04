# CADEUR

CADEUR is a modular adaptive TCP network scanner for authorized security testing and lab environments.


[![CADEUR CI](https://github.com/VivaLeMire/cadeur/actions/workflows/ci.yml/badge.svg)](https://github.com/VivaLeMire/cadeur/actions/workflows/ci.yml)

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
