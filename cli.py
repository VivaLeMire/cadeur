from __future__ import annotations

import argparse
import socket
from pathlib import Path

from analyzer import analyze_results
from config import ScanConfig
from discovery import discover_targets
from errors import CadeurError, TargetError
from models import HostDiscoveryResult, HostReport, PortState
from reporter import export_html, export_json, print_analysis, print_discovery, print_results, print_services, print_summary
from scanner import scan_ports
from service_detector import detect_services
from state import ScanState
from targets import expand_targets

VERSION = "1.1.0"
EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_TARGET = 3
EXIT_RUNTIME = 4
EXIT_INTERRUPTED = 130
BANNER = r'''
 ██████╗ █████╗ ██████╗ ███████╗██╗   ██╗██████╗
██╔════╝██╔══██╗██╔══██╗██╔════╝██║   ██║██╔══██╗
██║     ███████║██║  ██║█████╗  ██║   ██║██████╔╝
██║     ██╔══██║██║  ██║██╔══╝  ╚██╗ ██╔╝██╔══██╗
╚██████╗██║  ██║██████╔╝███████╗ ╚████╔╝ ██║  ██║
 ╚═════╝╚═╝  ╚═╝╚═════╝ ╚══════╝  ╚═══╝  ╚═╝  ╚═╝
             ADAPTIVE NETWORK SCANNER v1.1
'''


def parse_ports(value: str) -> list[int]:
    ports: set[int] = set()
    try:
        for chunk in value.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                left, right = map(int, chunk.split("-", 1))
                ports.update(range(min(left, right), max(left, right) + 1))
            else:
                ports.add(int(chunk))
    except ValueError as exc:
        raise ValueError("invalid port range") from exc
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("port range must be within 1-65535")
    return sorted(ports)


def parse_discovery_ports(value: str) -> tuple[int, ...]:
    return tuple(parse_ports(value))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cadeur",
        formatter_class=argparse.RawTextHelpFormatter,
        description="CADEUR v1.1 adaptive network scanner for authorized security testing and lab environments.",
        epilog=(
            "Examples:\n"
            "  python cli.py 192.0.2.10 -p 1-1000 -u\n"
            "  python cli.py 192.0.2.0/24 -p 1-1000 -s -a\n"
            "  python cli.py 192.0.2.10 -p 1-10000 --state scan.json\n"
            "  python cli.py 192.0.2.10 -p 1-10000 --state scan.json --resume\n"
            "  python cli.py 192.0.2.10 --config cadeur.toml --json report.json --html report.html"
        ),
    )
    parser.add_argument("target", nargs="?", help="IP/hostname/CIDR; comma-separated targets accepted")
    parser.add_argument("--config", metavar="PATH", help="TOML configuration file")
    parser.add_argument("-u", "--open", action="store_true", dest="only_open")
    parser.add_argument("-c", "--closed", action="store_true", dest="only_closed")
    parser.add_argument("-d", "--timeout-ports", action="store_true", dest="only_timeout")
    parser.add_argument("-e", "--error", action="store_true", dest="only_error")
    parser.add_argument("-fl", "--full", action="store_true")
    parser.add_argument("-a", "--analysis", action="store_true")
    parser.add_argument("-r", "--retry-history", action="store_true")
    parser.add_argument("-s", "--services", action="store_true")
    parser.add_argument("-p", "--ports", default="1-65535")
    parser.add_argument("-tm", "--timeout-sec", type=float)
    parser.add_argument("-w", "--workers", type=int)
    parser.add_argument("-rc", "--retry-count", type=int)
    parser.add_argument("-rt", "--retry-timeouts", action="store_const", const=True, default=None, dest="retry_timeouts")
    parser.add_argument("--no-retry-timeouts", action="store_const", const=False, dest="retry_timeouts", help="disable timeout retries even when enabled in cadeur.toml")
    parser.add_argument("--fast", action="store_const", const="fast", dest="profile")
    parser.add_argument("--normal", action="store_const", const="normal", dest="profile")
    parser.add_argument("--accurate", action="store_const", const="accurate", dest="profile")
    parser.add_argument("--no-discovery", action="store_true", default=None, help="skip host discovery")
    parser.add_argument("--discover-single", action="store_true", default=None, help="run discovery for one explicit target")
    parser.add_argument("--discovery-ports")
    parser.add_argument("--discovery-timeout", type=float)
    parser.add_argument("--discovery-workers", type=int)
    parser.add_argument("--max-targets", type=int)
    parser.add_argument("--service-workers", type=int)
    parser.add_argument("--service-timeout", type=float)
    parser.add_argument("--checkpoint-every", type=int)
    parser.add_argument("--state", metavar="PATH", help="checkpoint file for interrupted/resumable scans")
    parser.add_argument("--resume", action="store_true", help="resume completed ports from --state")
    parser.add_argument("--json", metavar="PATH")
    parser.add_argument("--html", metavar="PATH")
    parser.add_argument("-v", "--version", action="version", version=f"CADEUR {VERSION}")
    return parser


def _existing_config_path(args) -> Path | None:
    if args.config:
        return Path(args.config)
    auto = Path("cadeur.toml")
    return auto if auto.exists() else None


def _build_config(args, discovery_ports: tuple[int, ...] | None) -> ScanConfig:
    overrides = {
        "timeout_sec": args.timeout_sec,
        "workers": args.workers,
        "retry_timeouts": args.retry_timeouts,
        "retry_count": args.retry_count,
        "service_workers": args.service_workers,
        "service_timeout_sec": args.service_timeout,
        "discovery_workers": args.discovery_workers,
        "discovery_timeout_sec": args.discovery_timeout,
        "discovery_ports": discovery_ports,
        "discovery": (not args.no_discovery) if args.no_discovery is not None else None,
        "discover_single": args.discover_single,
        "max_targets": args.max_targets,
        "json_path": args.json,
        "html_path": args.html,
        "checkpoint_every": args.checkpoint_every,
    }
    config_path = _existing_config_path(args)
    if config_path:
        return ScanConfig.from_toml(config_path, args.profile, **overrides)
    return ScanConfig.from_profile(args.profile or "normal", **overrides)


def _aggregate_config(cfg: ScanConfig) -> dict:
    return {
        "version": VERSION,
        "profile": cfg.profile,
        "timeout_sec": cfg.timeout_sec,
        "workers": cfg.workers,
        "retry_timeouts": cfg.retry_timeouts,
        "retry_count": cfg.retry_count,
        "checkpoint_every": cfg.checkpoint_every,
        "discovery": cfg.discovery,
        "discovery_ports": list(cfg.discovery_ports),
        "service_workers": cfg.service_workers,
        "service_timeout_sec": cfg.service_timeout_sec,
    }


def _print_retry_history(results):
    print("\nRETRY HISTORY\n" + "═" * 78)
    for result in results:
        if len(result.attempts) > 1:
            print(f"{result.port:>5}/tcp  " + " -> ".join(p.state.value for p in result.attempts))


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    print(BANNER)

    target_text = args.target or input("Target: ").strip()
    if not target_text:
        parser.error("target is required")
    if args.resume and not args.state:
        parser.error("--resume requires --state PATH")

    try:
        ports = parse_ports(args.ports)
        discovery_ports = parse_discovery_ports(args.discovery_ports) if args.discovery_ports else None
        cfg = _build_config(args, discovery_ports)
        print(f"MODE: {cfg.profile.upper()}   RETRY TIMEOUTS: {"ON" if cfg.retry_timeouts else "OFF"}")
        targets = expand_targets([target_text], cfg.max_targets)
    except CadeurError as exc:
        print(f"Configuration error: {exc}")
        return exc.exit_code
    except ValueError as exc:
        print(f"Configuration error: {exc}")
        return EXIT_CONFIG
    except OSError as exc:
        print(f"Configuration error: {exc}")
        return EXIT_CONFIG

    is_multi_target = len(targets) > 1 or any("/" in target.value for target in targets)
    should_discover = cfg.discovery and (is_multi_target or cfg.discover_single)

    discoveries: list[HostDiscoveryResult]
    try:
        if should_discover:
            print("\nHOST DISCOVERY\n" + "═" * 78)
            discoveries = discover_targets(
                targets,
                cfg.discovery_ports,
                cfg.discovery_timeout_sec,
                cfg.discovery_workers,
                use_icmp=True,
            )
            for discovery in discoveries:
                print_discovery(discovery)
        else:
            discoveries = [
                HostDiscoveryResult(t.value, t.address, True, "ASSUMED TARGET", None, "single explicit target", [])
                for t in targets
            ]
    except OSError as exc:
        print(f"Target discovery error: {exc}")
        return EXIT_TARGET

    state_store = ScanState(args.state) if args.state else None
    discovery_by_address = {d.address: d for d in discoveries}
    reports: list[HostReport] = []

    try:
        for target in targets:
            discovery = discovery_by_address[target.address]
            if should_discover and not discovery.alive:
                if len(targets) == 1 and target.value == target.address:
                    print(f"\nDiscovery did not confirm {target.address}; scanning explicit target anyway.")
                else:
                    reports.append(HostReport(target, discovery))
                    continue

            ports_signature = ",".join(map(str, ports))
            resume_results = (
                state_store.load_results(target.target_id, ports_signature) if state_store and args.resume else []
            )
            if resume_results:
                print(f"\nRESUME: loaded {len(resume_results)} completed ports for {target.address}")

            results, summary = scan_ports(
                target.address,
                ports,
                cfg,
                args.ports,
                address=target.address,
                family=socket.AF_INET6 if target.family == "IPv6" else socket.AF_INET,
                target_id=target.target_id,
                resume_results=resume_results,
                state_store=state_store,
            )
            services = detect_services(results, cfg.service_workers, cfg.service_timeout_sec) if args.services else []
            assessments = analyze_results(results) if args.analysis else []
            report = HostReport(target, discovery, results, summary, services, assessments)
            reports.append(report)

            print_summary(summary)
            selected_states = []
            for enabled, state in (
                (args.only_open, PortState.OPEN),
                (args.only_closed, PortState.CLOSED),
                (args.only_timeout, PortState.TIMEOUT),
                (args.only_error, PortState.ERROR),
            ):
                if enabled:
                    selected_states.append(state)
            if selected_states:
                for state in selected_states:
                    print_results(results, state)
            elif args.full:
                print_results(results)
            else:
                print_results(results, PortState.OPEN)

            if args.services:
                print_services(services)
            if args.analysis:
                print_analysis(assessments)
            if args.retry_history:
                _print_retry_history(results)

        config_payload = _aggregate_config(cfg)
        if args.json or cfg.json_path:
            path = args.json or cfg.json_path
            export_json(path, reports, config_payload)
            print(f"\nJSON exported to: {path}")
        if args.html or cfg.html_path:
            path = args.html or cfg.html_path
            export_html(path, reports, config_payload)
            print(f"HTML exported to: {path}")
        if state_store is not None:
            state_store.mark_complete()
        return EXIT_OK
    except KeyboardInterrupt:
        print("\n\nCADEUR: scan interrupted. Checkpoint was preserved when --state was used.")
        return EXIT_INTERRUPTED
    except CadeurError as exc:
        print(f"CADEUR error: {exc}")
        return exc.exit_code
    except OSError as exc:
        print(f"CADEUR runtime error: {exc}")
        return EXIT_RUNTIME


if __name__ == "__main__":
    raise SystemExit(main())
