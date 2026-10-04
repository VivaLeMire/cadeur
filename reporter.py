from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Iterable

from analyzer import build_patterns, format_port_ranges
from models import HostReport, PortAssessment, PortResult, PortState, ScanSummary, ServiceInfo

SCHEMA_VERSION = "1.0"


def print_results(results: Iterable[PortResult], state: PortState | None = None) -> None:
    selected = [r for r in results if state is None or r.state is state]
    title = state.value if state else "ALL RESULTS"
    print(f"\n{title}\n" + "═" * 78)
    if not selected:
        print("No matching ports.")
        return
    for result in selected:
        latency = f"{result.latency_ms:.2f} ms" if result.latency_ms is not None else "—"
        print(f"{result.port:>5}/tcp  {result.state.value:<8} latency={latency:<12} attempts={len(result.attempts)}")


def print_discovery(discovery) -> None:
    status = "ALIVE" if discovery.alive else "UNREACHABLE"
    latency = f"{discovery.latency_ms:.2f} ms" if discovery.latency_ms is not None else "—"
    print(f"  {discovery.address:<39} {status:<12} method={discovery.method:<18} latency={latency}")


def print_summary(summary: ScanSummary) -> None:
    print("\nSCAN SUMMARY\n" + "═" * 78)
    print(
        f"Target:            {summary.host}\n"
        f"Address:           {summary.address or '—'}\n"
        f"Total ports:       {summary.total}\n"
        f"OPEN:              {summary.open_count}\n"
        f"CLOSED:            {summary.closed_count}\n"
        f"TIMEOUT:           {summary.timeout_count}\n"
        f"ERROR:             {summary.error_count}\n"
        f"Initial timeouts:  {summary.initial_timeout_count}\n"
        f"Retry resolved:    {summary.retry_resolved_count}\n"
        f"Elapsed:           {summary.elapsed_seconds:.2f}s"
    )


def print_services(services: Iterable[ServiceInfo]) -> None:
    services = list(services)
    print("\nSERVICE DETECTION\n" + "═" * 78)
    if not services:
        print("No OPEN ports available for service detection.")
        return
    for service in sorted(services, key=lambda s: (s.host, s.port)):
        detail = service.product or service.version or "—"
        print(
            f"{service.port:>5}/tcp  {service.name:<8} confidence={service.confidence:>3}% "
            f"method={service.method:<18} evidence={service.evidence or '—'} detail={detail}"
        )


def print_analysis(assessments: Iterable[PortAssessment]) -> None:
    print("\nCADEUR ANALYSIS\n" + "═" * 78)
    patterns = build_patterns(list(assessments))
    if not patterns:
        print("No timeout patterns detected.")
        return
    for pattern in patterns:
        average = f"{pattern.average_latency_ms:.2f} ms" if pattern.average_latency_ms is not None else "—"
        print(
            f"\nHOST:         {pattern.host}\n"
            f"PATTERN:      {pattern.assessment.value}\n"
            f"Ports:        {format_port_ranges(pattern.ports)}\n"
            f"Affected:     {len(pattern.ports)}\n"
            f"Attempts:     {pattern.attempts}\n"
            f"Timeouts:     {pattern.timeout_attempts}/{pattern.attempts}\n"
            f"Stability:    {pattern.stability}\n"
            f"Avg latency:  {average}\n"
            f"Confidence:   {pattern.confidence}%\n"
            f"Reason:       {pattern.reason}"
        )


def _result_dict(result: PortResult) -> dict:
    return {
        "host": result.host,
        "address": result.address,
        "family": result.family,
        "target_id": result.target_id,
        "port": result.port,
        "state": result.state.value,
        "latency_ms": result.latency_ms,
        "error": result.error,
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


def _service_dict(service: ServiceInfo) -> dict:
    return {
        "host": service.host,
        "port": service.port,
        "name": service.name,
        "confidence": service.confidence,
        "banner": service.banner,
        "method": service.method,
        "evidence": service.evidence,
        "product": service.product,
        "version": service.version,
        "metadata": service.metadata,
    }


def _summary_dict(summary: ScanSummary) -> dict:
    return {
        "host": summary.host,
        "address": summary.address,
        "total_ports": summary.total,
        "open": summary.open_count,
        "closed": summary.closed_count,
        "timeout": summary.timeout_count,
        "error": summary.error_count,
        "elapsed_seconds": summary.elapsed_seconds,
        "initial_timeouts": summary.initial_timeout_count,
        "retry_resolved": summary.retry_resolved_count,
        "started_at": summary.started_at,
    }


def build_report(host_reports: list[HostReport], config: dict | None = None) -> dict:
    alive = [report for report in host_reports if report.discovery.alive]
    total_ports = sum(report.summary.total for report in alive if report.summary)
    totals = {
        "targets": len(host_reports),
        "alive_hosts": len(alive),
        "scanned_hosts": len([r for r in alive if r.summary]),
        "total_ports": total_ports,
        "open": sum(r.summary.open_count for r in alive if r.summary),
        "closed": sum(r.summary.closed_count for r in alive if r.summary),
        "timeout": sum(r.summary.timeout_count for r in alive if r.summary),
        "error": sum(r.summary.error_count for r in alive if r.summary),
        "elapsed_seconds": sum(r.summary.elapsed_seconds for r in alive if r.summary),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "config": config or {},
        "summary": totals,
        "hosts": [
            {
                "target": {
                    "value": report.target.value,
                    "address": report.target.address,
                    "family": report.target.family,
                    "target_id": report.target.target_id,
                },
                "discovery": {
                    "alive": report.discovery.alive,
                    "method": report.discovery.method,
                    "latency_ms": report.discovery.latency_ms,
                    "evidence": report.discovery.evidence,
                    "probes": report.discovery.probes,
                },
                "summary": _summary_dict(report.summary) if report.summary else None,
                "results": [_result_dict(r) for r in report.results],
                "services": [_service_dict(s) for s in report.services],
                "analysis": [
                    {
                        "host": a.host,
                        "port": a.port,
                        "assessment": a.assessment.value,
                        "confidence": a.confidence,
                        "attempts": a.attempts,
                        "timeout_attempts": a.timeout_attempts,
                        "average_latency_ms": a.average_latency_ms,
                        "reason": a.reason,
                    }
                    for a in report.assessments
                ],
            }
            for report in host_reports
        ],
    }


def export_json(path: str | Path, host_reports: list[HostReport], config: dict | None = None) -> None:
    payload = build_report(host_reports, config)
    Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def export_html(path: str | Path, host_reports: list[HostReport], config: dict | None = None) -> None:
    payload = build_report(host_reports, config)
    rows = []
    for host in payload["hosts"]:
        address = html.escape(host["target"]["address"])
        status = "ALIVE" if host["discovery"]["alive"] else "UNREACHABLE"
        summary = host["summary"] or {}
        rows.append(
            f"<section><h2>{address} <span class='badge'>{status}</span></h2>"
            f"<p>{summary.get('open', 0)} open · {summary.get('closed', 0)} closed · "
            f"{summary.get('timeout', 0)} timeout · {summary.get('error', 0)} error</p>"
            "<table><tr><th>Port</th><th>State</th><th>Latency</th><th>Service</th><th>Confidence</th></tr>"
            + "".join(
                f"<tr><td>{r['port']}/tcp</td><td>{html.escape(r['state'])}</td>"
                f"<td>{r['latency_ms'] if r['latency_ms'] is not None else '—'}</td>"
                f"<td>{html.escape(next((s['name'] for s in host['services'] if s['port'] == r['port']), '—'))}</td>"
                f"<td>{next((s['confidence'] for s in host['services'] if s['port'] == r['port']), '—')}</td></tr>"
                for r in host["results"] if r["state"] == "OPEN"
            )
            + "</table></section>"
        )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CADEUR v1.1 Report</title><style>
body{{margin:0;background:#0b0d10;color:#e8edf2;font:14px system-ui,sans-serif}}main{{max-width:1200px;margin:40px auto;padding:0 20px}}
h1{{font-size:32px}}h2{{margin-top:0}}section{{background:#12161b;border:1px solid #27303a;border-radius:14px;padding:20px;margin:18px 0}}
.badge{{font-size:12px;border:1px solid #42505d;border-radius:999px;padding:4px 8px;color:#aab6c2}}table{{width:100%;border-collapse:collapse;margin-top:16px}}th,td{{text-align:left;padding:9px;border-bottom:1px solid #27303a}}th{{color:#9ca8b5}}
</style></head><body><main><h1>CADEUR v1.1</h1><p>Generated {html.escape(payload['generated_at'])}</p>
<p>{payload['summary']['alive_hosts']} alive / {payload['summary']['targets']} targets · {payload['summary']['open']} open ports</p>{''.join(rows)}</main></body></html>"""
    Path(path).write_text(document, encoding="utf-8")
