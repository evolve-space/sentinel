"""SENTINEL orchestration engine."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from sentinel.core.scoring import ThreatScorer
from sentinel.modules.abuse_module import AbuseIPDBModule
from sentinel.modules.cloud_module import CloudModule
from sentinel.modules.geo_module import GeoModule
from sentinel.modules.ports_module import PortsModule
from sentinel.modules.threat_module import ThreatModule
from sentinel.modules.tor_module import TorModule
from sentinel.report.generator import ReportGenerator


PhaseRunner = Callable[[str], dict[str, Any]]


class SentinelEngine:
    """Runs OSINT phases and keeps partial results when a phase fails."""

    def __init__(self, output_dir: Path, timeout: int = 20, scan_ports: bool = True) -> None:
        self.output_dir = output_dir
        self.timeout = timeout
        self.scan_ports = scan_ports
        self.scorer = ThreatScorer()
        self.reporter = ReportGenerator()

    def run(self, ip: str) -> dict[str, Any]:
        timestamp = datetime.now(UTC).isoformat()
        phases: dict[str, PhaseRunner] = {
            "geo": GeoModule(timeout=self.timeout).run,
            "abuse": AbuseIPDBModule(timeout=self.timeout).run,
            "threat": ThreatModule(timeout=self.timeout).run,
            "cloud": CloudModule(timeout=self.timeout).run,
            "tor": TorModule(timeout=self.timeout).run,
        }
        if self.scan_ports:
            phases["ports"] = PortsModule(timeout=self.timeout).run

        results: dict[str, Any] = {}
        errors: dict[str, str] = {}

        for phase, runner in phases.items():
            try:
                results[phase] = runner(ip)
            except Exception as exc:  # noqa: BLE001 - phase isolation is intentional.
                errors[phase] = f"{exc.__class__.__name__}: {exc}"
                results[phase] = {"ok": False, "error": errors[phase]}

        score = self.scorer.score(results)
        payload: dict[str, Any] = {
            "tool": "SENTINEL",
            "version": "0.1.0",
            "ip": ip,
            "timestamp": timestamp,
            "results": results,
            "score": score,
            "errors": errors,
        }

        self.output_dir.mkdir(parents=True, exist_ok=True)
        stem = f"sentinel_{ip.replace(':', '_')}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"
        json_path = self.output_dir / f"{stem}.json"
        html_path = self.output_dir / f"{stem}.html"

        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        self.reporter.render(payload=payload, output_path=html_path)

        payload["artifacts"] = {
            "json": str(json_path.resolve()),
            "html": str(html_path.resolve()),
        }
        return payload
