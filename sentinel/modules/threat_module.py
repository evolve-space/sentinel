"""AlienVault OTX integration."""

from __future__ import annotations

import os
from typing import Any

import requests


class ThreatModule:
    def __init__(self, timeout: int = 20) -> None:
        self.timeout = timeout
        self.api_key = os.getenv("OTX_KEY", "").strip()

    def run(self, ip: str) -> dict[str, Any]:
        if not self.api_key or self.api_key.startswith("REPLACE_"):
            return {"ok": False, "skipped": True, "reason": "OTX_KEY no configurada"}
        headers = {"X-OTX-API-KEY": self.api_key}
        base = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}"
        sections = ["general", "reputation", "malware", "url_list", "passive_dns"]
        collected: dict[str, Any] = {}
        active_sections: list[str] = []
        indicator_types: list[str] = []
        pulse_count = 0

        for section in sections:
            response = requests.get(f"{base}/{section}", headers=headers, timeout=self.timeout)
            if response.status_code == 404:
                collected[section] = {"ok": False, "status": 404}
                continue
            response.raise_for_status()
            data = response.json()
            collected[section] = data
            if data:
                active_sections.append(section)
            if section == "general":
                pulse_info = data.get("pulse_info") or {}
                pulses = pulse_info.get("pulses") or []
                pulse_count = int(pulse_info.get("count") or len(pulses))
                for pulse in pulses:
                    for indicator in pulse.get("indicators") or []:
                        indicator_type = indicator.get("type")
                        if indicator_type:
                            indicator_types.append(indicator_type)

        return {
            "ok": True,
            "pulse_count": pulse_count,
            "sections": active_sections,
            "indicator_types": sorted(set(indicator_types)),
            "raw": collected,
        }
