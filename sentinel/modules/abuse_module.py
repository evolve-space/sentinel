"""AbuseIPDB integration."""

from __future__ import annotations

import os
from typing import Any

import requests


class AbuseIPDBModule:
    def __init__(self, timeout: int = 20) -> None:
        self.timeout = timeout
        self.api_key = os.getenv("ABUSEIPDB_KEY", "").strip()

    def run(self, ip: str) -> dict[str, Any]:
        if not self.api_key or self.api_key.startswith("REPLACE_"):
            return {"ok": False, "skipped": True, "reason": "ABUSEIPDB_KEY no configurada"}
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data", {})
        reports = data.get("reports") or []
        categories: list[int] = []
        for report in reports:
            categories.extend(report.get("categories") or [])
        data["categories"] = sorted(set(categories))
        return {"ok": True, "data": data}
