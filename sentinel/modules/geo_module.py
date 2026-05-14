"""Geolocation lookup via ip-api.com."""

from __future__ import annotations

from typing import Any

import requests


class GeoModule:
    def __init__(self, timeout: int = 20) -> None:
        self.timeout = timeout

    def run(self, ip: str) -> dict[str, Any]:
        url = f"http://ip-api.com/json/{ip}"
        params = {
            "fields": "status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,query",
            "lang": "es",
        }
        response = requests.get(url, params=params, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        if data.get("status") != "success":
            raise RuntimeError(data.get("message", "ip-api lookup failed"))
        data["ok"] = True
        return data
