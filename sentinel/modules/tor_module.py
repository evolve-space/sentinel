"""Tor exit node detection via dan.me.uk torlist."""

from __future__ import annotations

from typing import Any

import requests


class TorModule:
    def __init__(self, timeout: int = 20) -> None:
        self.timeout = timeout

    def run(self, ip: str) -> dict[str, Any]:
        primary_source = "https://www.dan.me.uk/torlist/"
        try:
            response = requests.get(
                primary_source,
                headers={"User-Agent": "SENTINEL-OSINT/0.1"},
                timeout=self.timeout,
            )
            response.raise_for_status()
            nodes = {line.strip() for line in response.text.splitlines() if line.strip()}
            return {
                "ok": True,
                "is_tor": ip in nodes,
                "source": primary_source,
                "active_nodes": len(nodes),
            }
        except requests.RequestException as exc:
            fallback = self._tor_project_fallback(ip)
            fallback["primary_error"] = f"{exc.__class__.__name__}: {exc}"
            return fallback

    def _tor_project_fallback(self, ip: str) -> dict[str, Any]:
        response = requests.get(
            "https://onionoo.torproject.org/details",
            params={"search": ip},
            headers={"User-Agent": "SENTINEL-OSINT/0.1"},
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        relays = data.get("relays") or []
        matches = []
        for relay in relays:
            addresses = set(relay.get("or_addresses") or [])
            addresses.update(relay.get("exit_addresses") or [])
            if any(address.split(":")[0] == ip for address in addresses):
                matches.append(
                    {
                        "nickname": relay.get("nickname"),
                        "fingerprint": relay.get("fingerprint"),
                        "flags": relay.get("flags", []),
                    }
                )
        return {
            "ok": True,
            "is_tor": bool(matches),
            "source": "https://www.dan.me.uk/torlist/",
            "fallback_source": "https://onionoo.torproject.org/details",
            "matches": matches,
            "active_nodes": None,
        }
