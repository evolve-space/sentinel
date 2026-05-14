"""Cloud provider detection using public IP ranges."""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Any

import requests


AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_URL = "https://www.gstatic.com/ipranges/cloud.json"
CLOUDFLARE_URL = "https://api.cloudflare.com/client/v4/ips"
AZURE_URL = "https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20260504.json"


class CloudModule:
    def __init__(self, timeout: int = 20) -> None:
        self.timeout = timeout

    def run(self, ip: str) -> dict[str, Any]:
        target = ipaddress.ip_address(ip)
        providers = self._ranges(self.timeout)
        for provider, ranges in providers.items():
            for cidr, meta in ranges:
                if target in ipaddress.ip_network(cidr, strict=False):
                    return {
                        "ok": True,
                        "is_cloud": True,
                        "provider": provider,
                        "cidr": cidr,
                        "meta": meta,
                    }
        return {"ok": True, "is_cloud": False}

    @staticmethod
    @lru_cache(maxsize=4)
    def _ranges(timeout: int) -> dict[str, list[tuple[str, dict[str, Any]]]]:
        ranges: dict[str, list[tuple[str, dict[str, Any]]]] = {
            "AWS": [],
            "Azure": [],
            "GCP": [],
            "Cloudflare": [],
        }

        aws = requests.get(AWS_URL, timeout=timeout).json()
        for prefix in aws.get("prefixes", []):
            ranges["AWS"].append(
                (
                    prefix["ip_prefix"],
                    {"region": prefix.get("region"), "service": prefix.get("service")},
                )
            )

        gcp = requests.get(GCP_URL, timeout=timeout).json()
        for prefix in gcp.get("prefixes", []):
            if "ipv4Prefix" in prefix:
                ranges["GCP"].append(
                    (
                        prefix["ipv4Prefix"],
                        {"scope": prefix.get("scope"), "service": prefix.get("service")},
                    )
                )

        cloudflare = requests.get(CLOUDFLARE_URL, timeout=timeout).json()
        for cidr in cloudflare.get("result", {}).get("ipv4_cidrs", []):
            ranges["Cloudflare"].append((cidr, {}))

        azure = requests.get(AZURE_URL, timeout=timeout).json()
        for value in azure.get("values", []):
            props = value.get("properties", {})
            for prefix in props.get("addressPrefixes", []):
                if ":" not in prefix:
                    ranges["Azure"].append(
                        (
                            prefix,
                            {"name": value.get("name"), "region": props.get("region")},
                        )
                    )
        return ranges
