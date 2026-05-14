"""Threat scoring model for SENTINEL."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


HIGH_RISK_COUNTRIES = {
    "CN",
    "IR",
    "KP",
    "RU",
    "SY",
}

BULLETPROOF_ASN_HINTS = {
    "m247",
    "choopa",
    "datacamp",
    "hostkey",
    "selectel",
    "pq hosting",
    "alexhost",
    "dedipath",
    "frantech",
    "blazingseo",
    "flokinet",
}

SENSITIVE_PORTS = {
    21: 6,
    22: 8,
    23: 12,
    25: 5,
    445: 12,
    1433: 10,
    1521: 10,
    2049: 8,
    2375: 14,
    3306: 10,
    3389: 14,
    5432: 10,
    5900: 12,
    6379: 12,
    9200: 12,
    11211: 12,
    27017: 12,
}


@dataclass(slots=True)
class ThreatScorer:
    """Scores an IP from 0 to 100 across OSINT phases."""

    def score(self, results: dict[str, Any]) -> dict[str, Any]:
        contributions = {
            "geo": self._geo(results.get("geo", {})),
            "abuse": self._abuse(results.get("abuse", {})),
            "threat": self._threat(results.get("threat", {})),
            "ports": self._ports(results.get("ports", {})),
            "tor": self._tor(results.get("tor", {})),
            "cloud": self._cloud(results.get("cloud", {})),
        }
        raw_score = sum(item["points"] for item in contributions.values())
        total = max(0, min(100, round(raw_score)))
        return {
            "score": total,
            "label": self._label(total),
            "contributions": contributions,
        }

    def _geo(self, geo: dict[str, Any]) -> dict[str, Any]:
        points = 0.0
        reasons: list[str] = []
        country_code = geo.get("countryCode")
        as_text = f"{geo.get('as', '')} {geo.get('isp', '')} {geo.get('org', '')}".lower()
        if country_code in HIGH_RISK_COUNTRIES:
            points += 8
            reasons.append(f"País con riesgo elevado: {country_code}")
        for hint in BULLETPROOF_ASN_HINTS:
            if hint in as_text:
                points += 12
                reasons.append(f"ASN/hosting con histórico abusivo: {hint}")
                break
        return {"points": points, "reasons": reasons}

    def _abuse(self, abuse: dict[str, Any]) -> dict[str, Any]:
        data = abuse.get("data", {})
        confidence = float(data.get("abuseConfidenceScore") or 0)
        reports = int(data.get("totalReports") or 0)
        categories = data.get("categories") or []
        category_count = len(set(categories)) if isinstance(categories, list) else 0
        points = min(35, (confidence * 0.25) + min(reports, 100) * 0.06 + category_count * 1.5)
        reasons = []
        if confidence:
            reasons.append(f"AbuseIPDB confidence {confidence:.0f}")
        if reports:
            reasons.append(f"{reports} reportes de abuso")
        if category_count:
            reasons.append(f"{category_count} categorias de ataque")
        return {"points": points, "reasons": reasons}

    def _threat(self, threat: dict[str, Any]) -> dict[str, Any]:
        pulses = int(threat.get("pulse_count") or 0)
        sections = threat.get("sections") or []
        indicator_types = threat.get("indicator_types") or []
        points = min(25, pulses * 4 + len(sections) * 2 + len(set(indicator_types)) * 2)
        reasons = []
        if pulses:
            reasons.append(f"{pulses} pulsos OTX")
        if sections:
            reasons.append(f"Feeds OTX: {', '.join(sections[:5])}")
        return {"points": points, "reasons": reasons}

    def _ports(self, ports: dict[str, Any]) -> dict[str, Any]:
        open_ports = ports.get("open_ports") or []
        points = 0.0
        reasons = []
        for item in open_ports:
            port = int(item.get("port", 0))
            if port in SENSITIVE_PORTS:
                points += SENSITIVE_PORTS[port]
                reasons.append(f"Puerto sensible abierto: {port}")
            else:
                points += 1
        return {"points": min(25, points), "reasons": reasons}

    def _tor(self, tor: dict[str, Any]) -> dict[str, Any]:
        if tor.get("is_tor"):
            return {"points": 30, "reasons": ["Nodo Tor activo"]}
        return {"points": 0, "reasons": []}

    def _cloud(self, cloud: dict[str, Any]) -> dict[str, Any]:
        if cloud.get("is_cloud"):
            provider = cloud.get("provider", "cloud")
            return {"points": -8, "reasons": [f"Proveedor cloud legítimo detectado: {provider}"]}
        return {"points": 0, "reasons": []}

    def _label(self, score: int) -> str:
        if score >= 85:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 30:
            return "medium"
        return "low"
