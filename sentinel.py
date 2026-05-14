#!/usr/bin/env python3
"""SENTINEL CLI entrypoint."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path

from dotenv import load_dotenv

from sentinel.core.engine import SentinelEngine


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="SENTINEL - análisis OSINT de reputación de IPs.",
    )
    parser.add_argument("ip", help="Dirección IP a analizar")
    parser.add_argument(
        "-o",
        "--output-dir",
        default="output",
        help="Directorio de salida para HTML y JSON (default: output)",
    )
    parser.add_argument(
        "--no-ports",
        action="store_true",
        help="Omite el escaneo nmap de puertos.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="Timeout por peticion externa en segundos (default: 20)",
    )
    return parser.parse_args()


def main() -> int:
    load_dotenv()
    args = parse_args()

    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        print(f"IP inválida: {args.ip}")
        return 2

    engine = SentinelEngine(
        output_dir=Path(args.output_dir),
        timeout=args.timeout,
        scan_ports=not args.no_ports,
    )
    result = engine.run(args.ip)

    print("\nSENTINEL completado")
    print(f"IP: {args.ip}")
    print(f"Threat Score: {result['score']['score']}/100 ({result['score']['label']})")
    print(f"HTML: {result['artifacts']['html']}")
    print(f"JSON: {result['artifacts']['json']}")
    if result.get("errors"):
        print("\nErrores no fatales por fase:")
        print(json.dumps(result["errors"], indent=2, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
