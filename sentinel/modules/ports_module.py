"""Port scanning via system nmap."""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any


class PortsModule:
    def __init__(self, timeout: int = 20) -> None:
        self.timeout = timeout

    def run(self, ip: str) -> dict[str, Any]:
        if not shutil.which("nmap"):
            return {"ok": False, "skipped": True, "reason": "nmap no encontrado"}

        ports = "21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,2049,2375,3306,3389,5432,5900,6379,8080,8443,9200,11211,27017"
        command = ["nmap", "-Pn", "-T3", "--open", "-p", ports, "-oX", "-", ip]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=max(self.timeout * 3, 45),
        )
        if completed.returncode not in (0, 1):
            raise RuntimeError(completed.stderr.strip() or "nmap failed")

        open_ports: list[dict[str, Any]] = []
        if completed.stdout.strip():
            root = ET.fromstring(completed.stdout)
            for port_node in root.findall(".//port"):
                state = port_node.find("state")
                if state is None or state.attrib.get("state") != "open":
                    continue
                service = port_node.find("service")
                port = int(port_node.attrib["portid"])
                name = service.attrib.get("name", "unknown") if service is not None else "unknown"
                product = service.attrib.get("product", "") if service is not None else ""
                open_ports.append(
                    {
                        "port": port,
                        "protocol": port_node.attrib.get("protocol", "tcp"),
                        "service": name,
                        "product": product,
                        "severity": self._severity(port),
                    }
                )

        return {"ok": True, "open_ports": open_ports, "count": len(open_ports), "command": " ".join(command)}

    def _severity(self, port: int) -> str:
        if port in {23, 445, 2375, 3389, 5900, 6379, 9200, 11211, 27017}:
            return "danger"
        if port in {21, 22, 25, 1433, 1521, 2049, 3306, 5432, 8080, 8443}:
            return "warning"
        return "safe"
