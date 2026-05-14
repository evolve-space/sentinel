"""Standalone HTML report rendering."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


class ReportGenerator:
    def __init__(self) -> None:
        self.template_dir = Path(__file__).resolve().parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def render(self, payload: dict[str, Any], output_path: Path) -> None:
        template = self.env.get_template("report.html")
        html = template.render(payload=payload)
        output_path.write_text(html, encoding="utf-8")
