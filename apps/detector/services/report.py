import os
import json
from datetime import datetime
from typing import Any, Dict
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def generate_pdf(report: Dict[str, Any], out_path: str) -> str:
    """Generate a simple PDF report from structured `report` and save to `out_path`.

    Returns path to generated file.
    """
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    c = canvas.Canvas(out_path, pagesize=A4)
    width, height = A4
    x = 40
    y = height - 40

    title = report.get("title") or f"Email Analysis Report {datetime.utcnow().isoformat()}"
    c.setFont("Helvetica-Bold", 16)
    c.drawString(x, y, title)
    y -= 30

    c.setFont("Helvetica", 10)
    sections = [
        ("Summary", report.get("summary", "")),
        ("AI Result", json.dumps(report.get("ai", {}), indent=2, ensure_ascii=False)),
        ("Scoring", json.dumps(report.get("scoring", {}), indent=2, ensure_ascii=False)),
        ("Parsed Indicators", json.dumps(report.get("parsed", {}), indent=2, ensure_ascii=False)),
        ("Reputation", json.dumps(report.get("reputation", {}), indent=2, ensure_ascii=False)),
    ]

    for heading, body in sections:
        if y < 120:
            c.showPage()
            y = height - 40
            c.setFont("Helvetica", 10)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(x, y, heading)
        y -= 18
        c.setFont("Helvetica", 9)
        for line in str(body).splitlines():
            if y < 60:
                c.showPage()
                y = height - 40
            c.drawString(x + 10, y, line[:1000])
            y -= 12
        y -= 10

    c.showPage()
    c.save()
    return out_path