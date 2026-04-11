# Python modules
import os
import json
from datetime import datetime
from typing import Any, Dict

# Project modules
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.pdfbase.pdfmetrics import stringWidth


def wrap_line(text: str, font_name: str, font_size: int, max_width: float):
    """Wrap a single line of text to fit within max_width when rendered with the given font."""
    words = text.split(" ")
    lines = []
    current_line = ""

    for word in words:
        test_line = current_line + (" " if current_line else "") + word
        if stringWidth(test_line, font_name, font_size) <= max_width:
            current_line = test_line
        else:
            if current_line:
                lines.append(current_line)
            current_line = word

    if current_line:
        lines.append(current_line)

    return lines


def _pdf_safe_text(value: Any) -> str:
    """Convert arbitrary text to a representation safe for built-in ReportLab fonts."""
    if value is None:
        return ""
    text = str(value)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def generate_pdf(report: Dict[str, Any], out_path: str) -> str:
    """Generate a PDF report from the given data and save it to out_path."""
    directory = os.path.dirname(out_path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    c = canvas.Canvas(out_path, pagesize=A4)
    width, height = A4

    margin = 40
    y = height - margin
    max_width = width - 2 * margin

    # ----- Title -----
    title = _pdf_safe_text(report.get("title") or f"Email Analysis Report {datetime.utcnow().isoformat()}")
    c.setFont("Helvetica-Bold", 16)
    c.drawString(margin, y, title)
    y -= 30

    c.setFont("Helvetica", 10)

    sections = [
        ("Summary", report.get("summary", "")),
        ("AI Result", json.dumps(report.get("ai", {}), indent=2, ensure_ascii=True)),
        ("Scoring", json.dumps(report.get("scoring", {}), indent=2, ensure_ascii=True)),
        ("Parsed Indicators", json.dumps(report.get("parsed", {}), indent=2, ensure_ascii=True)),
        ("Reputation", json.dumps(report.get("reputation", {}), indent=2, ensure_ascii=True)),
    ]

    for heading, body in sections:
        if y < 80:
            c.showPage()
            c.setFont("Helvetica", 10)
            y = height - margin

        # Section title
        c.setFont("Helvetica-Bold", 12)
        c.drawString(margin, y, _pdf_safe_text(heading))
        y -= 18
        c.setFont("Courier", 9)

        for raw_line in str(body).splitlines():
            raw_line = _pdf_safe_text(raw_line)
            wrapped_lines = wrap_line(raw_line, "Courier", 9, max_width)

            for line in wrapped_lines:
                if y < 60:
                    c.showPage()
                    c.setFont("Courier", 9)
                    y = height - margin

                c.drawString(margin + 10, y, _pdf_safe_text(line))
                y -= 12

        y -= 10

    c.save()
    return out_path