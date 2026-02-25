import os
import json
from datetime import datetime
from typing import Any, Dict

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    XPreformatted,
    HRFlowable
)
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet
)
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4


def force_wrap(text: str, max_chars: int = 90) -> str:
    """
    Принудительно разбивает длинные строки,
    даже если в них нет пробелов.
    """
    wrapped_lines = []

    for line in text.splitlines():
        while len(line) > max_chars:
            wrapped_lines.append(line[:max_chars])
            line = line[max_chars:]
        wrapped_lines.append(line)

    return "\n".join(wrapped_lines)


def generate_pdf(report: Dict[str, Any], out_path: str) -> str:

    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    doc = SimpleDocTemplate(
        out_path,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    elements = []
    styles = getSampleStyleSheet()

    title_style = styles["Heading1"]
    section_style = styles["Heading2"]

    normal_style = styles["BodyText"]
    normal_style.wordWrap = "CJK"

    json_style = ParagraphStyle(
        "JsonStyle",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        backColor=colors.whitesmoke,
        leftIndent=6,
        rightIndent=6,
        spaceAfter=8,
    )

    title = report.get("title") or f"Email Analysis Report — {datetime.utcnow().isoformat()}"
    elements.append(Paragraph(title, title_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    elements.append(Spacer(1, 14))

    sections = [
        ("Summary", report.get("summary", "")),
        ("AI Result", report.get("ai", {})),
        ("Scoring", report.get("scoring", {})),
        ("Parsed Indicators", report.get("parsed", {})),
        ("Reputation", report.get("reputation", {})),
    ]

    for heading, body in sections:
        elements.append(Paragraph(heading, section_style))
        elements.append(Spacer(1, 6))

        if isinstance(body, dict):
            formatted_json = json.dumps(body, indent=2, ensure_ascii=False)

            formatted_json = force_wrap(formatted_json, 90)

            elements.append(XPreformatted(formatted_json, json_style))
        else:
            text = force_wrap(str(body), 100)
            elements.append(Paragraph(text, normal_style))

        elements.append(Spacer(1, 14))

    doc.build(elements)

    return out_path