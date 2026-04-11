# Python modules
from typing import Any, Dict
import os
from uuid import uuid4
import logging

# Third-party modules
from celery import shared_task

# Project modules
from apps.detector.models import DetectorResult
from apps.detector.services.parser import parse_email
from apps.detector.services.ai_service import analyze_parsed
from apps.detector.services.report import generate_pdf
from apps.detector.services.analysis import build_reputation, compute_scores

# Django modules
from django.conf import settings


logger = logging.getLogger(__name__)



@shared_task(bind=True)
def analyze_email_task(self, detector_result_id: int) -> Dict[str, Any]:
    """Background task to analyze a DetectorResult by id.

    Steps:
    - Load DetectorResult
    - Parse input_data
    - Run reputation checks
    - Call AI analyze_parsed
    - Generate PDF report and attach to model
    - Update model fields
    """
    try:
        dr = DetectorResult.objects.get(id=detector_result_id)
    except DetectorResult.DoesNotExist:
        return {"error": "not_found"}

    # parse
    parsed = parse_email(dr.input_data)

    # reputation
    reputation = build_reputation(parsed, use_concurrency=False)

    # AI
    ai_out = analyze_parsed(parsed, reputation)

    # scoring (reuse same logic as views)
    scores = compute_scores(parsed, reputation, ai_out)
    final_score = scores["final_score"]

    report = {
        "title": "Email Analysis Report",
        "summary": f"Final score: {final_score:.2f}",
        "parsed": parsed,
        "reputation": reputation,
        "ai": ai_out,
        "scoring": scores,
    }

    # save PDF
    media_root = getattr(settings, "MEDIA_ROOT", "media") or "media"
    filename = f"report_{uuid4().hex}.pdf"
    out_dir = os.path.join(media_root, "reports")
    out_path = os.path.join(out_dir, filename)
    try:
        pdf_path = generate_pdf(report, out_path)
        # attach to model
        if pdf_path and os.path.exists(pdf_path):
            from django.core.files import File as DjangoFile
            with open(pdf_path, "rb") as f:
                django_file = DjangoFile(f)
                dr.report_file.save(filename, django_file, save=True)
    except Exception:
        logger.exception("Failed to generate or attach PDF report for detector_result_id=%s", detector_result_id)

    # update model
    dr.score = round(final_score, 2)
    dr.explanation = ai_out.get("reasoning", "")
    dr.is_safe = not bool(ai_out.get("is_phishing", False))
    dr.save()

    return {"status": "ok", "id": dr.id}
