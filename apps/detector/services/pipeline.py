# Python modules
import os
import posixpath
import tempfile
from typing import Any, Dict, Optional, Tuple
from uuid import uuid4

# Django modules
from django.conf import settings
from django.core.files import File as DjangoFile
from django.urls import reverse
from django.utils import timezone

# Project modules
from apps.detector.models import DetectorResult
from apps.detector.services.analysis import build_reputation, compute_scores
from apps.detector.services.ai_service import analyze_parsed, analyze_url
from apps.detector.services.parser import parse_email
from apps.detector.services.report import generate_pdf
from apps.detector.services.rules import evaluate_rules
from apps.detector.services.privacy import scrub_data, mask_sensitive_text
from apps.detector.services.audit import log_event


def _build_url_parsed(url: str) -> Dict[str, Any]:
    parsed = {"urls": [url], "domains": [], "ips": [], "headers": {}}
    try:
        from urllib.parse import urlparse

        netloc = urlparse(url).netloc or url
        domain = netloc.split(":")[0]
        if domain:
            parsed["domains"].append(domain)
    except Exception:
        return parsed

    return parsed


def _build_report_payload(analysis: Dict[str, Any], mask_pii: bool) -> Dict[str, Any]:
    report = {
        "title": "Email Analysis Report",
        "summary": f"Final score: {analysis['score']:.2f}",
        "parsed": analysis.get("parsed"),
        "reputation": analysis.get("reputation"),
        "ai": analysis.get("ai_out"),
        "scoring": analysis.get("scores"),
        "score_details": analysis.get("score_details"),
    }
    if mask_pii:
        return scrub_data(report)
    return report


def _generate_report_pdf(report: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    filename = f"report_{uuid4().hex}.pdf"
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pdf", prefix="report_")
        os.close(tmp_fd)
        pdf_path = generate_pdf(report, tmp_path)
        return pdf_path, filename
    except Exception:
        return None, None


def _build_media_report_url(filename: str) -> str:
    media_url = getattr(settings, "MEDIA_URL", "/media/") or "/media/"
    return posixpath.join(media_url.rstrip("/"), "reports", filename)


def build_report_download_url(request, detector_result: DetectorResult) -> Optional[str]:
    if not detector_result.report_file:
        return None
    path = reverse("detector-download-report", kwargs={"pk": detector_result.id})
    if request is None:
        return path
    return request.build_absolute_uri(path)


def analyze_input(
    input_type: str,
    input_data: str,
    *,
    use_concurrency: bool = True,
) -> Dict[str, Any]:
    if input_type in ("text", "file"):
        parsed = parse_email(input_data)
        reputation = build_reputation(parsed, use_concurrency=use_concurrency)
        ai_out = analyze_parsed(parsed, reputation)
    else:
        parsed = _build_url_parsed(input_data)
        reputation = build_reputation(parsed, use_concurrency=use_concurrency)
        ai_out = analyze_url(input_data, reputation)

    rules_result = evaluate_rules(parsed)
    scores = compute_scores(parsed, reputation, ai_out, rules_result=rules_result)
    classification = "phishing" if ai_out.get("is_phishing") else "benign"
    explanation = str(ai_out.get("reasoning", ""))
    score_details = dict(scores.get("breakdown", {}))
    score_details["rules"] = rules_result.get("triggered", [])

    return {
        "classification": classification,
        "score": scores.get("final_score", 0.0),
        "explanation": explanation,
        "parsed": parsed,
        "reputation": reputation,
        "ai_out": ai_out,
        "scores": scores,
        "score_details": score_details,
    }


def create_queued_result(user, input_type: str, input_data: str) -> DetectorResult:
    detector_result = DetectorResult.objects.create(
        user=user,
        input_type=input_type,
        input_data=input_data,
        status=DetectorResult.STATUS_QUEUED,
    )
    log_event("scan_queued", user=user, obj=detector_result)
    return detector_result


def run_sync_scan(
    input_type: str,
    input_data: str,
    *,
    user=None,
    request=None,
    use_concurrency: bool = True,
) -> Dict[str, Any]:
    allow_guest_reports = bool(getattr(settings, "ALLOW_GUEST_REPORTS", False))
    allow_report = bool(user) or allow_guest_reports
    mask_pii = bool(getattr(settings, "MASK_PII_IN_REPORTS", False)) or not bool(user)

    started_at = timezone.now()
    analysis = analyze_input(input_type, input_data, use_concurrency=use_concurrency)

    pdf_path = None
    filename = None
    report_url = None
    if allow_report:
        report_payload = _build_report_payload(analysis, mask_pii=mask_pii)
        pdf_path, filename = _generate_report_pdf(report_payload)

    detector_result = None
    if user and user.is_authenticated:
        detector_result = DetectorResult.objects.create(
            user=user,
            input_type=input_type,
            input_data=input_data,
            score=round(float(analysis["score"]), 2),
            explanation=analysis.get("explanation", ""),
            is_safe=analysis.get("classification") == "benign",
            status=DetectorResult.STATUS_COMPLETED,
            started_at=started_at,
            score_details=analysis.get("score_details"),
        )

        detector_result.finished_at = timezone.now()
        if pdf_path and filename and os.path.exists(pdf_path):
            try:
                with open(pdf_path, "rb") as f:
                    detector_result.report_file.save(filename, DjangoFile(f), save=True)
            except Exception:
                pass
            finally:
                try:
                    os.unlink(pdf_path)
                except OSError:
                    pass
        detector_result.save(update_fields=["finished_at"])
        report_url = build_report_download_url(request, detector_result)
        log_event("scan_completed", user=user, obj=detector_result)
    elif allow_guest_reports and filename:
        report_url = _build_media_report_url(filename)
        log_event(
            "scan_completed_guest",
            user=None,
            obj=None,
            meta={"input_type": input_type},
            request=request,
        )

    response_data = {
        "classification": analysis.get("classification"),
        "score": round(float(analysis.get("score", 0.0)), 2),
        "explanation": mask_sensitive_text(analysis.get("explanation", "")) if mask_pii else analysis.get("explanation", ""),
        "saved": detector_result is not None,
        "result_id": detector_result.id if detector_result else None,
        "report_url": report_url,
        "status": detector_result.status if detector_result else DetectorResult.STATUS_COMPLETED,
        "score_details": analysis.get("score_details"),
    }
    return response_data


def process_detector_result(detector_result_id: int, *, use_concurrency: bool = False) -> Dict[str, Any]:
    try:
        dr = DetectorResult.objects.get(id=detector_result_id)
    except DetectorResult.DoesNotExist:
        return {"error": "not_found"}

    dr.status = DetectorResult.STATUS_RUNNING
    dr.started_at = timezone.now()
    dr.error_message = None
    dr.save(update_fields=["status", "started_at", "error_message", "updated_at"])

    try:
        analysis = analyze_input(dr.input_type, dr.input_data, use_concurrency=use_concurrency)
        report_payload = _build_report_payload(
            analysis,
            mask_pii=bool(getattr(settings, "MASK_PII_IN_REPORTS", False)),
        )
        pdf_path, filename = _generate_report_pdf(report_payload)

        dr.score = round(float(analysis.get("score", 0.0)), 2)
        dr.explanation = analysis.get("explanation", "")
        dr.is_safe = analysis.get("classification") == "benign"
        dr.status = DetectorResult.STATUS_COMPLETED
        dr.finished_at = timezone.now()
        dr.score_details = analysis.get("score_details")
        dr.error_message = None

        if pdf_path and filename and os.path.exists(pdf_path):
            try:
                with open(pdf_path, "rb") as f:
                    dr.report_file.save(filename, DjangoFile(f), save=True)
            except Exception:
                pass
            finally:
                try:
                    os.unlink(pdf_path)
                except OSError:
                    pass

        dr.save()
        log_event("scan_completed", user=dr.user, obj=dr)
        return {"status": "ok", "id": dr.id}

    except Exception as e:
        dr.status = DetectorResult.STATUS_FAILED
        dr.finished_at = timezone.now()
        dr.error_message = str(e)
        dr.save(update_fields=["status", "finished_at", "error_message", "updated_at"])
        log_event("scan_failed", user=dr.user, obj=dr, meta={"error": str(e)})
        return {"status": "failed", "id": dr.id, "error": str(e)}
