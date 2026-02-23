from celery import shared_task
from typing import Any, Dict
from apps.detector.models import DetectorResult
from apps.detector.services.parser import parse_email
from apps.detector.services.reputation import ReputationService
from apps.detector.services.ai_service import analyze_parsed
from apps.detector.services.report import generate_pdf
from django.conf import settings
import os
import time


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
    rep_service = ReputationService()
    reputation = {"urls": {}, "domains": {}, "ips": {}}
    for u in parsed.get("urls", []):
        reputation["urls"][u] = rep_service.check_url(u)
    for d in parsed.get("domains", []):
        reputation["domains"][d] = rep_service.check_domain(d)
    for ip in parsed.get("ips", []):
        reputation["ips"][ip] = rep_service.check_ip(ip)

    # AI
    ai_out = analyze_parsed(parsed, reputation)

    # scoring (simplified: mirror view's logic)
    malicious_count = 0
    total_indicators = 0

    def _is_malicious(rep: dict) -> bool:
        try:
            vt = rep.get("virustotal") or rep.get("virustotal_submit")
            if isinstance(vt, dict):
                data = vt.get("data") or vt
                attrs = data.get("attributes") if isinstance(data, dict) else None
                if attrs and isinstance(attrs, dict):
                    stats = attrs.get("last_analysis_stats") or {}
                    if isinstance(stats, dict) and int(stats.get("malicious", 0)) > 0:
                        return True
            abuse = rep.get("abuseipdb") or {}
            if isinstance(abuse, dict):
                a_data = abuse.get("data") or {}
                if isinstance(a_data, dict) and a_data.get("abuseConfidenceScore", 0) and int(a_data.get("abuseConfidenceScore", 0)) > 0:
                    return True
        except Exception:
            return False
        return False

    for r in reputation["urls"].values():
        total_indicators += 1
        if _is_malicious(r):
            malicious_count += 1
    for r in reputation["domains"].values():
        total_indicators += 1
        if _is_malicious(r):
            malicious_count += 1
    for r in reputation["ips"].values():
        total_indicators += 1
        if _is_malicious(r):
            malicious_count += 1

    malicious_ratio = (malicious_count / total_indicators) if total_indicators > 0 else 0.0
    ai_conf = float(ai_out.get("confidence", 0))

    anomalies = 0
    checks = 0
    for field in ("spf", "dkim", "dmarc"):
        val = parsed.get(field)
        if val is not None:
            checks += 1
            if str(val).lower() != "pass":
                anomalies += 1
    header_score = (anomalies / checks * 100) if checks > 0 else 0.0

    final_score = ai_conf * 0.5 + malicious_ratio * 100 * 0.3 + header_score * 0.2

    report = {
        "title": "Email Analysis Report",
        "summary": f"Final score: {final_score:.2f}",
        "parsed": parsed,
        "reputation": reputation,
        "ai": ai_out,
        "scoring": {"final_score": round(final_score, 2), "malicious_ratio": malicious_ratio, "header_score": header_score},
    }

    # save PDF
    media_root = getattr(settings, "MEDIA_ROOT", "media") or "media"
    filename = f"report_{int(time.time())}.pdf"
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
        pass

    # update model
    dr.score = round(final_score, 2)
    dr.explanation = ai_out.get("reasoning", "")
    dr.is_safe = not bool(ai_out.get("is_phishing", False))
    dr.save()

    return {"status": "ok", "id": dr.id}
