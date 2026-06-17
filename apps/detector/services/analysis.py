# Python modules
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from typing import Any, Dict

# Django modules
from django.conf import settings

# Project modules
from apps.detector.services.reputation import ReputationService


EMAIL_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
SUSPICIOUS_SUBJECT_MARKERS = (
    "<script",
    "</script",
    "javascript:",
    "onload=",
    "onerror=",
    "<iframe",
    "alert(",
    "document.cookie",
    "eval(",
)


def build_reputation(parsed: Dict[str, Any], use_concurrency: bool = True) -> Dict[str, Any]:
    """Run reputation checks for URLs, domains and IPs found in parsed data."""
    rep_service = ReputationService()
    reputation: Dict[str, Any] = {"urls": {}, "domains": {}, "ips": {}}

    urls = parsed.get("urls", []) or []
    domains = parsed.get("domains", []) or []
    ips = parsed.get("ips", []) or []

    if use_concurrency:
        with ThreadPoolExecutor(max_workers=6) as ex:
            futures: Dict[Any, Any] = {}
            for u in urls:
                futures[ex.submit(rep_service.check_url, u)] = ("url", u)
            for d in domains:
                futures[ex.submit(rep_service.check_domain, d)] = ("domain", d)
            for ip in ips:
                futures[ex.submit(rep_service.check_ip, ip)] = ("ip", ip)

            for fut in as_completed(futures):
                kind, val = futures[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = {"error": str(e)}
                if kind == "url":
                    reputation["urls"][val] = res
                elif kind == "domain":
                    reputation["domains"][val] = res
                else:
                    reputation["ips"][val] = res
    else:
        for u in urls:
            reputation["urls"][u] = rep_service.check_url(u)
        for d in domains:
            reputation["domains"][d] = rep_service.check_domain(d)
        for ip in ips:
            reputation["ips"][ip] = rep_service.check_ip(ip)

    return reputation


def compute_scores(
    parsed: Dict[str, Any],
    reputation: Dict[str, Any],
    ai_out: Dict[str, Any],
    rules_result: Dict[str, Any] | None = None,
) -> Dict[str, float | Dict[str, float]]:
    """Combine AI output, reputation and header anomalies into final scores.

    The AI service returns a confidence score plus an ``is_phishing`` boolean.
    ``confidence`` is converted to a risk-oriented AI score before weighting.
    For phishing classifications, confidence maps directly to risk.
    For benign classifications, a capped low-risk mapping is used so the final
    score does not become unrealistically high, but also does not collapse to 0
    too often when there is non-zero model uncertainty.
    """

    def _is_malicious(rep: dict) -> bool:
        try:
            vt = rep.get("virustotal_report") or rep.get("virustotal") or rep.get("virustotal_submit")
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
                if (
                    isinstance(a_data, dict)
                    and a_data.get("abuseConfidenceScore", 0)
                    and int(a_data.get("abuseConfidenceScore", 0)) > 0
                ):
                    return True
        except Exception:
            return False
        return False

    def _extract_domain_from_header(value: Any) -> str:
        if value is None:
            return ""
        text = str(value).strip().lower()
        if not text:
            return ""

        match = EMAIL_DOMAIN_RE.search(text)
        if match:
            return match.group(1)

        if "@" in text and " " not in text:
            return text.split("@", 1)[1]

        return ""

    total_indicators = 0
    malicious_count = 0

    for r in reputation.get("urls", {}).values():
        total_indicators += 1
        if _is_malicious(r):
            malicious_count += 1
    for r in reputation.get("domains", {}).values():
        total_indicators += 1
        if _is_malicious(r):
            malicious_count += 1
    for r in reputation.get("ips", {}).values():
        total_indicators += 1
        if _is_malicious(r):
            malicious_count += 1

    malicious_ratio = (malicious_count / total_indicators) if total_indicators > 0 else 0.0

    try:
        ai_conf_raw = float(ai_out.get("confidence", 0))
    except (TypeError, ValueError):
        ai_conf_raw = 0.0
    ai_conf_raw = max(0.0, min(100.0, ai_conf_raw))
    is_phishing = bool(ai_out.get("is_phishing", False))
    attack_type_lower = str(ai_out.get("attack_type", "") or "").strip().lower().replace("_", "-")
    if is_phishing:
        ai_risk_score = ai_conf_raw
    else:
        # Handle both semantics:
        # - risk-like benign confidence in [0, 50] -> keep as-is (capped)
        # - class-confidence-like benign confidence in (50, 100] -> invert
        #   so very confident benign predictions stay low-risk.
        benign_risk = ai_conf_raw if ai_conf_raw <= 50 else (100.0 - ai_conf_raw)
        ai_risk_score = max(5.0, min(40.0, benign_risk))
        if attack_type_lower in ("phishing", "spear-phishing", "spoofing", "scam"):
            ai_risk_score = max(ai_risk_score, 55.0)
        if attack_type_lower == "malware":
            ai_risk_score = max(ai_risk_score, 65.0)

    # Header anomaly: missing auth checks are treated as anomalies.
    anomalies = 0
    checks = 3
    for field in ("spf", "dkim", "dmarc"):
        val = parsed.get(field)
        if val is None or str(val).strip() == "":
            anomalies += 1
            continue
        if str(val).strip().lower() != "pass":
            anomalies += 1
    header_score = anomalies / checks * 100

    headers = parsed.get("headers") if isinstance(parsed.get("headers"), dict) else {}
    from_domain = _extract_domain_from_header(headers.get("From", "")) if isinstance(headers, dict) else ""
    parsed_domains = parsed.get("domains") or []
    url_domains = {
        str(domain).strip().lower()
        for domain in parsed_domains
        if str(domain).strip()
    }
    has_urls = bool(parsed.get("urls"))
    sender_domain_mismatch = bool(from_domain and url_domains and from_domain not in url_domains)
    subject_text = str(headers.get("Subject", "") or "").lower() if isinstance(headers, dict) else ""
    subject_suspicious = any(marker in subject_text for marker in SUSPICIOUS_SUBJECT_MARKERS)

    structural_score = 0.0
    if has_urls:
        structural_score += 10.0
    if has_urls and anomalies >= 2:
        structural_score += 25.0
    elif has_urls and anomalies == 1:
        structural_score += 10.0
    if sender_domain_mismatch:
        structural_score += 20.0 if anomalies >= 1 else 8.0
    if subject_suspicious:
        structural_score += 20.0
    if subject_suspicious and anomalies >= 2:
        structural_score += 15.0
    structural_score = min(structural_score, 100.0)

    rules_score = 0.0
    if rules_result and isinstance(rules_result, dict):
        try:
            rules_score = float(rules_result.get("score", 0.0))
        except (TypeError, ValueError):
            rules_score = 0.0

    weight_ai = float(getattr(settings, "SCORE_AI_WEIGHT", 0.45))
    weight_rep = float(getattr(settings, "SCORE_REPUTATION_WEIGHT", 0.2))
    weight_header = float(getattr(settings, "SCORE_HEADER_WEIGHT", 0.2))
    weight_struct = float(getattr(settings, "SCORE_STRUCTURAL_WEIGHT", 0.15))
    weight_rules = float(getattr(settings, "SCORE_RULES_WEIGHT", 0.0))

    weighted_score = (
        ai_risk_score * weight_ai
        + malicious_ratio * 100 * weight_rep
        + header_score * weight_header
        + structural_score * weight_struct
        + rules_score * weight_rules
    )
    weighted_score = max(0.0, min(100.0, weighted_score))
    final_score = max(weighted_score, ai_risk_score, structural_score, rules_score)
    final_score = max(0.0, min(100.0, final_score))

    breakdown = {
        "ai_risk_score": float(round(ai_risk_score, 2)),
        "reputation_score": float(round(malicious_ratio * 100, 2)),
        "header_score": float(round(header_score, 2)),
        "structural_score": float(round(structural_score, 2)),
        "rules_score": float(round(rules_score, 2)),
        "weighted_score": float(round(weighted_score, 2)),
    }

    return {
        "final_score": float(round(final_score, 2)),
        "malicious_ratio": float(malicious_ratio),
        "header_score": float(round(header_score, 2)),
        "structural_score": float(round(structural_score, 2)),
        "rules_score": float(round(rules_score, 2)),
        "breakdown": breakdown,
    }

