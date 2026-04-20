# Python modules
import re
from typing import Any, Dict, List

# Django modules
from django.conf import settings

EMAIL_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")

DEFAULT_RULES: List[Dict[str, Any]] = [
    {
        "id": "subject_urgent_language",
        "type": "subject_regex",
        "pattern": r"(urgent|immediate action|verify|account|invoice)",
        "score": 15,
    },
    {
        "id": "auth_anomalies_gte_2",
        "type": "auth_anomalies_gte",
        "threshold": 2,
        "score": 20,
    },
    {
        "id": "url_count_gte_1",
        "type": "url_count_gte",
        "threshold": 1,
        "score": 10,
    },
    {
        "id": "sender_domain_mismatch",
        "type": "sender_domain_mismatch",
        "score": 15,
    },
]


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


def _count_auth_anomalies(parsed: Dict[str, Any]) -> int:
    anomalies = 0
    for field in ("spf", "dkim", "dmarc"):
        value = parsed.get(field)
        if value is None or str(value).strip() == "":
            anomalies += 1
            continue
        if str(value).strip().lower() != "pass":
            anomalies += 1
    return anomalies


def _get_rules() -> List[Dict[str, Any]]:
    rules = getattr(settings, "DETECTION_RULES", None)
    if rules is None:
        return DEFAULT_RULES
    if not isinstance(rules, list):
        return DEFAULT_RULES
    return rules


def evaluate_rules(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate deterministic rules and return score and triggered rules list."""
    rules = _get_rules()
    headers = parsed.get("headers") if isinstance(parsed.get("headers"), dict) else {}
    subject = str(headers.get("Subject", "") or "") if isinstance(headers, dict) else ""
    from_header = str(headers.get("From", "") or "") if isinstance(headers, dict) else ""
    body = "\n".join(
        [
            str(parsed.get("plain", "") or ""),
            str(parsed.get("html", "") or ""),
        ]
    )

    auth_anomalies = _count_auth_anomalies(parsed)
    urls = parsed.get("urls") or []
    attachments = parsed.get("attachments") or []

    from_domain = _extract_domain_from_header(from_header)
    parsed_domains = parsed.get("domains") or []
    url_domains = {
        str(domain).strip().lower()
        for domain in parsed_domains
        if str(domain).strip()
    }
    sender_domain_mismatch = bool(from_domain and url_domains and from_domain not in url_domains)

    triggered: List[Dict[str, Any]] = []
    total_score = 0.0

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rule_type = str(rule.get("type", "")).strip()
        rule_id = str(rule.get("id", rule_type or "rule")).strip() or "rule"
        try:
            rule_score = float(rule.get("score", 0) or 0)
        except (TypeError, ValueError):
            rule_score = 0.0
        detail = None
        matched = False

        if rule_type == "subject_regex":
            pattern = rule.get("pattern")
            if pattern:
                if re.search(pattern, subject, flags=re.I):
                    matched = True
                    detail = f"subject matched /{pattern}/"
        elif rule_type == "body_regex":
            pattern = rule.get("pattern")
            if pattern:
                if re.search(pattern, body, flags=re.I):
                    matched = True
                    detail = f"body matched /{pattern}/"
        elif rule_type == "from_regex":
            pattern = rule.get("pattern")
            if pattern:
                if re.search(pattern, from_header, flags=re.I):
                    matched = True
                    detail = f"from matched /{pattern}/"
        elif rule_type == "auth_anomalies_gte":
            threshold = int(rule.get("threshold", 0) or 0)
            if auth_anomalies >= threshold and threshold > 0:
                matched = True
                detail = f"auth anomalies >= {threshold}"
        elif rule_type == "url_count_gte":
            threshold = int(rule.get("threshold", 0) or 0)
            if len(urls) >= threshold and threshold > 0:
                matched = True
                detail = f"urls >= {threshold}"
        elif rule_type == "sender_domain_mismatch":
            if sender_domain_mismatch:
                matched = True
                detail = "sender domain mismatch"
        elif rule_type == "has_attachments":
            if attachments:
                matched = True
                detail = "has attachments"

        if matched:
            triggered.append({"id": rule_id, "score": rule_score, "detail": detail})
            total_score += rule_score

    total_score = min(100.0, max(0.0, total_score))
    return {"score": total_score, "triggered": triggered}
