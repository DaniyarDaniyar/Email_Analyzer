# Python modules
import json
import os
import re
from typing import Any, Dict

#Django modules

# Third-party modules
from openai import OpenAI


_client: OpenAI | None = None
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


def _get_client() -> OpenAI:
    """Initialize and return a singleton OpenAI client instance."""
    global _client

    if _client is not None:
        return _client

    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_KEY")

    if not api_key:
        try:
            from decouple import config
            api_key = config("OPENAI_API_KEY", default=None) or config("OPENAI_KEY", default=None)
        except Exception:
            api_key = None

    if not api_key:
        raise ValueError(
            "OPENAI_API_KEY (or OPENAI_KEY) environment variable is not set."
        )

    _client = OpenAI(api_key=api_key)
    return _client


def _generate_structured(prompt: str) -> Dict[str, Any]:
    """Send a structured prompt to the AI model and return the parsed JSON response."""
    try:
        
        client = _get_client()

        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an email security analyst integrated "
                        "into an automated threat detection system. "
                        "Respond ONLY with valid JSON."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
            max_tokens=800,
        )

        content = response.choices[0].message.content

        if not content:
            raise ValueError("Empty response from model")

        data = json.loads(content)

        return data

    except Exception as e:
        raise ValueError(f"AI service error: {str(e)}")


def _truncate_for_context(text: str, max_chars: int = 800) -> str:
    """Truncate text to fit within context limits, adding an indicator if truncated."""
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "...[truncated]"


def _safe_int(value: Any, default: int = 0) -> int:
    """Safely parse an integer value with a fallback default."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _extract_domain_from_header(value: Any) -> str:
    """Extract a sender domain from typical email header values."""
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
    """Count SPF/DKIM/DMARC checks that are missing or not passing."""
    anomalies = 0
    for field in ("spf", "dkim", "dmarc"):
        value = parsed.get(field)
        if value is None or str(value).strip() == "":
            anomalies += 1
            continue
        if str(value).strip().lower() != "pass":
            anomalies += 1
    return anomalies


def _subject_looks_suspicious(headers: Dict[str, Any]) -> bool:
    """Detect script/XSS-like payload markers in Subject header."""
    subject = str(headers.get("Subject", "") or "").lower()
    return any(marker in subject for marker in SUSPICIOUS_SUBJECT_MARKERS)


def _prepare_reputation_for_ai(reputation: Dict[str, Any]) -> Dict[str, Any]:
    """Extract compact reputation summaries and explicit high-risk indicators for AI analysis."""
    prepared: Dict[str, Any] = {
        "summary": {
            "urls": [],
            "domains": [],
            "ips": [],
        },
        "high_risk_indicators": [],
    }

    for url, data in list((reputation.get("urls") or {}).items())[:5]:
        if not isinstance(data, dict):
            continue
        item: Dict[str, Any] = {"url": url}

        vt_submit = data.get("virustotal_submit", {})
        if isinstance(vt_submit, dict) and vt_submit.get("error"):
            item["vt_error"] = str(vt_submit.get("error"))

        urlscan_submit = data.get("urlscan_submit", {})
        if isinstance(urlscan_submit, dict) and urlscan_submit.get("error"):
            item["urlscan_error"] = str(urlscan_submit.get("error"))

        prepared["summary"]["urls"].append(item)

    for domain, data in list((reputation.get("domains") or {}).items())[:5]:
        if not isinstance(data, dict):
            continue
        vt = data.get("virustotal") or {}
        vt_data = vt.get("data") if isinstance(vt, dict) else {}
        attrs = vt_data.get("attributes") if isinstance(vt_data, dict) else {}
        attrs = attrs if isinstance(attrs, dict) else {}

        stats = attrs.get("last_analysis_stats") or {}
        stats = stats if isinstance(stats, dict) else {}

        vt_malicious = _safe_int(stats.get("malicious"), 0)
        vt_suspicious = _safe_int(stats.get("suspicious"), 0)

        item = {
            "domain": domain,
            "vt_malicious": vt_malicious,
            "vt_suspicious": vt_suspicious,
            "vt_reputation": _safe_int(attrs.get("reputation"), 0),
        }
        prepared["summary"]["domains"].append(item)

        if vt_malicious > 0 or vt_suspicious > 0:
            prepared["high_risk_indicators"].append({
                "type": "domain",
                "value": domain,
                "vt_malicious": vt_malicious,
                "vt_suspicious": vt_suspicious,
            })

    for ip, data in list((reputation.get("ips") or {}).items())[:5]:
        if not isinstance(data, dict):
            continue
        abuse = data.get("abuseipdb") or {}
        abuse_data = abuse.get("data") if isinstance(abuse, dict) else {}
        abuse_data = abuse_data if isinstance(abuse_data, dict) else {}
        abuse_score = _safe_int(abuse_data.get("abuseConfidenceScore"), 0)

        vt = data.get("virustotal") or {}
        vt_data = vt.get("data") if isinstance(vt, dict) else {}
        attrs = vt_data.get("attributes") if isinstance(vt_data, dict) else {}
        attrs = attrs if isinstance(attrs, dict) else {}
        stats = attrs.get("last_analysis_stats") or {}
        stats = stats if isinstance(stats, dict) else {}
        vt_malicious = _safe_int(stats.get("malicious"), 0)
        vt_suspicious = _safe_int(stats.get("suspicious"), 0)

        item = {
            "ip": ip,
            "abuseipdb_confidence": abuse_score,
            "vt_malicious": vt_malicious,
            "vt_suspicious": vt_suspicious,
        }
        prepared["summary"]["ips"].append(item)

        if abuse_score > 0 or vt_malicious > 0 or vt_suspicious > 0:
            prepared["high_risk_indicators"].append({
                "type": "ip",
                "value": ip,
                "abuseipdb_confidence": abuse_score,
                "vt_malicious": vt_malicious,
                "vt_suspicious": vt_suspicious,
            })

    has_any_summary = any(prepared["summary"][k] for k in ("urls", "domains", "ips"))
    if not has_any_summary:
        return {"status": "no_reputation_data"}

    if not prepared["high_risk_indicators"]:
        prepared["high_risk_indicators"] = "none_detected"

    return prepared


def _apply_risk_guardrails(
    parsed: Dict[str, Any],
    is_phishing: bool,
    confidence: int,
    attack_type: str,
    signals: Any,
    reasoning: str,
) -> Dict[str, Any]:
    """Apply deterministic security guardrails to reduce AI false negatives."""
    adjusted_is_phishing = bool(is_phishing)
    adjusted_confidence = _safe_int(confidence, 0)
    adjusted_attack_type = str(attack_type or "unknown")
    adjusted_signals = list(signals) if isinstance(signals, list) else []
    adjusted_reasoning = str(reasoning or "")

    headers = parsed.get("headers") if isinstance(parsed.get("headers"), dict) else {}
    from_domain = _extract_domain_from_header(headers.get("From", "")) if isinstance(headers, dict) else ""

    parsed_domains = parsed.get("domains") or []
    url_domains = {
        str(domain).strip().lower()
        for domain in parsed_domains
        if str(domain).strip()
    }
    has_urls = bool(parsed.get("urls"))
    auth_anomalies = _count_auth_anomalies(parsed)
    sender_domain_mismatch = bool(from_domain and url_domains and from_domain not in url_domains)
    attack_type_lower = adjusted_attack_type.strip().lower().replace("_", "-")
    subject_suspicious = _subject_looks_suspicious(headers) if isinstance(headers, dict) else False

    # If model says benign but attack_type itself is high-risk, treat as inconsistency and escalate.
    if (not adjusted_is_phishing) and attack_type_lower in (
        "phishing",
        "spear-phishing",
        "spoofing",
        "malware",
        "scam",
    ):
        adjusted_is_phishing = True
        adjusted_confidence = max(adjusted_confidence, 70 if attack_type_lower == "malware" else 65)
        marker = "rule:attack_type_threat_inconsistency"
        if marker not in adjusted_signals:
            adjusted_signals.append(marker)
        adjusted_reasoning = (
            f"{adjusted_reasoning} Rule-based escalation: attack_type indicates a threat "
            "while is_phishing was false."
        ).strip()

    # Subject with script/XSS markers plus weak authentication is a strong indicator.
    if (not adjusted_is_phishing) and subject_suspicious and auth_anomalies >= 2:
        adjusted_is_phishing = True
        if attack_type_lower in ("unknown", "benign", ""):
            adjusted_attack_type = "malware"
        adjusted_confidence = max(adjusted_confidence, 72)
        marker = "rule:suspicious_subject_with_auth_failures"
        if marker not in adjusted_signals:
            adjusted_signals.append(marker)
        adjusted_reasoning = (
            f"{adjusted_reasoning} Rule-based escalation: Subject contains script-like payload "
            "markers with multiple authentication anomalies."
        ).strip()

    if (not adjusted_is_phishing) and has_urls and auth_anomalies >= 2 and sender_domain_mismatch:
        adjusted_is_phishing = True
        adjusted_attack_type = "spoofing"
        adjusted_confidence = max(adjusted_confidence, 75)
        marker = "rule:multi_auth_failures_with_sender_domain_mismatch"
        if marker not in adjusted_signals:
            adjusted_signals.append(marker)
        extra_reason = (
            "Rule-based escalation: email contains URLs, multiple authentication "
            "anomalies, and sender domain mismatch with linked domain(s)."
        )
        adjusted_reasoning = f"{adjusted_reasoning} {extra_reason}".strip()
    elif (not adjusted_is_phishing) and has_urls and auth_anomalies >= 2:
        adjusted_confidence = max(adjusted_confidence, 45)
        marker = "rule:multiple_authentication_anomalies"
        if marker not in adjusted_signals:
            adjusted_signals.append(marker)

    return {
        "is_phishing": adjusted_is_phishing,
        "confidence": int(max(0, min(100, adjusted_confidence))),
        "attack_type": adjusted_attack_type,
        "signals": adjusted_signals,
        "reasoning": adjusted_reasoning,
    }


def _normalize_confidence(raw_confidence: int, attack_type: str, is_phishing: bool) -> int:
    """Normalize confidence score to specific ranges based on attack type and phishing status.
    
    Score ranges:
    - Явный фишинг (phishing, spear-phishing): 90-100
    - Высокий риск (spoofing, malware, scam): 70-89
    - Средний риск (другие угрозы): 40-69
    - Низкий риск / Benign: 10-39
    
    Args:
        raw_confidence: Raw confidence (0-100) from AI model
        attack_type: Type of attack detected
        is_phishing: Whether phishing was detected
    
    Returns:
        Normalized confidence in appropriate range
    """
    if not is_phishing:
        # Benign - low risk range (10-39)
        return max(10, min(39, raw_confidence // 3 + 10))
    
    attack_type_lower = attack_type.lower() if attack_type else ""
    
    if attack_type_lower in ("phishing", "spear-phishing", "spear_phishing"):
        # Явный фишинг - 90-100
        return max(90, min(100, raw_confidence + 80 if raw_confidence >= 20 else 90))
    elif attack_type_lower in ("spoofing", "malware", "scam"):
        # Высокий риск - 70-89
        return max(70, min(89, raw_confidence + 60 if raw_confidence >= 10 else 70))
    else:
        # Средний риск - 40-69
        return max(40, min(69, raw_confidence + 40 if raw_confidence >= 5 else 40))


def _prepare_parsed_for_ai(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and prepare relevant parsed email data for AI analysis.
    
    NOTE: Include full content without truncation to ensure unique analysis for each email.
    Previously, aggressive truncation (100 chars From, 50 chars To, 600 chars body) caused
    similar emails to generate identical prompts and hit the cache with same results.
    """
    return {
        "from": parsed.get("headers", {}).get("From", ""),
        "to": parsed.get("headers", {}).get("To", ""),
        "subject": parsed.get("headers", {}).get("Subject", ""),
        "auth": {
            "spf": parsed.get("spf"),
            "dkim": parsed.get("dkim"),
            "dmarc": parsed.get("dmarc"),
        },
        "indicators": {
            "urls": parsed.get("urls", []),
            "emails": parsed.get("emails", []),
            "ips": parsed.get("ips", []),
            "domains": parsed.get("domains", []),
        },
        "body_preview": _truncate_for_context(parsed.get("plain", ""), 2000),
        "attachments": parsed.get("attachments", []),
    }


def analyze_parsed(parsed: Dict[str, Any], reputation: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze parsed email data and reputation indicators using AI to determine phishing likelihood."""
    prepared_parsed = _prepare_parsed_for_ai(parsed)
    prepared_reputation = _prepare_reputation_for_ai(reputation)

    prompt = f"""
# CONTEXT
You are an AI cybersecurity system integrated into an automated email threat detection pipeline.

Email Data:
{json.dumps(prepared_parsed, ensure_ascii=False)}

Reputation Data:
{json.dumps(prepared_reputation, ensure_ascii=False)}

# OBJECTIVE
Analyze the email and determine the threat level. Classify the attack type carefully:

ATTACK TYPES:
- "phishing": Direct phishing attempts (credential harvesting, fake login pages, urgent actions)
- "spear-phishing": Personalized phishing targeting specific individuals with researched details
- "spoofing": Sender address/domain spoofing or header manipulation
- "malware": Suspicious attachments, malicious links, exploit attempts
- "scam": Financial scams, overpayment schemes, lottery scams, fake invoices
- "benign": Legitimate email with no security concerns

Provide a confidence score (0-100) based on:
- Authentication failures (SPF, DKIM, DMARC)
- Domain reputation and reputation service data
- Content patterns (urgency, threats, requests for sensitive info)
- Technical indicators (suspicious URLs, IPs, attachments)
- Social engineering signals

IMPORTANT:
- If email has URLs and 2+ authentication anomalies (missing/fail SPF/DKIM/DMARC),
  avoid classifying as strictly benign unless there is strong contradictory evidence.
- If sender domain differs from linked URL domain and auth is weak/missing,
  treat as at least spoofing risk.

# RESPONSE FORMAT
Return EXACTLY this JSON structure:

{{
  "is_phishing": true or false,
  "confidence": integer between 0 and 100,
  "attack_type": "phishing" | "spear-phishing" | "spoofing" | "malware" | "scam" | "benign" | etc,
  "signals": ["list of detected technical indicators"],
  "reasoning": "concise technical explanation"
}}
"""

    data = _generate_structured(prompt)

    is_phishing_flag = bool(data.get("is_phishing", False))
    raw_confidence = _safe_int(data.get("confidence", 0), 0)
    attack_type = str(data.get("attack_type", "unknown"))
    
    normalized_confidence = _normalize_confidence(raw_confidence, attack_type, is_phishing_flag)

    guarded = _apply_risk_guardrails(
        parsed=parsed,
        is_phishing=is_phishing_flag,
        confidence=normalized_confidence,
        attack_type=attack_type,
        signals=data.get("signals", []),
        reasoning=str(data.get("reasoning", "")),
    )

    return guarded