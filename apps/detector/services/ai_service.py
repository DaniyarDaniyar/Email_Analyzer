# Python modules
import json
import os
from typing import Any, Dict

#Django modules

# Third-party modules
from openai import OpenAI


_client: OpenAI | None = None


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
        # NOTE: Disabled caching for email analysis to ensure unique analysis per email.
        # Previously, similar email headers/subjects could generate identical hashes,
        # causing the system to return the same cached confidence (85) for different emails.
        # Each email should be independently analyzed.
        
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
            temperature=0.7,
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


def _prepare_reputation_for_ai(reputation: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and prepare relevant reputation indicators for AI analysis."""
    prepared: Dict[str, Any] = {}

    # URLs
    if "urls" in reputation:
        suspicious_urls = {}
        for url, data in list(reputation.get("urls", {}).items())[:5]:
            if isinstance(data, dict):
                vt = data.get("virustotal_submit", {})
                if isinstance(vt, dict) and vt.get("error") and "no_api_key" not in str(vt):
                    suspicious_urls[url] = {"virustotal": vt}

        if suspicious_urls:
            prepared["suspicious_urls"] = suspicious_urls

    # Domains
    if "domains" in reputation:
        suspicious_domains = {}
        for domain, data in list(reputation.get("domains", {}).items())[:3]:
            if isinstance(data, dict):
                vt = data.get("virustotal", {})
                if isinstance(vt, dict) and vt.get("error") and "no_api_key" not in str(vt):
                    suspicious_domains[domain] = {"virustotal_error": vt.get("error")}

        if suspicious_domains:
            prepared["suspicious_domains"] = suspicious_domains

    return prepared if prepared else {"status": "no_suspicious_found"}


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
    raw_confidence = int(data.get("confidence", 0))
    attack_type = str(data.get("attack_type", "unknown"))
    
    # Normalize confidence to specific ranges based on attack type
    normalized_confidence = _normalize_confidence(raw_confidence, attack_type, is_phishing_flag)

    return {
        "is_phishing": is_phishing_flag,
        "confidence": normalized_confidence,
        "attack_type": attack_type,
        "signals": data.get("signals", []),
        "reasoning": str(data.get("reasoning", "")),
    }