import hashlib
import json
import os
import re
from typing import Any, Dict

import openai
from django.core.cache import cache

# Lazy initialization flag
_initialized = False


def _get_client():
    """Initialize OpenAI client (set API key) and return the `openai` module.

    Attempts the following environment variables, in order:
    - `OPENAI_API_KEY`
    - `OPENAI_KEY`
    - `GOOGLE_API_KEY` (fallback when migrating)
    Values are first read from `os.environ`; if not present we try
    `decouple.config()` to allow reading from a local `.env` file.
    """
    global _initialized
    if _initialized:
        return openai

    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_KEY") 
    if not api_key:
        try:
            from decouple import config
            api_key = config('OPENAI_API_KEY', default=None) or config('OPENAI_KEY', default=None)
        except Exception:
            api_key = None

    if not api_key:
        raise ValueError(
            "OPENAI_API_KEY (or OPENAI_KEY / GOOGLE_API_KEY) environment variable is not set. "
            "Please set it before using the AI service."
        )

    openai.api_key = api_key
    _initialized = True
    return openai


def _extract_json_from_text(text: str) -> Dict[str, Any]:
    """Try to extract the first JSON object from model text output and parse it.

    This is tolerant to some common formatting issues (like surrounding text
    or single quotes) but will raise ValueError if parsing fails.
    """
    # Find the first {...} block
    m = re.search(r"\{.*\}", text, flags=re.S)
    if not m:
        raise ValueError("No JSON object found in model response")
    s = m.group(0)
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        # Try a quick fix: replace single quotes with double quotes
        try:
            fixed = s.replace("'", '"')
            return json.loads(fixed)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON from model response: {e}")


def _generate_structured(prompt: str) -> Dict[str, Any]:
    """Call OpenAI Chat API with the prompt and extract JSON from the reply."""
    try:
        # cache key based on prompt hash to avoid repeated model calls
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        cache_key = f"ai:prompt:{prompt_hash}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        client = _get_client()
        # Use the correct Chat Completions API with messages format
        resp = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are an email security analyst. Respond ONLY with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0,
            max_tokens=512,
        )

        # Extract text from chat response
        text = resp.choices[0].message.content if resp.choices else None

        # Ensure we always work with a string before JSON extraction
        if text is None:
            raise ValueError("Empty response from model")
        if not isinstance(text, str):
            text = str(text)

        # Try to parse JSON; if the model didn't return valid JSON (which can
        # happen on long / tricky inputs), fall back to a safe default structure
        try:
            data = _extract_json_from_text(text)
        except ValueError as parse_err:
            data = {
                "is_phishing": False,
                "confidence": 0,
                "attack_type": "unknown",
                "signals": [],
                "reasoning": f"Model response could not be parsed as JSON: {parse_err}",
            }

        # cache AI response for 24 hours
        cache.set(cache_key, data, timeout=60 * 60 * 24)
        return data
    except Exception as e:
        raise ValueError(f"AI service error: {str(e)}")


def _truncate_for_context(text: str, max_chars: int = 800) -> str:
    """Truncate text to fit within context window."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"...[truncated]"


def _prepare_reputation_for_ai(reputation: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare reputation data for AI, extracting only essential malicious indicators."""
    prepared = {}
    
    # Extract only URLs with issues
    if "urls" in reputation:
        suspicious_urls = {}
        for url, data in list(reputation.get("urls", {}).items())[:5]:  # Limit to 5 URLs
            if isinstance(data, dict):
                has_vt_issue = data.get("virustotal_submit", {}).get("error") and "no_api_key" not in str(data.get("virustotal_submit"))
                if has_vt_issue:
                    suspicious_urls[url] = {"virustotal": data.get("virustotal_submit")}
        if suspicious_urls:
            prepared["suspicious_urls"] = suspicious_urls
    
    # Extract only domains with issues
    if "domains" in reputation:
        suspicious_domains = {}
        for domain, data in list(reputation.get("domains", {}).items())[:3]:  # Limit to 3 domains
            if isinstance(data, dict):
                vt = data.get("virustotal", {})
                if isinstance(vt, dict) and vt.get("error") and "no_api_key" not in str(vt):
                    suspicious_domains[domain] = {"virustotal_error": vt.get("error")}
        if suspicious_domains:
            prepared["suspicious_domains"] = suspicious_domains
    
    return prepared if prepared else {"status": "no_suspicious_found"}


def _prepare_parsed_for_ai(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare parsed email data for AI, truncating large fields to avoid context overflow."""
    prepared = {
        "from": parsed.get("headers", {}).get("From", "")[:100],
        "to": parsed.get("headers", {}).get("To", "")[:50],
        "subject": parsed.get("headers", {}).get("Subject", "")[:100],
        "auth": {
            "spf": parsed.get("spf"),
            "dkim": parsed.get("dkim"),
            "dmarc": parsed.get("dmarc"),
        },
        "indicators": {
            "urls": parsed.get("urls", [])[:5],  
            "emails": parsed.get("emails", [])[:3],  
            "ips": parsed.get("ips", [])[:3],  
            "domains": parsed.get("domains", [])[:3],  
        },
        "body_preview": _truncate_for_context(parsed.get("plain", ""), max_chars=600),
    }
    return prepared


def analyze_parsed(parsed: Dict[str, Any], reputation: Dict[str, Any]) -> Dict[str, Any]:
    """Build a detailed prompt from parsed indicators and reputation results,
    call the model and return the structured JSON expected by the system:

    {
      "is_phishing": bool,
      "confidence": 0-100,
      "attack_type": "...",
      "signals": [],
      "reasoning": "..."
    }
    """
    # Prepare data to avoid context window overflow
    prepared_parsed = _prepare_parsed_for_ai(parsed)
    prepared_reputation = _prepare_reputation_for_ai(reputation)
    
    # Build minimal prompt to save tokens
    prompt = f"""Analyze this email for phishing. Return ONLY valid JSON.

Email:
{json.dumps(prepared_parsed, ensure_ascii=False)}

Reputation:
{json.dumps(prepared_reputation, ensure_ascii=False)}

Return JSON with: is_phishing (bool), confidence (0-100), attack_type (string), signals (list), reasoning (string)"""

    data = _generate_structured(prompt)

    # Normalize expected fields
    out = {
        "is_phishing": bool(data.get("is_phishing", False)),
        "confidence": float(data.get("confidence", 0)),
        "attack_type": str(data.get("attack_type", "unknown")),
        "signals": data.get("signals", []),
        "reasoning": str(data.get("reasoning", data.get("explanation", ""))),
    }
    return out