# Python modules
import re
from typing import Any
from urllib.parse import urlparse

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
URL_RE = re.compile(r"https?://[^\s<>\"']+", flags=re.I)


def _mask_email(match: re.Match) -> str:
    domain = match.group(1)
    return f"***@{domain}"


def _mask_ip(match: re.Match) -> str:
    ip = match.group(0)
    parts = ip.split(".")
    if len(parts) != 4:
        return "x.x.x.x"
    return f"{parts[0]}.{parts[1]}.x.x"


def _mask_url(match: re.Match) -> str:
    raw_url = match.group(0)
    parsed = urlparse(raw_url)
    if not parsed.scheme or not parsed.netloc:
        return "https://.../"
    return f"{parsed.scheme}://{parsed.netloc}/..."


def mask_sensitive_text(text: str) -> str:
    """Mask emails, IPs, and URLs in a string for safer output."""
    if not text:
        return text
    masked = URL_RE.sub(_mask_url, text)
    masked = EMAIL_RE.sub(_mask_email, masked)
    masked = IPV4_RE.sub(_mask_ip, masked)
    return masked


def scrub_data(value: Any) -> Any:
    """Recursively scrub sensitive strings in dicts/lists/strings."""
    if isinstance(value, dict):
        return {k: scrub_data(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub_data(item) for item in value]
    if isinstance(value, str):
        return mask_sensitive_text(value)
    return value
