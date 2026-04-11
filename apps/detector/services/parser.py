# Python modules
import hashlib
import re
from email import policy
from email.parser import Parser
from typing import Any, Dict, List
from urllib.parse import urlparse

# Django modules
from django.core.cache import cache


URL_RE = re.compile(r'https?://[^\s<>"\']+', flags=re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def _deobfuscate(text: str) -> str:
    return text.replace("hxxp", "http").replace("HXXP", "http")


def _hostname_from_url(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def hash_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def parse_email(raw: str) -> Dict[str, Any]:
    """Parse raw email text (RFC) and extract IOC and metadata.

    Returns a dictionary with keys: headers, spf, dkim, dmarc, plain, html,
    urls, emails, ips, domains, attachments (list of {filename, sha256}).
    """
    # cache by hash of raw content
    raw_hash = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
    cache_key = f"parsed_email:{raw_hash}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    result: Dict[str, Any] = {
        "headers": {},
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "plain": "",
        "html": "",
        "urls": [],
        "emails": [],
        "ips": [],
        "domains": [],
        "attachments": [],
    }

    parser = Parser(policy=policy.default)
    try:
        msg = parser.parsestr(raw)
    except Exception:
        # fallback: treat input as plain text body
        body = _deobfuscate(raw)
        result["plain"] = body
        # still extract some indicators
        result["urls"] = list(set(URL_RE.findall(body)))
        result["emails"] = list(set(EMAIL_RE.findall(body)))
        result["ips"] = list(set(IPV4_RE.findall(body)))
        result["domains"] = list({_hostname_from_url(u) for u in result["urls"] if _hostname_from_url(u)})
        cache.set(cache_key, result, timeout=60 * 60 * 24)
        return result

    # Headers
    for k, v in msg.items():
        result["headers"][k] = v

    # Authentication-Results parsing (simple heuristics)
    auth = msg.get("Authentication-Results") or msg.get("Authentication-Results:") or ""
    # quick parse for spf/dkim/dmarc tokens
    if auth:
        spf_m = re.search(r"spf=(\w+)", auth)
        dkim_m = re.search(r"dkim=(\w+)", auth)
        dmarc_m = re.search(r"dmarc=(\w+)", auth)
        if spf_m:
            result["spf"] = spf_m.group(1)
        if dkim_m:
            result["dkim"] = dkim_m.group(1)
        if dmarc_m:
            result["dmarc"] = dmarc_m.group(1)

    # Parts: body + attachments
    if msg.is_multipart():
        plain_parts: List[str] = []
        html_parts: List[str] = []
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get_content_disposition()
            if disp == "attachment":
                payload = part.get_payload(decode=True) or b""
                fname = part.get_filename() or "attachment"
                result["attachments"].append({"filename": fname, "sha256": hash_bytes(payload)})
            elif ctype == "text/plain":
                try:
                    plain_parts.append(part.get_content())
                except Exception:
                    plain_parts.append(part.get_payload(decode=True).decode("utf-8", errors="replace"))
            elif ctype == "text/html":
                try:
                    html_parts.append(part.get_content())
                except Exception:
                    html_parts.append(part.get_payload(decode=True).decode("utf-8", errors="replace"))
        result["plain"] = "\n".join(plain_parts).strip()
        result["html"] = "\n".join(html_parts).strip()
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            try:
                text = payload.decode("utf-8", errors="replace")
            except Exception:
                text = str(payload)
        else:
            text = msg.get_payload()
        text = _deobfuscate(text)
        result["plain"] = text

    # Extract URLs, emails, IPs from combined text
    combined = (result.get("plain", "") + "\n" + result.get("html", ""))
    combined = _deobfuscate(combined)
    urls = set(URL_RE.findall(combined))
    result["urls"] = list(urls)
    result["emails"] = list(set(EMAIL_RE.findall(combined)))
    result["ips"] = list(set(IPV4_RE.findall(combined)))
    # domains from urls
    domains = {h for h in (_hostname_from_url(u) for u in urls) if h}
    result["domains"] = list(domains)

    cache.set(cache_key, result, timeout=60 * 60 * 24)
    return result
