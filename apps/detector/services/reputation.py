# Python modules
import time
from typing import Any, Dict, Optional

# Django modules
from django.core.cache import cache
from django.conf import settings

# Third-party modules
import requests
from decouple import config
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class ReputationService:
    """Service to check reputation of URLs, IPs and domains using external APIs.

    Uses environment variables for API keys:
    - VIRUSTOTAL_API_KEY
    - ABUSEIPDB_API_KEY
    - URLSCAN_API_KEY (optional)
    """

    def __init__(self, session: Optional[requests.Session] = None):
        self.vt_key = config("VIRUSTOTAL_API_KEY", default=None)
        self.abuse_key = config("ABUSEIPDB_API_KEY", default=None)
        self.urlscan_key = config("URLSCAN_API_KEY", default=None)
        self.session = session or requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504))
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

    def _safe_get(self, url: str, headers: Dict[str, str] = None, params: Dict[str, str] = None) -> Dict[str, Any]:
        """Helper method to perform a GET request and return JSON, handling errors gracefully."""
        try:
            r = self.session.get(url, headers=headers or {}, params=params or {}, timeout=15)
            if r.status_code == 429:
                # rate limited -- backoff then raise
                time.sleep(2)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"error": str(e), "status_code": getattr(e, 'response', None) and getattr(e.response, 'status_code', None)}

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check reputation of an IP address using AbuseIPDB and VirusTotal."""
        cache_key = f"rep:ip:{ip}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        out: Dict[str, Any] = {"ip": ip}
        if self.abuse_key:
            try:
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {"Key": self.abuse_key, "Accept": "application/json"}
                params = {"ipAddress": ip, "maxAgeInDays": "90"}
                out["abuseipdb"] = self._safe_get(url, headers=headers, params=params)
            except Exception as e:
                out["abuseipdb"] = {"error": str(e)}
        else:
            out["abuseipdb"] = {"error": "no_api_key"}

        if self.vt_key:
            try:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                headers = {"x-apikey": self.vt_key}
                out["virustotal"] = self._safe_get(url, headers=headers)
            except Exception as e:
                out["virustotal"] = {"error": str(e)}
        else:
            out["virustotal"] = {"error": "no_api_key"}

        # cache for 12 hours
        cache.set(cache_key, out, timeout=60 * 60 * 12)
        return out

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check reputation of a domain using VirusTotal."""
        cache_key = f"rep:domain:{domain}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        out: Dict[str, Any] = {"domain": domain}
        if self.vt_key:
            try:
                url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                headers = {"x-apikey": self.vt_key}
                out["virustotal"] = self._safe_get(url, headers=headers)
            except Exception as e:
                out["virustotal"] = {"error": str(e)}
        else:
            out["virustotal"] = {"error": "no_api_key"}

        if getattr(settings, "ENABLE_RDAP_ENRICHMENT", False):
            try:
                rdap_url = f"https://rdap.org/domain/{domain}"
                out["rdap"] = self._safe_get(rdap_url)
            except Exception as e:
                out["rdap"] = {"error": str(e)}

        cache.set(cache_key, out, timeout=60 * 60 * 12)
        return out

    def check_url(self, url_to_check: str) -> Dict[str, Any]:
        """Check reputation of a URL using VirusTotal and URLScan."""
        cache_key = f"rep:url:{url_to_check}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        out: Dict[str, Any] = {"url": url_to_check}
        if self.vt_key:
            try:
                # VT requires URL to be submitted or id - use URL report endpoint
                vt_url = "https://www.virustotal.com/api/v3/urls"
                headers = {"x-apikey": self.vt_key}
                # vt expects url encoded in form
                resp = self.session.post(vt_url, headers=headers, data={"url": url_to_check}, timeout=15)
                if resp.status_code in (200, 201):
                    rj = resp.json()
                    out["virustotal_submit"] = rj
                    if getattr(settings, "ENABLE_VT_URL_REPORT", False):
                        vt_id = None
                        if isinstance(rj, dict):
                            vt_id = (rj.get("data") or {}).get("id")
                        if vt_id:
                            delay = float(getattr(settings, "VT_URL_REPORT_DELAY_SEC", 0) or 0)
                            if delay > 0:
                                time.sleep(delay)
                            report_url = f"https://www.virustotal.com/api/v3/urls/{vt_id}"
                            out["virustotal_report"] = self._safe_get(report_url, headers=headers)
                else:
                    out["virustotal_submit"] = {"status_code": resp.status_code, "text": resp.text}
            except Exception as e:
                out["virustotal_submit"] = {"error": str(e)}
        else:
            out["virustotal_submit"] = {"error": "no_api_key"}

        if self.urlscan_key:
            try:
                urlscan_endpoint = "https://urlscan.io/api/v1/scan/"
                headers = {"API-Key": self.urlscan_key, "Content-Type": "application/json"}
                payload = {"url": url_to_check, "public": "off"}
                r = self.session.post(urlscan_endpoint, headers=headers, json=payload, timeout=15)
                out["urlscan_submit"] = r.json() if r.status_code in (200, 201) else {"status_code": r.status_code, "text": r.text}
            except Exception as e:
                out["urlscan_submit"] = {"error": str(e)}
        else:
            out["urlscan_submit"] = {"error": "no_api_key"}

        # cache for 6 hours (URL reputation can change more often)
        cache.set(cache_key, out, timeout=60 * 60 * 6)
        return out