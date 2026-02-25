from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict

from apps.detector.services.reputation import ReputationService


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


def compute_scores(parsed: Dict[str, Any], reputation: Dict[str, Any], ai_out: Dict[str, Any]) -> Dict[str, float]:
    """Combine AI output, reputation and header anomalies into final scores."""

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
                if (
                    isinstance(a_data, dict)
                    and a_data.get("abuseConfidenceScore", 0)
                    and int(a_data.get("abuseConfidenceScore", 0)) > 0
                ):
                    return True
        except Exception:
            return False
        return False

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

    ai_conf = float(ai_out.get("confidence", 0))

    # header anomaly: count non-pass results
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

    return {
        "final_score": float(round(final_score, 2)),
        "malicious_ratio": float(malicious_ratio),
        "header_score": float(round(header_score, 2)),
    }

