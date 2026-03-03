"""
online_enrichment.py - Post-scan VirusTotal & AbuseIPDB enrichment.

Queries external threat intelligence APIs AFTER all scanners complete.
Enriches finding.details with reputation data. Never modifies scanner logic.

OFFLINE BY DEFAULT — only runs when --online flag is passed.
API keys read from config.json or CLI args, never logged or exported.
"""

import ssl
import json
import time
import logging
from typing import List, Dict, Optional, Tuple
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from ipaddress import ip_address

from scanner_core.models import Finding, RiskLevel

logger = logging.getLogger("scanner.online_enrichment")

# ---------------------------------------------------------------------------
# Module state — set via configure()
# ---------------------------------------------------------------------------
_vt_api_key: str = ""
_abuseipdb_api_key: str = ""
_enabled: bool = False

# Rate limiting
_VT_REQUESTS_PER_MINUTE: int = 4
_VT_REQUESTS_PER_DAY: int = 500
_ABUSEIPDB_CHECKS_PER_DAY: int = 1000

_vt_request_times: List[float] = []
_vt_daily_count: int = 0
_abuseipdb_daily_count: int = 0

# Session caches (cleared on configure)
_vt_cache: Dict[str, dict] = {}
_abuseipdb_cache: Dict[str, dict] = {}

# Query caps (prevent excessive API usage on large scans)
_VT_MAX_HASHES: int = 20
_ABUSEIPDB_MAX_IPS: int = 50

# Risk ordering (lower = more severe)
_RISK_ORDER = {
    RiskLevel.CRITICAL: 0,
    RiskLevel.HIGH: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.INFO: 3,
}

# HTTP config
_TIMEOUT: int = 15
_USER_AGENT: str = "Corvus-Enrichment/1.0"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def configure(online_cfg: dict) -> None:
    """Initialize enrichment with API keys and settings.

    Args:
        online_cfg: dict with keys: vt_api_key, abuseipdb_api_key
                    (from config.json["online"] or CLI args)
    """
    global _vt_api_key, _abuseipdb_api_key, _enabled
    global _vt_daily_count, _abuseipdb_daily_count

    _vt_api_key = (online_cfg.get("vt_api_key") or "").strip()
    _abuseipdb_api_key = (online_cfg.get("abuseipdb_api_key") or "").strip()
    _enabled = bool(_vt_api_key or _abuseipdb_api_key)

    # Reset caches and counters for new session
    _vt_cache.clear()
    _abuseipdb_cache.clear()
    _vt_request_times.clear()
    _vt_daily_count = 0
    _abuseipdb_daily_count = 0

    if _enabled:
        sources = []
        if _vt_api_key:
            sources.append("VirusTotal")
        if _abuseipdb_api_key:
            sources.append("AbuseIPDB")
        print(f"  [+] Online enrichment configured: {', '.join(sources)}")
    else:
        print("  [i] Online enrichment: no API keys configured")


# ---------------------------------------------------------------------------
# Main enrichment entry point
# ---------------------------------------------------------------------------
def enrich_findings(findings: List[Finding]) -> Optional[dict]:
    """Enrich findings with VT and AbuseIPDB data. Called post-scan.

    Returns summary dict or None if disabled.
    Modifies finding.details in-place — adds enrichment keys.
    Never modifies core Finding fields except risk (upgrade only).
    """
    if not _enabled:
        return None

    summary = {
        "hashes_queried": 0,
        "ips_queried": 0,
        "vt_hits": 0,
        "abuseipdb_hits": 0,
        "risk_upgrades": 0,
    }

    # Collect unique enrichable items from findings
    hash_findings: Dict[str, List[Finding]] = {}
    ip_findings: Dict[str, List[Finding]] = {}

    for f in findings:
        sha256 = f.details.get("sha256") or f.details.get("hash")
        if sha256 and isinstance(sha256, str) and len(sha256) == 64:
            hash_findings.setdefault(sha256.lower(), []).append(f)

        remote_ip = f.details.get("remote_ip") or f.details.get("ip")
        if remote_ip and isinstance(remote_ip, str):
            try:
                addr = ip_address(remote_ip)
                if not (addr.is_private or addr.is_loopback or addr.is_reserved):
                    ip_findings.setdefault(remote_ip, []).append(f)
            except ValueError:
                pass

    # --- VirusTotal Hash Enrichment ---
    if _vt_api_key and hash_findings:
        sorted_hashes = _risk_priority(hash_findings.items())[:_VT_MAX_HASHES]
        print(f"  [*] VirusTotal: querying {len(sorted_hashes)} unique hash(es)...")

        for sha256, related_findings in sorted_hashes:
            vt_result = _vt_lookup(sha256)
            if vt_result:
                summary["vt_hits"] += 1
                for f in related_findings:
                    f.details["vt_score"] = vt_result["vt_score"]
                    f.details["vt_detection"] = vt_result["vt_detection"]
                    f.details["vt_total"] = vt_result["vt_total"]
                    f.details["vt_link"] = vt_result["vt_link"]
                    if _maybe_upgrade_risk_vt(f, vt_result):
                        summary["risk_upgrades"] += 1
            summary["hashes_queried"] += 1

    # --- AbuseIPDB IP Enrichment ---
    if _abuseipdb_api_key and ip_findings:
        sorted_ips = _risk_priority(ip_findings.items())[:_ABUSEIPDB_MAX_IPS]
        print(f"  [*] AbuseIPDB: querying {len(sorted_ips)} unique IP(s)...")

        for ip, related_findings in sorted_ips:
            abuseipdb_result = _abuseipdb_lookup(ip)
            if abuseipdb_result:
                summary["abuseipdb_hits"] += 1
                for f in related_findings:
                    f.details["abuseipdb_score"] = abuseipdb_result["abuseipdb_score"]
                    f.details["abuseipdb_reports"] = abuseipdb_result["abuseipdb_reports"]
                    f.details["abuseipdb_country"] = abuseipdb_result["abuseipdb_country"]
                    f.details["abuseipdb_link"] = abuseipdb_result["abuseipdb_link"]
                    if _maybe_upgrade_risk_abuseipdb(f, abuseipdb_result):
                        summary["risk_upgrades"] += 1
            summary["ips_queried"] += 1

    return summary


# ---------------------------------------------------------------------------
# Prioritization helper
# ---------------------------------------------------------------------------
def _risk_priority(items) -> list:
    """Sort items by highest-risk finding first (CRITICAL > HIGH > MEDIUM > INFO)."""
    return sorted(items, key=lambda kv: min(f.risk.order for f in kv[1]))


# ---------------------------------------------------------------------------
# VirusTotal API
# ---------------------------------------------------------------------------
def _vt_lookup(sha256: str) -> Optional[dict]:
    """Query VirusTotal v3 API for file hash reputation.

    Returns enrichment dict or None on error. Results are cached.
    """
    if not _vt_api_key:
        return None

    # Cache check
    if sha256 in _vt_cache:
        return _vt_cache[sha256]

    # Daily limit check
    global _vt_daily_count
    if _vt_daily_count >= _VT_REQUESTS_PER_DAY:
        logger.warning("VT daily limit reached (%d), skipping", _VT_REQUESTS_PER_DAY)
        return None

    # Rate limit (sliding window)
    _vt_rate_wait()

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    req = Request(url, headers={
        "x-apikey": _vt_api_key,
        "User-Agent": _USER_AGENT,
    })

    try:
        ctx = ssl.create_default_context()
        with urlopen(req, timeout=_TIMEOUT, context=ctx) as resp:
            data = json.loads(resp.read())

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + undetected + harmless

        result = {
            "vt_detection": malicious,
            "vt_total": total,
            "vt_score": f"{malicious}/{total}" if total > 0 else "0/0",
            "vt_link": f"https://www.virustotal.com/gui/file/{sha256}",
        }

        _vt_cache[sha256] = result
        _vt_daily_count += 1
        _vt_request_times.append(time.time())

        if malicious > 0:
            print(f"  [!] VT: {sha256[:16]}... \u2192 {malicious}/{total} detections")
        else:
            print(f"  [i] VT: {sha256[:16]}... \u2192 clean")

        return result

    except HTTPError as e:
        if e.code == 404:
            result = {
                "vt_detection": 0,
                "vt_total": 0,
                "vt_score": "not found",
                "vt_link": "",
            }
            _vt_cache[sha256] = result
            _vt_daily_count += 1
            _vt_request_times.append(time.time())
            print(f"  [i] VT: {sha256[:16]}... \u2192 not in database")
            return result
        elif e.code == 429:
            print("  [!] VT rate limit hit (429) \u2014 stopping VT queries")
            _vt_daily_count = _VT_REQUESTS_PER_DAY
            return None
        else:
            logger.error("VT HTTP error %d for %s", e.code, sha256[:16])
            return None

    except ssl.SSLError as e:
        print(f"  [!] VT SSL error: {e}")
        print("  [i] If behind corporate proxy, ensure system CA certificates are up to date")
        return None

    except (URLError, TimeoutError, OSError) as e:
        logger.error("VT connection error for %s: %s", sha256[:16], e)
        return None

    except (json.JSONDecodeError, KeyError) as e:
        logger.error("VT response parse error for %s: %s", sha256[:16], e)
        return None


def _vt_rate_wait() -> None:
    """Enforce VT rate limit: max N requests per 60-second sliding window."""
    now = time.time()
    window_start = now - 60.0

    # Remove timestamps outside window
    while _vt_request_times and _vt_request_times[0] < window_start:
        _vt_request_times.pop(0)

    # If at limit, wait until oldest request exits the window
    if len(_vt_request_times) >= _VT_REQUESTS_PER_MINUTE:
        wait_until = _vt_request_times[0] + 60.0
        wait_seconds = wait_until - now
        if wait_seconds > 0:
            print(f"  [i] VT rate limit \u2014 waiting {wait_seconds:.0f}s...")
            time.sleep(wait_seconds + 0.5)


# ---------------------------------------------------------------------------
# AbuseIPDB API
# ---------------------------------------------------------------------------
def _abuseipdb_lookup(ip: str) -> Optional[dict]:
    """Query AbuseIPDB v2 API for IP reputation.

    Returns enrichment dict or None on error. Results are cached.
    """
    if not _abuseipdb_api_key:
        return None

    # Cache check
    if ip in _abuseipdb_cache:
        return _abuseipdb_cache[ip]

    # Daily limit check
    global _abuseipdb_daily_count
    if _abuseipdb_daily_count >= _ABUSEIPDB_CHECKS_PER_DAY:
        logger.warning("AbuseIPDB daily limit reached, skipping")
        return None

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    req = Request(url, headers={
        "Key": _abuseipdb_api_key,
        "Accept": "application/json",
        "User-Agent": _USER_AGENT,
    })

    try:
        ctx = ssl.create_default_context()
        with urlopen(req, timeout=_TIMEOUT, context=ctx) as resp:
            raw = resp.read()
            data = json.loads(raw)

        report = data.get("data", {})
        score = report.get("abuseConfidenceScore", 0)
        total_reports = report.get("totalReports", 0)
        country = report.get("countryCode", "??")

        result = {
            "abuseipdb_score": score,
            "abuseipdb_reports": total_reports,
            "abuseipdb_country": country,
            "abuseipdb_link": f"https://www.abuseipdb.com/check/{ip}",
        }

        _abuseipdb_cache[ip] = result
        _abuseipdb_daily_count += 1

        if score > 50:
            print(f"  [!] AbuseIPDB: {ip} \u2192 score {score}/100 ({total_reports} reports, {country})")
        else:
            print(f"  [i] AbuseIPDB: {ip} \u2192 score {score}/100")

        return result

    except HTTPError as e:
        if e.code == 429:
            print("  [!] AbuseIPDB rate limit hit \u2014 stopping IP queries")
            _abuseipdb_daily_count = _ABUSEIPDB_CHECKS_PER_DAY
            return None
        logger.error("AbuseIPDB HTTP error %d for %s", e.code, ip)
        return None

    except ssl.SSLError as e:
        print(f"  [!] AbuseIPDB SSL error: {e}")
        print("  [i] Corporate proxy? Ensure system CA certificates are current")
        return None

    except (URLError, TimeoutError, OSError) as e:
        logger.error("AbuseIPDB connection error for %s: %s", ip, e)
        return None

    except (json.JSONDecodeError, KeyError) as e:
        logger.error("AbuseIPDB parse error for %s: %s", ip, e)
        return None


# ---------------------------------------------------------------------------
# Risk upgrade logic
# ---------------------------------------------------------------------------
def _maybe_upgrade_risk_vt(finding: Finding, vt_result: dict) -> bool:
    """Upgrade finding risk based on VT detection ratio. Never downgrade."""
    detection = vt_result.get("vt_detection", 0)
    total = vt_result.get("vt_total", 0)
    if total == 0:
        return False

    ratio = detection / total

    if ratio > 0.50:
        new_risk = RiskLevel.CRITICAL
    elif ratio > 0.20:
        new_risk = RiskLevel.HIGH
    else:
        return False

    return _apply_upgrade(finding, new_risk, "virustotal")


def _maybe_upgrade_risk_abuseipdb(finding: Finding, result: dict) -> bool:
    """Upgrade finding risk based on AbuseIPDB confidence score. Never downgrade."""
    score = result.get("abuseipdb_score", 0)

    if score > 80:
        new_risk = RiskLevel.CRITICAL
    elif score > 50:
        new_risk = RiskLevel.HIGH
    else:
        return False

    return _apply_upgrade(finding, new_risk, "abuseipdb")


def _apply_upgrade(finding: Finding, new_risk: RiskLevel, source: str) -> bool:
    """Apply risk upgrade if new_risk is higher severity. Never downgrade."""
    if _RISK_ORDER[new_risk] < _RISK_ORDER[finding.risk]:
        finding.details["original_risk"] = finding.risk.value
        finding.details["risk_upgraded_by"] = source
        finding.risk = new_risk
        return True
    return False
