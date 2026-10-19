"""Threat intelligence enrichment: VirusTotal, AbuseIPDB and AlienVault OTX, with a SQLite cache.

Rules:
- A provider with no API key, a timeout or an HTTP error is recorded under "errors";
  the other providers still run and enrich_ioc() never raises for provider failures.
- Private and other non-public addresses are not sent to public providers.
- Reputation is HIGH, MEDIUM, LOW (providers answered and found nothing) or UNKNOWN
  (no provider answered).
"""
import base64
import ipaddress
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from backend import config
from backend.database.db import get_db, parse_ts, utcnow

log = logging.getLogger("soar.threat_intel")

IOC_TYPES = ("ip", "url", "hash")
HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")


class ProviderError(Exception):
    pass


def _http_get_json(url, headers):
    """GET a URL and decode JSON. Tests replace this function."""
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=config.HTTP_TIMEOUT_SECONDS) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None  # provider has no record of this indicator
        raise ProviderError(f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderError(f"network error: {exc}") from exc
    except ValueError as exc:
        raise ProviderError("invalid JSON from provider") from exc


def validate_ioc(ioc, ioc_type):
    """Return the normalized indicator, or raise ValueError."""
    if ioc_type not in IOC_TYPES:
        raise ValueError(f"type must be one of {', '.join(IOC_TYPES)}")
    ioc = str(ioc or "").strip()
    if ioc_type == "ip":
        return str(ipaddress.ip_address(ioc))
    if ioc_type == "hash":
        if not HASH_RE.match(ioc):
            raise ValueError("hash must be an MD5, SHA-1 or SHA-256 hex digest")
        return ioc.lower()
    parsed = urllib.parse.urlparse(ioc)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or len(ioc) > 2048:
        raise ValueError("url must be an http(s) URL")
    return ioc


def query_virustotal(ioc, ioc_type):
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    else:
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    data = _http_get_json(url, {"x-apikey": config.VT_API_KEY, "Accept": "application/json"})
    if not data:
        return {"found": False, "malicious": 0, "suspicious": 0}
    stats = (data.get("data") or {}).get("attributes", {}).get("last_analysis_stats") or {}
    return {
        "found": True,
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
    }


def query_abuseipdb(ioc, ioc_type):
    query = urllib.parse.urlencode({"ipAddress": ioc, "maxAgeInDays": 90})
    data = _http_get_json(
        f"https://api.abuseipdb.com/api/v2/check?{query}",
        {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
    )
    info = (data or {}).get("data") or {}
    return {
        "found": bool(info),
        "abuse_confidence_score": int(info.get("abuseConfidenceScore", 0)),
        "total_reports": int(info.get("totalReports", 0)),
        "country": info.get("countryCode"),
    }


def query_otx(ioc, ioc_type):
    section = {"ip": "IPv4", "url": "url", "hash": "file"}[ioc_type]
    if ioc_type == "ip" and ipaddress.ip_address(ioc).version == 6:
        section = "IPv6"
    target = urllib.parse.quote(ioc, safe="")
    data = _http_get_json(
        f"https://otx.alienvault.com/api/v1/indicators/{section}/{target}/general",
        {"X-OTX-API-KEY": config.OTX_API_KEY, "Accept": "application/json"},
    )
    pulses = ((data or {}).get("pulse_info") or {}).get("count", 0)
    return {"found": bool(data), "pulse_count": int(pulses)}


# name, settings attribute holding the key, supported types, query function name
PROVIDERS = (
    ("virustotal", "VT_API_KEY", ("ip", "url", "hash"), "query_virustotal"),
    ("abuseipdb", "ABUSEIPDB_API_KEY", ("ip",), "query_abuseipdb"),
    ("otx", "OTX_API_KEY", ("ip", "url", "hash"), "query_otx"),
)


def reputation_from(sources):
    if not sources:
        return "UNKNOWN"
    vt = sources.get("virustotal") or {}
    abuse = sources.get("abuseipdb") or {}
    otx = sources.get("otx") or {}
    if vt.get("malicious", 0) >= 3 or abuse.get("abuse_confidence_score", 0) >= 75:
        return "HIGH"
    if vt.get("malicious", 0) >= 1 or vt.get("suspicious", 0) >= 1 \
            or abuse.get("abuse_confidence_score", 0) >= 25 or otx.get("pulse_count", 0) >= 1:
        return "MEDIUM"
    return "LOW"


def _cache_get(ioc, ioc_type):
    with get_db() as conn:
        row = conn.execute(
            "SELECT result_json, fetched_at FROM threat_intel_cache WHERE ioc = ? AND ioc_type = ?",
            (ioc, ioc_type),
        ).fetchone()
    if not row:
        return None
    fetched = parse_ts(row["fetched_at"])
    if fetched is None or datetime.now(timezone.utc) - fetched > timedelta(hours=config.TI_CACHE_HOURS):
        return None
    return json.loads(row["result_json"])


def _cache_put(ioc, ioc_type, result):
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO threat_intel_cache (ioc, ioc_type, result_json, fetched_at) VALUES (?, ?, ?, ?)",
            (ioc, ioc_type, json.dumps(result), utcnow()),
        )


def enrich_ioc(ioc, ioc_type, use_cache=True):
    """Enrich one indicator. Raises ValueError only for invalid input."""
    ioc = validate_ioc(ioc, ioc_type)

    if ioc_type == "ip" and not ipaddress.ip_address(ioc).is_global:
        return {
            "ioc": ioc, "type": ioc_type, "reputation": "UNKNOWN", "sources": {}, "errors": {},
            "note": "non-public address: not sent to public providers", "cached": False,
        }

    if use_cache:
        cached = _cache_get(ioc, ioc_type)
        if cached is not None:
            cached["cached"] = True
            return cached

    sources, errors = {}, {}
    for name, key_attr, types, func_name in PROVIDERS:
        if ioc_type not in types:
            continue
        if not getattr(config, key_attr):
            errors[name] = "no API key configured"
            continue
        try:
            sources[name] = globals()[func_name](ioc, ioc_type)
        except Exception as exc:  # degrade: one provider failing never stops enrichment
            log.warning("%s lookup for %s failed: %s", name, ioc, exc)
            errors[name] = str(exc) or exc.__class__.__name__

    result = {
        "ioc": ioc, "type": ioc_type, "reputation": reputation_from(sources),
        "sources": sources, "errors": errors, "cached": False,
    }
    if sources:
        _cache_put(ioc, ioc_type, result)
    return result
