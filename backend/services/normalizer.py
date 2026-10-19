"""Alert normalization: turn a raw Wazuh alert into the SOAR Lite alert model.

Alert types match the report's attack scenarios: sql_injection, xss_attack,
brute_force, malware, port_scan, and unknown.
"""
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from urllib.parse import unquote_plus

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")

SQLI_RE = re.compile(
    r"union(?:\s|\+|/\*.*?\*/)+(?:all(?:\s|\+)+)?select"
    r"|'\s*or\s*'?\d+'?\s*=\s*'?\d+"
    r"|\bor\s+1\s*=\s*1\b"
    r"|sqlmap"
    r"|information_schema"
    r"|\bsleep\s*\(\s*\d+\s*\)"
    r"|benchmark\s*\("
    r"|;\s*drop\s+table",
    re.IGNORECASE,
)
XSS_RE = re.compile(
    r"<\s*script\b|javascript\s*:|\bon(?:error|load|mouseover)\s*=|\balert\s*\(|document\.cookie"
    r"|<\s*(?:svg|img|iframe)\b[^>]*\bon\w+\s*=",
    re.IGNORECASE,
)

MALWARE_GROUPS = {"malware", "virus", "trojan", "ransomware", "rootkit"}
MALWARE_WORDS = ("malware", "virus", "trojan", "eicar", "ransomware", "engines detected")
BRUTE_FORCE_GROUPS = {"authentication_failures", "brute_force"}
BRUTE_FORCE_RULES = {"5712", "5720", "5763", "60204", "18152"}
SCAN_GROUPS = {"recon", "scan", "portscan", "port_scan"}

SOURCE_IP_PATHS = (
    ("data", "srcip"),
    ("data", "src_ip"),
    ("data", "win", "eventdata", "ipAddress"),
    ("data", "win", "eventdata", "sourceAddress"),
    ("data", "win", "eventdata", "sourceNetworkAddress"),
    ("data", "aws", "sourceIPAddress"),
)


def _get(obj, path):
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _clean_ip(value):
    """Return a normalized IP string, or None if value is not a valid address."""
    if value is None:
        return None
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def _strings(obj):
    """Yield every string value inside a nested dict/list."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from _strings(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _strings(value)


def _evidence_text(alert):
    """Text that may carry attacker indicators: the log line and the decoded data fields."""
    parts = [alert.get("full_log") or ""]
    parts.extend(_strings(alert.get("data") or {}))
    parts.extend(_strings(alert.get("syscheck") or {}))
    return "\n".join(p for p in parts if p)


def extract_source_ip(alert):
    for path in SOURCE_IP_PATHS:
        ip = _clean_ip(_get(alert, path))
        if ip:
            return ip
    return None


def extract_iocs(alert):
    """Extract IPs, URLs and file hashes. Results are de-duplicated and keep their order."""
    text = _evidence_text(alert)
    ips, urls, hashes = [], [], []

    source_ip = extract_source_ip(alert)
    if source_ip:
        ips.append(source_ip)
    agent_ip = _clean_ip(_get(alert, ("agent", "ip")))
    for candidate in IPV4_RE.findall(text):
        ip = _clean_ip(candidate)
        if ip and ip != agent_ip and ip not in ips:
            ips.append(ip)

    for candidate in URL_RE.findall(text):
        url = candidate.rstrip(").,;]")
        if url not in urls:
            urls.append(url)

    for candidate in HASH_RE.findall(text):
        value = candidate.lower()
        if value not in hashes:
            hashes.append(value)

    return {"ips": ips, "urls": urls, "hashes": hashes}


def classify(alert):
    rule = alert.get("rule") or {}
    groups = {str(g).lower() for g in rule.get("groups") or []}
    description = str(rule.get("description") or "").lower()
    rule_id = str(rule.get("id") or "")
    text = unquote_plus(_evidence_text(alert))

    if groups & MALWARE_GROUPS or any(word in description for word in MALWARE_WORDS):
        return "malware"
    if {"sql_injection", "sqli"} & groups or SQLI_RE.search(text) or "sql injection" in description:
        return "sql_injection"
    if "xss" in groups or XSS_RE.search(text) or "cross site scripting" in description \
            or "cross-site scripting" in description:
        return "xss_attack"
    if groups & BRUTE_FORCE_GROUPS or rule_id in BRUTE_FORCE_RULES or "brute force" in description \
            or ("multiple" in description and ("logon failure" in description or "authentication failure" in description)):
        return "brute_force"
    if groups & SCAN_GROUPS or "scan" in description or "nmap" in description:
        return "port_scan"
    return "unknown"


def severity_from_level(level):
    try:
        level = int(level)
    except (TypeError, ValueError):
        return "LOW"
    if level >= 12:
        return "CRITICAL"
    if level >= 8:
        return "HIGH"
    if level >= 5:
        return "MEDIUM"
    return "LOW"


def normalize_alert(raw):
    """Map a raw Wazuh alert to the fields stored in the alerts table."""
    rule = raw.get("rule") or {}
    agent = raw.get("agent") or {}
    wazuh_id = raw.get("id")
    if not wazuh_id:
        canonical = json.dumps(raw, sort_keys=True, default=str).encode("utf-8")
        wazuh_id = "sha256:" + hashlib.sha256(canonical).hexdigest()
    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0
    return {
        "wazuh_id": str(wazuh_id),
        "timestamp": raw.get("timestamp") or datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "rule_id": str(rule.get("id") or ""),
        "rule_level": level,
        "description": str(rule.get("description") or ""),
        "groups": [str(g) for g in rule.get("groups") or []],
        "alert_type": classify(raw),
        "severity": severity_from_level(level),
        "source_ip": extract_source_ip(raw),
        "agent_id": str(agent.get("id")) if agent.get("id") is not None else None,
        "agent_name": agent.get("name"),
        "iocs": extract_iocs(raw),
        "raw": raw,
    }
