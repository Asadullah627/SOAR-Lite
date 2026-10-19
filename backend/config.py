"""SOAR Lite settings.

Every setting, including every secret, is read from an environment variable.
Nothing secret has a default value in source (NFR-04).
"""
import os
import platform
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
IS_WINDOWS = platform.system() == "Windows"


def _str(name, default=""):
    return os.environ.get(name, default).strip()


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _float(name, default):
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _list(name):
    return [item.strip() for item in _str(name).split(",") if item.strip()]


# Storage
DB_PATH = _str("SOAR_DB_PATH", str(BASE_DIR / "backend" / "soar_lite.db"))

# Authentication (FR-01, NFR-04)
ADMIN_USER = _str("SOAR_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("SOAR_ADMIN_PASSWORD", "")
SESSION_TTL_HOURS = _float("SESSION_TTL_HOURS", 8)

# Alert ingestion
WAZUH_SIMULATION = _bool("WAZUH_SIMULATION", True)
WAZUH_ALERTS_FILE = _str("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json")
WAZUH_READ_FROM_START = _bool("WAZUH_READ_FROM_START", False)
SIMULATION_FILE = _str("SOAR_SIMULATION_FILE", str(BASE_DIR / "simulation" / "sample_alerts.jsonl"))
POLL_INTERVAL_SECONDS = _float("POLL_INTERVAL_SECONDS", 10)

# Threat intelligence
VT_API_KEY = _str("VT_API_KEY")
ABUSEIPDB_API_KEY = _str("ABUSEIPDB_API_KEY")
OTX_API_KEY = _str("OTX_API_KEY")
TI_CACHE_HOURS = _float("TI_CACHE_HOURS", 24)
HTTP_TIMEOUT_SECONDS = _float("HTTP_TIMEOUT_SECONDS", 5)

# Endpoint agents
AGENT_TOKEN = _str("AGENT_TOKEN")
AGENT_PORT = _int("AGENT_PORT", 5055)
AGENT_OFFLINE_SECONDS = _int("AGENT_OFFLINE_SECONDS", 120)

# Safety (NFR-14): addresses that must never be blocked
SAFELIST = set(_list("SOAR_SAFELIST"))
BACKEND_IP = _str("SOAR_BACKEND_IP")
GATEWAY_IP = _str("SOAR_GATEWAY_IP")

# Optional perimeter fallback
PFSENSE_URL = _str("PFSENSE_URL").rstrip("/")
PFSENSE_API_KEY = _str("PFSENSE_API_KEY")
PFSENSE_ALIAS = _str("PFSENSE_ALIAS", "SOAR_BLOCKLIST")

DASHBOARD_FILE = BASE_DIR / "dashboard" / "index.html"

# Severities treated as HIGH for the reputation-aware block decision
HIGH_SEVERITIES = ("HIGH", "CRITICAL")

# Playbooks. AUTO runs as soon as a matching alert arrives; MANUAL waits for approval.
PLAYBOOKS = {
    "PB-002": {
        "name": "Brute force containment",
        "alert_type": "brute_force",
        "mode": "AUTO",
        "steps": ["enrich", "create_case", "block_ip", "collect_evidence"],
    },
    "PB-003": {
        "name": "SQL injection containment",
        "alert_type": "sql_injection",
        "mode": "AUTO",
        "steps": ["enrich", "create_case", "block_ip", "collect_evidence"],
    },
    "PB-004": {
        "name": "Cross-site scripting containment",
        "alert_type": "xss_attack",
        "mode": "AUTO",
        "steps": ["enrich", "create_case", "block_ip", "collect_evidence"],
    },
    "PB-005": {
        "name": "Malware host isolation",
        "alert_type": "malware",
        "mode": "MANUAL",
        "steps": ["enrich", "create_case", "isolate_host", "collect_evidence"],
    },
}
