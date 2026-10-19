"""Containment and case actions: block/unblock IPs, isolate hosts, collect evidence, create cases.

Safety (NFR-14): block_ip() refuses loopback, unspecified, multicast, link-local, broadcast,
the backend, the gateway and anything in SOAR_SAFELIST. The endpoint agent repeats the check.
"""
import ipaddress
import json
import logging
import re
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from backend import config
from backend.database.db import audit, get_db, parse_ts, row_to_dict, utcnow
from backend.services import events

log = logging.getLogger("soar.response")

CASE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class AgentError(Exception):
    pass


def validate_ip(value):
    """Return the normalized address string, or raise ValueError."""
    ip = ipaddress.ip_address(str(value or "").strip())
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def validate_case_id(case_id):
    if not isinstance(case_id, str) or not CASE_ID_RE.match(case_id):
        raise ValueError("case_id must match ^[A-Za-z0-9_-]{1,64}$")
    return case_id


def _same_ip(a, b):
    try:
        return validate_ip(a) == validate_ip(b)
    except ValueError:
        return False


def is_protected(ip):
    """Return (protected, reason). An address that fails to parse counts as protected."""
    try:
        addr = ipaddress.ip_address(validate_ip(ip))
    except ValueError:
        return True, f"{ip!r} is not a valid IP address"
    text = str(addr)
    if addr.is_loopback:
        return True, f"{text} is a loopback address"
    if addr.is_unspecified:
        return True, f"{text} is the unspecified address"
    if addr.is_multicast:
        return True, f"{text} is a multicast address"
    if addr.is_link_local:
        return True, f"{text} is a link-local address"
    if text == "255.255.255.255":
        return True, f"{text} is the broadcast address"
    if config.BACKEND_IP and _same_ip(text, config.BACKEND_IP):
        return True, f"{text} is the SOAR backend"
    if config.GATEWAY_IP and _same_ip(text, config.GATEWAY_IP):
        return True, f"{text} is the gateway"
    if any(_same_ip(text, entry) for entry in config.SAFELIST):
        return True, f"{text} is safelisted"
    return False, ""


# ---------------------------------------------------------------- agents

def _agent_is_online(row):
    seen = parse_ts(row["last_seen"])
    return seen is not None and datetime.now(timezone.utc) - seen <= timedelta(seconds=config.AGENT_OFFLINE_SECONDS)


def list_agents():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM agents ORDER BY agent_id").fetchall()
    out = []
    for row in rows:
        agent = row_to_dict(row)
        agent["status"] = "Online" if _agent_is_online(row) else "Offline"
        agent["admin"] = bool(agent["admin"])
        agent["isolated"] = bool(agent["isolated"])
        agent["dry_run"] = bool(agent["dry_run"])
        out.append(agent)
    return out


def online_agents(agent_id=None):
    agents = [a for a in list_agents() if a["status"] == "Online"]
    if agent_id is not None:
        agents = [a for a in agents if a["agent_id"] == str(agent_id)]
    return agents


def _agent_call(agent, method, path, payload=None):
    """Call an endpoint agent. Tests replace this function."""
    if not config.AGENT_TOKEN:
        raise AgentError("AGENT_TOKEN is not configured on the backend")
    url = f"http://{agent['ip']}:{agent['port']}{path}"
    if ":" in agent["ip"]:
        url = f"http://[{agent['ip']}]:{agent['port']}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url, data=data, method=method,
        headers={"X-Agent-Token": config.AGENT_TOKEN, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=max(config.HTTP_TIMEOUT_SECONDS, 30)) as resp:
            return json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        try:
            message = json.loads(exc.read().decode("utf-8")).get("error", "")
        except Exception:
            message = ""
        raise AgentError(f"agent {agent['agent_id']} returned HTTP {exc.code}: {message}".rstrip(": ")) from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise AgentError(f"agent {agent['agent_id']} unreachable: {exc}") from exc


def _require_online(agent_id):
    if not agent_id:
        raise AgentError("alert has no agent ID")
    agents = online_agents(agent_id)
    if not agents:
        raise AgentError(f"agent {agent_id} offline")
    return agents[0]


# ---------------------------------------------------------------- pfSense fallback

def _pfsense_block(ip):
    """Add ip to the pfSense alias. Generic alias-entry call; untested against a real pfSense."""
    body = json.dumps({"name": config.PFSENSE_ALIAS, "address": [ip], "detail": ["SOAR Lite"], "apply": True}).encode()
    request = urllib.request.Request(
        f"{config.PFSENSE_URL}/api/v1/firewall/alias/entry", data=body, method="POST",
        headers={"Authorization": config.PFSENSE_API_KEY, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=config.HTTP_TIMEOUT_SECONDS,
                                    context=ssl.create_default_context()) as resp:
            if resp.status >= 300:
                raise AgentError(f"pfSense returned HTTP {resp.status}")
    except urllib.error.HTTPError as exc:
        raise AgentError(f"pfSense returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AgentError(f"pfSense unreachable: {exc}") from exc


# ---------------------------------------------------------------- containment

def block_ip(ip, reason="", alert_id=None, agent_id=None, actor="system"):
    """Block ip on the alert's agent (or every online agent), falling back to pfSense.

    Returns {"success": bool, ...}. Refusals carry "refused": True and are never sent anywhere.
    """
    try:
        ip = validate_ip(ip)
    except ValueError:
        return {"success": False, "refused": True, "error": "invalid IP address"}
    protected, why = is_protected(ip)
    if protected:
        log.warning("refused to block %s: %s", ip, why)
        return {"success": False, "refused": True, "ip": ip, "error": f"refused: {why}"}

    agents = online_agents(agent_id)
    enforced, errors = [], []
    for agent in agents:
        try:
            _agent_call(agent, "POST", "/block-ip", {"ip": ip})
            enforced.append(f"agent:{agent['agent_id']}")
        except AgentError as exc:
            errors.append(str(exc))
    if not agents:
        errors.append(f"agent {agent_id} offline" if agent_id else "no agent online")

    if not enforced and config.PFSENSE_URL and config.PFSENSE_API_KEY:
        try:
            _pfsense_block(ip)
            enforced.append("pfsense")
        except AgentError as exc:
            errors.append(str(exc))

    if not enforced:
        return {"success": False, "ip": ip, "error": "; ".join(errors)}

    with get_db() as conn:
        conn.execute(
            """INSERT INTO blocked_ips (ip, reason, enforced_by, alert_id, blocked_by, blocked_at, unblocked_at, active)
               VALUES (?, ?, ?, ?, ?, ?, NULL, 1)
               ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, enforced_by = excluded.enforced_by,
                   alert_id = excluded.alert_id, blocked_by = excluded.blocked_by,
                   blocked_at = excluded.blocked_at, unblocked_at = NULL, active = 1""",
            (ip, reason, ",".join(enforced), alert_id, actor, utcnow()),
        )
    events.publish("ip_blocked", {"ip": ip, "enforced_by": enforced})
    return {"success": True, "ip": ip, "enforced_by": enforced, "errors": errors}


def unblock_ip(ip, actor="system"):
    try:
        ip = validate_ip(ip)
    except ValueError:
        return {"success": False, "error": "invalid IP address"}
    released, errors = [], []
    for agent in online_agents():
        try:
            _agent_call(agent, "POST", "/unblock-ip", {"ip": ip})
            released.append(f"agent:{agent['agent_id']}")
        except AgentError as exc:
            errors.append(str(exc))
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE blocked_ips SET active = 0, unblocked_at = ? WHERE ip = ? AND active = 1", (utcnow(), ip)
        )
        was_blocked = cur.rowcount > 0
    if not was_blocked and not released:
        return {"success": False, "ip": ip, "error": "IP is not blocked", "errors": errors}
    events.publish("ip_unblocked", {"ip": ip})
    return {"success": True, "ip": ip, "released_on": released, "errors": errors}


def list_blocked(active_only=True):
    query = "SELECT * FROM blocked_ips"
    if active_only:
        query += " WHERE active = 1"
    with get_db() as conn:
        return [row_to_dict(r) for r in conn.execute(query + " ORDER BY blocked_at DESC").fetchall()]


def isolate_host(agent_id, alert_id=None, actor="system"):
    """Isolate a host. The backend address stays reachable so the agent can be released."""
    if not config.BACKEND_IP:
        raise AgentError("SOAR_BACKEND_IP must be set before a host can be isolated")
    agent = _require_online(agent_id)
    result = _agent_call(agent, "POST", "/isolate", {"backend_ip": config.BACKEND_IP})
    with get_db() as conn:
        conn.execute("UPDATE agents SET isolated = 1 WHERE agent_id = ?", (agent["agent_id"],))
    events.publish("host_isolated", {"agent_id": agent["agent_id"], "alert_id": alert_id})
    return result


def release_host(agent_id, actor="system"):
    agent = _require_online(agent_id)
    result = _agent_call(agent, "POST", "/release", {})
    with get_db() as conn:
        conn.execute("UPDATE agents SET isolated = 0 WHERE agent_id = ?", (agent["agent_id"],))
    events.publish("host_released", {"agent_id": agent["agent_id"]})
    return result


def collect_evidence(agent_id, case_id):
    validate_case_id(case_id)
    agent = _require_online(agent_id)
    result = _agent_call(agent, "POST", "/collect-evidence", {"case_id": case_id})
    with get_db() as conn:
        conn.execute(
            "UPDATE cases SET evidence_json = ? WHERE case_id = ?",
            (json.dumps({"agent_id": agent["agent_id"], **result}), case_id),
        )
    events.publish("evidence_collected", {"case_id": case_id, "agent_id": agent["agent_id"]})
    return result


def verify_evidence(agent_id, case_id):
    validate_case_id(case_id)
    agent = _require_online(agent_id)
    return _agent_call(agent, "POST", "/verify-evidence", {"case_id": case_id})


def create_case(alert, playbook_id=None):
    """Create (or reuse) the case for an alert. Case IDs look like ALERT-<alert id>."""
    case_id = f"ALERT-{int(alert['id'])}"
    title = f"{alert.get('alert_type', 'unknown')}: {alert.get('description') or 'alert'}"[:200]
    with get_db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO cases (case_id, alert_id, title, severity, status, created_at) VALUES (?, ?, ?, ?, 'open', ?)",
            (case_id, alert["id"], title, alert.get("severity"), utcnow()),
        )
    return case_id


def get_case(case_id):
    with get_db() as conn:
        row = conn.execute(
            "SELECT c.*, a.agent_id AS agent_id FROM cases c LEFT JOIN alerts a ON a.id = c.alert_id WHERE c.case_id = ?",
            (case_id,),
        ).fetchone()
    return row_to_dict(row)


def list_cases():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT c.*, a.agent_id AS agent_id FROM cases c LEFT JOIN alerts a ON a.id = c.alert_id ORDER BY c.created_at DESC"
        ).fetchall()
    return [row_to_dict(r) for r in rows]


def manual_block(ip, actor, reason="manual block"):
    """Dashboard/API block, with audit."""
    result = block_ip(ip, reason=reason, actor=actor)
    audit(actor, "manual_block" if result.get("success") else "manual_block_failed",
          result.get("ip", ip), result.get("error", ",".join(result.get("enforced_by", []))))
    return result
