"""Playbook engine: select, run, approve and reject playbooks, logging every step.

Step outcomes are success, skipped or failed. A failed step never stops later steps.
An execution ends as completed (no failed step) or completed_with_errors.
"""
import json
import logging

from backend import config
from backend.database.db import audit, get_db, row_to_dict, rows_to_dicts, utcnow
from backend.services import events, response, threat_intel

log = logging.getLogger("soar.playbooks")

MAX_IOCS_PER_ALERT = 10


def select_playbook(alert_type):
    for playbook_id, playbook in config.PLAYBOOKS.items():
        if playbook["alert_type"] == alert_type:
            return playbook_id
    return None


def should_block(reputation, severity):
    """Fail safe: unknown reputation blocks. Only a clean LOW verdict on a non-HIGH alert skips."""
    return not (reputation == "LOW" and severity not in config.HIGH_SEVERITIES)


# ---------------------------------------------------------------- steps
# Each step takes the execution context and returns (status, detail).

def _step_enrich(ctx):
    alert = ctx["alert"]
    iocs = alert.get("iocs") or {}
    candidates = []
    if alert.get("source_ip"):
        candidates.append((alert["source_ip"], "ip"))
    candidates += [(v, "ip") for v in iocs.get("ips", [])]
    candidates += [(v, "url") for v in iocs.get("urls", [])]
    candidates += [(v, "hash") for v in iocs.get("hashes", [])]

    results = {}
    for value, ioc_type in candidates:
        if value in results or len(results) >= MAX_IOCS_PER_ALERT:
            continue
        try:
            results[value] = threat_intel.enrich_ioc(value, ioc_type)
        except Exception as exc:  # never let intel abort a playbook
            results[value] = {"ioc": value, "type": ioc_type, "reputation": "UNKNOWN",
                              "sources": {}, "errors": {"internal": str(exc)}}
    ctx["intel"] = results
    source = alert.get("source_ip")
    ctx["reputation"] = results.get(source, {}).get("reputation", "UNKNOWN") if source else "UNKNOWN"
    return "success", f"{len(results)} indicator(s) enriched; source reputation {ctx['reputation']}"


def _step_create_case(ctx):
    ctx["case_id"] = response.create_case(ctx["alert"], ctx["playbook_id"])
    return "success", f"case {ctx['case_id']}"


def _step_block_ip(ctx):
    alert = ctx["alert"]
    ip = alert.get("source_ip")
    if not ip:
        return "skipped", "no source IP in alert"
    reputation = ctx.get("reputation", "UNKNOWN")
    if not should_block(reputation, alert.get("severity")):
        return "skipped", f"source reputation LOW and alert severity {alert.get('severity')}: block skipped"
    result = response.block_ip(
        ip, reason=f"{ctx['playbook_id']} alert {alert['id']}", alert_id=alert["id"],
        agent_id=alert.get("agent_id"), actor=ctx["actor"],
    )
    if result.get("success"):
        return "success", f"{ip} blocked by {', '.join(result['enforced_by'])}"
    return "failed", result.get("error", "block failed")


def _step_isolate_host(ctx):
    response.isolate_host(ctx["alert"].get("agent_id"), alert_id=ctx["alert"]["id"], actor=ctx["actor"])
    return "success", f"agent {ctx['alert'].get('agent_id')} isolated; backend kept reachable"


def _step_collect_evidence(ctx):
    case_id = ctx.get("case_id") or response.create_case(ctx["alert"], ctx["playbook_id"])
    result = response.collect_evidence(ctx["alert"].get("agent_id"), case_id)
    return "success", f"{len(result.get('files', []))} file(s) collected and hashed for {case_id}"


STEPS = {
    "enrich": _step_enrich,
    "create_case": _step_create_case,
    "block_ip": _step_block_ip,
    "isolate_host": _step_isolate_host,
    "collect_evidence": _step_collect_evidence,
}


# ---------------------------------------------------------------- data access

def _load_alert(alert_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return row_to_dict(row)


def get_execution(execution_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM playbook_executions WHERE id = ?", (execution_id,)).fetchone()
        if row is None:
            return None
        steps = conn.execute(
            "SELECT * FROM playbook_steps WHERE execution_id = ? ORDER BY id", (execution_id,)
        ).fetchall()
    execution = row_to_dict(row)
    execution["steps"] = rows_to_dicts(steps)
    return execution


def list_executions(limit=200):
    with get_db() as conn:
        rows = conn.execute(
            """SELECT e.*, a.alert_type, a.source_ip, a.severity FROM playbook_executions e
               JOIN alerts a ON a.id = e.alert_id ORDER BY e.id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return rows_to_dicts(rows)


# ---------------------------------------------------------------- running

def run_playbook(alert_id, playbook_id=None, actor="system"):
    """Start a playbook for an alert. MANUAL playbooks stop at awaiting_approval."""
    alert = _load_alert(alert_id)
    if alert is None:
        raise LookupError(f"alert {alert_id} not found")
    playbook_id = playbook_id or select_playbook(alert["alert_type"])
    if not playbook_id:
        raise ValueError(f"no playbook for alert type {alert['alert_type']}")
    playbook = config.PLAYBOOKS.get(playbook_id)
    if playbook is None:
        raise ValueError(f"unknown playbook {playbook_id}")

    status = "awaiting_approval" if playbook["mode"] == "MANUAL" else "pending"
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO playbook_executions (alert_id, playbook_id, mode, status, triggered_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (alert_id, playbook_id, playbook["mode"], status, actor, utcnow()),
        )
        execution_id = cur.lastrowid
    audit(actor, "playbook_run", playbook_id, f"alert {alert_id}, execution {execution_id}, mode {playbook['mode']}")
    events.publish("playbook", {"execution_id": execution_id, "status": status})

    if status == "awaiting_approval":
        with get_db() as conn:
            conn.execute("UPDATE alerts SET status = 'awaiting_approval' WHERE id = ?", (alert_id,))
        return get_execution(execution_id)
    return _execute(execution_id, actor)


def approve(execution_id, actor):
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE playbook_executions SET status = 'approved', approved_by = ? WHERE id = ? AND status = 'awaiting_approval'",
            (actor, execution_id),
        )
        if cur.rowcount == 0:
            raise ValueError("execution is not awaiting approval")
    audit(actor, "playbook_approved", f"execution {execution_id}")
    return _execute(execution_id, actor)


def reject(execution_id, actor, reason=""):
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE playbook_executions SET status = 'rejected', approved_by = ?, finished_at = ? WHERE id = ? AND status = 'awaiting_approval'",
            (actor, utcnow(), execution_id),
        )
        if cur.rowcount == 0:
            raise ValueError("execution is not awaiting approval")
        conn.execute(
            "UPDATE alerts SET status = 'rejected' WHERE id = (SELECT alert_id FROM playbook_executions WHERE id = ?)",
            (execution_id,),
        )
    audit(actor, "playbook_rejected", f"execution {execution_id}", reason)
    events.publish("playbook", {"execution_id": execution_id, "status": "rejected"})
    return get_execution(execution_id)


def _execute(execution_id, actor):
    execution = get_execution(execution_id)
    alert = _load_alert(execution["alert_id"])
    playbook = config.PLAYBOOKS[execution["playbook_id"]]
    ctx = {"alert": alert, "playbook_id": execution["playbook_id"], "actor": actor}

    with get_db() as conn:
        conn.execute(
            "UPDATE playbook_executions SET status = 'running', started_at = ? WHERE id = ?",
            (utcnow(), execution_id),
        )
    events.publish("playbook", {"execution_id": execution_id, "status": "running"})

    failed = 0
    for step in playbook["steps"]:
        started = utcnow()
        try:
            status, detail = STEPS[step](ctx)
        except Exception as exc:
            log.warning("execution %s step %s failed: %s", execution_id, step, exc)
            status, detail = "failed", str(exc) or exc.__class__.__name__
        if status == "failed":
            failed += 1
        with get_db() as conn:
            conn.execute(
                "INSERT INTO playbook_steps (execution_id, step, status, detail, started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?)",
                (execution_id, step, status, detail, started, utcnow()),
            )

    final = "completed_with_errors" if failed else "completed"
    result = {"case_id": ctx.get("case_id"), "reputation": ctx.get("reputation"),
              "intel": ctx.get("intel", {}), "failed_steps": failed}
    with get_db() as conn:
        conn.execute(
            "UPDATE playbook_executions SET status = ?, finished_at = ?, result_json = ? WHERE id = ?",
            (final, utcnow(), json.dumps(result, default=str), execution_id),
        )
        conn.execute(
            "UPDATE alerts SET status = ? WHERE id = ?",
            ("responded" if not failed else "response_errors", alert["id"]),
        )
    events.publish("playbook", {"execution_id": execution_id, "status": final})
    return get_execution(execution_id)
