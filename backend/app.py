"""SOAR Lite backend: REST API, live WebSocket and the Wazuh poller.

Run with:  python -m uvicorn backend.app:app --port 8000
"""
import asyncio
import hashlib
import hmac
import logging
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket

from backend import config
from backend.database.db import audit, get_db, init_db, parse_ts, row_to_dict, rows_to_dicts, utcnow
from backend.services import events, playbook_engine, response, threat_intel
from backend.services.wazuh import WazuhPoller, make_source

log = logging.getLogger("soar.app")

PBKDF2_ITERATIONS = 200_000
AGENT_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


# ---------------------------------------------------------------- authentication

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt.hex(), digest.hex()


def verify_password(password, salt_hex, hash_hex):
    _, digest = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(digest, hash_hex)


def ensure_admin():
    """Create the first admin user. Without SOAR_ADMIN_PASSWORD a one-time password is logged."""
    with get_db() as conn:
        if conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            return
    password, generated = config.ADMIN_PASSWORD, False
    if not password:
        password, generated = secrets.token_urlsafe(12), True
    salt, digest = hash_password(password)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO users (username, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (config.ADMIN_USER, salt, digest, utcnow()),
        )
    if generated:
        log.warning("SOAR_ADMIN_PASSWORD not set. One-time password for user %r: %s  (change it by setting "
                    "SOAR_ADMIN_PASSWORD and deleting the database, or by updating the users table)",
                    config.ADMIN_USER, password)


def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def authenticate(username, password):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        hash_password(password)  # spend the same time as a real check
        return False
    return verify_password(password, row["password_salt"], row["password_hash"])


def create_session(username):
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=config.SESSION_TTL_HOURS)
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (utcnow(),))
        conn.execute(
            "INSERT INTO sessions (token_hash, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (_token_hash(token), username, utcnow(), expires.isoformat(timespec="milliseconds")),
        )
    return token, expires.isoformat(timespec="seconds")


def resolve_session(token):
    """Return the username for a valid, unexpired session token, else None."""
    if not token or not isinstance(token, str) or len(token) > 256:
        return None
    with get_db() as conn:
        row = conn.execute("SELECT username, expires_at FROM sessions WHERE token_hash = ?",
                           (_token_hash(token),)).fetchone()
    if row is None:
        return None
    expires = parse_ts(row["expires_at"])
    if expires is None or expires <= datetime.now(timezone.utc):
        return None
    return row["username"]


def _bearer(request):
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def require_user(request):
    user = resolve_session(_bearer(request))
    if not user:
        raise HTTPException(401, "authentication required")
    return user


def require_agent_token(request):
    provided = request.headers.get("x-agent-token", "")
    if not config.AGENT_TOKEN or not hmac.compare_digest(provided.encode(), config.AGENT_TOKEN.encode()):
        raise HTTPException(401, "invalid agent token")


async def read_json(request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "request body must be JSON")
    if not isinstance(body, dict):
        raise HTTPException(400, "request body must be a JSON object")
    return body


def _int_param(value, name):
    if isinstance(value, bool):
        raise HTTPException(400, f"{name} must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError):
        raise HTTPException(400, f"{name} must be an integer")


# ---------------------------------------------------------------- public routes

async def index(request):
    return FileResponse(config.DASHBOARD_FILE, media_type="text/html")


async def health(request):
    return JSONResponse({"status": "ok", "time": utcnow()})


async def login(request):
    body = await read_json(request)
    username = str(body.get("username") or "")
    password = str(body.get("password") or "")
    ok = await run_in_threadpool(authenticate, username, password)
    if not ok:
        audit(username or "?", "login_failed", "", f"from {request.client.host if request.client else '?'}")
        raise HTTPException(401, "invalid username or password")
    token, expires = create_session(username)
    audit(username, "login", "", f"from {request.client.host if request.client else '?'}")
    return JSONResponse({"token": token, "expires_at": expires, "username": username})


async def logout(request):
    user = require_user(request)
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(_bearer(request)),))
    audit(user, "logout")
    return JSONResponse({"success": True})


# ---------------------------------------------------------------- alerts

def _alert_summary(row):
    alert = row_to_dict(row)
    alert.pop("raw", None)
    return alert


async def list_alerts(request):
    require_user(request)
    limit = min(_int_param(request.query_params.get("limit", 200), "limit"), 1000)
    alert_type = request.query_params.get("type")
    query, params = "SELECT * FROM alerts", []
    if alert_type:
        query += " WHERE alert_type = ?"
        params.append(alert_type)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return JSONResponse({"alerts": [_alert_summary(r) for r in rows]})


async def get_alert(request):
    require_user(request)
    alert_id = request.path_params["alert_id"]
    with get_db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "alert not found")
        executions = conn.execute(
            "SELECT * FROM playbook_executions WHERE alert_id = ? ORDER BY id", (alert_id,)
        ).fetchall()
    alert = row_to_dict(row)
    alert["executions"] = rows_to_dicts(executions)
    return JSONResponse(alert)


# ---------------------------------------------------------------- playbooks

async def list_playbooks(request):
    require_user(request)
    return JSONResponse({"playbooks": [{"id": pid, **pb} for pid, pb in config.PLAYBOOKS.items()]})


async def list_executions(request):
    require_user(request)
    return JSONResponse({"executions": playbook_engine.list_executions()})


async def get_execution(request):
    require_user(request)
    execution = playbook_engine.get_execution(request.path_params["execution_id"])
    if execution is None:
        raise HTTPException(404, "execution not found")
    return JSONResponse(execution)


async def run_playbook(request):
    user = require_user(request)
    body = await read_json(request)
    alert_id = _int_param(body.get("alert_id"), "alert_id")
    playbook_id = body.get("playbook_id")
    if playbook_id is not None and playbook_id not in config.PLAYBOOKS:
        raise HTTPException(400, "unknown playbook_id")
    try:
        execution = await run_in_threadpool(playbook_engine.run_playbook, alert_id, playbook_id, user)
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return JSONResponse(execution)


async def approve_execution(request):
    user = require_user(request)
    try:
        execution = await run_in_threadpool(playbook_engine.approve, request.path_params["execution_id"], user)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return JSONResponse(execution)


async def reject_execution(request):
    user = require_user(request)
    reason = ""
    if await request.body():
        reason = str((await read_json(request)).get("reason") or "")[:500]
    try:
        execution = await run_in_threadpool(playbook_engine.reject, request.path_params["execution_id"], user, reason)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return JSONResponse(execution)


# ---------------------------------------------------------------- firewall

async def block(request):
    user = require_user(request)
    body = await read_json(request)
    try:
        response.validate_ip(body.get("ip"))
    except ValueError:
        raise HTTPException(400, "ip must be a valid IP address")
    reason = str(body.get("reason") or "manual block")[:200]
    result = await run_in_threadpool(response.manual_block, body["ip"], user, reason)
    if result.get("refused"):
        return JSONResponse(result, status_code=422)
    return JSONResponse(result, status_code=200 if result["success"] else 502)


async def unblock(request):
    user = require_user(request)
    ip = request.path_params["ip"]
    try:
        response.validate_ip(ip)
    except ValueError:
        raise HTTPException(400, "ip must be a valid IP address")
    result = await run_in_threadpool(response.unblock_ip, ip, user)
    audit(user, "unblock" if result["success"] else "unblock_failed", ip, result.get("error", ""))
    return JSONResponse(result, status_code=200 if result["success"] else 404)


async def blocked_list(request):
    require_user(request)
    active_only = request.query_params.get("all") not in ("1", "true")
    return JSONResponse({"blocked": response.list_blocked(active_only)})


# ---------------------------------------------------------------- threat intel

async def threat_intel_check(request):
    user = require_user(request)
    body = await read_json(request)
    try:
        result = await run_in_threadpool(threat_intel.enrich_ioc, body.get("ioc"), body.get("type"))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    audit(user, "threat_intel_check", result["ioc"], result["reputation"])
    return JSONResponse(result)


# ---------------------------------------------------------------- agents

async def list_agents(request):
    require_user(request)
    return JSONResponse({"agents": response.list_agents()})


async def register_agent(request):
    require_agent_token(request)
    body = await read_json(request)
    agent_id = str(body.get("agent_id") or "")
    if not AGENT_ID_RE.match(agent_id):
        raise HTTPException(400, "agent_id must match ^[A-Za-z0-9_.-]{1,64}$")
    port = _int_param(body.get("port", config.AGENT_PORT), "port")
    if not 1 <= port <= 65535:
        raise HTTPException(400, "port out of range")
    ip = request.client.host if request.client else None
    try:
        ip = response.validate_ip(ip)
    except ValueError:
        raise HTTPException(400, "cannot determine agent address")
    with get_db() as conn:
        existing = conn.execute("SELECT 1 FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        conn.execute(
            """INSERT INTO agents (agent_id, hostname, ip, port, admin, isolated, dry_run, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(agent_id) DO UPDATE SET hostname = excluded.hostname, ip = excluded.ip,
                   port = excluded.port, admin = excluded.admin, isolated = excluded.isolated,
                   dry_run = excluded.dry_run, last_seen = excluded.last_seen""",
            (agent_id, str(body.get("hostname") or "")[:255], ip, port, int(bool(body.get("admin"))),
             int(bool(body.get("isolated"))), int(bool(body.get("dry_run"))), utcnow()),
        )
    if not existing:
        audit(f"agent:{agent_id}", "agent_registered", agent_id, f"{ip}:{port}")
        events.publish("agent", {"agent_id": agent_id, "status": "Online"})
    return JSONResponse({"success": True, "agent_id": agent_id, "ip": ip})


async def isolate_agent(request):
    user = require_user(request)
    agent_id = request.path_params["agent_id"]
    try:
        result = await run_in_threadpool(response.isolate_host, agent_id, None, user)
    except response.AgentError as exc:
        audit(user, "isolate_failed", agent_id, str(exc))
        raise HTTPException(502, str(exc))
    audit(user, "isolate", agent_id)
    return JSONResponse({"success": True, "result": result})


async def release_agent(request):
    user = require_user(request)
    agent_id = request.path_params["agent_id"]
    try:
        result = await run_in_threadpool(response.release_host, agent_id, user)
    except response.AgentError as exc:
        audit(user, "release_failed", agent_id, str(exc))
        raise HTTPException(502, str(exc))
    audit(user, "release", agent_id)
    return JSONResponse({"success": True, "result": result})


# ---------------------------------------------------------------- cases and evidence

async def list_cases(request):
    require_user(request)
    return JSONResponse({"cases": response.list_cases()})


async def _case_and_agent(request):
    case_id = request.path_params["case_id"]
    try:
        response.validate_case_id(case_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    case = response.get_case(case_id)
    if case is None:
        raise HTTPException(404, "case not found")
    body = await read_json(request) if await request.body() else {}
    agent_id = body.get("agent_id") or case.get("agent_id")
    if not agent_id:
        raise HTTPException(400, "no agent for this case; pass agent_id")
    return case_id, str(agent_id)


async def collect_case_evidence(request):
    user = require_user(request)
    case_id, agent_id = await _case_and_agent(request)
    try:
        result = await run_in_threadpool(response.collect_evidence, agent_id, case_id)
    except response.AgentError as exc:
        raise HTTPException(502, str(exc))
    audit(user, "evidence_collected", case_id, f"agent {agent_id}")
    return JSONResponse(result)


async def verify_case_evidence(request):
    user = require_user(request)
    case_id, agent_id = await _case_and_agent(request)
    try:
        result = await run_in_threadpool(response.verify_evidence, agent_id, case_id)
    except response.AgentError as exc:
        raise HTTPException(502, str(exc))
    audit(user, "evidence_verified", case_id, "valid" if result.get("valid") else f"problems: {result.get('problems')}")
    return JSONResponse(result)


# ---------------------------------------------------------------- metrics, reports, audit

def _seconds_between(start, end):
    a, b = parse_ts(start), parse_ts(end)
    if a is None or b is None:
        return None
    return (b - a).total_seconds()


def _mean(values):
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), 3) if values else None


def compute_metrics():
    with get_db() as conn:
        by_type = {r["alert_type"]: r["n"] for r in conn.execute(
            "SELECT alert_type, COUNT(*) AS n FROM alerts GROUP BY alert_type")}
        by_severity = {r["severity"]: r["n"] for r in conn.execute(
            "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity")}
        by_status = {r["status"]: r["n"] for r in conn.execute(
            "SELECT status, COUNT(*) AS n FROM playbook_executions GROUP BY status")}
        finished = conn.execute(
            """SELECT e.mode, e.started_at, e.finished_at, a.timestamp, a.received_at
               FROM playbook_executions e JOIN alerts a ON a.id = e.alert_id
               WHERE e.finished_at IS NOT NULL AND e.started_at IS NOT NULL""").fetchall()
        block_steps = {r["status"]: r["n"] for r in conn.execute(
            "SELECT status, COUNT(*) AS n FROM playbook_steps WHERE step = 'block_ip' GROUP BY status")}
        active_blocks = conn.execute("SELECT COUNT(*) FROM blocked_ips WHERE active = 1").fetchone()[0]
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    auto = [r for r in finished if r["mode"] == "AUTO"]
    attempted = block_steps.get("success", 0) + block_steps.get("failed", 0)
    return {
        "total_alerts": total_alerts,
        "alerts_by_type": by_type,
        "alerts_by_severity": by_severity,
        "executions_by_status": by_status,
        "automated_executions": len(auto),
        "avg_execution_seconds": _mean(_seconds_between(r["started_at"], r["finished_at"]) for r in finished),
        "avg_ingest_to_response_seconds": _mean(_seconds_between(r["received_at"], r["finished_at"]) for r in auto),
        "avg_detection_to_response_seconds": _mean(_seconds_between(r["timestamp"], r["finished_at"]) for r in auto),
        "block_steps": block_steps,
        "block_success_rate": round(block_steps.get("success", 0) / attempted, 3) if attempted else None,
        "active_blocks": active_blocks,
    }


async def metrics(request):
    require_user(request)
    return JSONResponse(compute_metrics())


async def generate_report(request):
    user = require_user(request)
    with get_db() as conn:
        alerts = [_alert_summary(r) for r in conn.execute("SELECT * FROM alerts ORDER BY id")]
        execution_ids = [r[0] for r in conn.execute("SELECT id FROM playbook_executions ORDER BY id")]
    report = {
        "generated_at": utcnow(),
        "generated_by": user,
        "metrics": compute_metrics(),
        "alerts": alerts,
        "executions": [playbook_engine.get_execution(i) for i in execution_ids],
        "blocked_ips": response.list_blocked(active_only=False),
        "cases": response.list_cases(),
        "agents": response.list_agents(),
    }
    audit(user, "report_generated", "", f"{len(alerts)} alerts")
    return JSONResponse(report)


async def audit_log(request):
    require_user(request)
    limit = min(_int_param(request.query_params.get("limit", 500), "limit"), 5000)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return JSONResponse({"audit": rows_to_dicts(rows)})


# ---------------------------------------------------------------- WebSocket

async def ws_endpoint(websocket: WebSocket):
    """Live updates. The session token is passed as ?token= because browsers cannot set WS headers."""
    user = resolve_session(websocket.query_params.get("token", ""))
    if not user:
        await websocket.close(code=1008)
        return
    await websocket.accept()

    loop = asyncio.get_running_loop()
    queue = asyncio.Queue(maxsize=500)

    def on_event(event):
        def put():
            if not queue.full():
                queue.put_nowait(event)
        try:
            loop.call_soon_threadsafe(put)
        except RuntimeError:
            pass  # loop already closed

    async def wait_for_disconnect():
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return

    events.subscribe(on_event)
    receiver = asyncio.ensure_future(wait_for_disconnect())
    try:
        await websocket.send_json({"type": "hello", "data": {"user": user}, "timestamp": utcnow()})
        while True:
            getter = asyncio.ensure_future(queue.get())
            done, _ = await asyncio.wait({getter, receiver}, return_when=asyncio.FIRST_COMPLETED)
            if receiver in done:
                getter.cancel()
                break
            await websocket.send_json(getter.result())
    except Exception:
        pass  # client went away
    finally:
        events.unsubscribe(on_event)
        receiver.cancel()


# ---------------------------------------------------------------- app

async def http_error(request, exc):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


def startup():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    init_db()
    ensure_admin()
    if not config.AGENT_TOKEN:
        log.error("AGENT_TOKEN is not set: agents cannot register and containment will fail")
    if not config.BACKEND_IP:
        log.warning("SOAR_BACKEND_IP is not set: host isolation is disabled")


@asynccontextmanager
async def lifespan(app):
    startup()
    poller = WazuhPoller(make_source(), config.POLL_INTERVAL_SECONDS)
    task = asyncio.create_task(poller.run())
    try:
        yield
    finally:
        poller.stop()
        try:
            await asyncio.wait_for(task, timeout=10)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            task.cancel()


routes = [
    Route("/", index),
    Route("/health", health),
    Route("/login", login, methods=["POST"]),
    Route("/logout", logout, methods=["POST"]),
    Route("/alerts", list_alerts),
    Route("/alerts/{alert_id:int}", get_alert),
    Route("/playbooks", list_playbooks),
    Route("/playbooks/run", run_playbook, methods=["POST"]),
    Route("/playbooks/executions", list_executions),
    Route("/playbooks/executions/{execution_id:int}", get_execution),
    Route("/playbooks/executions/{execution_id:int}/approve", approve_execution, methods=["POST"]),
    Route("/playbooks/executions/{execution_id:int}/reject", reject_execution, methods=["POST"]),
    Route("/firewall/block", block, methods=["POST"]),
    Route("/firewall/unblock/{ip}", unblock, methods=["DELETE"]),
    Route("/firewall/blocked", blocked_list),
    Route("/threat-intel/check", threat_intel_check, methods=["POST"]),
    Route("/agents", list_agents),
    Route("/agents/register", register_agent, methods=["POST"]),
    Route("/agents/{agent_id}/isolate", isolate_agent, methods=["POST"]),
    Route("/agents/{agent_id}/release", release_agent, methods=["POST"]),
    Route("/cases", list_cases),
    Route("/cases/{case_id}/collect-evidence", collect_case_evidence, methods=["POST"]),
    Route("/cases/{case_id}/verify", verify_case_evidence, methods=["POST"]),
    Route("/metrics", metrics),
    Route("/reports/generate", generate_report, methods=["POST"]),
    Route("/audit", audit_log),
    WebSocketRoute("/ws", ws_endpoint),
]

app = Starlette(routes=routes, exception_handlers={HTTPException: http_error}, lifespan=lifespan)
