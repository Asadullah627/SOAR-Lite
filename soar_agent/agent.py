"""SOAR Lite Windows endpoint agent.

Listens on port 5055 and performs containment for the backend:
  - block / unblock an IP with Windows Defender Firewall (netsh)
  - isolate / release the host (everything blocked except the SOAR backend)
  - collect forensic evidence (processes, connections, event logs) and hash it

Every route requires the X-Agent-Token header. The agent refuses to start without AGENT_TOKEN.
With SOAR_AGENT_DRY_RUN=1 commands are recorded instead of executed (for testing on Linux).

Run (Administrator):  python -m uvicorn soar_agent.agent:app --host 0.0.0.0 --port 5055
"""
import asyncio
import hmac
import ipaddress
import json
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse
from starlette.routing import Route

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.evidence import MANIFEST_NAME, build_manifest, verify_manifest  # noqa: E402

try:
    import psutil
except ImportError:  # evidence collection reports the gap instead of crashing
    psutil = None

log = logging.getLogger("soar.agent")

IS_WINDOWS = platform.system() == "Windows"
CASE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
BLOCK_PREFIX = "SOAR_BLOCK_"
ISOLATE_RULES = {"in": "SOAR_ISOLATE_IN", "out": "SOAR_ISOLATE_OUT"}
IPV4_ALL = ("0.0.0.0", "255.255.255.255")
IPV6_ALL = ("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")


def _flag(value):
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


class Settings:
    def __init__(self, env):
        self.token = (env.get("AGENT_TOKEN") or "").strip()
        self.agent_id = (env.get("SOAR_AGENT_ID") or socket.gethostname()).strip()
        self.backend_url = (env.get("SOAR_BACKEND_URL") or "").strip().rstrip("/")
        self.backend_ip = (env.get("SOAR_BACKEND_IP") or "").strip()
        self.gateway_ip = (env.get("SOAR_GATEWAY_IP") or "").strip()
        self.safelist = {s.strip() for s in (env.get("SOAR_SAFELIST") or "").split(",") if s.strip()}
        default_dir = r"C:\SOAR-Agent\evidence" if IS_WINDOWS else str(ROOT / "evidence")
        self.evidence_dir = Path(env.get("SOAR_EVIDENCE_DIR") or default_dir)
        self.dry_run = _flag(env.get("SOAR_AGENT_DRY_RUN"))
        try:
            self.port = int(env.get("AGENT_PORT") or 5055)
        except ValueError:
            self.port = 5055
        try:
            self.heartbeat_seconds = max(int(env.get("SOAR_HEARTBEAT_SECONDS") or 60), 5)
        except ValueError:
            self.heartbeat_seconds = 60


def is_admin():
    try:
        if IS_WINDOWS:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


# ---------------------------------------------------------------- safety

def _normalize_ip(value):
    ip = ipaddress.ip_address(str(value or "").strip())
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip


def _local_addresses():
    addresses = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addresses.add(info[4][0].split("%")[0])
    except OSError:
        pass
    return addresses


def is_protected(ip, settings):
    """Return (protected, reason). Repeats the backend's check so a bad request can't lock us out."""
    try:
        addr = _normalize_ip(ip)
    except ValueError:
        return True, f"{ip!r} is not a valid IP address"
    text = str(addr)
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local \
            or text == "255.255.255.255":
        return True, f"{text} is a local, multicast or reserved address"
    for label, value in (("the SOAR backend", settings.backend_ip), ("the gateway", settings.gateway_ip)):
        if value:
            try:
                if _normalize_ip(value) == addr:
                    return True, f"{text} is {label}"
            except ValueError:
                pass
    for entry in settings.safelist:
        try:
            if _normalize_ip(entry) == addr:
                return True, f"{text} is safelisted"
        except ValueError:
            continue
    if text in _local_addresses():
        return True, f"{text} is this host"
    return False, ""


def isolation_ranges(backend_ip):
    """Remote address ranges to block so that only backend_ip stays reachable."""
    backend = _normalize_ip(backend_ip)
    if backend.version == 4:
        low, high = ipaddress.IPv4Address(IPV4_ALL[0]), ipaddress.IPv4Address(IPV4_ALL[1])
        other = [f"{IPV6_ALL[0]}-{IPV6_ALL[1]}"]
    else:
        low, high = ipaddress.IPv6Address(IPV6_ALL[0]), ipaddress.IPv6Address(IPV6_ALL[1])
        other = [f"{IPV4_ALL[0]}-{IPV4_ALL[1]}"]
    ranges = []
    if backend > low:
        ranges.append(f"{low}-{backend - 1}")
    if backend < high:
        ranges.append(f"{backend + 1}-{high}")
    return ranges + other


def safe_case_dir(base, case_id):
    """Resolve the evidence directory for case_id, refusing anything that escapes base."""
    if not isinstance(case_id, str) or not CASE_ID_RE.match(case_id):
        raise ValueError("case_id must match ^[A-Za-z0-9_-]{1,64}$")
    base = Path(base).resolve()
    path = (base / case_id).resolve()
    if path.parent != base:
        raise ValueError("case_id escapes the evidence directory")
    return path


# ---------------------------------------------------------------- command runner

class Runner:
    """Run commands as argument lists, never through a shell. Dry-run records them instead."""

    def __init__(self, dry_run):
        self.dry_run = dry_run
        self.commands = []

    def run(self, args, check=True):
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise TypeError("commands must be lists of strings")
        if self.dry_run:
            self.commands.append(args)
            log.info("[dry-run] %s", " ".join(args))
            return 0, ""
        proc = subprocess.run(args, capture_output=True, text=True, timeout=120, shell=False)
        output = (proc.stdout or "") + (proc.stderr or "")
        if check and proc.returncode != 0:
            raise RuntimeError(f"{args[0]} exited with {proc.returncode}: {output.strip()[:300]}")
        return proc.returncode, output


def _netsh_rule(name, direction, remoteip):
    return ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={direction}",
            "action=block", f"remoteip={remoteip}", "enable=yes", "profile=any"]


def _netsh_delete(name):
    return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]


# ---------------------------------------------------------------- actions

def do_block(state, ip):
    names = []
    for direction in ("in", "out"):
        name = f"{BLOCK_PREFIX}{ip}_{direction.upper()}"
        state.runner.run(_netsh_delete(name), check=False)  # avoid duplicate rules
        state.runner.run(_netsh_rule(name, direction, ip))
        names.append(name)
    return names


def do_unblock(state, ip):
    names = []
    for direction in ("in", "out"):
        name = f"{BLOCK_PREFIX}{ip}_{direction.upper()}"
        state.runner.run(_netsh_delete(name), check=False)
        names.append(name)
    return names


def do_isolate(state, backend_ip):
    remote = ",".join(isolation_ranges(backend_ip))
    for direction, name in ISOLATE_RULES.items():
        state.runner.run(_netsh_delete(name), check=False)
        state.runner.run(_netsh_rule(name, direction, remote))
    state.isolated = True
    state.isolated_backend = str(_normalize_ip(backend_ip))
    return list(ISOLATE_RULES.values())


def do_release(state):
    for name in ISOLATE_RULES.values():
        state.runner.run(_netsh_delete(name), check=False)
    state.isolated = False
    state.isolated_backend = None
    return list(ISOLATE_RULES.values())


def _write_processes(path):
    lines = []
    if psutil is None:
        lines.append("psutil not installed")
    else:
        for proc in psutil.process_iter(["pid", "ppid", "name", "username", "exe", "cmdline", "create_time"]):
            info = proc.info
            created = datetime.fromtimestamp(info.get("create_time") or 0, timezone.utc).isoformat(timespec="seconds")
            cmdline = " ".join(info.get("cmdline") or [])
            lines.append(f"{info.get('pid')}\t{info.get('ppid')}\t{info.get('name')}\t{info.get('username')}\t"
                         f"{created}\t{info.get('exe') or ''}\t{cmdline}")
    path.write_text("pid\tppid\tname\tuser\tstarted\texe\tcmdline\n" + "\n".join(lines) + "\n", encoding="utf-8")


def _write_connections(path):
    lines = []
    if psutil is None:
        lines.append("psutil not installed")
    else:
        try:
            for conn in psutil.net_connections(kind="inet"):
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                lines.append(f"{conn.pid}\t{conn.status}\t{laddr}\t{raddr}")
        except (psutil.AccessDenied, PermissionError) as exc:
            lines.append(f"access denied: {exc} (run the agent as Administrator)")
    path.write_text("pid\tstatus\tlocal\tremote\n" + "\n".join(lines) + "\n", encoding="utf-8")


def do_collect(state, case_id):
    settings = state.settings
    case_dir = safe_case_dir(settings.evidence_dir, case_id)
    if (case_dir / MANIFEST_NAME).exists():
        raise FileExistsError(f"evidence for {case_id} already collected; verify it instead")
    case_dir.mkdir(parents=True, exist_ok=True)

    _write_processes(case_dir / "processes.txt")
    _write_connections(case_dir / "network_connections.txt")
    info = {
        "agent_id": settings.agent_id,
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "isolated": state.isolated,
        "dry_run": settings.dry_run,
    }
    if psutil is not None:
        info["boot_time"] = datetime.fromtimestamp(psutil.boot_time(), timezone.utc).isoformat(timespec="seconds")
        info["users"] = [u.name for u in psutil.users()]
    (case_dir / "system_info.json").write_text(json.dumps(info, indent=2), encoding="utf-8")

    log_errors = {}
    if IS_WINDOWS or settings.dry_run:
        for channel in ("Security", "System"):
            target = case_dir / f"{channel}.evtx"
            try:
                state.runner.run(["wevtutil", "epl", channel, str(target)])
            except Exception as exc:
                log_errors[channel] = str(exc)
    manifest = build_manifest(case_dir, case_id, extra={"agent_id": settings.agent_id,
                                                        "log_export_errors": log_errors})
    return {
        "case_id": case_id,
        "path": str(case_dir),
        "files": sorted(manifest["files"]),
        "manifest_sha256": manifest["manifest_sha256"],
        "log_export_errors": log_errors,
    }


def do_verify(state, case_id):
    case_dir = safe_case_dir(state.settings.evidence_dir, case_id)
    if not case_dir.is_dir():
        raise FileNotFoundError(f"no evidence for {case_id}")
    valid, problems = verify_manifest(case_dir)
    return {"case_id": case_id, "valid": valid, "problems": problems}


# ---------------------------------------------------------------- HTTP layer

class AgentState:
    def __init__(self, settings):
        self.settings = settings
        self.runner = Runner(settings.dry_run)
        self.isolated = False
        self.isolated_backend = None


def _error(message, status):
    return JSONResponse({"error": message}, status_code=status)


def _authorized(request):
    expected = request.app.state.agent.settings.token.encode()
    provided = request.headers.get("x-agent-token", "").encode()
    return bool(expected) and hmac.compare_digest(provided, expected)


async def _body(request):
    try:
        body = await request.json()
    except Exception:
        return None
    return body if isinstance(body, dict) else None


def guarded(privileged=False):
    """Require the agent token; for privileged actions also require Administrator (unless dry-run)."""
    def wrap(handler):
        async def endpoint(request):
            if not _authorized(request):
                return _error("invalid agent token", 401)
            state = request.app.state.agent
            if privileged and not state.settings.dry_run:
                if not IS_WINDOWS:
                    return _error("firewall actions are supported on Windows only (use SOAR_AGENT_DRY_RUN=1)", 501)
                if not is_admin():
                    return _error("agent is not running as Administrator", 403)
            return await handler(request, state)
        return endpoint
    return wrap


@guarded()
async def status(request, state):
    return JSONResponse({
        "status": "Online",
        "agent_id": state.settings.agent_id,
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "admin": is_admin(),
        "isolated": state.isolated,
        "dry_run": state.settings.dry_run,
    })


@guarded()
async def commands(request, state):
    if not state.settings.dry_run:
        return _error("command log is only available in dry-run mode", 404)
    return JSONResponse({"commands": state.runner.commands})


@guarded(privileged=True)
async def block_ip(request, state):
    body = await _body(request)
    if body is None:
        return _error("request body must be a JSON object", 400)
    try:
        ip = str(_normalize_ip(body.get("ip")))
    except ValueError:
        return _error("ip must be a valid IP address", 400)
    protected, why = is_protected(ip, state.settings)
    if protected:
        return _error(f"refused: {why}", 422)
    try:
        rules = await run_in_threadpool(do_block, state, ip)
    except Exception as exc:
        return _error(str(exc), 500)
    log.info("blocked %s", ip)
    return JSONResponse({"success": True, "ip": ip, "rules": rules, "dry_run": state.settings.dry_run})


@guarded(privileged=True)
async def unblock_ip(request, state):
    body = await _body(request)
    if body is None:
        return _error("request body must be a JSON object", 400)
    try:
        ip = str(_normalize_ip(body.get("ip")))
    except ValueError:
        return _error("ip must be a valid IP address", 400)
    rules = await run_in_threadpool(do_unblock, state, ip)
    return JSONResponse({"success": True, "ip": ip, "rules": rules})


@guarded(privileged=True)
async def isolate(request, state):
    body = await _body(request) or {}
    backend_ip = body.get("backend_ip") or state.settings.backend_ip
    if not backend_ip:
        return _error("refusing to isolate: no backend_ip, the host would become unmanageable", 400)
    try:
        backend_ip = str(_normalize_ip(backend_ip))
    except ValueError:
        return _error("backend_ip must be a valid IP address", 400)
    if state.settings.backend_ip:
        try:
            if _normalize_ip(state.settings.backend_ip) != _normalize_ip(backend_ip):
                return _error("backend_ip does not match SOAR_BACKEND_IP on this agent", 400)
        except ValueError:
            pass
    try:
        rules = await run_in_threadpool(do_isolate, state, backend_ip)
    except Exception as exc:
        return _error(str(exc), 500)
    log.warning("host isolated; only %s remains reachable", backend_ip)
    return JSONResponse({"success": True, "isolated": True, "backend_ip": backend_ip, "rules": rules})


@guarded(privileged=True)
async def release(request, state):
    rules = await run_in_threadpool(do_release, state)
    return JSONResponse({"success": True, "isolated": False, "rules": rules})


@guarded(privileged=True)
async def collect_evidence(request, state):
    body = await _body(request)
    if body is None:
        return _error("request body must be a JSON object", 400)
    try:
        result = await run_in_threadpool(do_collect, state, body.get("case_id"))
    except ValueError as exc:
        return _error(str(exc), 400)
    except FileExistsError as exc:
        return _error(str(exc), 409)
    return JSONResponse(result)


@guarded()
async def verify_evidence(request, state):
    body = await _body(request)
    if body is None:
        return _error("request body must be a JSON object", 400)
    try:
        result = await run_in_threadpool(do_verify, state, body.get("case_id"))
    except ValueError as exc:
        return _error(str(exc), 400)
    except FileNotFoundError as exc:
        return _error(str(exc), 404)
    return JSONResponse(result)


def send_heartbeat(state):
    settings = state.settings
    payload = json.dumps({
        "agent_id": settings.agent_id, "hostname": socket.gethostname(), "port": settings.port,
        "admin": is_admin(), "isolated": state.isolated, "dry_run": settings.dry_run,
    }).encode()
    request = urllib.request.Request(
        f"{settings.backend_url}/agents/register", data=payload, method="POST",
        headers={"X-Agent-Token": settings.token, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as resp:
        return resp.status


async def heartbeat_loop(state):
    while True:
        try:
            await asyncio.to_thread(send_heartbeat, state)
        except Exception as exc:
            log.warning("heartbeat to %s failed: %s", state.settings.backend_url, exc)
        await asyncio.sleep(state.settings.heartbeat_seconds)


def create_app(env=None):
    settings = Settings(os.environ if env is None else env)
    if not settings.token:
        raise RuntimeError("AGENT_TOKEN is not set; the agent refuses to start without it")
    state = AgentState(settings)

    @asynccontextmanager
    async def lifespan(app):
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        if settings.dry_run:
            log.warning("DRY-RUN mode: firewall and wevtutil commands are recorded, not executed")
        elif not is_admin():
            log.error("not running as Administrator: containment requests will return 403")
        task = asyncio.create_task(heartbeat_loop(state)) if settings.backend_url else None
        if task is None:
            log.warning("SOAR_BACKEND_URL not set: the agent will not register with the backend")
        try:
            yield
        finally:
            if task:
                task.cancel()

    app = Starlette(routes=[
        Route("/agent/status", status),
        Route("/agent/commands", commands),
        Route("/block-ip", block_ip, methods=["POST"]),
        Route("/unblock-ip", unblock_ip, methods=["POST"]),
        Route("/isolate", isolate, methods=["POST"]),
        Route("/release", release, methods=["POST"]),
        Route("/collect-evidence", collect_evidence, methods=["POST"]),
        Route("/verify-evidence", verify_evidence, methods=["POST"]),
    ], lifespan=lifespan)
    app.state.agent = state
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=app.state.agent.settings.port)
