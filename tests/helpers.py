"""Test helpers: isolated settings, a fresh database per test, and an in-process ASGI client.

Import this module before any backend module so the environment below is in place
when backend.config is first loaded.
"""
import asyncio
import json
import os
import shutil
import tempfile
import uuid

TMP = tempfile.mkdtemp(prefix="soar-lite-tests-")

os.environ.update({
    "AGENT_TOKEN": "test-agent-token",
    "SOAR_DB_PATH": os.path.join(TMP, "default.db"),
    "SOAR_ADMIN_USER": "admin",
    "SOAR_ADMIN_PASSWORD": "test-password",
    "WAZUH_SIMULATION": "1",
    "SOAR_SAFELIST": "10.0.0.1,10.0.0.10,10.0.0.20",
    "SOAR_BACKEND_IP": "10.0.0.10",
    "SOAR_GATEWAY_IP": "10.0.0.1",
    "VT_API_KEY": "",
    "ABUSEIPDB_API_KEY": "",
    "OTX_API_KEY": "",
    "PFSENSE_URL": "",
    "PFSENSE_API_KEY": "",
    "SOAR_AGENT_ID": "001",
    "SOAR_AGENT_DRY_RUN": "1",
    "SOAR_EVIDENCE_DIR": os.path.join(TMP, "evidence"),
    "SOAR_BACKEND_URL": "",
})

from backend import config  # noqa: E402
from backend import app as backend_app  # noqa: E402
from backend.database import db  # noqa: E402

backend_app.PBKDF2_ITERATIONS = 1000  # keep the suite fast; production uses 200,000

AGENT_HEADERS = {"X-Agent-Token": "test-agent-token"}


def fresh_db():
    """Point the backend at a new empty database with the admin user created."""
    config.DB_PATH = os.path.join(TMP, f"db-{uuid.uuid4().hex}.db")
    db.init_db()
    backend_app.ensure_admin()
    return config.DB_PATH


def fresh_dir(name="case"):
    path = os.path.join(TMP, f"{name}-{uuid.uuid4().hex}")
    os.makedirs(path)
    return path


def cleanup():
    shutil.rmtree(TMP, ignore_errors=True)


class Response:
    def __init__(self, status, headers, body):
        self.status_code = status
        self.headers = headers
        self.content = body

    def json(self):
        return json.loads(self.content.decode("utf-8"))


class ASGIClient:
    """Minimal in-process HTTP and WebSocket client for an ASGI app (no httpx needed)."""

    def __init__(self, app, client_host="127.0.0.1"):
        self.app = app
        self.client_host = client_host

    def request(self, method, path, json_body=None, headers=None, raw_body=None):
        return asyncio.run(self._request(method, path, json_body, headers, raw_body))

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, json_body=None, **kw):
        return self.request("POST", path, json_body=json_body, **kw)

    def delete(self, path, **kw):
        return self.request("DELETE", path, **kw)

    async def _request(self, method, path, json_body, headers, raw_body):
        path, _, query = path.partition("?")
        if raw_body is not None:
            body = raw_body
        elif json_body is not None:
            body = json.dumps(json_body).encode()
        else:
            body = b""
        hdrs = [(b"host", b"testserver"), (b"content-length", str(len(body)).encode())]
        if json_body is not None or raw_body is not None:
            hdrs.append((b"content-type", b"application/json"))
        for key, value in (headers or {}).items():
            hdrs.append((key.lower().encode(), value.encode()))
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": method.upper(), "scheme": "http", "path": path, "raw_path": path.encode(),
            "query_string": query.encode(), "root_path": "", "headers": hdrs,
            "client": (self.client_host, 50000), "server": ("testserver", 80),
        }
        sent = False

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        messages = []

        async def send(message):
            messages.append(message)

        await self.app(scope, receive, send)
        start = next(m for m in messages if m["type"] == "http.response.start")
        content = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
        headers_out = {k.decode().lower(): v.decode() for k, v in start.get("headers", [])}
        return Response(start["status"], headers_out, content)

    def websocket(self, path):
        """Connect, record what the server sends, then disconnect after the first message.

        Returns the list of ASGI messages the app sent (websocket.accept / .send / .close).
        """
        return asyncio.run(self._websocket(path))

    async def _websocket(self, path):
        path, _, query = path.partition("?")
        scope = {
            "type": "websocket", "asgi": {"version": "3.0"}, "scheme": "ws", "path": path,
            "raw_path": path.encode(), "query_string": query.encode(), "root_path": "",
            "headers": [(b"host", b"testserver")], "client": (self.client_host, 50001),
            "server": ("testserver", 80), "subprotocols": [],
        }
        incoming = asyncio.Queue()
        incoming.put_nowait({"type": "websocket.connect"})
        sent = []

        async def receive():
            return await incoming.get()

        async def send(message):
            sent.append(message)
            if message["type"] == "websocket.send":
                incoming.put_nowait({"type": "websocket.disconnect", "code": 1000})

        await asyncio.wait_for(self.app(scope, receive, send), timeout=5)
        return sent


def login(client, username="admin", password="test-password"):
    res = client.post("/login", {"username": username, "password": password})
    assert res.status_code == 200, res.content
    return {"Authorization": "Bearer " + res.json()["token"]}


def register_agent(client, agent_id="001", port=5055):
    res = client.post("/agents/register", {"agent_id": agent_id, "hostname": "WIN-ENDPOINT", "port": port,
                                           "admin": True, "dry_run": True}, headers=AGENT_HEADERS)
    assert res.status_code == 200, res.content
    return res.json()


def dry_run_agent(**overrides):
    """A fresh in-process endpoint agent in dry-run mode, with its own evidence directory."""
    from soar_agent import agent
    env = {
        "AGENT_TOKEN": "test-agent-token", "SOAR_AGENT_ID": "001", "SOAR_AGENT_DRY_RUN": "1",
        "SOAR_BACKEND_IP": "10.0.0.10", "SOAR_GATEWAY_IP": "10.0.0.1",
        "SOAR_SAFELIST": "10.0.0.1,10.0.0.10,10.0.0.20", "SOAR_EVIDENCE_DIR": fresh_dir("agent-evidence"),
    }
    env.update(overrides)
    return agent.create_app(env)


def route_to_agent(agent_app):
    """A replacement for response._agent_call that sends requests to an in-process agent."""
    from backend.services import response
    client = ASGIClient(agent_app)
    calls = []

    def call(agent, method, path, payload=None):
        calls.append((agent["agent_id"], path, payload))
        res = client.request(method, path, json_body=payload if payload is not None else {}, headers=AGENT_HEADERS)
        data = res.json()
        if res.status_code >= 400:
            raise response.AgentError(f"agent {agent['agent_id']} returned HTTP {res.status_code}: {data.get('error')}")
        return data

    call.calls = calls
    return call


def sample_alerts():
    with open(config.SIMULATION_FILE, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]
