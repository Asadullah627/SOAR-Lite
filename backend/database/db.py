"""SQLite storage for SOAR Lite: schema, connections and the audit log."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from backend import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    wazuh_id    TEXT NOT NULL UNIQUE,
    timestamp   TEXT,
    received_at TEXT NOT NULL,
    rule_id     TEXT,
    rule_level  INTEGER,
    description TEXT,
    groups_json TEXT,
    alert_type  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    source_ip   TEXT,
    agent_id    TEXT,
    agent_name  TEXT,
    iocs_json   TEXT,
    raw_json    TEXT,
    status      TEXT NOT NULL DEFAULT 'new'
);

CREATE TABLE IF NOT EXISTS threat_intel_cache (
    ioc         TEXT NOT NULL,
    ioc_type    TEXT NOT NULL,
    result_json TEXT NOT NULL,
    fetched_at  TEXT NOT NULL,
    PRIMARY KEY (ioc, ioc_type)
);

CREATE TABLE IF NOT EXISTS playbook_executions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id     INTEGER NOT NULL REFERENCES alerts(id),
    playbook_id  TEXT NOT NULL,
    mode         TEXT NOT NULL,
    status       TEXT NOT NULL,
    triggered_by TEXT NOT NULL,
    approved_by  TEXT,
    created_at   TEXT NOT NULL,
    started_at   TEXT,
    finished_at  TEXT,
    result_json  TEXT
);

CREATE TABLE IF NOT EXISTS playbook_steps (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id INTEGER NOT NULL REFERENCES playbook_executions(id),
    step         TEXT NOT NULL,
    status       TEXT NOT NULL,
    detail       TEXT,
    started_at   TEXT NOT NULL,
    finished_at  TEXT
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip           TEXT PRIMARY KEY,
    reason       TEXT,
    enforced_by  TEXT,
    alert_id     INTEGER,
    blocked_by   TEXT,
    blocked_at   TEXT NOT NULL,
    unblocked_at TEXT,
    active       INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS cases (
    case_id       TEXT PRIMARY KEY,
    alert_id      INTEGER REFERENCES alerts(id),
    title         TEXT NOT NULL,
    severity      TEXT,
    status        TEXT NOT NULL DEFAULT 'open',
    created_at    TEXT NOT NULL,
    evidence_json TEXT
);

CREATE TABLE IF NOT EXISTS agents (
    agent_id  TEXT PRIMARY KEY,
    hostname  TEXT,
    ip        TEXT NOT NULL,
    port      INTEGER NOT NULL,
    admin     INTEGER NOT NULL DEFAULT 0,
    isolated  INTEGER NOT NULL DEFAULT 0,
    dry_run   INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT,
    detail    TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_exec_alert ON playbook_executions(alert_id);
CREATE INDEX IF NOT EXISTS idx_steps_exec ON playbook_steps(execution_id);
"""


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def parse_ts(value):
    """Parse an ISO or Wazuh timestamp (e.g. 2024-05-01T10:15:02.123+0000) to an aware datetime."""
    if not value:
        return None
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        parsed = None
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        if parsed is None:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@contextmanager
def get_db():
    """Open a connection, commit on success, roll back on error, always close."""
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    Path(config.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with get_db() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)


def audit(actor, action, target="", detail=""):
    """Write one entry to audit_logs. Every security-relevant action calls this."""
    if not isinstance(detail, str):
        detail = json.dumps(detail, default=str)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO audit_logs (timestamp, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
            (utcnow(), actor or "system", action, str(target or ""), detail),
        )


def row_to_dict(row):
    """Convert a Row to a dict, decoding *_json columns into their base names."""
    if row is None:
        return None
    out = {}
    for key in row.keys():
        value = row[key]
        if key.endswith("_json"):
            try:
                out[key[:-5]] = json.loads(value) if value else None
            except ValueError:
                out[key[:-5]] = None
        else:
            out[key] = value
    return out


def rows_to_dicts(rows):
    return [row_to_dict(r) for r in rows]
