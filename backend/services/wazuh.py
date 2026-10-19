"""Wazuh alert ingestion.

Wazuh's REST API does not return alerts by default, so SOAR Lite tails the manager's
alerts.json (one JSON object per line). SimulationSource replays a sample file instead.
"""
import asyncio
import json
import logging
import os

from backend import config
from backend.database.db import get_db, utcnow
from backend.services import events, playbook_engine
from backend.services.normalizer import normalize_alert

log = logging.getLogger("soar.wazuh")


def _parse_lines(data):
    alerts = []
    for line in data.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line.decode("utf-8", errors="replace"))
        except ValueError:
            log.warning("skipping malformed alert line (%d bytes)", len(line))
            continue
        if isinstance(obj, dict):
            alerts.append(obj)
    return alerts


class AlertSource:
    """Tail a JSON-lines file. Only complete lines are consumed; rotation and truncation reset the offset."""

    def __init__(self, path, from_start=False):
        self.path = path
        self.from_start = from_start
        self.offset = None
        self.inode = None

    def poll(self):
        try:
            stat = os.stat(self.path)
        except OSError:
            return []
        if self.offset is None:
            self.offset = 0 if self.from_start else stat.st_size
            self.inode = stat.st_ino
        if stat.st_ino != self.inode or stat.st_size < self.offset:
            log.info("%s rotated or truncated; reading from the start", self.path)
            self.offset = 0
            self.inode = stat.st_ino
        if stat.st_size == self.offset:
            return []
        with open(self.path, "rb") as handle:
            handle.seek(self.offset)
            chunk = handle.read(stat.st_size - self.offset)
        end = chunk.rfind(b"\n")
        if end == -1:
            return []  # wait until the current line is complete
        self.offset += end + 1
        return _parse_lines(chunk[: end + 1])


class SimulationSource:
    """Return every alert in the sample file once."""

    def __init__(self, path):
        self.path = path
        self.done = False

    def poll(self):
        if self.done:
            return []
        self.done = True
        try:
            with open(self.path, "rb") as handle:
                return _parse_lines(handle.read())
        except OSError as exc:
            log.error("cannot read simulation file %s: %s", self.path, exc)
            return []


def make_source():
    if config.WAZUH_SIMULATION:
        log.info("simulation mode: replaying %s", config.SIMULATION_FILE)
        return SimulationSource(config.SIMULATION_FILE)
    log.info("tailing %s", config.WAZUH_ALERTS_FILE)
    return AlertSource(config.WAZUH_ALERTS_FILE, from_start=config.WAZUH_READ_FROM_START)


def ingest_alert(raw, auto_run=True):
    """Store one raw alert and run its playbook. Returns the new alert ID, or None for a duplicate."""
    alert = normalize_alert(raw)
    with get_db() as conn:
        cur = conn.execute(
            """INSERT OR IGNORE INTO alerts (wazuh_id, timestamp, received_at, rule_id, rule_level, description,
                   groups_json, alert_type, severity, source_ip, agent_id, agent_name, iocs_json, raw_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (alert["wazuh_id"], alert["timestamp"], utcnow(), alert["rule_id"], alert["rule_level"],
             alert["description"], json.dumps(alert["groups"]), alert["alert_type"], alert["severity"],
             alert["source_ip"], alert["agent_id"], alert["agent_name"], json.dumps(alert["iocs"]),
             json.dumps(raw, default=str)),
        )
        if cur.rowcount == 0:
            return None
        alert_id = cur.lastrowid
    log.info("alert %s: %s (%s) from %s", alert_id, alert["alert_type"], alert["severity"], alert["source_ip"])
    events.publish("alert", {"id": alert_id, "alert_type": alert["alert_type"], "severity": alert["severity"]})

    if auto_run:
        playbook_id = playbook_engine.select_playbook(alert["alert_type"])
        if playbook_id:
            try:
                playbook_engine.run_playbook(alert_id, playbook_id, actor="system")
            except Exception:
                log.exception("playbook %s for alert %s failed", playbook_id, alert_id)
    return alert_id


class WazuhPoller:
    def __init__(self, source, interval):
        self.source = source
        self.interval = max(float(interval), 0.5)
        self._stop = None

    def poll_once(self):
        count = 0
        for raw in self.source.poll():
            try:
                if ingest_alert(raw) is not None:
                    count += 1
            except Exception:
                log.exception("failed to ingest alert")
        return count

    async def run(self):
        self._stop = asyncio.Event()
        while not self._stop.is_set():
            try:
                await asyncio.to_thread(self.poll_once)
            except Exception:
                log.exception("poll failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except asyncio.TimeoutError:
                pass

    def stop(self):
        if self._stop is not None:
            self._stop.set()
