# SOAR Lite

SOAR Lite is a lightweight, open-source Security Orchestration, Automation and Response platform,
built as the artifact for a final-year BS Computer Science project (Design Science Research). It
connects Wazuh SIEM alerts to automated response:

1. **Ingest** Wazuh alerts by tailing `alerts.json`, or by replaying sample alerts in simulation mode.
2. **Normalize** each alert, classify it (`sql_injection`, `xss_attack`, `brute_force`, `malware`,
   `port_scan`, `unknown`) and extract indicators (IPs, URLs, hashes).
3. **Enrich** the indicators with VirusTotal, AbuseIPDB and AlienVault OTX, with a 24-hour cache.
4. **Run a playbook**: automatically (PB-002/003/004), or after analyst approval (PB-005, malware).
5. **Contain** the threat through the Windows endpoint agent (Windows Defender Firewall block or host
   isolation), with pfSense as an optional fallback.
6. **Collect evidence** (processes, connections, event logs), hash every file with SHA-256, and write a
   manifest that can be re-verified to detect tampering.
7. **Audit and report**: every action is logged, reports export as JSON, and a live dashboard shows it all.

It is meant as an affordable alternative to commercial SOAR tools for universities and small organizations.

```
 Wazuh manager ──alerts.json──► SOAR Lite backend ──HTTP + X-Agent-Token──► Windows agent (5055)
                                  │   ▲                                         │
              threat intel APIs ◄─┘   └── dashboard (HTTP + WebSocket) ◄── analyst  netsh / psutil / wevtutil
```

## Quick start (simulation, one machine)

```bash
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export SOAR_ADMIN_PASSWORD='choose-one'
export AGENT_TOKEN="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
export WAZUH_SIMULATION=1

python3 -m uvicorn backend.app:app --port 8000          # open http://localhost:8000
python3 -m unittest discover -s tests -t . -v           # run the tests
```

On Windows PowerShell, set variables with `$env:SOAR_ADMIN_PASSWORD = 'choose-one'` and use `python` instead of `python3`.

Within one poll interval the dashboard shows six alerts. Three AUTO playbooks end as
`completed_with_errors`, because no agent is connected yet and the block and evidence steps fail.
The malware playbook (PB-005) waits in `awaiting_approval`.

To test with an agent on the same machine (dry-run: commands are recorded, not executed):

```bash
SOAR_AGENT_DRY_RUN=1 SOAR_AGENT_ID=001 SOAR_BACKEND_URL=http://127.0.0.1:8000 SOAR_BACKEND_IP=127.0.0.1 \
  AGENT_TOKEN=$AGENT_TOKEN AGENT_PORT=5056 python3 -m uvicorn soar_agent.agent:app --port 5056
```

For the full lab (Wazuh, Windows endpoint, Kali, DVWA) follow
[docs/IMPLEMENTATION_GUIDE.md](docs/IMPLEMENTATION_GUIDE.md).

## Layout

| Path | Contents |
|---|---|
| `backend/app.py` | Starlette app: REST routes, WebSocket, startup (lifespan) |
| `backend/config.py` | Settings from environment variables, `PLAYBOOKS`, `SAFELIST` |
| `backend/database/db.py` | SQLite schema, `get_db()`, `audit()` |
| `backend/services/wazuh.py` | `AlertSource` (tails alerts.json), `SimulationSource`, `WazuhPoller`, `ingest_alert()` |
| `backend/services/normalizer.py` | `normalize_alert()`, `extract_source_ip()`, `extract_iocs()`, `classify()` |
| `backend/services/threat_intel.py` | VirusTotal / AbuseIPDB / OTX clients, cache, `enrich_ioc()` |
| `backend/services/playbook_engine.py` | `run_playbook()`, approve/reject, step logging, reputation-aware block |
| `backend/services/response.py` | `block_ip()`, `unblock_ip()`, `isolate_host()`, `collect_evidence()`, `create_case()` |
| `backend/services/events.py` | In-process event bus feeding the dashboard WebSocket |
| `common/evidence.py` | `build_manifest()`, `verify_manifest()`, `sha256_file()` (shared) |
| `soar_agent/agent.py` | Windows endpoint agent (port 5055) — see [soar_agent/README.md](soar_agent/README.md) |
| `dashboard/index.html` | Single-page dashboard, no build step |
| `simulation/sample_alerts.jsonl` | Six sample Wazuh alerts: SQLi, XSS, brute force, malware, scan, benign |
| `tests/` | `unittest` suite; `helpers.py` has an in-process ASGI client |

## Playbooks

| ID | Alert type | Mode | Steps |
|---|---|---|---|
| PB-002 | brute_force | AUTO | enrich → create_case → block_ip → collect_evidence |
| PB-003 | sql_injection | AUTO | enrich → create_case → block_ip → collect_evidence |
| PB-004 | xss_attack | AUTO | enrich → create_case → block_ip → collect_evidence |
| PB-005 | malware | MANUAL | enrich → create_case → isolate_host → collect_evidence |

Port scans and unknown alerts are recorded but trigger no playbook.

**Block decision (fail safe).** When no threat intelligence is available (reputation `UNKNOWN`), the IP is
blocked. When every provider that answered says the IP is clean (`LOW`) and the alert is not HIGH or
CRITICAL, the block step is skipped. An external API failure never aborts a playbook. Private lab
addresses are never sent to public providers, so in the lab they are `UNKNOWN` and get blocked.

## Safety and security

- **Safelist (NFR-14).** Loopback, unspecified, multicast, link-local, broadcast, the backend
  (`SOAR_BACKEND_IP`), the gateway (`SOAR_GATEWAY_IP`) and every `SOAR_SAFELIST` address are refused, in
  `response.block_ip()` and again in the agent's `is_protected()`. The agent also refuses its own addresses.
- **Isolation** blocks every remote address except the backend, so the agent stays reachable and can
  be released. Isolation is refused when no backend address is configured.
- **Authentication (FR-01, NFR-04).** Dashboard and REST routes need `Authorization: Bearer <token>` from
  `POST /login`. The WebSocket takes the token as `/ws?token=`. Passwords use PBKDF2-SHA256, and session
  tokens are stored only as SHA-256 hashes. Agent routes need `X-Agent-Token`, compared with
  `hmac.compare_digest`, and the agent will not start without `AGENT_TOKEN`.
- **No secrets in source.** Every secret comes from environment variables (see `.env.example`).
- **No shell.** Subprocesses run as argument lists. IPs are validated with `ipaddress`, and case IDs
  must match `^[A-Za-z0-9_-]{1,64}$` and resolve inside the evidence directory.
- **Integrity (NFR-05).** Evidence files are hashed with SHA-256 into `evidence_manifest.json`, and the
  manifest itself is hashed into `evidence_manifest.json.sha256`. Verification reports modified, missing,
  added and tampered-manifest files. An existing evidence package is never overwritten.
- **Audit.** Logins, failed logins, manual blocks, unblocks, isolations, playbook runs, approvals,
  rejections, evidence actions, threat-intel checks and reports are written to `audit_logs`.
- **Dashboard XSS.** Alerts carry attacker payloads, so the dashboard renders all server data with
  `textContent`, never `innerHTML`.

## API summary

All routes except `/`, `/health`, `/login` and `/agents/register` (agent token) need a bearer token.

| Method | Path | Purpose |
|---|---|---|
| POST | `/login`, `/logout` | Start or end a session |
| GET | `/alerts`, `/alerts/{id}` | List alerts (`?type=`, `?limit=`); alert detail with raw JSON and executions |
| GET | `/playbooks` | Playbook definitions |
| POST | `/playbooks/run` | `{"alert_id": 1, "playbook_id": "PB-003"}` (playbook optional) |
| GET | `/playbooks/executions`, `/playbooks/executions/{id}` | Executions, with steps |
| POST | `/playbooks/executions/{id}/approve` · `/reject` | Approve or reject a MANUAL run |
| POST | `/firewall/block` | `{"ip": "10.0.0.99"}`; 422 if protected |
| DELETE | `/firewall/unblock/{ip}` | Remove a block |
| GET | `/firewall/blocked` | Active blocks (`?all=1` for history) |
| POST | `/threat-intel/check` | `{"ioc": "8.8.8.8", "type": "ip"}` (`ip`, `url`, `hash`) |
| GET | `/agents` | Registered agents with Online/Offline status |
| POST | `/agents/register` | Agent heartbeat (`X-Agent-Token`) |
| POST | `/agents/{id}/isolate` · `/release` | Isolate or release a host |
| GET | `/cases` | Cases (`ALERT-<id>`) with evidence summary |
| POST | `/cases/{id}/collect-evidence` · `/verify` | Collect, or verify the integrity of, a case's evidence |
| GET | `/metrics` | Counts, average response times, block success rate |
| POST | `/reports/generate` | Full JSON report |
| GET | `/audit` | Audit log |
| WS | `/ws?token=` | Live events: alert, playbook, ip_blocked, host_isolated, … |

## Deviations from the report

| Report says | Implementation does | Why |
|---|---|---|
| FastAPI | Starlette (FastAPI's underlying framework) | Fewer dependencies; routes and responses map one to one |
| SQLAlchemy | sqlite3 with explicit SQL | Standard library; fewer dependencies |
| httpx | urllib | Standard library |
| Poll the Wazuh API for alerts | Tail Wazuh's `alerts.json` | Wazuh's REST API does not return alerts by default |
| Hard-coded agent token | `AGENT_TOKEN` environment variable | NFR-04 |
| pfSense connector | Generic alias-entry call, untested | No pfSense available |

`websockets` is listed in `requirements.txt` because uvicorn needs it to serve the dashboard's `/ws`.

## Status and limitations

**Covered by automated tests:** normalization, classification, IOC extraction, evidence tamper detection
(modified, missing, added, tampered manifest), playbook selection, execution, approval and rejection,
reputation-aware blocking, threat-intel cache and degradation, safelist, API and WebSocket
authentication, agent authentication, agent firewall commands (dry-run), isolation ranges, path
traversal, and invalid input. Backend-to-agent containment is tested end to end in-process, with the
agent in dry-run mode.

**Not verified:**
- Real Windows Defender Firewall changes and `wevtutil` export (only dry-run is tested).
- A live Wazuh manager, and live threat-intel responses.
- The pfSense fallback against a real pfSense API (and pfSense unblock is not implemented).
- The dashboard in a real browser.

**Not implemented (future work):** USB ejection, MITRE ATT&CK mapping, Linux/macOS agents, ML-based
playbook selection, multi-tenancy, PostgreSQL, and roles beyond a single admin.
#   S O A R - L i t e  
 #   S O A R - L i t e  
 #   S O A R - L i t e  
 