# SOAR Lite: Implementation Guide

This guide takes you from an empty lab to a working, tested, and evaluated SOAR Lite
deployment. It follows the methodology in the FYP report: Design Science Research with
Agile-style incremental delivery. Each phase ends with a check you can run, so you know
it works before you move on.

**Contents**

0. Overview and architecture
1. Prerequisites
2. Phase 1: Run the platform on one machine (simulation)
3. Phase 2: Build the virtual lab
4. Phase 3: Install and configure Wazuh
5. Phase 4: Connect the backend to Wazuh
6. Phase 5: Install the Windows endpoint agent
7. Phase 6: Configure threat intelligence
8. Phase 7: Configure the safelist and perimeter fallback
9. Phase 8: Attack simulation and evaluation
10. Phase 9: Hardening before submission
11. Troubleshooting
12. Appendix A: Environment variable reference
13. Appendix B: API quick reference
14. Appendix C: Checklist

---

## 0. Overview and architecture

```
 Kali (attacker) ──attack──► Windows endpoint (Wazuh agent + SOAR agent)
                                    │ logs
                                    ▼
                           Wazuh Manager ──writes──► alerts.json
                                                          │ tail
                                                          ▼
                 Analyst browser ◄──WS/HTTP── SOAR Lite backend ──HTTP──► SOAR agent (port 5055)
                                                          │                  │
                                                          ▼                  ▼
                                               threat intel APIs     netsh firewall / psutil evidence
                                                                              (optional) pfSense
```

**Pipeline.** Wazuh raises an alert. The backend reads it and normalizes it, extracts the
indicators (IPs, URLs, hashes), and enriches them with threat intelligence. It then runs the
matching playbook. Containment goes to the Windows agent, which blocks the IP or isolates the
host. Evidence is collected and hashed, and the dashboard updates live.

**Components**

| Component | Where it runs | Code |
|---|---|---|
| Backend (API, poller, playbooks) | Host machine or Wazuh VM | `backend/` |
| Wazuh manager and agent | Wazuh VM and endpoint VM | third-party install |
| Endpoint agent (containment) | Windows endpoint VM | `soar_agent/` |
| Dashboard | Browser, served by the backend | `dashboard/` |
| Shared evidence logic | Both | `common/` |

---

## 1. Prerequisites

### 1.1 Hardware (from the report)

| Machine | Minimum | Recommended |
|---|---|---|
| Host / backend | Core i5, 8 GB RAM, 20 GB free | Core i7, 16 GB RAM, 50 GB |
| Wazuh server VM | 2 vCPU, 4 GB RAM | 4 vCPU, 8 GB RAM |
| Windows endpoint VM | 4 GB RAM | 8 GB RAM |
| Kali attacker VM | 2 GB RAM | 4 GB RAM |

### 1.2 Software

- **Virtualization:** VirtualBox or VMware Workstation.
- **ISOs:** Ubuntu Server 22.04 or 24.04 (Wazuh manager), Windows 10 or 11 (endpoint), Kali Linux (attacker).
- **Target app:** DVWA (Damn Vulnerable Web Application), or a similar intentionally vulnerable app. Run it on the Windows VM or a separate Linux VM.
- **Python 3.9 or newer** on the host and the Windows VM.
- **Git** (optional, for version control).

### 1.3 Accounts

- Free API keys from VirusTotal, AbuseIPDB, and AlienVault OTX (Phase 6).

### 1.4 Networking

Use a single host-only or internal network for all VMs. Set static addresses, for example:

| Role | Address |
|---|---|
| Host (SOAR backend) | 10.0.0.10 |
| Wazuh manager | 10.0.0.20 |
| Windows endpoint | 10.0.0.30 |
| Kali attacker | 10.0.0.40 |

Use `10.0.0.1` for the gateway if you have one. Confirm that every VM can ping every other VM
before you continue.

---

## 2. Phase 1: Run the platform on one machine (simulation)

**Goal:** prove the backend works before any other component is involved.

### 2.1 Install

```bash
cd soar-lite
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2.2 Configure

Create a file named `env.sh` in the project root, or set these variables in your shell:

```bash
export SOAR_ADMIN_USER=admin
export SOAR_ADMIN_PASSWORD='ChooseAStrongPassword!'   # required on first start
export AGENT_TOKEN="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
export WAZUH_SIMULATION=1                              # replays simulation/sample_alerts.jsonl
export POLL_INTERVAL_SECONDS=5
export SOAR_SAFELIST="10.0.0.1,10.0.0.10,10.0.0.20"    # never block these
export SOAR_BACKEND_IP=10.0.0.10
export SOAR_GATEWAY_IP=10.0.0.1
```

Load it with `source env.sh`. Save the `AGENT_TOKEN` value: the agent needs the same token later.

### 2.3 Start the backend

```bash
python3 -m uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

On first start the backend creates `backend/soar_lite.db`. If you did not set
`SOAR_ADMIN_PASSWORD`, it prints a one-time password in the log.

### 2.4 Verify

1. Open `http://localhost:8000` and sign in.
2. Within about 10 seconds, the Alerts tab should show six alerts.
3. Open the Playbooks tab. Three AUTO executions should appear as `completed_with_errors`.
   This is expected: there is no agent yet, so the block and evidence steps fail. Case
   creation and enrichment should succeed.
4. The MANUAL malware playbook (PB-005) should show `awaiting_approval`.

### 2.5 Run the automated tests

```bash
python3 -m unittest discover -s tests -t . -v
```

Expected result: `Ran 49 tests ... OK`. Do not continue if any test fails.

**Phase 1 done when:** the dashboard shows alerts, the tests pass, and no traceback appears in the log.

---

## 3. Phase 2: Build the virtual lab

**Goal:** a network with an attacker, a vulnerable target, a SIEM, and a backend.

### 3.1 Create the VMs

1. **Wazuh manager:** Ubuntu Server, 4 GB RAM, 2 vCPU, 30 GB disk. Set the address to 10.0.0.20.
2. **Windows endpoint:** Windows 10 or 11, 4 GB RAM (8 GB recommended), 40 GB disk. Set the address to 10.0.0.30.
3. **Kali:** the official Kali VM image, 4 GB RAM. Set the address to 10.0.0.40.
4. **Target web app:** install DVWA on the Windows endpoint (XAMPP or WAMP, then copy DVWA into the web root). Alternatively, run DVWA in Docker on a separate Ubuntu VM.

### 3.2 Use one network for all VMs

In VirtualBox, set each VM's adapter to **Host-only** or **Internal Network** with the same name.
Do not use NAT for the lab traffic, or the VMs won't reach each other.

### 3.3 Verify

From Kali:

```bash
ping -c 3 10.0.0.30
curl http://10.0.0.30/dvwa/login.php   # should return the DVWA login page
```

**Phase 2 done when:** the DVWA login page loads from Kali.

---

## 4. Phase 3: Install and configure Wazuh

**Goal:** Wazuh collects Windows logs and web logs, then writes alerts to `alerts.json`.

### 4.1 Install the Wazuh manager (Ubuntu VM, 10.0.0.20)

Follow the official quickstart for your Wazuh version. The all-in-one installer is the simplest:

```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Save the admin password it prints. Check that the services are running:

```bash
sudo systemctl status wazuh-manager
```

Confirm that the alerts file exists. It may be empty at first:

```bash
ls -l /var/ossec/logs/alerts/alerts.json
```

### 4.2 Install the Wazuh agent on Windows (10.0.0.30)

1. Open an Administrator PowerShell and download the Windows agent MSI from the Wazuh
   documentation, or use the deployment command shown in the Wazuh dashboard.
2. Install it and set the manager address to `10.0.0.20`.
3. Start the service:

```powershell
NET START WazuhSvc
```

### 4.3 Enable Windows event and Sysmon logging

Wazuh needs these logs to detect Windows events. In the Windows agent config file
(`C:\Program Files (x86)\ossec-agent\ossec.conf`), make sure these entries exist inside `<ossec_config>`:

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>System</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the agent after editing: `Restart-Service WazuhSvc`.

### 4.4 Collect the DVWA web logs

On the Windows endpoint, DVWA's Apache log (for XAMPP:
`C:\xampp\apache\logs\access.log`) should be monitored. Add it to `ossec.conf`:

```xml
<localfile>
  <log_format>apache</log_format>
  <location>C:\xampp\apache\logs\access.log</location>
</localfile>
```

Restart the agent. If the Wazuh manager is on Linux, its default rules already include Apache
rules for SQL injection and XSS detection. Otherwise, add the rules in Section 4.6.

### 4.5 Verify that alerts reach the manager

From Kali, send an attack:

```bash
curl "http://10.0.0.30/dvwa/vulnerabilities/sqli/?id=1' OR 1=1 --&Submit=Submit"
```

On the Wazuh manager:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

Look for a JSON object containing `"rule"` and `"agent"`. If nothing appears, see
Troubleshooting (Section 11).

### 4.6 Add custom rules if the default ones do not fire

Create `/var/ossec/etc/rules/soar_lite_rules.xml` on the manager:

```xml
<group name="web,attack,">
  <rule id="100201" level="10">
    <if_sid>31103</if_sid>
    <match>OR 1=1|UNION SELECT|sqlmap</match>
    <description>SQL injection attempt detected in web request</description>
    <group>sqli,attack,</group>
  </rule>
  <rule id="100202" level="8">
    <if_sid>31103</if_sid>
    <match>&lt;script&gt;|alert(1)|javascript:</match>
    <description>Cross-site scripting attempt detected</description>
    <group>xss,attack,</group>
  </rule>
</group>
```

Restart the manager: `sudo systemctl restart wazuh-manager`. Repeat the SQLi test. The new
rule ID (100201) should appear in `alerts.json`.

**Phase 3 done when:** a SQL injection from Kali produces a JSON alert in `alerts.json` on the manager.

---

## 5. Phase 4: Connect the backend to Wazuh

**Goal:** the backend reads the real alerts file instead of the simulation.

### 5.1 Choose how the backend gets the file

Pick one option:

- **Option A (simplest):** run the backend on the Wazuh VM. Then it reads `alerts.json` directly.
- **Option B:** run the backend on the host and sync the file. For example, with a cron job on the manager:

  ```bash
  # on the host, pull every 10 seconds
  while true; do scp wazuh@10.0.0.20:/var/ossec/logs/alerts/alerts.json ./wazuh_alerts.json; sleep 10; done
  ```

  Then set `WAZUH_ALERTS_FILE=./wazuh_alerts.json`. Note that `scp` copies the whole file each
  time. The reader only processes new lines, so duplicates are still avoided.

- **Option C:** mount the manager's `/var/ossec/logs/alerts/` directory on the host with `sshfs` or an SMB share.

### 5.2 Set the environment

```bash
export WAZUH_SIMULATION=0
export WAZUH_ALERTS_FILE=/var/ossec/logs/alerts/alerts.json   # or the path from 5.1
```

Restart the backend.

### 5.3 Verify

1. Send another attack from Kali (Section 4.5).
2. The alert should appear in the dashboard within `POLL_INTERVAL_SECONDS`.
3. Check that `source_ip` matches the attacker address `10.0.0.40`.
4. Check that the playbook selected is PB-003 for SQLi.

**Phase 4 done when:** a live attack from Kali appears on the dashboard with the correct type and source IP.

---

## 6. Phase 5: Install the Windows endpoint agent

**Goal:** the backend can block IPs and collect evidence on the endpoint.

### 6.1 Install Python on Windows

Install Python 3.9 or newer from python.org. Tick **Add Python to PATH**.

### 6.2 Copy the project and install dependencies

Copy the `soar-lite` folder to the Windows VM, for example to `C:\SOAR-Agent\`. Then, in an
Administrator PowerShell:

```powershell
cd C:\SOAR-Agent
python -m pip install -r requirements.txt
```

### 6.3 Set the agent environment

In the same Administrator PowerShell:

```powershell
$env:AGENT_TOKEN = "PASTE-THE-SAME-TOKEN-AS-THE-BACKEND"
$env:SOAR_BACKEND_IP = "10.0.0.10"
$env:SOAR_BACKEND_URL = "http://10.0.0.10:8000"
$env:SOAR_SAFELIST = "10.0.0.1,10.0.0.10,10.0.0.20"
$env:SOAR_GATEWAY_IP = "10.0.0.1"
$env:SOAR_AGENT_ID = "001"      # the Wazuh agent ID of this host (see 6.6)
```

Make sure `SOAR_AGENT_DRY_RUN` is **not** set on the real endpoint. Dry-run is only for
testing on Linux.

### 6.4 Start the agent

```powershell
.\soar_agent\start_agent.bat
```

Keep this window open. The agent listens on port 5055 and registers itself with the backend
every 60 seconds.

### 6.5 Allow the agent port through Windows Firewall

The agent must be reachable from the backend:

```powershell
netsh advfirewall firewall add rule name="SOAR Agent 5055" dir=in action=allow protocol=TCP localport=5055
```

### 6.6 Verify the agent

From the host:

```bash
curl -H "X-Agent-Token: $AGENT_TOKEN" http://10.0.0.30:5055/agent/status
```

Expected output includes `"status":"Online"` and `"admin":true`.

Then open the Agents tab in the dashboard. The endpoint should appear as Online. The agent
ID is the Wazuh agent ID, and it must match the `agent.id` in the alerts. Check the ID with
`/var/ossec/bin/agent_control -l` on the manager. If the IDs don't match, containment will
target the wrong host, or none.

### 6.7 Test a single manual block

Pick a test address that is not in the safelist, for example `10.0.0.99`. In the dashboard,
open the Blocked IPs tab, enter `10.0.0.99`, and click **Block IP**. Then check the firewall on
the Windows VM:

```powershell
netsh advfirewall firewall show rule name="SOAR_BLOCK_10.0.0.99_IN"
```

Remove it when you're done:

```powershell
netsh advfirewall firewall delete rule name="SOAR_BLOCK_10.0.0.99_IN"
netsh advfirewall firewall delete rule name="SOAR_BLOCK_10.0.0.99_OUT"
```

Or use **Unblock** in the dashboard.

**Phase 5 done when:** the agent is Online, a manual block creates the firewall rule, and the
backend records it in Blocked IPs.

---

## 7. Phase 6: Configure threat intelligence

**Goal:** alerts are enriched with reputation data, and clean IPs on low-severity alerts are not blocked.

### 7.1 Get API keys

Provider sign-up pages and free-tier quotas change over time. Check each site before you rely on them.

| Provider | Sign-up | Free tier note |
|---|---|---|
| VirusTotal | virustotal.com, then your profile → API key | free tier is rate-limited; check the current quota on the site |
| AbuseIPDB | abuseipdb.com/register | free tier is daily-limited; check the current quota |
| AlienVault OTX | otx.alienvault.com, then Settings → API key | free |

### 7.2 Set the keys on the backend

```bash
export VT_API_KEY=...
export ABUSEIPDB_API_KEY=...
export OTX_API_KEY=...
export TI_CACHE_HOURS=24
```

Restart the backend.

### 7.3 Verify

In the dashboard, open **Threat intel**, enter `8.8.8.8` as type `ip`, and click **Check**.
You should see results from each provider. A missing key appears under `errors`, and
the other providers still return results.

**Note:** Your lab addresses (10.0.0.x) are private, so public providers return little or no
data for them. For a realistic demo, use a known malicious public IP in your attack traffic,
or accept that enrichment will mostly return "unknown" in the lab and explain this in your report.

**Phase 6 done when:** the check returns data from at least one provider.

---

## 8. Phase 7: Safelist and perimeter fallback

**Goal:** the platform can never lock out critical infrastructure, and blocks have a second enforcement point.

### 8.1 Safelist

The safelist must contain every address you must keep reachable: the gateway, the backend, the
Wazuh manager, and your own admin workstation. Set it on the backend and the agent:

```bash
export SOAR_SAFELIST="10.0.0.1,10.0.0.10,10.0.0.20"
```

Loopback addresses (127.0.0.1, ::1) are always protected.

**Test it:** try to block `10.0.0.20` from the dashboard. The response should be 422 with
`refused: ... is safelisted`.

### 8.2 pfSense (optional)

Only do this if you have a pfSense VM. The code calls a generic alias-entry endpoint and has
not been tested against a real pfSense API, so verify it against your pfSense version before
depending on it.

```bash
export PFSENSE_URL=https://10.0.0.1
export PFSENSE_API_KEY=...
```

Create an alias named `SOAR_BLOCKLIST` in pfSense first. The backend uses it only when the
endpoint agent is offline.

**Phase 7 done when:** blocking a safelisted address is refused.

---

## 9. Phase 8: Attack simulation and evaluation

**Goal:** collect the evidence the report needs. Every test needs a before and after measurement.

### 9.1 Test plan

Run each scenario three times, and record the results in a table.

| ID | Attack (from Kali) | Expected alert | Expected playbook | Expected containment |
|---|---|---|---|---|
| S1 | SQLi: `1' OR 1=1 --` | sql_injection | PB-003 | block attacker IP |
| S2 | XSS: `<script>alert(1)</script>` | xss_attack | PB-004 | block attacker IP |
| S3 | Brute force: `hydra -l administrator -P list.txt ...` against the Windows RDP or SMB service | brute_force | PB-002 | block attacker IP |
| S4 | Malware-like event (drop a test EICAR file) | malware | PB-005 (approve) | isolate host |
| S5 | Scan: `nmap -sS 10.0.0.30` | (add a custom rule) | none | record only |
| S6 | Clean noise: normal browsing | low severity | none | no block |

Use the DVWA URLs for S1 and S2. Use `hydra` for S3 only against your own lab VMs.

### 9.2 Metrics to record

| Metric | How to measure | Report section |
|---|---|---|
| Detection-to-response time | `GET /metrics` for automated time. Also note the time between the attack timestamp and the playbook `finished_at` | 7.10 |
| Manual response time (baseline) | Time yourself performing the same block by hand in the dashboard or on the endpoint | 8.2 |
| IP blocking success rate | Blocked attacker IPs ÷ attacks that reached the block step | 7.8 |
| Evidence integrity | Run `POST /verify-evidence` on each case. Then modify one file and verify again | 7.9 |
| Playbook correctness | Compare the expected and actual playbook for each scenario | 7.6 |
| False-positive handling | Confirm S6 produces no block | 7.2 |

### 9.3 Procedure for each run

1. Reset state: `/firewall/unblock/{ip}` for each test IP, and clear the database if you want clean numbers (stop the backend, delete `backend/soar_lite.db`, restart).
2. Note the start time.
3. Run the attack from Kali.
4. Wait for the playbook to finish. Check the Playbooks tab.
5. Note the end time. Export the report with `POST /reports/generate` and save it.
6. Confirm the firewall rule on the endpoint with `netsh advfirewall firewall show rule ...`.

### 9.4 Evidence integrity test

```bash
# On the agent (Windows), after an evidence collection for ALERT-1:
curl -X POST http://10.0.0.30:5055/verify-evidence \
  -H "X-Agent-Token: $AGENT_TOKEN" -H "Content-Type: application/json" \
  -d '{"case_id":"ALERT-1"}'
# Expected: {"valid": true, "problems": []}

# Now modify one file:
echo tampered >> C:\SOAR-Agent\evidence\ALERT-1\processes.txt
# Run the verify call again.
# Expected: {"valid": false, "problems": ["processes.txt: modified"]}
```

### 9.5 Save your results

Keep these artifacts for your appendices:
- The `/reports/generate` JSON for each scenario.
- Screenshots of the dashboard during each attack.
- The `alerts.json` lines for each attack.
- The `evidence_manifest.json` files.
- The results table with at least three runs per scenario.

**Phase 8 done when:** every scenario has three recorded runs and the metrics table is complete.

---

## 10. Phase 9: Hardening before submission

- **Change every default secret.** Use new values for `SOAR_ADMIN_PASSWORD` and `AGENT_TOKEN`. Do not reuse examples from the documentation.
- **Restrict the backend.** Bind to the LAN address only, not `0.0.0.0`, unless you need other machines to reach it. Put it behind a reverse proxy with HTTPS if the dashboard is used from another machine.
- **Restrict the agent.** Allow port 5055 only from `SOAR_BACKEND_IP` in the Windows firewall:
  ```powershell
  netsh advfirewall firewall set rule name="SOAR Agent 5055" new remoteip=10.0.0.10
  ```
- **Back up the database.** Copy `backend/soar_lite.db` after each evaluation run.
- **Review the audit log.** Open `/audit` after a demo to confirm every action was recorded.
- **Remove test blocks.** Unblock every test IP before you finish.
- **Do not commit secrets.** Keep `env.sh` and `.env` out of version control. Add them to `.gitignore`.

---

## 11. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Dashboard shows no alerts | `WAZUH_SIMULATION` still 1, or wrong file path | Set `WAZUH_SIMULATION=0` and check `WAZUH_ALERTS_FILE`. Confirm the file grows when you attack. |
| `alerts.json` stays empty | Wazuh agent not connected, or the log source isn't monitored | `/var/ossec/bin/agent_control -l` on the manager. Check Section 4.3 and 4.4. |
| Alert arrives but type is `unknown` | Payload not in the fields the normalizer checks | Check `data.url` and `data.payload` in the JSON. Add a rule or extend `normalizer.classify`. |
| Block step says "agent offline" | Agent not registered, or heartbeat older than 2 minutes | Check the Agents tab. Confirm `AGENT_TOKEN` matches on both sides and `SOAR_BACKEND_URL` is set on the agent. |
| Block step says "refused: ... safelisted" | Target is in `SOAR_SAFELIST` or is a local address | Expected behavior. Use a different test IP. |
| Agent returns 401 | Token mismatch | Set the same `AGENT_TOKEN` on backend and agent, then restart both. |
| Agent returns 403 | Agent not running as Administrator | Reopen PowerShell as Administrator and run the agent again. |
| `netsh` rule not created | Windows Firewall service disabled | `Get-Service mpssvc` should show Running. Start it if it doesn't. |
| Evidence collection gives "access denied" in `network_connections.txt` | Agent not running as Administrator | Same as above. |
| Dashboard live updates don't appear | WebSocket token missing or expired | Log in again. Sessions last 8 hours by default (`SESSION_TTL_HOURS`). |
| Threat intel returns only errors | Keys missing, or free-tier rate limit reached | Check `errors` in the response. Wait for the limit to reset, or rely on the 24-hour cache. |
| `ModuleNotFoundError: starlette` | Dependencies not installed in the active environment | Activate `.venv` and run `pip install -r requirements.txt`. |
| Playbook stuck in `running` | A step hung on a network call | Each external call times out after `HTTP_TIMEOUT_SECONDS` (default 5). Check the backend log. |

**Logs to check first:** the backend terminal, the agent terminal, and `/var/ossec/logs/ossec.log`
on the manager.

---

## 12. Appendix A: Environment variable reference

**Backend**

| Variable | Default | Purpose |
|---|---|---|
| `SOAR_DB_PATH` | `backend/soar_lite.db` | SQLite file location |
| `SOAR_ADMIN_USER` | `admin` | Initial dashboard user |
| `SOAR_ADMIN_PASSWORD` | (none) | Initial password. Required on first start. |
| `SESSION_TTL_HOURS` | `8` | Login session lifetime |
| `WAZUH_SIMULATION` | `1` | `1` replays sample alerts, `0` reads the real file |
| `WAZUH_ALERTS_FILE` | `/var/ossec/logs/alerts/alerts.json` | Wazuh alert file to tail |
| `WAZUH_READ_FROM_START` | `0` | `1` processes the existing alerts file on start; `0` only reads new alerts |
| `POLL_INTERVAL_SECONDS` | `10` | How often the poller checks for new alerts |
| `VT_API_KEY` | (none) | VirusTotal key |
| `ABUSEIPDB_API_KEY` | (none) | AbuseIPDB key |
| `OTX_API_KEY` | (none) | AlienVault OTX key |
| `TI_CACHE_HOURS` | `24` | Threat intel cache lifetime |
| `HTTP_TIMEOUT_SECONDS` | `5` | Timeout for external calls |
| `AGENT_TOKEN` | (none) | Shared secret with agents. Required. |
| `AGENT_PORT` | `5055` | Default agent port |
| `AGENT_OFFLINE_SECONDS` | `120` | Agents not seen for this long are Offline |
| `SOAR_SAFELIST` | (empty) | Comma-separated addresses never to block |
| `SOAR_BACKEND_IP` | (empty) | Backend address the isolated host must still reach. Isolation is refused without it. |
| `SOAR_GATEWAY_IP` | (empty) | Gateway address, never blocked |
| `PFSENSE_URL` | (empty) | Optional perimeter firewall |
| `PFSENSE_API_KEY` | (empty) | pfSense API key |

**Agent (Windows)**

| Variable | Default | Purpose |
|---|---|---|
| `AGENT_TOKEN` | (none) | Must match the backend. Required. |
| `SOAR_BACKEND_URL` | (empty) | Where to send heartbeats, for example `http://10.0.0.10:8000` |
| `SOAR_BACKEND_IP` | (empty) | Backend address (kept reachable during isolation) |
| `SOAR_AGENT_ID` | hostname | Must match the Wazuh agent ID |
| `SOAR_SAFELIST` | (empty) | Addresses the agent will refuse to block |
| `SOAR_GATEWAY_IP` | (empty) | Gateway address the agent will refuse to block |
| `AGENT_PORT` | `5055` | Port reported to the backend at registration |
| `SOAR_HEARTBEAT_SECONDS` | `60` | How often the agent registers with the backend |
| `SOAR_EVIDENCE_DIR` | `C:\SOAR-Agent\evidence` | Where evidence packages are written |
| `SOAR_AGENT_DRY_RUN` | `0` | `1` records commands without running them (testing only) |

---

## 13. Appendix B: API quick reference

All endpoints except `/login`, `/health`, `/`, and agent registration need
`Authorization: Bearer <token>`. Get the token from `POST /login`.

```bash
TOKEN=$(curl -s -X POST localhost:8000/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"ChooseAStrongPassword!"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
```

| Action | Command |
|---|---|
| List alerts | `curl -H "Authorization: Bearer $TOKEN" localhost:8000/alerts` |
| Alert detail | `curl -H "Authorization: Bearer $TOKEN" localhost:8000/alerts/1` |
| Run playbook | `curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' localhost:8000/playbooks/run -d '{"alert_id":1,"playbook_id":"PB-003"}'` |
| Approve playbook | `curl -X POST -H "Authorization: Bearer $TOKEN" localhost:8000/playbooks/executions/4/approve` |
| Block IP | `curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' localhost:8000/firewall/block -d '{"ip":"10.0.0.99"}'` |
| Unblock IP | `curl -X DELETE -H "Authorization: Bearer $TOKEN" localhost:8000/firewall/unblock/10.0.0.99` |
| Threat intel | `curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' localhost:8000/threat-intel/check -d '{"ioc":"8.8.8.8","type":"ip"}'` |
| Report | `curl -X POST -H "Authorization: Bearer $TOKEN" localhost:8000/reports/generate > report.json` |
| Metrics | `curl -H "Authorization: Bearer $TOKEN" localhost:8000/metrics` |
| Audit log | `curl -H "Authorization: Bearer $TOKEN" localhost:8000/audit` |

---

## 14. Appendix C: Checklist

Tick each item as you complete it.

**Setup**
- [ ] Python 3.9+ installed on host and Windows VM
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] 49 tests pass
- [ ] Secrets generated and saved securely

**Lab**
- [ ] Four VMs on one internal network, all pings succeed
- [ ] DVWA reachable from Kali

**Wazuh**
- [ ] Manager running, `alerts.json` exists
- [ ] Windows agent connected (Active in `agent_control -l`)
- [ ] Windows event and Apache logs monitored
- [ ] SQLi test produces an alert in `alerts.json`

**Backend**
- [ ] Simulation run works (Phase 1)
- [ ] Live alerts reach the dashboard (Phase 4)
- [ ] Threat intel check returns a result (Phase 6)

**Agent**
- [ ] Agent Online on the Agents tab
- [ ] Manual block creates the firewall rule and it can be removed
- [ ] Isolation keeps port 5055 open to the backend (tested in dry-run; test carefully on the real VM)
- [ ] Evidence collected and `verify-evidence` returns valid, then detects tampering

**Safety**
- [ ] Safelisted address refused
- [ ] Localhost refused
- [ ] Test blocks removed at the end

**Evaluation**
- [ ] Each scenario S1–S6 run three times
- [ ] Automated and manual response times recorded
- [ ] Block success rate calculated
- [ ] Evidence integrity tested
- [ ] Reports and screenshots saved

**Submission**
- [ ] Deviations from the report documented (Starlette, file tailing, env-var secrets)
- [ ] Report performance figures replaced with measured values
- [ ] Hardening steps from Section 10 applied
