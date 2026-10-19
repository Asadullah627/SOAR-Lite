# SOAR Lite endpoint agent

The agent runs on the Windows endpoint. The backend calls it to contain threats:

| Route | Purpose |
|---|---|
| `GET /agent/status` | Health, admin rights, isolation state |
| `POST /block-ip` `{"ip": "..."}` | Adds `SOAR_BLOCK_<ip>_IN` and `_OUT` block rules (netsh) |
| `POST /unblock-ip` `{"ip": "..."}` | Removes those rules |
| `POST /isolate` `{"backend_ip": "..."}` | Blocks every remote address except the backend (rules `SOAR_ISOLATE_IN/OUT`) |
| `POST /release` | Removes the isolation rules |
| `POST /collect-evidence` `{"case_id": "ALERT-1"}` | Processes, connections, system info, Security/System event logs, SHA-256 manifest |
| `POST /verify-evidence` `{"case_id": "ALERT-1"}` | Re-hashes the package: reports modified, missing, added and tampered-manifest files |
| `GET /agent/commands` | Dry-run only: the commands that would have run |

Every route needs the `X-Agent-Token` header, which is compared in constant time. The agent will not
start without `AGENT_TOKEN`. It refuses to block loopback, multicast, link-local, its own addresses,
the backend, the gateway and anything in `SOAR_SAFELIST`. It also refuses to isolate the host when no
backend address is known, because the host could not be released afterwards.

## Install (Windows 10/11)

1. Install Python 3.9 or newer from python.org and tick **Add Python to PATH**.
2. Copy the whole `soar-lite` folder to the endpoint, for example `C:\SOAR-Agent\`.
3. Open an **Administrator** PowerShell:

   ```powershell
   cd C:\SOAR-Agent
   python -m pip install -r requirements.txt

   $env:AGENT_TOKEN      = "PASTE-THE-SAME-TOKEN-AS-THE-BACKEND"
   $env:SOAR_BACKEND_URL = "http://10.0.0.10:8000"
   $env:SOAR_BACKEND_IP  = "10.0.0.10"
   $env:SOAR_GATEWAY_IP  = "10.0.0.1"
   $env:SOAR_AGENT_ID    = "001"          # the Wazuh agent ID of this host
   $env:SOAR_SAFELIST    = "10.0.0.1,10.0.0.10,10.0.0.20"

   netsh advfirewall firewall add rule name="SOAR Agent 5055" dir=in action=allow protocol=TCP localport=5055 remoteip=10.0.0.10
   .\soar_agent\start_agent.bat
   ```

4. From the backend host, check it:

   ```bash
   curl -H "X-Agent-Token: $AGENT_TOKEN" http://10.0.0.30:5055/agent/status
   ```

## Testing on Linux (dry-run)

```bash
SOAR_AGENT_DRY_RUN=1 AGENT_TOKEN=... SOAR_BACKEND_URL=http://127.0.0.1:8000 SOAR_BACKEND_IP=127.0.0.1 \
  python3 -m uvicorn soar_agent.agent:app --port 5056
```

In dry-run mode `netsh` and `wevtutil` are recorded, not executed. Use `GET /agent/commands` to see
them. Never set `SOAR_AGENT_DRY_RUN=0` on a machine you don't intend to change.
