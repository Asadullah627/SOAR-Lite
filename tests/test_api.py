from tests import helpers

import unittest
from unittest import mock

from backend.database.db import get_db
from backend.services import response
from backend.services.wazuh import ingest_alert

app = helpers.backend_app.app


def audit_actions():
    with get_db() as conn:
        return [r[0] for r in conn.execute("SELECT action FROM audit_logs ORDER BY id")]


class ApiTests(unittest.TestCase):
    def setUp(self):
        helpers.fresh_db()
        self.client = helpers.ASGIClient(app)

    def test_protected_routes_require_a_session(self):
        self.assertEqual(self.client.get("/health").status_code, 200)
        for method, path in (("GET", "/alerts"), ("GET", "/metrics"), ("GET", "/audit"), ("POST", "/firewall/block"),
                             ("POST", "/playbooks/run"), ("POST", "/reports/generate"), ("GET", "/agents")):
            res = self.client.request(method, path, json_body={})
            self.assertEqual(res.status_code, 401, path)
            self.assertEqual(res.json()["error"], "authentication required")
        bad = self.client.get("/alerts", headers={"Authorization": "Bearer not-a-real-token"})
        self.assertEqual(bad.status_code, 401)

    def test_login_logout_and_audit(self):
        self.assertEqual(self.client.post("/login", {"username": "admin", "password": "wrong"}).status_code, 401)
        self.assertEqual(self.client.post("/login", {"username": "ghost", "password": "x"}).status_code, 401)
        self.assertEqual(self.client.post("/login", raw_body=b"{not json").status_code, 400)
        headers = helpers.login(self.client)
        self.assertEqual(self.client.get("/alerts", headers=headers).status_code, 200)
        self.assertEqual(self.client.post("/logout", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/alerts", headers=headers).status_code, 401)
        self.assertEqual(audit_actions(), ["login_failed", "login_failed", "login", "logout"])

    def test_manual_block_validation_and_safelist(self):
        headers = helpers.login(self.client)
        res = self.client.post("/firewall/block", {"ip": "10.0.0.20"}, headers=headers)
        self.assertEqual(res.status_code, 422)
        self.assertEqual(res.json()["error"], "refused: 10.0.0.20 is safelisted")
        self.assertEqual(self.client.post("/firewall/block", {"ip": "localhost"}, headers=headers).status_code, 400)
        self.assertEqual(self.client.post("/firewall/block", {"ip": "127.0.0.1"}, headers=headers).status_code, 422)
        self.assertEqual(self.client.post("/firewall/block", {"ip": "10.0.0.99"}, headers=headers).status_code, 502)
        self.assertEqual(self.client.delete("/firewall/unblock/not-an-ip", headers=headers).status_code, 400)
        self.assertIn("manual_block_failed", audit_actions())

    def test_manual_block_and_unblock_through_agent(self):
        headers = helpers.login(self.client)
        helpers.register_agent(self.client)
        with mock.patch.object(response, "_agent_call", helpers.route_to_agent(helpers.dry_run_agent())):
            res = self.client.post("/firewall/block", {"ip": "10.0.0.99"}, headers=headers)
            self.assertEqual(res.status_code, 200, res.content)
            self.assertEqual(res.json()["enforced_by"], ["agent:001"])
            blocked = self.client.get("/firewall/blocked", headers=headers).json()["blocked"]
            self.assertEqual([b["ip"] for b in blocked], ["10.0.0.99"])
            self.assertEqual(self.client.delete("/firewall/unblock/10.0.0.99", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/firewall/blocked", headers=headers).json()["blocked"], [])
        self.assertIn("manual_block", audit_actions())
        self.assertIn("unblock", audit_actions())

    def test_websocket_requires_valid_token(self):
        for path in ("/ws", "/ws?token=", "/ws?token=forged"):
            sent = self.client.websocket(path)
            self.assertEqual(sent[0]["type"], "websocket.close", path)
            self.assertEqual(sent[0]["code"], 1008)
        token = helpers.login(self.client)["Authorization"].split(" ", 1)[1]
        sent = self.client.websocket("/ws?token=" + token)
        self.assertEqual(sent[0]["type"], "websocket.accept")
        self.assertEqual(sent[1]["type"], "websocket.send")
        self.assertIn('"hello"', sent[1]["text"])

    def test_agent_registration_requires_agent_token(self):
        body = {"agent_id": "001", "port": 5055}
        self.assertEqual(self.client.post("/agents/register", body).status_code, 401)
        self.assertEqual(self.client.post("/agents/register", body, headers={"X-Agent-Token": "wrong"}).status_code, 401)
        bad_id = self.client.post("/agents/register", {"agent_id": "../x", "port": 5055}, headers=helpers.AGENT_HEADERS)
        self.assertEqual(bad_id.status_code, 400)
        helpers.register_agent(self.client)
        agents = self.client.get("/agents", headers=helpers.login(self.client)).json()["agents"]
        self.assertEqual([(a["agent_id"], a["ip"], a["status"]) for a in agents], [("001", "127.0.0.1", "Online")])

    def test_playbook_api_invalid_input_and_approval(self):
        headers = helpers.login(self.client)
        alerts = helpers.sample_alerts()
        malware_id = ingest_alert(alerts[3], auto_run=False)
        scan_id = ingest_alert(alerts[4], auto_run=False)
        self.assertEqual(self.client.post("/playbooks/run", {"alert_id": "abc"}, headers=headers).status_code, 400)
        self.assertEqual(self.client.post("/playbooks/run", {"alert_id": 9999}, headers=headers).status_code, 404)
        self.assertEqual(self.client.post("/playbooks/run", {"alert_id": scan_id}, headers=headers).status_code, 400)
        self.assertEqual(self.client.post("/playbooks/run", {"alert_id": malware_id, "playbook_id": "PB-999"},
                                          headers=headers).status_code, 400)
        run = self.client.post("/playbooks/run", {"alert_id": malware_id}, headers=headers).json()
        self.assertEqual(run["status"], "awaiting_approval")
        approved = self.client.post(f"/playbooks/executions/{run['id']}/approve", headers=headers)
        self.assertEqual(approved.status_code, 200)
        self.assertEqual(approved.json()["status"], "completed_with_errors")  # no agent online
        again = self.client.post(f"/playbooks/executions/{run['id']}/approve", headers=headers)
        self.assertEqual(again.status_code, 409)
        self.assertIn("playbook_approved", audit_actions())

    def test_case_path_traversal_rejected(self):
        headers = helpers.login(self.client)
        for case_id in ("..%2F..%2Fwindows", "ALERT-1%00", "a" * 65):
            res = self.client.post(f"/cases/{case_id}/verify", headers=headers)
            self.assertEqual(res.status_code, 400, case_id)

    def test_metrics_and_report(self):
        headers = helpers.login(self.client)
        for raw in helpers.sample_alerts():
            ingest_alert(raw)
        metrics = self.client.get("/metrics", headers=headers).json()
        self.assertEqual(metrics["total_alerts"], 6)
        self.assertEqual(metrics["automated_executions"], 3)
        self.assertEqual(metrics["block_success_rate"], 0.0)
        report = self.client.post("/reports/generate", headers=headers).json()
        self.assertEqual(len(report["alerts"]), 6)
        self.assertEqual(len(report["executions"]), 4)
        self.assertNotIn("raw", report["alerts"][0])
        self.assertEqual(self.client.get("/", headers={}).status_code, 200)


if __name__ == "__main__":
    unittest.main()
