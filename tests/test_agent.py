from tests import helpers

import os
import unittest

from soar_agent import agent


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.app = helpers.dry_run_agent()
        self.client = helpers.ASGIClient(self.app)
        self.state = self.app.state.agent

    def post(self, path, body, headers=helpers.AGENT_HEADERS):
        return self.client.post(path, body, headers=headers)

    def test_refuses_to_start_without_token(self):
        with self.assertRaises(RuntimeError):
            agent.create_app({"SOAR_AGENT_DRY_RUN": "1"})
        with self.assertRaises(RuntimeError):
            agent.create_app({"AGENT_TOKEN": "   "})

    def test_every_route_requires_the_agent_token(self):
        for path in ("/block-ip", "/unblock-ip", "/isolate", "/release", "/collect-evidence", "/verify-evidence"):
            self.assertEqual(self.post(path, {"ip": "10.0.0.99"}, headers={}).status_code, 401, path)
            self.assertEqual(self.post(path, {"ip": "10.0.0.99"}, headers={"X-Agent-Token": "wrong"}).status_code, 401)
        self.assertEqual(self.client.get("/agent/status").status_code, 401)
        status = self.client.get("/agent/status", headers=helpers.AGENT_HEADERS).json()
        self.assertEqual((status["status"], status["agent_id"], status["dry_run"]), ("Online", "001", True))
        self.assertEqual(self.state.runner.commands, [])

    def test_block_uses_argument_lists_and_refuses_protected(self):
        res = self.post("/block-ip", {"ip": "10.0.0.99"})
        self.assertEqual(res.status_code, 200, res.content)
        adds = [c for c in self.state.runner.commands if "add" in c]
        self.assertEqual(adds[0], ["netsh", "advfirewall", "firewall", "add", "rule", "name=SOAR_BLOCK_10.0.0.99_IN",
                                   "dir=in", "action=block", "remoteip=10.0.0.99", "enable=yes", "profile=any"])
        self.assertEqual(len(adds), 2)
        before = len(self.state.runner.commands)
        for ip, code in (("10.0.0.10", 422), ("10.0.0.1", 422), ("10.0.0.20", 422), ("127.0.0.1", 422),
                         ("10.0.0.99 & calc", 400), ("", 400)):
            self.assertEqual(self.post("/block-ip", {"ip": ip}).status_code, code, ip)
        self.assertEqual(len(self.state.runner.commands), before)  # nothing ran for refused input

    def test_isolation_keeps_backend_reachable(self):
        ranges = agent.isolation_ranges("10.0.0.10")
        self.assertEqual(ranges[:2], ["0.0.0.0-10.0.0.9", "10.0.0.11-255.255.255.255"])
        self.assertEqual(ranges[2], "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
        self.assertEqual(agent.isolation_ranges("0.0.0.1")[0], "0.0.0.0-0.0.0.0")

        self.assertEqual(self.post("/isolate", {"backend_ip": "10.0.0.66"}).status_code, 400)  # not our backend
        res = self.post("/isolate", {"backend_ip": "10.0.0.10"})
        self.assertEqual(res.status_code, 200, res.content)
        rules = [c for c in self.state.runner.commands if "add" in c]
        self.assertEqual({c[5] for c in rules}, {"name=SOAR_ISOLATE_IN", "name=SOAR_ISOLATE_OUT"})
        for rule in rules:
            self.assertIn("remoteip=0.0.0.0-10.0.0.9,10.0.0.11-255.255.255.255,::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                          rule)
        self.assertTrue(self.client.get("/agent/status", headers=helpers.AGENT_HEADERS).json()["isolated"])
        self.assertEqual(self.post("/release", {}).status_code, 200)
        self.assertFalse(self.state.isolated)

        no_backend = helpers.ASGIClient(helpers.dry_run_agent(SOAR_BACKEND_IP=""))
        self.assertEqual(no_backend.post("/isolate", {}, headers=helpers.AGENT_HEADERS).status_code, 400)

    def test_evidence_collect_verify_and_tamper(self):
        res = self.post("/collect-evidence", {"case_id": "ALERT-1"})
        self.assertEqual(res.status_code, 200, res.content)
        self.assertIn("processes.txt", res.json()["files"])
        self.assertIn(["wevtutil", "epl", "Security", os.path.join(res.json()["path"], "Security.evtx")],
                      self.state.runner.commands)
        self.assertEqual(self.post("/collect-evidence", {"case_id": "ALERT-1"}).status_code, 409)  # no overwrite
        self.assertEqual(self.post("/verify-evidence", {"case_id": "ALERT-1"}).json(),
                         {"case_id": "ALERT-1", "valid": True, "problems": []})
        with open(os.path.join(res.json()["path"], "processes.txt"), "a", encoding="utf-8") as handle:
            handle.write("tampered\n")
        self.assertEqual(self.post("/verify-evidence", {"case_id": "ALERT-1"}).json()["problems"],
                         ["processes.txt: modified"])
        self.assertEqual(self.post("/verify-evidence", {"case_id": "ALERT-2"}).status_code, 404)

    def test_case_id_path_traversal_rejected(self):
        for case_id in ("../outside", "..\\outside", "/etc", "C:\\Windows", "a" * 65, "", None, 7):
            self.assertEqual(self.post("/collect-evidence", {"case_id": case_id}).status_code, 400, case_id)
            self.assertEqual(self.post("/verify-evidence", {"case_id": case_id}).status_code, 400, case_id)
        with self.assertRaises(ValueError):
            agent.safe_case_dir(self.state.settings.evidence_dir, "..")


if __name__ == "__main__":
    unittest.main()
