from tests import helpers

import unittest
from unittest import mock

from backend import config
from backend.database.db import get_db
from backend.services import playbook_engine, response, threat_intel
from backend.services.wazuh import AlertSource, ingest_alert


def steps_by_name(execution):
    return {s["step"]: s for s in execution["steps"]}


class PlaybookTests(unittest.TestCase):
    def setUp(self):
        helpers.fresh_db()
        self.alerts = helpers.sample_alerts()  # 0 sqli, 1 xss, 2 brute force, 3 malware, 4 scan, 5 noise

    def ingest(self, index, auto_run=False):
        return ingest_alert(self.alerts[index], auto_run=auto_run)

    def connect_agent(self):
        helpers.register_agent(helpers.ASGIClient(helpers.backend_app.app))
        call = helpers.route_to_agent(helpers.dry_run_agent())
        patcher = mock.patch.object(response, "_agent_call", call)
        patcher.start()
        self.addCleanup(patcher.stop)
        return call

    def test_selection_and_modes(self):
        self.assertEqual(playbook_engine.select_playbook("brute_force"), "PB-002")
        self.assertEqual(playbook_engine.select_playbook("sql_injection"), "PB-003")
        self.assertEqual(playbook_engine.select_playbook("xss_attack"), "PB-004")
        self.assertEqual(playbook_engine.select_playbook("malware"), "PB-005")
        self.assertIsNone(playbook_engine.select_playbook("port_scan"))
        self.assertEqual({pid: pb["mode"] for pid, pb in config.PLAYBOOKS.items()},
                         {"PB-002": "AUTO", "PB-003": "AUTO", "PB-004": "AUTO", "PB-005": "MANUAL"})

    def test_simulation_replay_without_agent(self):
        """Phase 1 check: six alerts, three AUTO runs completed_with_errors, PB-005 awaiting approval."""
        for raw in self.alerts:
            ingest_alert(raw)
        self.assertIsNone(ingest_alert(self.alerts[0]))  # duplicates are ignored
        executions = playbook_engine.list_executions()
        with get_db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 6)
        statuses = sorted((e["playbook_id"], e["status"]) for e in executions)
        self.assertEqual(statuses, [("PB-002", "completed_with_errors"), ("PB-003", "completed_with_errors"),
                                    ("PB-004", "completed_with_errors"), ("PB-005", "awaiting_approval")])
        detail = steps_by_name(playbook_engine.get_execution(
            next(e["id"] for e in executions if e["playbook_id"] == "PB-003")))
        self.assertEqual(detail["enrich"]["status"], "success")
        self.assertEqual(detail["create_case"]["status"], "success")
        self.assertEqual(detail["block_ip"]["status"], "failed")
        self.assertIn("offline", detail["block_ip"]["detail"])
        self.assertEqual(detail["collect_evidence"]["status"], "failed")

    def test_auto_playbook_blocks_through_agent(self):
        call = self.connect_agent()
        alert_id = self.ingest(0)
        execution = playbook_engine.run_playbook(alert_id)
        self.assertEqual(execution["status"], "completed", execution["steps"])
        steps = steps_by_name(execution)
        self.assertIn("agent:001", steps["block_ip"]["detail"])
        self.assertEqual([path for _, path, _ in call.calls], ["/block-ip", "/collect-evidence"])
        self.assertEqual(response.list_blocked()[0]["ip"], "10.0.0.40")
        case = response.get_case(f"ALERT-{alert_id}")
        self.assertIn("processes.txt", case["evidence"]["files"])

    def test_manual_playbook_waits_then_isolates_on_approval(self):
        call = self.connect_agent()
        alert_id = self.ingest(3)
        execution = playbook_engine.run_playbook(alert_id)
        self.assertEqual(execution["status"], "awaiting_approval")
        self.assertEqual(execution["steps"], [])
        self.assertEqual(call.calls, [])
        done = playbook_engine.approve(execution["id"], "analyst")
        self.assertEqual(done["status"], "completed", done["steps"])
        self.assertEqual(done["approved_by"], "analyst")
        self.assertEqual(call.calls[0], ("001", "/isolate", {"backend_ip": "10.0.0.10"}))
        self.assertTrue(response.list_agents()[0]["isolated"])
        with self.assertRaises(ValueError):
            playbook_engine.approve(execution["id"], "analyst")  # cannot run twice

    def test_reject(self):
        execution = playbook_engine.run_playbook(self.ingest(3))
        rejected = playbook_engine.reject(execution["id"], "analyst", "false positive")
        self.assertEqual(rejected["status"], "rejected")
        with self.assertRaises(ValueError):
            playbook_engine.approve(execution["id"], "analyst")
        with get_db() as conn:
            actions = [r[0] for r in conn.execute("SELECT action FROM audit_logs")]
        self.assertIn("playbook_rejected", actions)

    def test_block_decision_table(self):
        self.assertTrue(playbook_engine.should_block("UNKNOWN", "LOW"))   # no intel: fail safe
        self.assertTrue(playbook_engine.should_block("HIGH", "LOW"))
        self.assertTrue(playbook_engine.should_block("MEDIUM", "MEDIUM"))
        self.assertTrue(playbook_engine.should_block("LOW", "HIGH"))      # HIGH alert blocks anyway
        self.assertTrue(playbook_engine.should_block("LOW", "CRITICAL"))
        self.assertFalse(playbook_engine.should_block("LOW", "MEDIUM"))   # clean IP, non-HIGH alert

    def test_clean_reputation_skips_block_on_medium_alert(self):
        call = self.connect_agent()
        alert_id = self.ingest(0)  # SQLi, level 7 => MEDIUM
        clean = {"ioc": "10.0.0.40", "type": "ip", "reputation": "LOW", "sources": {"virustotal": {}}, "errors": {}}
        with mock.patch.object(threat_intel, "enrich_ioc", return_value=clean):
            execution = playbook_engine.run_playbook(alert_id)
        self.assertEqual(steps_by_name(execution)["block_ip"]["status"], "skipped")
        self.assertNotIn("/block-ip", [path for _, path, _ in call.calls])

    def test_intel_exception_never_aborts_playbook(self):
        self.connect_agent()
        alert_id = self.ingest(2)  # brute force, HIGH
        with mock.patch.object(threat_intel, "enrich_ioc", side_effect=RuntimeError("provider exploded")):
            execution = playbook_engine.run_playbook(alert_id)
        steps = steps_by_name(execution)
        self.assertEqual(steps["enrich"]["status"], "success")
        self.assertEqual(steps["block_ip"]["status"], "success")
        self.assertEqual(execution["status"], "completed")

    def test_alert_file_tailing(self):
        path = helpers.fresh_dir("tail") + "/alerts.json"
        source = AlertSource(path, from_start=True)
        self.assertEqual(source.poll(), [])  # file does not exist yet
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('{"id": "1"}\nnot json\n{"id": "2"}\n{"id": "3"')  # last line incomplete
        self.assertEqual([a["id"] for a in source.poll()], ["1", "2"])
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("}\n")
        self.assertEqual([a["id"] for a in source.poll()], ["3"])
        self.assertEqual(source.poll(), [])
        with open(path, "w", encoding="utf-8") as handle:  # rotation / truncation
            handle.write('{"id": "4"}\n')
        self.assertEqual([a["id"] for a in source.poll()], ["4"])


if __name__ == "__main__":
    unittest.main()
