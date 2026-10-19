from tests import helpers  # noqa: F401  (sets the test environment first)

import unittest

from backend.services.normalizer import (classify, extract_iocs, extract_source_ip, normalize_alert,
                                         severity_from_level)


def web_alert(url, rule_id="31100", groups=("web", "accesslog"), description="Web request", level=5):
    return {
        "rule": {"id": rule_id, "level": level, "description": description, "groups": list(groups)},
        "agent": {"id": "001", "name": "WIN", "ip": "10.0.0.30"},
        "data": {"srcip": "10.0.0.40", "url": url},
        "full_log": f'10.0.0.40 - - "GET {url} HTTP/1.1" 200',
    }


class ClassificationTests(unittest.TestCase):
    def test_sql_injection_from_payload_and_group(self):
        self.assertEqual(classify(web_alert("/sqli/?id=1%27+OR+1%3D1+--")), "sql_injection")
        self.assertEqual(classify(web_alert("/p?q=1 UNION SELECT user,password FROM users")), "sql_injection")
        self.assertEqual(classify(web_alert("/x", groups=("web", "sql_injection"))), "sql_injection")

    def test_xss_from_encoded_payload(self):
        self.assertEqual(classify(web_alert("/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E")), "xss_attack")
        self.assertEqual(classify(web_alert("/p?x=<img src=x onerror=alert(1)>")), "xss_attack")

    def test_brute_force(self):
        alert = {"rule": {"id": "60204", "level": 10, "description": "Multiple Windows Logon Failures",
                          "groups": ["windows", "authentication_failures"]},
                 "data": {"win": {"eventdata": {"ipAddress": "10.0.0.40"}}}}
        self.assertEqual(classify(alert), "brute_force")
        ssh = {"rule": {"id": "5712", "level": 10, "description": "sshd: brute force trying to get access",
                        "groups": ["sshd"]}}
        self.assertEqual(classify(ssh), "brute_force")

    def test_malware(self):
        alert = {"rule": {"id": "87105", "level": 12, "groups": ["virustotal"],
                          "description": "VirusTotal: Alert - c:\\x.exe - 62 engines detected this file"}}
        self.assertEqual(classify(alert), "malware")
        self.assertEqual(classify({"rule": {"description": "EICAR test file found", "groups": []}}), "malware")

    def test_scan_and_benign_traffic(self):
        scan = {"rule": {"id": "100210", "level": 6, "description": "Network port scan detected", "groups": ["recon"]}}
        self.assertEqual(classify(scan), "port_scan")
        self.assertEqual(classify(web_alert("/dvwa/index.php?page=about")), "unknown")
        self.assertEqual(classify({}), "unknown")


class ExtractionTests(unittest.TestCase):
    def test_source_ip_paths_and_validation(self):
        self.assertEqual(extract_source_ip({"data": {"srcip": "10.0.0.40"}}), "10.0.0.40")
        self.assertEqual(extract_source_ip({"data": {"win": {"eventdata": {"ipAddress": "::ffff:10.0.0.41"}}}}),
                         "10.0.0.41")
        self.assertIsNone(extract_source_ip({"data": {"srcip": "-"}}))
        self.assertIsNone(extract_source_ip({"data": {"srcip": "999.1.1.1"}}))
        self.assertIsNone(extract_source_ip({}))

    def test_iocs_ips_urls_hashes(self):
        sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        alert = {
            "agent": {"ip": "10.0.0.30"},
            "data": {"srcip": "10.0.0.40", "note": "callback to 203.0.113.9 and 203.0.113.9 and 300.1.1.1",
                     "link": "see https://evil.example/payload.exe).", "md5": "44D88612FEA8A8F36DE82E1278ABB02F"},
            "full_log": f"victim 10.0.0.30 file {sha256}",
        }
        iocs = extract_iocs(alert)
        self.assertEqual(iocs["ips"], ["10.0.0.40", "203.0.113.9"])  # agent IP and invalid IP excluded
        self.assertEqual(iocs["urls"], ["https://evil.example/payload.exe"])
        self.assertEqual(sorted(iocs["hashes"]), sorted(["44d88612fea8a8f36de82e1278abb02f", sha256]))


class NormalizeTests(unittest.TestCase):
    def test_normalized_fields_and_severity(self):
        raw = helpers.sample_alerts()[0]
        alert = normalize_alert(raw)
        self.assertEqual(alert["wazuh_id"], raw["id"])
        self.assertEqual(alert["alert_type"], "sql_injection")
        self.assertEqual(alert["severity"], "MEDIUM")
        self.assertEqual(alert["source_ip"], "10.0.0.40")
        self.assertEqual(alert["agent_id"], "001")
        self.assertEqual([severity_from_level(x) for x in (0, 5, 8, 12, "bad")],
                         ["LOW", "MEDIUM", "HIGH", "CRITICAL", "LOW"])

    def test_stable_id_when_wazuh_id_missing(self):
        raw = {"rule": {"id": "1", "level": 3, "description": "x"}, "data": {"srcip": "10.0.0.40"}}
        self.assertEqual(normalize_alert(raw)["wazuh_id"], normalize_alert(dict(raw))["wazuh_id"])
        self.assertTrue(normalize_alert(raw)["wazuh_id"].startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
