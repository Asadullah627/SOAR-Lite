from tests import helpers

import unittest
from unittest import mock

from backend import config
from backend.database.db import get_db
from backend.services import threat_intel

GLOBAL_IP = "185.220.101.1"  # documentation ranges (TEST-NET) are not "global", so use a public address


def fake_http(responses, calls):
    """Return a stand-in for _http_get_json that answers per provider host."""
    def _get(url, headers):
        calls.append(url)
        for host, value in responses.items():
            if host in url:
                if isinstance(value, Exception):
                    raise value
                return value
        raise AssertionError(f"unexpected URL {url}")
    return _get


ALL_KEYS = {"VT_API_KEY": "vt", "ABUSEIPDB_API_KEY": "ab", "OTX_API_KEY": "otx"}


class ThreatIntelTests(unittest.TestCase):
    def setUp(self):
        helpers.fresh_db()

    def test_no_keys_degrades_to_unknown(self):
        result = threat_intel.enrich_ioc(GLOBAL_IP, "ip")
        self.assertEqual(result["reputation"], "UNKNOWN")
        self.assertEqual(set(result["errors"]), {"virustotal", "abuseipdb", "otx"})
        self.assertEqual(result["sources"], {})

    def test_one_provider_failing_does_not_stop_the_others(self):
        calls = []
        responses = {
            "virustotal": threat_intel.ProviderError("HTTP 429"),
            "abuseipdb": {"data": {"abuseConfidenceScore": 90, "totalReports": 40}},
            "otx": {"pulse_info": {"count": 0}},
        }
        with mock.patch.multiple(config, **ALL_KEYS), \
                mock.patch.object(threat_intel, "_http_get_json", fake_http(responses, calls)):
            result = threat_intel.enrich_ioc(GLOBAL_IP, "ip")
        self.assertEqual(result["errors"], {"virustotal": "HTTP 429"})
        self.assertEqual(result["sources"]["abuseipdb"]["abuse_confidence_score"], 90)
        self.assertEqual(result["reputation"], "HIGH")

    def test_cache_hit_and_expiry(self):
        calls = []
        responses = {"virustotal": {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 80}}}},
                     "abuseipdb": {"data": {"abuseConfidenceScore": 0}}, "otx": {"pulse_info": {"count": 0}}}
        with mock.patch.multiple(config, **ALL_KEYS), \
                mock.patch.object(threat_intel, "_http_get_json", fake_http(responses, calls)):
            first = threat_intel.enrich_ioc(GLOBAL_IP, "ip")
            second = threat_intel.enrich_ioc(GLOBAL_IP, "ip")
            self.assertEqual(len(calls), 3)
            self.assertFalse(first["cached"])
            self.assertTrue(second["cached"])
            self.assertEqual(second["reputation"], "LOW")
            with get_db() as conn:
                conn.execute("UPDATE threat_intel_cache SET fetched_at = '2000-01-01T00:00:00+00:00'")
            threat_intel.enrich_ioc(GLOBAL_IP, "ip")
            self.assertEqual(len(calls), 6)

    def test_reputation_levels(self):
        self.assertEqual(threat_intel.reputation_from({}), "UNKNOWN")
        self.assertEqual(threat_intel.reputation_from({"virustotal": {"malicious": 0}}), "LOW")
        self.assertEqual(threat_intel.reputation_from({"virustotal": {"malicious": 1}}), "MEDIUM")
        self.assertEqual(threat_intel.reputation_from({"otx": {"pulse_count": 2}}), "MEDIUM")
        self.assertEqual(threat_intel.reputation_from({"virustotal": {"malicious": 5}}), "HIGH")

    def test_private_addresses_not_sent_and_invalid_input_rejected(self):
        calls = []
        with mock.patch.multiple(config, **ALL_KEYS), \
                mock.patch.object(threat_intel, "_http_get_json", fake_http({}, calls)):
            result = threat_intel.enrich_ioc("10.0.0.40", "ip")
        self.assertEqual(calls, [])
        self.assertEqual(result["reputation"], "UNKNOWN")
        for ioc, ioc_type in (("not-an-ip", "ip"), ("ftp://x", "url"), ("xyz", "hash"), ("8.8.8.8", "domain")):
            with self.assertRaises(ValueError):
                threat_intel.enrich_ioc(ioc, ioc_type)


if __name__ == "__main__":
    unittest.main()
