from tests import helpers

import unittest
from unittest import mock

from backend import config
from backend.services import response


class SafelistTests(unittest.TestCase):
    def setUp(self):
        helpers.fresh_db()

    def test_local_and_special_addresses_protected(self):
        for ip in ("127.0.0.1", "::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "169.254.1.1", "255.255.255.255",
                   "::ffff:127.0.0.1"):
            protected, reason = response.is_protected(ip)
            self.assertTrue(protected, ip)
            self.assertTrue(reason)

    def test_safelist_backend_and_gateway_protected(self):
        self.assertEqual(response.is_protected("10.0.0.20"), (True, "10.0.0.20 is safelisted"))
        self.assertEqual(response.is_protected("10.0.0.10"), (True, "10.0.0.10 is the SOAR backend"))
        self.assertEqual(response.is_protected("10.0.0.1"), (True, "10.0.0.1 is the gateway"))
        with mock.patch.object(config, "SAFELIST", {"192.168.5.5"}):
            self.assertTrue(response.is_protected("192.168.5.5")[0])
        self.assertEqual(response.is_protected("10.0.0.40"), (False, ""))

    def test_invalid_input_is_refused(self):
        for value in ("", None, "10.0.0", "10.0.0.256", "10.0.0.1; rm -rf /", "a" * 300):
            self.assertTrue(response.is_protected(value)[0], value)
            self.assertFalse(response.block_ip(value)["success"])

    def test_refused_block_never_reaches_an_agent_or_the_database(self):
        helpers.register_agent(helpers.ASGIClient(helpers.backend_app.app))
        agent_call = mock.Mock(return_value={"success": True})
        with mock.patch.object(response, "_agent_call", agent_call):
            result = response.block_ip("10.0.0.20")
        self.assertEqual(result["error"], "refused: 10.0.0.20 is safelisted")
        self.assertTrue(result["refused"])
        agent_call.assert_not_called()
        self.assertEqual(response.list_blocked(active_only=False), [])

    def test_isolation_requires_backend_address(self):
        with mock.patch.object(config, "BACKEND_IP", ""):
            with self.assertRaises(response.AgentError):
                response.isolate_host("001")


if __name__ == "__main__":
    unittest.main()
