from tests import helpers

import json
import os
import unittest

from common.evidence import MANIFEST_NAME, SIDECAR_NAME, build_manifest, sha256_file, verify_manifest


class EvidenceIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.dir = helpers.fresh_dir("evidence")
        for name, content in (("processes.txt", "pid name\n4 System\n"), ("network_connections.txt", "none\n")):
            with open(os.path.join(self.dir, name), "w", encoding="utf-8") as handle:
                handle.write(content)
        os.makedirs(os.path.join(self.dir, "logs"))
        with open(os.path.join(self.dir, "logs", "Security.evtx"), "wb") as handle:
            handle.write(b"\x00\x01binary")
        self.manifest = build_manifest(self.dir, "ALERT-1")

    def test_untouched_package_verifies(self):
        self.assertEqual(set(self.manifest["files"]), {"processes.txt", "network_connections.txt", "logs/Security.evtx"})
        self.assertEqual(self.manifest["files"]["processes.txt"]["sha256"],
                         sha256_file(os.path.join(self.dir, "processes.txt")))
        self.assertEqual(verify_manifest(self.dir), (True, []))

    def test_modified_file_detected(self):
        with open(os.path.join(self.dir, "processes.txt"), "a", encoding="utf-8") as handle:
            handle.write("tampered\n")
        self.assertEqual(verify_manifest(self.dir), (False, ["processes.txt: modified"]))

    def test_missing_file_detected(self):
        os.remove(os.path.join(self.dir, "logs", "Security.evtx"))
        self.assertEqual(verify_manifest(self.dir), (False, ["logs/Security.evtx: missing"]))

    def test_added_file_detected(self):
        with open(os.path.join(self.dir, "planted.txt"), "w", encoding="utf-8") as handle:
            handle.write("x")
        self.assertEqual(verify_manifest(self.dir), (False, ["planted.txt: added"]))

    def test_tampered_manifest_detected(self):
        # Attacker edits a file AND rewrites its hash in the manifest; the sidecar catches it.
        path = os.path.join(self.dir, "processes.txt")
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("tampered\n")
        manifest_path = os.path.join(self.dir, MANIFEST_NAME)
        with open(manifest_path, encoding="utf-8") as handle:
            manifest = json.load(handle)
        manifest["files"]["processes.txt"]["sha256"] = sha256_file(path)
        with open(manifest_path, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle)
        valid, problems = verify_manifest(self.dir)
        self.assertFalse(valid)
        self.assertEqual(problems, [f"{MANIFEST_NAME}: tampered"])

    def test_missing_manifest_or_sidecar(self):
        os.remove(os.path.join(self.dir, SIDECAR_NAME))
        self.assertEqual(verify_manifest(self.dir), (False, [f"{SIDECAR_NAME}: missing"]))
        os.remove(os.path.join(self.dir, MANIFEST_NAME))
        self.assertEqual(verify_manifest(self.dir), (False, [f"{MANIFEST_NAME}: missing"]))


if __name__ == "__main__":
    unittest.main()
