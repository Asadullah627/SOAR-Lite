"""Evidence integrity (NFR-05), shared by the backend and the endpoint agent.

build_manifest() hashes every file in an evidence directory with SHA-256 and writes
evidence_manifest.json. The manifest itself is hashed into evidence_manifest.json.sha256,
so editing the manifest to hide a change is also detected.

verify_manifest() reports modified, missing and added files, and a tampered or missing manifest.
"""
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path

MANIFEST_NAME = "evidence_manifest.json"
SIDECAR_NAME = MANIFEST_NAME + ".sha256"
_CHUNK = 1024 * 1024


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def _evidence_files(directory):
    """Relative POSIX paths of every evidence file, excluding the manifest and its sidecar."""
    base = Path(directory)
    files = []
    for root, _dirs, names in os.walk(base):
        for name in names:
            rel = (Path(root) / name).relative_to(base).as_posix()
            if rel not in (MANIFEST_NAME, SIDECAR_NAME):
                files.append(rel)
    return sorted(files)


def build_manifest(directory, case_id, extra=None):
    base = Path(directory)
    manifest = {
        "case_id": case_id,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "algorithm": "SHA-256",
        "files": {},
    }
    if extra:
        manifest.update(extra)
    for rel in _evidence_files(base):
        path = base / rel
        manifest["files"][rel] = {"sha256": sha256_file(path), "size": path.stat().st_size}

    manifest_path = base / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    manifest_hash = sha256_file(manifest_path)
    (base / SIDECAR_NAME).write_text(manifest_hash + "\n", encoding="utf-8")
    manifest["manifest_sha256"] = manifest_hash
    return manifest


def verify_manifest(directory):
    """Return (valid, problems). problems is a list like ["processes.txt: modified"]."""
    base = Path(directory)
    manifest_path = base / MANIFEST_NAME
    sidecar_path = base / SIDECAR_NAME
    if not manifest_path.is_file():
        return False, [f"{MANIFEST_NAME}: missing"]

    problems = []
    if not sidecar_path.is_file():
        problems.append(f"{SIDECAR_NAME}: missing")
    else:
        expected = sidecar_path.read_text(encoding="utf-8").strip()
        if not hmac.compare_digest(expected, sha256_file(manifest_path)):
            problems.append(f"{MANIFEST_NAME}: tampered")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        recorded = manifest["files"]
        if not isinstance(recorded, dict):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        return False, problems + [f"{MANIFEST_NAME}: unreadable"]

    present = set(_evidence_files(base))
    for rel in sorted(recorded):
        entry = recorded[rel] or {}
        if rel not in present:
            problems.append(f"{rel}: missing")
        elif sha256_file(base / rel) != entry.get("sha256"):
            problems.append(f"{rel}: modified")
    for rel in sorted(present - set(recorded)):
        problems.append(f"{rel}: added")
    return not problems, problems
