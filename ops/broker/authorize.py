#!/usr/bin/env python3
"""Create a one-time OpenSSH Ed25519 deployment approval for a VPS challenge.

The private key is read only by the local ssh-keygen process. This program
never exports, uploads, or prints private key material.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

try:  # script execution and package import in tests
    from .guard import APP_COMMIT, APP_TREE, APP_PR, Reject, read_json
except ImportError:  # pragma: no cover - direct script invocation
    from guard import APP_COMMIT, APP_TREE, APP_PR, Reject, read_json

FIELDS = {
    "format", "challenge", "nonce", "expires_at", "preflight_run_id",
    "broker_sha", "app_pr", "app_commit", "app_tree", "preflight_sha256",
    "content_sha256", "archive_sha256",
}
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")


def canonical_payload(path: Path) -> tuple[dict, bytes]:
    raw = path.read_bytes()
    if len(raw) > 16_384:
        raise Reject("challenge_too_large")
    value = read_json(str(path))
    if set(value) != FIELDS or value.get("format") != 1:
        raise Reject("challenge_fields_invalid")
    if not isinstance(value.get("challenge"), str) or not TOKEN.fullmatch(value["challenge"]):
        raise Reject("challenge_id_invalid")
    if not isinstance(value.get("nonce"), str) or not TOKEN.fullmatch(value["nonce"]):
        raise Reject("challenge_nonce_invalid")
    current = int(time.time())
    if not isinstance(value.get("expires_at"), int) or not current < value["expires_at"] <= current + 1800:
        raise Reject("challenge_expiry_invalid")
    if not isinstance(value.get("preflight_run_id"), str) or not RUN_ID.fullmatch(value["preflight_run_id"]):
        raise Reject("challenge_run_invalid")
    if not isinstance(value.get("broker_sha"), str) or not SHA40.fullmatch(value["broker_sha"]):
        raise Reject("challenge_broker_sha_invalid")
    if value.get("app_pr") != APP_PR or value.get("app_commit") != APP_COMMIT or value.get("app_tree") != APP_TREE:
        raise Reject("challenge_source_pin_invalid")
    for field in ("preflight_sha256", "content_sha256", "archive_sha256"):
        if not isinstance(value.get(field), str) or not SHA64.fullmatch(value[field]):
            raise Reject("challenge_digest_invalid")
    canonical = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if raw != canonical:
        raise Reject("challenge_not_canonical")
    return value, raw


def create_approval(challenge_path: Path, private_key: Path, output: Path) -> None:
    claims, payload = canonical_payload(challenge_path)
    print("Review before authorizing this exact update:")
    print(f"  Preflight run: {claims['preflight_run_id']}")
    print(f"  Broker commit: {claims['broker_sha']}")
    print(f"  Application PR/commit/tree: #{claims['app_pr']} {claims['app_commit']} {claims['app_tree']}")
    print(f"  VPS Preflight SHA-256: {claims['preflight_sha256']}")
    print(f"  CRM content SHA-256: {claims['content_sha256']}")
    print(f"  Exact archive SHA-256: {claims['archive_sha256']}")
    confirmation = input("Type the full application commit SHA to sign this one-use approval: ").strip()
    if confirmation != claims["app_commit"]:
        raise Reject("owner_confirmation_mismatch")
    ssh_keygen = shutil.which("ssh-keygen")
    if not ssh_keygen:
        raise Reject("openssh_keygen_missing")
    # OpenSSH prompts for the passphrase interactively; never pass it through
    # command-line arguments or an environment variable.
    result = subprocess.run(
        [ssh_keygen, "-Y", "sign", "-f", str(private_key), "-n", "mmcrm-deploy-v1", str(challenge_path)],
        stdin=None, stdout=subprocess.DEVNULL, stderr=None, check=False,
    )
    signature_path = Path(str(challenge_path) + ".sig")
    try:
        if result.returncode != 0 or not signature_path.is_file():
            raise Reject("signature_creation_failed")
        signature = signature_path.read_bytes()
        if not signature or len(signature) > 16_384:
            raise Reject("signature_size_invalid")
        envelope = {
            "format": 1,
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }
        data = (json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        try:
            signature_path.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("challenge", type=Path, help="canonical VPS Preflight challenge JSON")
    parser.add_argument("private_key", type=Path, help="local OpenSSH Ed25519 private key")
    parser.add_argument("output", type=Path, help="write-only signed authorization envelope")
    args = parser.parse_args()
    try:
        create_approval(args.challenge, args.private_key, args.output)
        print("MMCRM_APPROVAL_CREATED signature=ed25519 private_key=local payload=preflight-and-archive-bound")
        return 0
    except Reject as exc:
        print(f"MMCRM_APPROVAL_REJECT reason={exc.reason}", file=sys.stderr)
        return 1
    except Exception:
        print("MMCRM_APPROVAL_REJECT reason=local_signing_error", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
