#!/usr/bin/env python3
"""Reference model for the fixed VPS one-use signed-approval verifier.

The production copy is shipped with the private infrastructure controller.
This reference is deliberately code-only and lets the public broker CI run
the same signature, binding, tamper, expiry, and replay checks on Linux and
Windows PowerShell 5.1 runners.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

FIELDS = {
    "format", "challenge", "nonce", "expires_at", "preflight_run_id",
    "broker_sha", "app_pr", "app_commit", "app_tree", "preflight_sha256",
    "content_sha256", "archive_sha256",
}
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
APP_PR = 20
APP_COMMIT = "df195e6da70206bdd2e690507558a63eaa3705e5"
APP_TREE = "81791ad20819d34990ba37a0678e292f9db02e44"


class Denied(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _json(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Denied("duplicate_json_key")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Denied:
        raise
    except Exception:
        raise Denied("json_invalid") from None
    if not isinstance(value, dict):
        raise Denied("json_object_required")
    return value


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def validate_payload(raw: bytes, now: int | None = None) -> dict:
    if len(raw) > 16_384:
        raise Denied("payload_too_large")
    value = _json(raw)
    if set(value) != FIELDS or value.get("format") != 1:
        raise Denied("payload_fields_invalid")
    if raw != canonical(value):
        raise Denied("payload_not_canonical")
    for field in ("challenge", "nonce"):
        if not isinstance(value.get(field), str) or not TOKEN.fullmatch(value[field]):
            raise Denied("challenge_identifier_invalid")
    current = now or int(time.time())
    if not isinstance(value.get("expires_at"), int) or not current < value["expires_at"] <= current + 1800:
        raise Denied("challenge_expired")
    if not isinstance(value.get("preflight_run_id"), str) or not RUN_ID.fullmatch(value["preflight_run_id"]):
        raise Denied("preflight_run_invalid")
    if not isinstance(value.get("broker_sha"), str) or not SHA40.fullmatch(value["broker_sha"]):
        raise Denied("broker_sha_invalid")
    if value.get("app_pr") != APP_PR or value.get("app_commit") != APP_COMMIT or value.get("app_tree") != APP_TREE:
        raise Denied("source_pin_invalid")
    for field in ("preflight_sha256", "content_sha256", "archive_sha256"):
        if not isinstance(value.get(field), str) or not SHA64.fullmatch(value[field]):
            raise Denied("digest_invalid")
    return value


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def issue(state_dir: Path, claims: dict, now: int | None = None) -> bytes:
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    current = now or int(time.time())
    value = dict(claims)
    value.update({"format": 1, "challenge": secrets.token_urlsafe(32), "nonce": secrets.token_urlsafe(32),
                  "expires_at": current + 1800})
    payload = canonical(value)
    validate_payload(payload, now=current)
    state = state_dir / (value["challenge"] + ".json")
    fd = os.open(state, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return payload


def verify_and_consume(state_dir: Path, allowed_signers: Path, envelope_raw: bytes,
                       archive: Path, now: int | None = None) -> dict:
    envelope = _json(envelope_raw)
    if set(envelope) != {"format", "payload_b64", "signature_b64"} or envelope.get("format") != 1:
        raise Denied("envelope_fields_invalid")
    try:
        payload = base64.b64decode(envelope["payload_b64"], validate=True)
        signature = base64.b64decode(envelope["signature_b64"], validate=True)
    except Exception:
        raise Denied("envelope_encoding_invalid") from None
    claims = validate_payload(payload, now=now)
    state_path = state_dir / (claims["challenge"] + ".json")
    try:
        state = state_path.read_bytes()
    except OSError:
        raise Denied("challenge_unknown") from None
    if state != payload:
        raise Denied("challenge_claims_mismatch")
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size <= 0 or archive.stat().st_size > 100 * 1024 * 1024:
        raise Denied("archive_type_or_size_invalid")
    if _hash(archive) != claims["archive_sha256"]:
        raise Denied("archive_hash_mismatch")
    ssh_keygen = shutil.which("ssh-keygen")
    if not ssh_keygen:
        raise Denied("signature_verifier_missing")
    with tempfile.TemporaryDirectory(prefix="mmcrm-signature-") as tmp:
        sig = Path(tmp) / "signature"
        sig.write_bytes(signature)
        result = subprocess.run([ssh_keygen, "-Y", "verify", "-f", str(allowed_signers), "-I", "mmcrm-owner",
                                 "-n", "mmcrm-deploy-v1", "-s", str(sig)], input=payload,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if result.returncode != 0:
        raise Denied("signature_invalid")
    # O_EXCL gives a single winner if two SSH sessions race to use the grant.
    consumed = state_dir / (claims["challenge"] + ".consumed")
    try:
        fd = os.open(consumed, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise Denied("authorization_replayed") from None
    with os.fdopen(fd, "wb") as stream:
        stream.write(hashlib.sha256(payload).hexdigest().encode("ascii") + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    return claims
