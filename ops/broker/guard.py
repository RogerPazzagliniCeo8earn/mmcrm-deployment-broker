#!/usr/bin/env python3
"""Fail-closed validators for the code-only MMcrm deployment broker."""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

OWNER = "RogerPazzagliniCeo8earn"
APP_REPO = f"{OWNER}/MegaMonitor"
APP_PR = 20
APP_BASE = "feat/mmcrm-project-cards-reminder-count-20261030"
APP_COMMIT = "df195e6da70206bdd2e690507558a63eaa3705e5"
APP_TREE = "81791ad20819d34990ba37a0678e292f9db02e44"
PREFLIGHT_PATH = ".github/workflows/mmcrm-preflight.yml"
MANIFEST_FIELDS = {
    "format", "challenge", "nonce", "expires_at", "preflight_run_id",
    "broker_sha", "app_pr", "app_commit", "app_tree", "preflight_sha256",
    "content_sha256", "archive_sha256",
}
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")


class Reject(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def reject(condition: bool, reason: str) -> None:
    if not condition:
        raise Reject(reason)


def read_json(path: str) -> dict:
    try:
        raw = Path(path).read_bytes()
        reject(len(raw) <= 16_384, "input_too_large")
        def unique_object(pairs):
            result = {}
            for key, item in pairs:
                if key in result:
                    raise Reject("json_duplicate_key")
                result[key] = item
            return result
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
        reject(isinstance(value, dict), "json_object_required")
        return value
    except Reject:
        raise
    except Exception:
        raise Reject("json_invalid") from None


def validate_manifest(value: dict, run_id: str, broker_sha: str) -> dict:
    reject(set(value) == MANIFEST_FIELDS, "manifest_fields_mismatch")
    reject(value.get("format") == 1, "manifest_version_mismatch")
    reject(isinstance(value.get("challenge"), str) and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value["challenge"]), "manifest_challenge_invalid")
    reject(isinstance(value.get("nonce"), str) and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value["nonce"]), "manifest_nonce_invalid")
    current = int(time.time())
    reject(isinstance(value.get("expires_at"), int) and current < value["expires_at"] <= current + 1800, "manifest_expiry_invalid")
    reject(isinstance(value.get("preflight_run_id"), str) and RUN_ID.fullmatch(value["preflight_run_id"]), "manifest_run_id_invalid")
    reject(value["preflight_run_id"] == run_id, "manifest_run_id_mismatch")
    reject(value.get("broker_sha") == broker_sha and SHA40.fullmatch(broker_sha), "manifest_broker_sha_mismatch")
    reject(value.get("app_pr") == APP_PR, "manifest_pr_mismatch")
    reject(value.get("app_commit") == APP_COMMIT, "manifest_commit_mismatch")
    reject(value.get("app_tree") == APP_TREE, "manifest_tree_mismatch")
    for field in ("preflight_sha256", "content_sha256", "archive_sha256"):
        reject(isinstance(value.get(field), str) and SHA64.fullmatch(value[field]), "manifest_digest_invalid")
    return value


def validate_envelope(path: str, manifest_path: str, run_id: str, broker_sha: str) -> None:
    envelope = read_json(path)
    reject(set(envelope) == {"format", "payload_b64", "signature_b64"} and envelope.get("format") == 1,
           "authorization_envelope_invalid")
    try:
        payload = base64.b64decode(envelope["payload_b64"], validate=True)
        signature = base64.b64decode(envelope["signature_b64"], validate=True)
    except Exception:
        raise Reject("authorization_encoding_invalid") from None
    manifest = validate_manifest(read_json(manifest_path), run_id, broker_sha)
    expected = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    reject(payload == expected, "authorization_payload_mismatch")
    reject(64 <= len(signature) <= 16_384, "authorization_signature_size_invalid")


def validate_run(run: dict, run_id: str, broker_sha: str, actor: str = OWNER) -> None:
    reject(isinstance(run_id, str) and RUN_ID.fullmatch(run_id), "preflight_run_id_invalid")
    reject(str(run.get("id")) == run_id, "preflight_run_id_mismatch")
    reject(run.get("event") == "workflow_dispatch", "preflight_event_invalid")
    reject(run.get("path") == PREFLIGHT_PATH, "preflight_workflow_invalid")
    reject(run.get("head_branch") == "main", "preflight_ref_invalid")
    reject(run.get("head_sha") == broker_sha and SHA40.fullmatch(broker_sha), "preflight_broker_sha_mismatch")
    reject(run.get("conclusion") == "success", "preflight_not_successful")
    run_actor = run.get("actor")
    reject(isinstance(run_actor, dict) and run_actor.get("login") == actor, "preflight_actor_invalid")


def validate_source(pr: dict, status: dict, checks: dict, commit: dict | None = None) -> None:
    reject(pr.get("number") == APP_PR, "source_pr_mismatch")
    reject(pr.get("state") == "open" and pr.get("draft") is False, "source_pr_not_ready")
    reject(isinstance(pr.get("base"), dict) and pr["base"].get("ref") == APP_BASE, "source_base_mismatch")
    head = pr.get("head")
    reject(isinstance(head, dict) and head.get("sha") == APP_COMMIT, "source_commit_mismatch")
    repo = head.get("repo") if isinstance(head, dict) else None
    reject(isinstance(repo, dict) and repo.get("full_name") == APP_REPO, "source_repository_mismatch")
    reject(status.get("state") == "success", "source_status_not_success")
    check_runs = checks.get("check_runs")
    reject(isinstance(check_runs, list) and bool(check_runs), "source_checks_missing")
    reject(checks.get("total_count") == len(check_runs), "source_checks_incomplete")
    reject(all(isinstance(x, dict) and x.get("status") == "completed" and x.get("conclusion") == "success" for x in check_runs), "source_check_failed")
    if commit is not None:
        commit_data = commit.get("commit")
        tree_data = commit_data.get("tree") if isinstance(commit_data, dict) else None
        reject(isinstance(tree_data, dict) and tree_data.get("sha") == APP_TREE, "source_tree_mismatch")


def validate_redirect(url: str) -> None:
    parsed = urlparse(url)
    reject(parsed.scheme == "https" and parsed.hostname == "codeload.github.com", "archive_redirect_host_invalid")
    reject(parsed.username is None and parsed.password is None, "archive_redirect_userinfo_invalid")
    reject(parsed.path == f"/{OWNER}/MegaMonitor/legacy.tar.gz/{APP_COMMIT}", "archive_redirect_path_invalid")
    reject(bool(parsed.query), "archive_redirect_signature_missing")


def self_test() -> None:
    manifest = {
        "format": 1, "challenge": "c" * 40, "nonce": "n" * 40,
        "expires_at": int(time.time()) + 1200, "preflight_run_id": "41192707703", "broker_sha": "a" * 40,
        "app_pr": APP_PR, "app_commit": APP_COMMIT, "app_tree": APP_TREE,
        "preflight_sha256": "d" * 64, "content_sha256": "b" * 64, "archive_sha256": "c" * 64,
    }
    run = {
        "id": 41192707703, "event": "workflow_dispatch", "path": PREFLIGHT_PATH,
        "head_branch": "main", "head_sha": "a" * 40, "conclusion": "success",
        "actor": {"login": OWNER},
    }
    pr = {
        "number": APP_PR, "state": "open", "draft": False,
        "base": {"ref": APP_BASE},
        "head": {"sha": APP_COMMIT, "repo": {"full_name": APP_REPO}},
    }
    status = {"state": "success"}
    checks = {"total_count": 2, "check_runs": [
        {"status": "completed", "conclusion": "success"},
        {"status": "completed", "conclusion": "success"},
    ]}
    validate_manifest(manifest, "41192707703", "a" * 40)
    validate_run(run, "41192707703", "a" * 40)
    validate_source(pr, status, checks)
    validate_redirect("https://codeload.github.com/RogerPazzagliniCeo8earn/MegaMonitor/legacy.tar.gz/" + APP_COMMIT + "?token=opaque")

    mutations = [
        (lambda m: m.update(app_commit="0" * 40), "manifest_commit_mismatch"),
        (lambda m: m.update(unexpected_archive="private-bytes"), "manifest_fields_mismatch"),
        (lambda m: m.update(archive_sha256="../path"), "manifest_digest_invalid"),
    ]
    for mutate, reason in mutations:
        bad = dict(manifest); mutate(bad)
        try: validate_manifest(bad, "41192707703", "a" * 40)
        except Reject as exc: assert exc.reason == reason
        else: raise AssertionError("tampered manifest accepted")

    for change, value in [
        ("event", "pull_request"), ("path", ".github/workflows/untrusted.yml"),
        ("head_branch", "attacker"), ("conclusion", "failure"),
        ("head_sha", "d" * 40),
    ]:
        bad = dict(run); bad[change] = value
        try: validate_run(bad, "41192707703", "a" * 40)
        except Reject: pass
        else: raise AssertionError("untrusted run accepted")
    bad_actor = dict(run); bad_actor["actor"] = {"login": "untrusted"}
    try: validate_run(bad_actor, "41192707703", "a" * 40)
    except Reject as exc: assert exc.reason == "preflight_actor_invalid"
    else: raise AssertionError("untrusted preflight initiator accepted")

    for bad_checks in [
        {"total_count": 2, "check_runs": checks["check_runs"][:1]},
        {"total_count": 1, "check_runs": [{"status": "completed", "conclusion": "failure"}]},
    ]:
        try: validate_source(pr, status, bad_checks)
        except Reject: pass
        else: raise AssertionError("missing or failed CI accepted")
    try: validate_source({**pr, "draft": True}, status, checks)
    except Reject as exc: assert exc.reason == "source_pr_not_ready"
    else: raise AssertionError("draft source PR accepted")
    for url in [
        "http://codeload.github.com/RogerPazzagliniCeo8earn/MegaMonitor/legacy.tar.gz/x?token=opaque",
        "https://attacker.example/RogerPazzagliniCeo8earn/MegaMonitor/legacy.tar.gz/x?token=opaque",
        "https://codeload.github.com/other/MegaMonitor/legacy.tar.gz/x?token=opaque",
    ]:
        try: validate_redirect(url)
        except Reject: pass
        else: raise AssertionError("untrusted archive redirect accepted")
    print("BROKER_GUARD_SELFTEST_OK manifest run actor source-CI redirect tampering-blocked")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--verify-manifest", nargs=3, metavar=("FILE", "RUN_ID", "BROKER_SHA"))
    parser.add_argument("--verify-envelope", nargs=4, metavar=("ENVELOPE", "MANIFEST", "RUN_ID", "BROKER_SHA"))
    parser.add_argument("--verify-run", nargs=4, metavar=("FILE", "RUN_ID", "BROKER_SHA", "ACTOR"))
    parser.add_argument("--verify-source", nargs=4, metavar=("PR_JSON", "COMMIT_JSON", "STATUS_JSON", "CHECKS_JSON"))
    parser.add_argument("--validate-redirect")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test(); return 0
        if args.verify_manifest:
            path, run_id, sha = args.verify_manifest
            validate_manifest(read_json(path), run_id, sha)
            print("BROKER_MANIFEST_OK")
            return 0
        if args.verify_envelope:
            envelope_path, manifest_path, run_id, sha = args.verify_envelope
            validate_envelope(envelope_path, manifest_path, run_id, sha)
            print("BROKER_AUTHORIZATION_PAYLOAD_OK")
            return 0
        if args.verify_run:
            path, run_id, sha, actor = args.verify_run
            validate_run(read_json(path), run_id, sha, actor)
            return 0
        if args.verify_source:
            pr_path, commit_path, status_path, checks_path = args.verify_source
            validate_source(read_json(pr_path), read_json(status_path), read_json(checks_path), read_json(commit_path))
            print("BROKER_SOURCE_OK")
            return 0
        if args.validate_redirect:
            validate_redirect(args.validate_redirect)
            return 0
        parser.error("select a validation mode")
    except Reject as exc:
        print(f"BROKER_REJECT reason={exc.reason}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
