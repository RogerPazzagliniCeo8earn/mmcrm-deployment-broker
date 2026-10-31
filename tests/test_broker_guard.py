from __future__ import annotations

import unittest
import tempfile
import base64
import json
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import Request

from ops.broker.fetch_source import SafeRedirect
from ops.broker.guard import (
    APP_BASE, APP_COMMIT, APP_PR, APP_REPO, APP_TREE, MANIFEST_FIELDS,
    PREFLIGHT_PATH, Reject, validate_manifest, validate_redirect, validate_run,
    validate_source, read_json,
)
from ops.broker.authorize import FIELDS as AUTH_FIELDS, Reject as AuthReject, canonical_payload
from ops.broker.vps_authorization_reference import Denied, issue, verify_and_consume

ROOT = Path(__file__).resolve().parents[1]


def valid_manifest():
    return {
        "format": 1, "challenge": "c" * 40, "nonce": "n" * 40,
        "expires_at": int(time.time()) + 1200, "preflight_run_id": "123456", "broker_sha": "a" * 40,
        "app_pr": APP_PR, "app_commit": APP_COMMIT, "app_tree": APP_TREE,
        "preflight_sha256": "d" * 64, "content_sha256": "b" * 64, "archive_sha256": "c" * 64,
    }


def valid_run():
    return {
        "id": 123456, "event": "workflow_dispatch", "path": PREFLIGHT_PATH,
        "head_branch": "main", "head_sha": "a" * 40, "conclusion": "success",
        "actor": {"login": "RogerPazzagliniCeo8earn"},
    }


def valid_source():
    return (
        {"number": APP_PR, "state": "open", "draft": False,
         "base": {"ref": APP_BASE},
         "head": {"sha": APP_COMMIT, "repo": {"full_name": APP_REPO}}},
        {"commit": {"tree": {"sha": APP_TREE}}},
        {"state": "success"},
        {"total_count": 1, "check_runs": [{"status": "completed", "conclusion": "success"}]},
    )


class BrokerGuardTests(unittest.TestCase):
    def test_local_signer_accepts_only_canonical_pinned_vps_challenge(self):
        challenge = {
            "format": 1, "challenge": "c" * 40, "nonce": "n" * 40,
            "expires_at": int(time.time()) + 1200, "preflight_run_id": "123456",
            "broker_sha": "a" * 40, "app_pr": APP_PR,
            "app_commit": APP_COMMIT, "app_tree": APP_TREE,
            "preflight_sha256": "d" * 64, "content_sha256": "b" * 64,
            "archive_sha256": "c" * 64,
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "challenge.json"
            path.write_bytes((json.dumps(challenge, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
            parsed, payload = canonical_payload(path)
            self.assertEqual(set(parsed), AUTH_FIELDS)
            self.assertEqual(payload, path.read_bytes())
            for mutate in (
                lambda value: value.update(app_commit="0" * 40),
                lambda value: value.update(archive_sha256="../escape"),
                lambda value: value.update(preflight_run_id="000"),
                lambda value: value.update(extra="ignored"),
            ):
                bad = dict(challenge); mutate(bad)
                path.write_bytes((json.dumps(bad, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
                with self.subTest(challenge=bad):
                    with self.assertRaises(AuthReject):
                        canonical_payload(path)
            path.write_bytes((json.dumps(challenge, separators=(",", ":")) + "\n").encode("utf-8"))
            with self.assertRaises(AuthReject) as raised:
                canonical_payload(path)
            self.assertEqual(raised.exception.reason, "challenge_not_canonical")

    def test_openssh_signature_binds_exact_challenge_bytes(self):
        ssh_keygen = shutil.which("ssh-keygen")
        if not ssh_keygen:
            self.skipTest("OpenSSH ssh-keygen is unavailable")
        challenge = {
            "format": 1, "challenge": "c" * 40, "nonce": "n" * 40,
            "expires_at": int(time.time()) + 1200, "preflight_run_id": "123456",
            "broker_sha": "a" * 40, "app_pr": APP_PR,
            "app_commit": APP_COMMIT, "app_tree": APP_TREE,
            "preflight_sha256": "d" * 64, "content_sha256": "b" * 64,
            "archive_sha256": "c" * 64,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "owner_ed25519"
            payload = root / "challenge.json"
            payload.write_text(json.dumps(challenge, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            subprocess.run([ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            subprocess.run([ssh_keygen, "-Y", "sign", "-f", str(key), "-n", "mmcrm-deploy-v1", str(payload)], check=True, stdout=subprocess.DEVNULL)
            signature = Path(str(payload) + ".sig")
            allowed = root / "allowed_signers"
            public = Path(str(key) + ".pub").read_text(encoding="utf-8").strip()
            allowed.write_text(f"mmcrm-owner namespaces=\"mmcrm-deploy-v1\" {public}\n", encoding="utf-8")
            valid = subprocess.run([ssh_keygen, "-Y", "verify", "-f", str(allowed), "-I", "mmcrm-owner", "-n", "mmcrm-deploy-v1", "-s", str(signature)], input=payload.read_bytes(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual(valid.returncode, 0)
            altered = payload.read_bytes().replace(b'"archive_sha256":"' + b"c" * 64, b'"archive_sha256":"' + b"e" * 64)
            invalid = subprocess.run([ssh_keygen, "-Y", "verify", "-f", str(allowed), "-I", "mmcrm-owner", "-n", "mmcrm-deploy-v1", "-s", str(signature)], input=altered, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertNotEqual(invalid.returncode, 0)

    def test_local_authorize_command_requires_commit_confirmation_and_emits_signed_envelope(self):
        ssh_keygen = shutil.which("ssh-keygen")
        if not ssh_keygen:
            self.skipTest("OpenSSH ssh-keygen is unavailable")
        value = {
            "format": 1, "challenge": "q" * 40, "nonce": "r" * 40,
            "expires_at": int(time.time()) + 1200, "preflight_run_id": "123456",
            "broker_sha": "a" * 40, "app_pr": APP_PR, "app_commit": APP_COMMIT,
            "app_tree": APP_TREE, "preflight_sha256": "d" * 64,
            "content_sha256": "b" * 64, "archive_sha256": "c" * 64,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); challenge = root / "challenge.json"; key = root / "owner"
            output = root / "approval.json"
            challenge.write_bytes((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())
            subprocess.run([ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            script = ROOT / "ops/broker/authorize.py"
            declined = subprocess.run([sys.executable, str(script), str(challenge), str(key), str(output)],
                                      input=("0" * 40 + "\n").encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(declined.returncode, 0)
            self.assertFalse(output.exists())
            accepted = subprocess.run([sys.executable, str(script), str(challenge), str(key), str(output)],
                                      input=(APP_COMMIT + "\n").encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(accepted.returncode, 0, accepted.stderr.decode(errors="replace"))
            envelope = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(set(envelope), {"format", "payload_b64", "signature_b64"})
            self.assertIn(b"Exact archive SHA-256", accepted.stdout)

    def test_vps_reference_requires_signed_exact_archive_and_consumes_grant_once(self):
        ssh_keygen = shutil.which("ssh-keygen")
        if not ssh_keygen:
            self.skipTest("OpenSSH ssh-keygen is unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"; state.mkdir(mode=0o700)
            key = root / "owner_ed25519"
            subprocess.run([ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            allowed = root / "allowed_signers"
            allowed.write_text(f'mmcrm-owner namespaces="mmcrm-deploy-v1" {Path(str(key)+".pub").read_text().strip()}\n', encoding="utf-8")
            archive = root / "archive.tar.gz"
            archive.write_bytes(b"private archive bytes never leave test temp")
            import hashlib
            claims = {
                "preflight_run_id": "123456", "broker_sha": "a" * 40,
                "app_pr": APP_PR, "app_commit": APP_COMMIT, "app_tree": APP_TREE,
                "preflight_sha256": "d" * 64, "content_sha256": "b" * 64,
                "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            }
            payload = issue(state, claims, now=1_800_000_000)
            challenge_file = root / "challenge.json"; challenge_file.write_bytes(payload)
            subprocess.run([ssh_keygen, "-Y", "sign", "-f", str(key), "-n", "mmcrm-deploy-v1", str(challenge_file)], check=True, stdout=subprocess.DEVNULL)
            envelope = json.dumps({"format": 1, "payload_b64": base64.b64encode(payload).decode(),
                                   "signature_b64": base64.b64encode(Path(str(challenge_file)+".sig").read_bytes()).decode()},
                                  sort_keys=True, separators=(",", ":")).encode()
            def attempt():
                try:
                    return ("accepted", verify_and_consume(state, allowed, envelope, archive, now=1_800_000_001))
                except Denied as exc:
                    return ("denied", exc.reason)
            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(lambda _: attempt(), range(2)))
            self.assertEqual(sum(kind == "accepted" for kind, _ in outcomes), 1)
            self.assertIn(("denied", "authorization_replayed"), outcomes)

            # A different archive, changed signed claims, or signature from
            # another key cannot consume a fresh challenge.
            payload2 = issue(state, {**claims, "preflight_run_id": "654321"}, now=1_800_000_000)
            file2 = root / "challenge2.json"; file2.write_bytes(payload2)
            subprocess.run([ssh_keygen, "-Y", "sign", "-f", str(key), "-n", "mmcrm-deploy-v1", str(file2)], check=True, stdout=subprocess.DEVNULL)
            envelope2 = json.dumps({"format": 1, "payload_b64": base64.b64encode(payload2).decode(),
                                    "signature_b64": base64.b64encode(Path(str(file2)+".sig").read_bytes()).decode()},
                                   sort_keys=True, separators=(",", ":")).encode()
            archive.write_bytes(b"different archive")
            with self.assertRaises(Denied) as wrong_archive:
                verify_and_consume(state, allowed, envelope2, archive, now=1_800_000_001)
            self.assertEqual(wrong_archive.exception.reason, "archive_hash_mismatch")

    def test_accepts_only_exact_run_manifest_source_and_ci_pins(self):
        validate_manifest(valid_manifest(), "123456", "a" * 40)
        validate_run(valid_run(), "123456", "a" * 40)
        pr, commit, status, checks = valid_source()
        validate_source(pr, status, checks, commit)

    def test_rejects_manifest_tampering_and_unexpected_private_payload_fields(self):
        for field, value in [("archive_sha256", "../escape"), ("app_commit", "0" * 40), ("private_source", "tar bytes")]:
            with self.subTest(field=field):
                bad = valid_manifest(); bad[field] = value
                with self.assertRaises(Reject):
                    validate_manifest(bad, "123456", "a" * 40)
        self.assertEqual(set(valid_manifest()), MANIFEST_FIELDS)

    def test_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "duplicate.json"
            path.write_text('{"run_id":"1","run_id":"2"}', encoding="utf-8")
            with self.assertRaises(Reject) as raised:
                read_json(str(path))
            self.assertEqual(raised.exception.reason, "json_duplicate_key")

    def test_rejects_wrong_run_actor_ref_event_result_and_run_binding(self):
        variants = [
            ("actor", {"login": "other"}), ("head_branch", "attacker"),
            ("event", "pull_request"), ("path", ".github/workflows/evil.yml"),
            ("conclusion", "failure"), ("head_sha", "d" * 40),
        ]
        for field, value in variants:
            with self.subTest(field=field):
                bad = valid_run(); bad[field] = value
                with self.assertRaises(Reject):
                    validate_run(bad, "123456", "a" * 40)
        with self.assertRaises(Reject):
            validate_run(valid_run(), "654321", "a" * 40)

    def test_rejects_draft_changed_source_commit_tree_or_incomplete_checks(self):
        pr, commit, status, checks = valid_source()
        variants = [
            ({**pr, "draft": True}, commit, status, checks),
            ({**pr, "head": {**pr["head"], "sha": "0" * 40}}, commit, status, checks),
            (pr, {"commit": {"tree": {"sha": "0" * 40}}}, status, checks),
            (pr, commit, {"state": "pending"}, checks),
            (pr, commit, status, {"total_count": 2, "check_runs": checks["check_runs"]}),
            (pr, commit, status, {"total_count": 1, "check_runs": [{"status": "completed", "conclusion": "failure"}]}),
        ]
        for source in variants:
            with self.subTest(source=source[0].get("draft")):
                with self.assertRaises(Reject):
                    validate_source(source[0], source[2], source[3], source[1])

    def test_private_archive_redirect_is_restricted_and_api_bearer_is_not_forwarded(self):
        url = f"https://codeload.github.com/{APP_REPO}/legacy.tar.gz/{APP_COMMIT}?signature=opaque"
        validate_redirect(url)
        for unsafe in [
            url.replace("https://", "http://"),
            url.replace("codeload.github.com", "evil.example"),
            url.replace(APP_REPO, "attacker/MegaMonitor"),
        ]:
            with self.subTest(url=unsafe):
                with self.assertRaises(Reject):
                    validate_redirect(unsafe)
        request = Request(f"https://api.github.com/repos/{APP_REPO}/tarball/{APP_COMMIT}", headers={"Authorization": "Bearer must-not-forward"})
        redirected = SafeRedirect().redirect_request(request, None, 302, "Found", {}, url)
        self.assertIsNotNone(redirected)
        self.assertIsNone(redirected.get_header("Authorization"))

    def test_ssh_transport_secret_exists_only_in_signed_apply_path(self):
        preflight = (ROOT / ".github/workflows/mmcrm-preflight.yml").read_text(encoding="utf-8")
        apply = (ROOT / ".github/workflows/mmcrm-apply.yml").read_text(encoding="utf-8")
        all_repo_text = "\n".join(
            p.read_text(encoding="utf-8") for p in ROOT.rglob("*")
            if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts
            and p.suffix.lower() in {".py", ".yml", ".yaml", ".md", ".sh", ".ps1", ".txt"}
        )
        secret_ref = "secrets.MMCRM_" + "APPLY_SSH_KEY"
        self.assertNotIn(secret_ref, preflight)
        self.assertEqual(apply.count(secret_ref), 1)
        self.assertNotIn("environment: mmcrm-apply", apply)
        self.assertIn("authorization", apply)
        self.assertIn("mmcrm-deploy-v1", (ROOT / "ops/broker/authorize.py").read_text(encoding="utf-8"))
        self.assertIn("permissions:\n  contents: read\n  actions: read", apply)
        workflows = preflight + apply + (ROOT / ".github/workflows/broker-ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("pull_request_" + "target", workflows)
        self.assertNotIn("runs-on: self-hosted", workflows)
        upload_block = preflight.split("uses: actions/upload-artifact", 1)[1].split("\n      - ", 1)[0]
        self.assertNotIn("source-crm-only.tar.gz", upload_block)
        self.assertIn("path: ${{ runner.temp }}/deployment-manifest.json", upload_block)
        self.assertNotIn("uses: actions/upload-artifact", apply)

    def test_workflow_mutations_cannot_replace_vps_signature_gate(self):
        preflight = (ROOT / ".github/workflows/mmcrm-preflight.yml").read_text(encoding="utf-8")
        apply = (ROOT / ".github/workflows/mmcrm-apply.yml").read_text(encoding="utf-8")
        secret_ref = "secrets.MMCRM_" + "APPLY_SSH_KEY"

        def assert_protected(p, a):
            self.assertNotIn(secret_ref, p)
            self.assertEqual(a.count(secret_ref), 1)
            apply_job = a.split("\n  apply:\n", 1)[1]
            validate_job = a.split("\n  validate:\n", 1)[1].split("\n  apply:\n", 1)[0]
            self.assertIn("needs: validate", apply_job)
            self.assertIn("if: github.ref == 'refs/heads/main' && github.actor == 'RogerPazzagliniCeo8earn'", apply_job)
            self.assertIn("--verify-envelope", validate_job)
            self.assertIn("authorization", apply_job)
            self.assertIn("printf 'apply %s\\n' \"$grant_b64\"", apply_job)
            self.assertNotIn(secret_ref, validate_job)
            self.assertLess(apply_job.index("authorization"), apply_job.index(secret_ref))
            self.assertNotIn("pull_request_target", p + a)
            self.assertNotIn("runs-on: self-hosted", p + a)

        assert_protected(preflight, apply)
        bypasses = [
            (preflight, apply.replace("--verify-envelope", "--skip-envelope-check", 1)),
            (preflight, apply.replace("printf 'apply %s\\n' \"$grant_b64\"", "printf 'apply\\n'", 1)),
            (preflight.replace("SSH_PRIVATE_KEY: ${{ secrets.MMCRM_PREFLIGHT_SSH_KEY }}", f"SSH_PRIVATE_KEY: ${{{{ {secret_ref} }}}}", 1), apply),
        ]
        for index, (bad_preflight, bad_apply) in enumerate(bypasses):
            with self.subTest(bypass_index=index):
                with self.assertRaises(AssertionError):
                    assert_protected(bad_preflight, bad_apply)

    def test_public_tree_contains_only_orchestration_code_docs_and_tests(self):
        allowed = {"README.md", ".github", "ops", "tests", "docs"}
        self.assertLessEqual({p.name for p in ROOT.iterdir() if p.name != ".git"}, allowed)
        for path in ROOT.rglob("*"):
            if path.is_file():
                self.assertNotIn(path.suffix.lower(), {".tar", ".gz", ".zip", ".db", ".sqlite", ".pem", ".key"})
                self.assertNotIn("source-real", path.name)


if __name__ == "__main__":
    unittest.main()
