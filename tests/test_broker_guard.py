from __future__ import annotations

import unittest
import tempfile
from pathlib import Path
from urllib.request import Request

from ops.broker.fetch_source import SafeRedirect
from ops.broker.guard import (
    APP_BASE, APP_COMMIT, APP_PR, APP_REPO, APP_TREE, MANIFEST_FIELDS,
    PREFLIGHT_PATH, Reject, validate_manifest, validate_redirect, validate_run,
    validate_source, read_json,
)

ROOT = Path(__file__).resolve().parents[1]


def valid_manifest():
    return {
        "format": 1, "run_id": "123456", "broker_sha": "a" * 40,
        "app_pr": APP_PR, "app_commit": APP_COMMIT, "app_tree": APP_TREE,
        "content_sha256": "b" * 64, "archive_sha256": "c" * 64,
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

    def test_apply_secret_is_environment_gated_and_not_in_preflight_or_private_checkout(self):
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
        self.assertIn("environment: mmcrm-apply", apply)
        self.assertLess(apply.index("environment: mmcrm-apply"), apply.index(secret_ref))
        self.assertIn("permissions:\n  contents: read\n  actions: read", apply)
        workflows = preflight + apply + (ROOT / ".github/workflows/broker-ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("pull_request_" + "target", workflows)
        self.assertNotIn("runs-on: self-hosted", workflows)
        upload_block = preflight.split("uses: actions/upload-artifact", 1)[1].split("\n      - ", 1)[0]
        self.assertNotIn("source-crm-only.tar.gz", upload_block)
        self.assertIn("path: ${{ runner.temp }}/deployment-manifest.json", upload_block)
        self.assertNotIn("uses: actions/upload-artifact", apply)

    def test_rejects_workflow_authorization_bypass_mutations(self):
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
            self.assertIn("environment: mmcrm-apply", apply_job)
            self.assertNotIn(secret_ref, validate_job)
            self.assertLess(apply_job.index("environment: mmcrm-apply"), apply_job.index(secret_ref))
            self.assertNotIn("pull_request_target", p + a)
            self.assertNotIn("runs-on: self-hosted", p + a)

        assert_protected(preflight, apply)
        bypasses = [
            (preflight, apply.replace("    environment: mmcrm-apply\n", "", 1)),
            (preflight, apply.replace("github.ref == 'refs/heads/main'", "github.ref != 'refs/heads/main'")),
            (preflight.replace("SSH_PRIVATE_KEY: ${{ secrets.MMCRM_PREFLIGHT_SSH_KEY }}", f"SSH_PRIVATE_KEY: ${{{{ {secret_ref} }}}}", 1), apply),
            (preflight, apply.replace("      - name: Apply through the fixed SSH dispatcher", f"      - name: Apply through the fixed SSH dispatcher\n        env:\n          UNPROTECTED_KEY: ${{{{ {secret_ref} }}}}", 1)),
        ]
        for index, (bad_preflight, bad_apply) in enumerate(bypasses):
            with self.subTest(bypass_index=index):
                with self.assertRaises(AssertionError):
                    assert_protected(bad_preflight, bad_apply)

    def test_public_tree_contains_only_orchestration_code_docs_and_tests(self):
        allowed = {"README.md", ".github", "ops", "tests", "docs"}
        self.assertLessEqual({p.name for p in ROOT.iterdir()}, allowed)
        for path in ROOT.rglob("*"):
            if path.is_file():
                self.assertNotIn(path.suffix.lower(), {".tar", ".gz", ".zip", ".db", ".sqlite", ".pem", ".key"})
                self.assertNotIn("source-real", path.name)


if __name__ == "__main__":
    unittest.main()
