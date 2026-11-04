from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/mmcrm-preflight.yml"


class PreflightWorkflowPermissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_token_requests_only_required_read_scopes_for_source_verification(self):
        token_block = self.workflow.split("uses: actions/create-github-app-token@", 1)[1].split(
            "\n      - uses:", 1
        )[0]
        self.assertIn("repositories: MegaMonitor,MMcrm-Infrastructure", token_block)
        for permission in (
            "permission-contents: read",
            "permission-pull-requests: read",
            "permission-actions: read",
            "permission-statuses: read",
            "permission-checks: read",
        ):
            with self.subTest(permission=permission):
                self.assertRegex(token_block, rf"(?m)^          {re.escape(permission)}$")
        self.assertNotRegex(token_block, r"(?m)^          permission-[a-z-]+: write$")

    def test_each_api_endpoint_has_its_minimum_read_permission_and_safe_failure_label(self):
        self.assertIn('gh api "repos/RogerPazzagliniCeo8earn/MegaMonitor/pulls/$APP_PR" |', self.workflow)
        self.assertIn('read_api commit "repos/RogerPazzagliniCeo8earn/MegaMonitor/commits/df195e6da70206bdd2e690507558a63eaa3705e5"', self.workflow)
        self.assertIn('read_api commit_status "repos/RogerPazzagliniCeo8earn/MegaMonitor/commits/df195e6da70206bdd2e690507558a63eaa3705e5/status"', self.workflow)
        self.assertIn('endpoint=check_runs', self.workflow)
        self.assertIn("SOURCE_API_FAILED endpoint=$endpoint_name", self.workflow)
        self.assertIn("pulls/", self.workflow)
        self.assertIn("/status", self.workflow)
        self.assertIn("/check-runs?per_page=100", self.workflow)

    def test_source_permissions_stay_scoped_and_read_only(self):
        self.assertIn("owner: RogerPazzagliniCeo8earn", self.workflow)
        self.assertIn("repositories: MegaMonitor,MMcrm-Infrastructure", self.workflow)
        self.assertNotRegex(self.workflow, r"(?m)^          permission-[a-z-]+: write$")
        self.assertNotIn("permission-administration:", self.workflow)
        self.assertNotIn("permission-workflows:", self.workflow)
        self.assertIn("SSH_PRIVATE_KEY: ${{ secrets.MMCRM_PREFLIGHT_SSH_KEY }}", self.workflow)
        self.assertIn("mmcrm-deploy@$DEPLOY_HOST", self.workflow)

    def test_large_pull_response_is_projected_to_only_guard_required_fields(self):
        projection = "jq -c '{number, state, draft, base: {ref: .base.ref}, head: {sha: .head.sha, repo: {full_name: .head.repo.full_name}}}'"
        self.assertIn(projection, self.workflow)
        self.assertIn('> "$RUNNER_TEMP/pr.json"', self.workflow)
        for required_field in ("number", "state", "draft", "base.ref", "head.sha", "head.repo.full_name"):
            with self.subTest(field=required_field):
                self.assertIn(required_field, projection)
        guard = (ROOT / "ops/broker/guard.py").read_text(encoding="utf-8")
        self.assertIn('reject(len(raw) <= 16_384, "input_too_large")', guard)



    def test_preflight_ssh_failure_diagnostic_is_captured_and_redacted(self):
        self.assertIn('ssh_err="$RUNNER_TEMP/preflight.err"', self.workflow)
        self.assertIn('python3 ops/broker/ssh_diagnostic.py "$ssh_err" "$ssh_rc" >&2 || true', self.workflow)
        self.assertIn('exit "$ssh_rc"', self.workflow)
        self.assertIn('StrictHostKeyChecking=yes', self.workflow)
        self.assertIn('UserKnownHostsFile="$ssh_dir/known_hosts"', self.workflow)
        self.assertNotIn('cat "$ssh_err"', self.workflow)
        self.assertNotIn('tee "$ssh_err"', self.workflow)
        self.assertNotIn('ssh -v', self.workflow)

    def test_diagnostic_classifier_is_part_of_regression_suite(self):
        self.assertTrue((ROOT / "ops/broker/ssh_diagnostic.py").is_file())
        self.assertTrue((ROOT / "tests/test_ssh_diagnostic.py").is_file())
        ci = (ROOT / ".github/workflows/broker-ci.yml").read_text(encoding="utf-8")
        self.assertIn("tests/test_ssh_diagnostic.py", ci)
        self.assertIn("ops/broker/ssh_diagnostic.py", ci)

if __name__ == "__main__":
    unittest.main()
