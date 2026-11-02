from pathlib import Path
import re
import unittest


class SourceAppWorkflowSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = Path(".github/workflows/source-app-readonly.yml").read_text(encoding="utf-8")

    def test_manual_dispatch_only_and_owner_main_gate(self):
        self.assertRegex(self.workflow, r"(?m)^  workflow_dispatch:\s*$")
        self.assertNotRegex(self.workflow, r"(?m)^  (push|pull_request|schedule|workflow_run):")
        self.assertIn("github.ref == 'refs/heads/main'", self.workflow)
        self.assertIn("github.actor == 'RogerPazzagliniCeo8earn'", self.workflow)

    def test_scoped_app_token_is_read_only_for_the_two_private_repositories(self):
        self.assertIn("actions/create-github-app-token@a8d616148505b5069dccd32f177bb87d7f39123b", self.workflow)
        self.assertIn("vars.MMCRM_SOURCE_APP_ID", self.workflow)
        self.assertIn("secrets.MMCRM_SOURCE_APP_PRIVATE_KEY", self.workflow)
        self.assertIn("repositories: MegaMonitor,MMcrm-Infrastructure", self.workflow)
        self.assertRegex(self.workflow, r"(?m)^          permission-contents: read$")
        self.assertRegex(self.workflow, r"(?m)^          permission-pull-requests: read$")
        self.assertRegex(self.workflow, r"(?m)^          permission-actions: read$")

    def test_only_fixed_github_contents_reads_and_no_transport_or_deployment(self):
        self.assertIn("MegaMonitor/contents/package.json?ref=main", self.workflow)
        self.assertIn("MMcrm-Infrastructure/contents/ops/updates/mmcrm-deploy-authorization.py?ref=main", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertIn("GH_TOKEN: ${{ steps.source-app-token.outputs.token }}", self.workflow)
        self.assertIn("> \"$response_dir/megamonitor.json\" 2>/dev/null", self.workflow)
        self.assertIn("> \"$response_dir/infrastructure.json\" 2>/dev/null", self.workflow)
        self.assertIn("repositories=2 contents=read", self.workflow)
        forbidden = re.compile(r"(?i)ssh|deploy_host|mmcrm_apply|mmcrm_preflight|195\.231\.83\.244|/opt/mmcrm")
        self.assertIsNone(forbidden.search(self.workflow))


if __name__ == "__main__":
    unittest.main()
