from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/"ops/broker/workflow-candidates"
PRE=SRC/"mmcrm-main-v2-preflight.yml"
APP=SRC/"mmcrm-main-v2-apply.yml"
SHA="715a40139f2951f2e499b2169a05089ada3e214e"
INFRA="4d9202819a64e9d5823aae3b471d8531aee02be7"

class CandidateV2WorkflowContracts(unittest.TestCase):
    def test_models_are_not_active_workflows(self):
        self.assertTrue(PRE.is_file() and APP.is_file())
        self.assertNotIn("mmcrm-main-v2-preflight.yml",[p.name for p in (ROOT/".github/workflows").glob("*.yml")])
        self.assertNotIn("mmcrm-main-v2-apply.yml",[p.name for p in (ROOT/".github/workflows").glob("*.yml")])
        self.assertIn("INACTIVE TEMPLATE",PRE.read_text())
        self.assertIn("INACTIVE TEMPLATE",APP.read_text())

    def test_v2_source_and_controller_are_immutable_pins(self):
        for f in (PRE,APP):
            t=f.read_text()
            self.assertIn(SHA,t)
            self.assertIn("ref: "+INFRA,t)
            self.assertIn("prepare-mmcrm-main-archive.py",t)
            self.assertIn("fetch_source_main_v2.py",t)
            self.assertIn("main_release_source.py --verify",t)
            self.assertIn("main_release_gate_v2.py",t)
            self.assertNotIn("prepare-mmcrm-pr20-",t)
            self.assertNotIn("MegaMonitor/pulls/20",t)
            self.assertNotIn("df195e6da70206bdd2e690507558a63eaa3705e5/check-runs",t)

    def test_enforced_signing_provenance_archive_and_loopback(self):
        p=PRE.read_text()
        a=APP.read_text()
        self.assertIn("mmcrm-deploy@$DEPLOY_HOST",p)
        self.assertIn("mmcrm-deploy@$DEPLOY_HOST",a)
        for t in (p,a):
            self.assertIn("StrictHostKeyChecking=yes",t)
            self.assertIn("IdentitiesOnly=yes",t)
        self.assertIn("main_release_gate_v2.py --manifest",p)
        self.assertIn("main_release_gate_v2.py --envelope",a)
        self.assertIn("main_release_gate_v2.py --run",a)
        self.assertIn('grant_b64=$(base64 -w0 "$RUNNER_TEMP/authorization.json" | base64 -w0)',a)
        self.assertIn("verify_apply_result_main_v2.py",a)
        self.assertIn("MMCRM_APPLY_SSH_KEY",a)
        self.assertNotIn("MMCRM_APPLY_SSH_KEY",p)
        self.assertIn("data=preserved", (ROOT/"docs/mmcrm-v2-integration-status.md").read_text())

if __name__=="__main__":
    unittest.main()
