import base64
import copy
import json
import time
import unittest
from ops.broker.main_release_gate_v2 import verify_manifest, verify_envelope, verify_run, Reject
from ops.broker.main_release_source import APP_COMMIT, APP_TREE

def good():
    return {
        "format":2,"challenge":"c"*40,"nonce":"n"*40,"expires_at":int(time.time())+1200,
        "preflight_run_id":"1234","broker_sha":"a"*40,
        "app_ref":"main","old_commit":"df195e6da70206bdd2e690507558a63eaa3705e5",
        "app_commit":APP_COMMIT,"app_tree":APP_TREE,
        "preflight_sha256":"d"*64,"content_sha256":"b"*64,"archive_sha256":"c"*64,
    }

class MainGateV2Tests(unittest.TestCase):
    def test_accepts_v2_signed_payload_but_not_v1(self):
        m=good()
        raw=verify_manifest(m,"1234","a"*40)
        envelope={"format":2,"payload_b64":base64.b64encode(raw).decode(),
                  "signature_b64":base64.b64encode(b"x"*80).decode()}
        verify_envelope(envelope,m,"1234","a"*40)
        for field,change in [("format",1),("app_ref","pr20"),("old_commit","0"*40),
                             ("app_commit","0"*40),("app_tree","0"*40),
                             ("preflight_run_id","99"),("expires_at",int(time.time())-1)]:
            bad={**m,field:change}
            with self.subTest(field=field),self.assertRaises(Reject):
                verify_manifest(bad,"1234","a"*40)
        for wrong in [
            {"format":1,**{k:v for k,v in envelope.items() if k!="format"}},
            {**envelope,"payload_b64":base64.b64encode(b"{}").decode()},
            {**envelope,"signature_b64":base64.b64encode(b"short").decode()},
        ]:
            with self.assertRaises(Reject):verify_envelope(wrong,m,"1234","a"*40)

    def test_denies_extra_manifest_fields_and_invalid_digest(self):
        for change in ({"app_pr":20},{"archive_sha256":"!"}):
            with self.assertRaises(Reject):verify_manifest({**good(),**change},"1234","a"*40)

    def test_enforces_exact_successful_preflight_run(self):
        run={"id":1234,"event":"workflow_dispatch","path":".github/workflows/mmcrm-preflight.yml",
             "head_branch":"main","head_sha":"a"*40,"conclusion":"success",
             "actor":{"login":"RogerPazzagliniCeo8earn"}}
        verify_run(run,"1234","a"*40)
        for k,v in [("id",1235),("path","malicious.yml"),("event","pull_request"),
                    ("head_branch","other"),("conclusion","failure"),
                    ("actor",{"login":"attacker"})]:
            with self.assertRaises(Reject):verify_run({**run,k:v},"1234","a"*40)

if __name__=="__main__":
    unittest.main()
