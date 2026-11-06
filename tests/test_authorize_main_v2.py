import json
import tempfile
import time
import unittest
from pathlib import Path
from ops.broker.authorize_main_v2 import canonical_payload, Reject
from ops.broker.main_release_source import APP_COMMIT, APP_TREE

def challenge():
    return {
        "format": 2, "challenge": "c"*40, "nonce": "n"*40,
        "expires_at": int(time.time())+1200, "preflight_run_id":"123456",
        "broker_sha":"a"*40, "app_ref":"main",
        "old_commit":"df195e6da70206bdd2e690507558a63eaa3705e5",
        "app_commit": APP_COMMIT, "app_tree": APP_TREE,
        "preflight_sha256":"d"*64, "content_sha256":"b"*64, "archive_sha256":"c"*64,
    }

class MainV2SigningTests(unittest.TestCase):
    def test_accepts_only_exact_canonical_v2_challenge(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"challenge.json"
            value=challenge()
            raw=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
            path.write_bytes(raw)
            parsed,payload=canonical_payload(path)
            self.assertEqual(payload,raw)
            self.assertEqual(parsed["old_commit"],value["old_commit"])
            for field,bad in [
                ("format",1),("app_ref","pr20"),("old_commit","0"*40),
                ("app_commit","0"*40),("app_tree","0"*40),
                ("archive_sha256","invalid-hash"),("expires_at",int(time.time())-1),
            ]:
                changed=dict(value); changed[field]=bad
                path.write_text(json.dumps(changed,sort_keys=True,separators=(",",":"))+"\n")
                with self.subTest(field=field),self.assertRaises(Reject):
                    canonical_payload(path)
            changed=dict(value);changed["app_pr"]=20
            path.write_text(json.dumps(changed,sort_keys=True,separators=(",",":"))+"\n")
            with self.assertRaises(Reject): canonical_payload(path)
            path.write_text(json.dumps(value)+"\n")
            with self.assertRaises(Reject):canonical_payload(path)

if __name__=="__main__":
    unittest.main()
