import unittest
from ops.broker.fetch_source_main_v2 import API_URL, validate_redirect, Reject
from ops.broker.verify_apply_result_main_v2 import has_valid_success
from ops.broker.main_release_source import APP_COMMIT

class MainTransportTests(unittest.TestCase):
    def test_immutable_archive_pin_and_redirect(self):
        self.assertTrue(API_URL.endswith("/tarball/"+APP_COMMIT))
        url=f"https://codeload.github.com/RogerPazzagliniCeo8earn/MegaMonitor/legacy.tar.gz/{APP_COMMIT}?token=opaque"
        validate_redirect(url)
        for candidate in (
            url.replace("codeload.github.com","attacker.example"),
            url.replace(APP_COMMIT,"df195e6da70206bdd2e690507558a63eaa3705e5"),
            url.replace("https://","http://"),
            url.split("?")[0],
        ):
            with self.subTest(candidate=candidate),self.assertRaises(Reject):
                validate_redirect(candidate)

    def test_result_requires_new_sha_and_verified_backup(self):
        base=("UPGRADE_RESULT=SUCCESS app_commit="+APP_COMMIT+
              " service=active bind=127.0.0.1:39217 database=integrity-ok existing-rows=preserved"+
              " backup_id=20261106T150000Z-0123456789abcdef backup_sha256="+("a"*64)+
              " prior_release=preserved")
        self.assertTrue(has_valid_success(base+"\n"))
        for changed in (
            base.replace(APP_COMMIT,"df195e6da70206bdd2e690507558a63eaa3705e5"),
            base.replace("database=integrity-ok","database=unchecked"),
            base.replace("prior_release=preserved","prior_release=missing"),
            base+"\n"+base,
        ):
            with self.subTest(case=changed[-70:]):
                self.assertFalse(has_valid_success(changed))
if __name__=="__main__":
    unittest.main()
