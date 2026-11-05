import unittest

from ops.broker.verify_apply_result import has_valid_success


VALID = (
    "UPGRADE_RESULT=SUCCESS "
    "app_commit=df195e6da70206bdd2e690507558a63eaa3705e5 "
    "service=active bind=127.0.0.1:39217 "
    "database=integrity-ok existing-rows=preserved "
    "backup_id=20261105T132200Z-0123456789abcdef "
    "backup_sha256=" + "a" * 64 + " prior_release=preserved"
)


class ApplyResultTests(unittest.TestCase):
    def test_accepts_fixed_controller_success_with_all_expected_fields(self):
        self.assertTrue(has_valid_success(VALID + "\n"))

    def test_accepts_non_result_diagnostics_around_one_success_line(self):
        self.assertTrue(has_valid_success("UPGRADE_PREFLIGHT_OK\n" + VALID + "\n"))

    def test_rejects_wrong_commit(self):
        self.assertFalse(has_valid_success(VALID.replace(
            "df195e6da70206bdd2e690507558a63eaa3705e5",
            "0" * 40,
        )))

    def test_rejects_missing_or_changed_service_database_and_bind_fields(self):
        for old, new in (
            ("service=active", "service=inactive"),
            ("bind=127.0.0.1:39217", "bind=0.0.0.0:39217"),
            ("database=integrity-ok", "database=unchecked"),
            ("existing-rows=preserved", "existing-rows=unknown"),
        ):
            with self.subTest(field=old):
                self.assertFalse(has_valid_success(VALID.replace(old, new)))

    def test_rejects_malformed_backup_metadata(self):
        self.assertFalse(has_valid_success(VALID.replace("backup_id=20261105T132200Z-0123456789abcdef", "backup_id=bad")))
        self.assertFalse(has_valid_success(VALID.replace("backup_sha256=" + "a" * 64, "backup_sha256=short")))

    def test_rejects_missing_or_duplicate_success_records(self):
        self.assertFalse(has_valid_success("UPGRADE_PREFLIGHT_OK\n"))
        self.assertFalse(has_valid_success(VALID + "\n" + VALID + "\n"))

    def test_rejects_failure_and_unknown_fields(self):
        self.assertFalse(has_valid_success(VALID.replace("UPGRADE_RESULT=SUCCESS", "UPGRADE_RESULT=FAILED")))
        self.assertFalse(has_valid_success(VALID + " extra=unexpected"))


if __name__ == "__main__":
    unittest.main()
