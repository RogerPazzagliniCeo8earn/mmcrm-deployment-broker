import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops.broker.ssh_diagnostic import classify, main


class SshDiagnosticTests(unittest.TestCase):
    def test_host_key_errors(self):
        self.assertEqual(classify("Host key verification failed.", 255), "host_key")
        self.assertEqual(classify("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!", 255), "host_key")

    def test_authentication_errors(self):
        self.assertEqual(classify("Permission denied (publickey).", 255), "ssh_authentication")
        self.assertEqual(classify('Load key "/tmp/private-key": invalid format', 255), "ssh_authentication")

    def test_transport_errors(self):
        self.assertEqual(classify("ssh: connect to host example port 22: Connection timed out", 255), "network_or_ssh_transport")
        self.assertEqual(classify("kex_exchange_identification: Connection closed by remote host", 255), "network_or_ssh_transport")

    def test_dispatcher_and_server_failures_in_stdout_or_stderr(self):
        self.assertEqual(classify("", 255, "DEPLOY_REJECT reason=invalid_challenge_request"), "dispatcher_rejected_request")
        self.assertEqual(classify("", 255, "UPGRADE_ERROR phase=preflight code=38"), "remote_controller_failure")
        self.assertEqual(classify("sudo: a password is required", 255), "remote_privilege_or_server_failure")

    def test_unclassified_255_does_not_claim_a_cause(self):
        self.assertEqual(classify("", 255), "ssh_255_unclassified")

    def test_cli_emits_only_fixed_category_not_captured_diagnostics(self):
        with tempfile.TemporaryDirectory() as temp:
            err_path = Path(temp) / "ssh.err"
            out_path = Path(temp) / "ssh.out"
            err_path.write_text("Permission denied (publickey); opaque-secret-value", encoding="utf-8")
            out_path.write_text("UPGRADE_ERROR phase=preflight code=38 opaque-secret-value", encoding="utf-8")
            captured = io.StringIO()
            with patch.object(sys, "argv", ["ssh_diagnostic.py", str(err_path), "255", str(out_path)]):
                with contextlib.redirect_stderr(captured):
                    self.assertEqual(main(), 0)
            self.assertEqual(captured.getvalue(), "SSH_DIAGNOSTIC category=ssh_authentication\n")
            self.assertNotIn("opaque-secret-value", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
