import unittest

from ops.broker.ssh_diagnostic import classify


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

    def test_dispatcher_and_server_failures(self):
        self.assertEqual(classify("DEPLOY_REJECT reason=invalid_challenge_request", 255), "dispatcher_rejected_request")
        self.assertEqual(classify("UPGRADE_ERROR phase=preflight code=38", 255), "remote_controller_failure")
        self.assertEqual(classify("sudo: a password is required", 255), "remote_privilege_or_server_failure")

    def test_unclassified_255_does_not_claim_a_cause(self):
        self.assertEqual(classify("", 255), "ssh_255_unclassified")


if __name__ == "__main__":
    unittest.main()
