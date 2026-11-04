"""Emit a non-sensitive category for a failed OpenSSH command."""
from __future__ import annotations

import re
import sys
from pathlib import Path


def classify(stderr: str, exit_code: int, stdout: str = "") -> str:
    """Return a fixed label; never return or echo captured process output."""
    lower = stderr.lower()
    if any(marker in lower for marker in (
        "host key verification failed", "remote host identification has changed",
        "no matching host key type found", "host key is known",
    )):
        return "host_key"
    if any(marker in lower for marker in (
        "permission denied (publickey", "no supported authentication methods available",
        "too many authentication failures", "load key ", "sign_and_send_pubkey:",
    )):
        return "ssh_authentication"
    if any(marker in lower for marker in (
        "could not resolve hostname", "connection timed out", "operation timed out", "no route to host", "network is unreachable",
        "connection refused", "connection reset", "kex_exchange_identification:",
        "banner exchange:", "connection closed by",
    )):
        return "network_or_ssh_transport"
    remote_output = stderr + "\n" + stdout
    if re.search(r"(?m)^DEPLOY_REJECT reason=[a-z0-9_]+\s*$", remote_output):
        return "dispatcher_rejected_request"
    if re.search(r"(?m)^UPGRADE_ERROR phase=[a-z0-9_-]+ code=[0-9]+\s*$", remote_output):
        return "remote_controller_failure"
    if re.search(r"(?m)^UPGRADE_RESULT=FAILED phase=[a-z0-9_-]+ exit=[0-9]+(?: .*)?$", remote_output):
        return "remote_controller_failure"
    if re.search(r"(?m)^sudo: .+", remote_output):
        return "remote_privilege_or_server_failure"
    if exit_code == 255:
        return "ssh_255_unclassified"
    return "remote_command_failure"


def main() -> int:
    if len(sys.argv) != 4 or not sys.argv[2].isdigit():
        print("SSH_DIAGNOSTIC category=invalid_diagnostic_input", file=sys.stderr)
        return 2
    try:
        stderr = Path(sys.argv[1]).read_bytes().decode("utf-8", errors="replace")
    except OSError:
        print("SSH_DIAGNOSTIC category=diagnostic_capture_unavailable", file=sys.stderr)
        return 2
    try:
        stdout = Path(sys.argv[3]).read_bytes().decode("utf-8", errors="replace")
    except OSError:
        stdout = ""
    print(f"SSH_DIAGNOSTIC category={classify(stderr, int(sys.argv[2]), stdout)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
