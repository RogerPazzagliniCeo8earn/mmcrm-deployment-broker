#!/usr/bin/env python3
"""Strictly validate the fixed controller's successful Apply result line."""
from __future__ import annotations

import re
import sys
from pathlib import Path

APP_COMMIT = "df195e6da70206bdd2e690507558a63eaa3705e5"
SUCCESS_LINE = re.compile(
    r"UPGRADE_RESULT=SUCCESS"
    rf" app_commit={APP_COMMIT}"
    r" service=active"
    r" bind=127\\.0\\.0\\.1:39217"
    r" database=integrity-ok"
    r" existing-rows=preserved"
    r" backup_id=[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}"
    r" backup_sha256=[0-9a-f]{64}"
    r" prior_release=preserved",
    re.ASCII,
)


def has_valid_success(output: str) -> bool:
    result_lines = [line for line in output.splitlines() if line.startswith("UPGRADE_RESULT=")]
    return len(result_lines) == 1 and SUCCESS_LINE.fullmatch(result_lines[0]) is not None


def main() -> int:
    if len(sys.argv) != 2:
        print("MMCRM_APPLY_RESULT_REJECT reason=invalid_arguments", file=sys.stderr)
        return 2
    try:
        output = Path(sys.argv[1]).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        print("MMCRM_APPLY_RESULT_REJECT reason=result_unreadable", file=sys.stderr)
        return 2
    if not has_valid_success(output):
        print("MMCRM_APPLY_RESULT_REJECT reason=success_marker_invalid", file=sys.stderr)
        return 1
    print("MMCRM_APPLY_SUCCESS_MARKER_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
