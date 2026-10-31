#!/usr/bin/env python3
"""Fetch only the pinned private PR archive; strip API auth on redirect."""
from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

try:
    from .guard import APP_COMMIT, APP_REPO, Reject, validate_redirect
except ImportError:  # direct invocation by the workflow
    from guard import APP_COMMIT, APP_REPO, Reject, validate_redirect

API_URL = f"https://api.github.com/repos/{APP_REPO}/tarball/{APP_COMMIT}"
MAX_ARCHIVE_BYTES = 1_500_000_000


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            validate_redirect(newurl)
        except Reject:
            raise urllib.error.HTTPError(req.full_url, code, "archive redirect rejected", headers, fp) from None
        # Never forward the private-repository bearer token to the CDN.
        return urllib.request.Request(newurl, headers={"Accept": "application/octet-stream"}, method="GET")


def fetch(token: str, output: str) -> None:
    if not token or len(token) > 16_384:
        raise Reject("source_token_invalid")
    request = urllib.request.Request(
        API_URL,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
        method="GET",
    )
    opener = urllib.request.build_opener(SafeRedirect())
    total = 0
    temp = output + ".part"
    try:
        with opener.open(request, timeout=60) as response, open(temp, "xb") as target:
            if not response.geturl().startswith("https://codeload.github.com/"):
                raise Reject("archive_redirect_missing")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise Reject("archive_size_limit")
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        if total == 0:
            raise Reject("archive_empty")
        os.replace(temp, output)
    except Reject:
        raise
    except Exception:
        raise Reject("archive_download_failed") from None
    finally:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: fetch_source.py OUTPUT_TAR_GZ", file=sys.stderr)
        return 2
    try:
        fetch(os.environ.get("GH_TOKEN", ""), sys.argv[1])
        return 0
    except Reject as exc:
        print(f"BROKER_REJECT reason={exc.reason}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
