#!/usr/bin/env python3
"""Candidate fail-closed source verifier for signed integrated MAIN release.

Standalone review candidate: NOT wired to production Preflight or Apply.
"""
from __future__ import annotations
import re

REPO = "RogerPazzagliniCeo8earn/MegaMonitor"
BRANCH = "main"
APP_COMMIT = "715a40139f2951f2e499b2169a05089ada3e214e"
APP_TREE = "c1b43bf7373c46dc57393dbade3f6a5a35b59a0e"
CI_WORKFLOW_PATH = ".github/workflows/mmcrm-linux-checks.yml"
CI_WORKFLOW_NAME = "MMcrm Linux security checks"
SHA40 = re.compile(r"[a-f0-9]{40}\Z")

class Reject(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason

def require(value: bool, reason: str) -> None:
    if not value:
        raise Reject(reason)

def validate_main_source(branch: dict, commit: dict, statuses: dict, checks: dict, run: dict) -> None:
    """Inputs are constrained projections of GitHub REST responses.

    Important: pin to the immutable commit AND tree plus the main branch head.
    All check-runs must succeed and the actual workflow run must be a successful
    push to main for that exact commit (rather than an arbitrary synthetic status).
    """
    require(branch.get("name") == BRANCH, "source_branch_mismatch")
    head = branch.get("commit")
    require(isinstance(head, dict) and head.get("sha") == APP_COMMIT, "source_branch_head_mismatch")
    require(commit.get("sha") == APP_COMMIT, "source_commit_mismatch")
    commit_body = commit.get("commit")
    tree = commit_body.get("tree") if isinstance(commit_body, dict) else None
    require(isinstance(tree, dict) and tree.get("sha") == APP_TREE, "source_tree_mismatch")
    require(commit.get("html_url") == f"https://github.com/{REPO}/commit/{APP_COMMIT}", "source_repository_mismatch")
    status_records = statuses.get("statuses")
    require(isinstance(status_records, list), "source_statuses_invalid")
    require(not status_records or (
        statuses.get("state") == "success"
        and all(isinstance(s, dict) and s.get("state") == "success" for s in status_records)
    ), "source_status_not_success")
    cr = checks.get("check_runs")
    require(isinstance(cr, list) and len(cr) > 0, "source_checks_missing")
    require(checks.get("total_count") == len(cr), "source_checks_incomplete")
    require(all(
        isinstance(c, dict) and c.get("status") == "completed" and c.get("conclusion") == "success"
        and isinstance(c.get("head_sha"), str) and c["head_sha"] == APP_COMMIT
        for c in cr
    ), "source_check_failed")
    require(run.get("head_sha") == APP_COMMIT and run.get("head_branch") == BRANCH,
            "source_run_commit_mismatch")
    require(run.get("event") == "push" and run.get("status") == "completed"
            and run.get("conclusion") == "success", "source_run_not_success")
    require(run.get("path") == CI_WORKFLOW_PATH, "source_run_workflow_mismatch")
    require(run.get("name") == CI_WORKFLOW_NAME, "source_run_name_mismatch")
    require(isinstance(run.get("repository"), dict)
            and run["repository"].get("full_name") == REPO, "source_run_repository_mismatch")
    require(isinstance(run.get("id"), int) and run["id"] > 0, "source_run_id_invalid")
    require(isinstance(run.get("head_sha"), str) and SHA40.fullmatch(run["head_sha"]) is not None,
            "source_run_sha_invalid")
