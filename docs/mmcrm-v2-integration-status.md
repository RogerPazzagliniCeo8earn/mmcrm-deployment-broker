# MMCRM integrated main — v2 deployment integration status (2026-11-06)

**Status: NO-GO for actual deployment.** This branch is a Draft candidate only.

## Independently read-only verified on Linux
- Active release source `df195e6da70206bdd2e690507558a63eaa3705e5`, tree `81791ad20819d34990ba37a0678e292f9db02e44`, profile `crm-only`.
- `mmcrm-staging` active, bound solely to `127.0.0.1:39217`.
- SQLite read-only `quick_check=ok`; 12 projects, 27 reminders, 15 project links, 0 orphan project links, 4 Gmail URL attachments, 0 orphan reminder attachments, 1 local user.
- Gmail URLs exist in SQLite; the external file access / Gmail permissions are unverified.
- **No new live backup** has been created or checked, and no Apply has been executed.

## New candidate, not connected to production
- `ops/broker/main_release_source.py`: only pinned, merged `main` SHA and tree with successful original GitHub CI on that SHA; explicitly checks the current branch head.
- `ops/broker/main_release_gate_v2.py`: canonical schema `format=2`, pinned `app_ref=main`, old/live and target SHAs, content/archive/preflight digests; validates successful preflight run and matching signed envelope bytes. The root verifier must additionally validate the Ed25519 signature.
- `ops/broker/authorize_main_v2.py`: owner must type full target commit locally; signs `mmcrm-deploy-v2`; private signing key never enters GitHub.
- `ops/broker/fetch_source_main_v2.py`: downloads only the pinned tarball; checks codeload redirect and does not send bearer token to redirect host.
- `ops/broker/verify_apply_result_main_v2.py`: strict success output requires service active loopback, database integrity and backup metadata.
- `ops/broker/workflow-candidates/`: **inactive** templates; not inside `.github/workflows`, cannot be dispatched. Templates pin the source, controller ref, hashes, separate Preflight/Apply SSH credentials and owner gate. They are not approved for deployment.
- Infra Draft PR #8 has candidate `upgrade-mmcrm-main-remote.sh`, `mmcrm-deploy-authorization-v2.py` and `mmcrm-deploy-root-v2.sh`. None is live.

## Promotion blockers
1. **Root-owned installation v1→v2 not designed, reviewed or executed.** Current allowed signer is namespaced `mmcrm-deploy-v1`; introducing v2 requires a verified root-owned signer configuration with no bypass, preserving SSH forced commands, exclusive nonce state, controller hash, sudoers, permissions, lock and rollback.
2. Production broker workflow files and `guard.py` still support the old PR #20. Do not merge, move, or activate templates until the whole deployment chain is coordinated with the VPS installation and signed owner consent.
3. Validate actual GitHub source tarball against the archive builder, and run end-to-end synthetic archive/Preflight/Apply simulations before production; CI static checks cannot prove real VPS compatibility.
4. Create and verify a consistent, recoverable SQLite backup (and any real local content) before Apply, with a separate restore plan. **No destructive migration, reset or overwrite of customer/reminder/project records**; data=preserved and previous release must remain available.
5. No Windows/MT5 change, no public DNS or port exposure, no uncontrolled credential disclosure. Any real Apply requires a new per-run owner-signed v2 authorization.

This document is a review artifact, not evidence that production deployment is ready.
