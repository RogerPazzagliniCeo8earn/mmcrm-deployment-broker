# MMcrm deployment broker

Deployment orchestration belongs in a separate public repository because the current GitHub Free plan does not provide required Environment reviewers or branch protection for this private repository. Keep `MegaMonitor` and `MMcrm-Infrastructure` private. This repository contains the fixed controller and tests only; it has no deployment workflow and stores no deployment credentials.

## Approval model

The public broker has separate manual Preflight and Apply workflows. Preflight checks the pinned application PR, commit, tree, and successful CI; prepares a CRM-only archive; runs the read-only controller preflight; then publishes only a manifest with the source and archive hashes. It does not upload the private source archive.

Apply accepts the successful Preflight run ID. A validation job verifies that run and its manifest, then writes the target commit, tree, content hash, archive hash, and run ID to the workflow summary. A separate `apply` job references the `mmcrm-apply` Environment. GitHub holds that job before its steps run; the SSH Apply key exists only as an Environment secret and becomes available to that job only after an Environment reviewer approves. After approval, the job rechecks the PR and CI, downloads the private controller and source at immutable pins, rebuilds the archive, and requires both hashes to match Preflight before contacting the fixed SSH dispatcher. The archive exists only on the hosted runner during this run and is never uploaded as an artifact.

Configure `mmcrm-apply` with a required reviewer, enable **Prevent self-review**, disable **Allow administrators to bypass configured protection rules**, restrict deployment branches to `main`, and add the SSH Apply private key only as an Environment secret. The initiator cannot approve their own run. A distinct trusted GitHub account with at least read access is therefore required; with only the owner's account, the deployment cannot be approved safely. The Environment approval is a real GitHub deployment gate, independent of workflow input strings.

Protect broker `main` with a rule requiring pull requests, one approving review from someone other than the PR author, dismissal of stale approvals, approval of the latest push, and the broker Linux and Windows CI checks. Disallow force pushes and deletion, enforce the rule for administrators, and do not add a bypass actor. The same trusted second account can review broker code and approve a deployment, but each is a separate GitHub action. Workflows use read-only `GITHUB_TOKEN` permissions; PR CI runs without secrets. Do not use `pull_request_target` or self-hosted runners. Pin every third-party Action to a reviewed full commit SHA.

## Why this is available on GitHub Free

GitHub's current documentation states that protected branches and required Environment reviewers are available on GitHub Free for public repositories. Environment reviewers may be a user or team with read access; if **Prevent self-review** is enabled, the person who initiated the run cannot approve it. The private repositories remain private; only the orchestration code and its tests are public. The public broker must not contain MMcrm source, downloaded source archives, private controller bundles, or customer data.

The GitHub owner remains the administrative trust root and can change repository or Environment settings. Required PR checks and reviewers do not protect against an administrator deliberately disabling those settings. Review the broker workflow diff and Environment deployment details before approval.

## One-time activation checklist (not performed by this PR)

1. Create the public broker repository with only the reviewed orchestration code. Verify `MegaMonitor` and `MMcrm-Infrastructure` remain private.
2. Protect broker `main` with PR-only changes, one independent approval, dismissal of stale approvals, approval of the latest push, and required `linux-broker-ci` / `windows-powershell-51` checks; enforce for administrators, and disallow force push and deletion.
3. Create Environment `mmcrm-apply`; set required reviewer to a distinct trusted account, enable **Prevent self-review**, disable administrator bypass, and restrict deployment branches to `main`.
4. Install a read-only GitHub App on the two private repositories, limited to Contents, Pull requests, and Actions read. Store its App ID and private key as broker repository variable/secret used only for private-source validation and downloads.
5. Through the existing trusted administrator procedure, provision the fixed SSH dispatcher and distinct read-only Preflight / restricted Apply SSH identities. Store the Preflight key in a broker-only secret and the Apply key only in the `mmcrm-apply` Environment. Pin the verified SSH host key. Do not store SSH keys in either private repository.
6. Run Preflight and inspect its hash manifest. Start Apply with that run ID. A distinct reviewer checks the summary and approves the pending `mmcrm-apply` job. After successful controller verification, check the website and version yourself.

No Environment, GitHub App, secret, key, VPS, service, database, DNS, firewall, or deployment is configured by this code change.
