# MMcrm signed deployment authorization

MegaMonitor and MMcrm-Infrastructure remain private. This public repository contains orchestration, validation, local signing code, documentation, and synthetic tests only. It contains no application source, source archive, database, SSH key, signing key, or customer data.

## Single-administrator trust model

The GitHub Environment reviewer mechanism is not the deployment authority. It cannot support the required single-administrator workflow with self-review disabled. A dedicated, fixed VPS dispatcher is the authority boundary. Its root-owned verifier trusts one OpenSSH Ed25519 public signing key installed during one-time activation. The corresponding encrypted private key stays on the administrator's device and is never stored in GitHub.

Preflight validates the pinned private application PR and its CI, regenerates the CRM-only archive, and invokes the fixed dispatcher in read-only challenge mode. The dispatcher runs its own read-only preflight and creates a root-owned, expiring, one-use challenge. Its canonical payload binds:

- Preflight run ID and broker commit;
- the pinned application PR, commit, and tree;
- a digest of the exact VPS Preflight result;
- the filtered content hash and exact archive hash;
- a random challenge ID, nonce, and expiry.

The challenge artifact contains no source or archive bytes. The administrator downloads it, inspects the workflow summary, and runs `ops/broker/authorize.py` locally. OpenSSH prompts for the private-key passphrase; the script does not read the key into Python, put the passphrase in arguments/environment, or upload the private key. It writes a compact signed envelope. The administrator starts Apply manually and supplies that envelope together with the Preflight run ID.

Apply validates that the envelope signs the exact Preflight payload, revalidates the private PR and all checks, regenerates the archive, compares both hashes, then sends the envelope and archive to the fixed dispatcher. The dispatcher and root helper reject absent/invalid/expired/replayed signatures, changed claims, a different archive, path/symlink violations, or target pins that do not match. The server consumes the challenge atomically before invoking the existing incremental controller. A failed/rolled-back Apply consumes the grant; obtain a fresh Preflight and signature for another attempt.

The SSH Apply key is a transport identity only. Possession of that key, or changing a broker workflow, cannot authorize different bytes or a different pinned release. The fixed verifier checks the user's signature independently of GitHub workflow logic. Keep the VPS verifier, allowed-signers file, state directory, and root helper owned by root and not writable by the deployment account. The existing controller's verified SQLite backup, integrity checks, preservation checks, and rollback remain mandatory and execute only after signature validation.

## Local authorization (after initial activation)

Use an up-to-date Python 3 and OpenSSH client on Windows PowerShell 5.1 or Linux. Download `deployment-manifest.json` from the successful Preflight run and inspect its summary and hashes. Then run locally:

```powershell
python .\ops\broker\authorize.py .\deployment-manifest.json .\mmcrm-owner-ed25519 .\mmcrm-approval.json
```

The script prints the exact approved run, commit, VPS preflight digest, content hash, and archive hash, then requires you to type the full application commit SHA before it signs. The SSH key passphrase is requested interactively by `ssh-keygen`. Submit the exact one-line JSON in `mmcrm-approval.json` as the `authorization` input to the separate Apply workflow, and enter the same Preflight run ID. Never put the private key or its passphrase in a workflow input or GitHub secret. The approval envelope is a single-use bearer authorization until it expires; keep it private and submit it only to the matching Apply run.

## Workflow and Bridge limits

Preflight cannot call Apply. Apply cannot create an owner signature. The server rejects the workflow even if a repository workflow skips its own checks. A one-time signature can only approve its exact pinned commit, preflight result, run ID, content hash, and archive hash; the root-owned nonce record prevents replay and concurrent duplicate Apply.

A future Bridge can collect test results, show the exact challenge and hashes, launch workflow runs, and report completion. It must not hold the private signing key, passphrase, or an API that signs on the administrator's behalf. The owner must perform the local signing action explicitly for every update.

This design does not protect against compromise of the administrator's device/private key, root access to the VPS, or a deliberate change by the sole GitHub repository owner to the broker's protected settings. No second GitHub account is needed for deployment authorization. The current broker `main` protection still requires a PR and an independent code review; this change does not relax that repository rule.

## One-time activation (not performed by this code change)

1. Review and merge the private controller changes and the broker changes independently; no merge or VPS action is performed by this work.
2. On the administrator's device, generate an encrypted Ed25519 signing key with OpenSSH, store its private half in an approved local secret store, and keep a tested offline recovery copy. Export only the public key. Do not send the private key or passphrase through chat.
3. Using the existing trusted VPS-administrator procedure, install the reviewed fixed dispatcher/verifier, its root-owned allowed-signers entry containing that public key, a root-only one-use challenge store, and the existing forced SSH commands. Provision distinct restricted Preflight and Apply transport identities and pin the SSH host key. This is a one-time server installation; it does not alter the application, database, service, DNS, or firewall.
4. Configure the broker's read-only GitHub App values and restricted SSH transport secrets/host variables. The Apply SSH key is a machine transport credential; the personal Ed25519 signing key is never a GitHub secret.
5. Run a read-only Preflight, inspect its commit/tree, CI and hashes, sign its challenge locally, and only then start Apply. After the controller reports success, verify the installed site and version before requesting another code change.

No key, credential, VPS setting, GitHub secret, Environment, service, database, DNS, firewall, or deployment is configured by these PR changes.
