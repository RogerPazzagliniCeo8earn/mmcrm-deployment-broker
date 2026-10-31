# MMcrm deployment broker

Public, code-only GitHub Actions orchestration for signed, incremental MMcrm deployments. The application and infrastructure repositories remain private. This repository contains no application source, source archive, database, SSH private key, personal signing key, or customer data.

The manual **Preflight** workflow validates the pinned application PR and CI, rebuilds the CRM-only archive, runs the fixed VPS read-only preflight, and creates an expiring one-use challenge bound to the exact run, commit, result, and archive hashes. The owner signs the challenge locally with an encrypted OpenSSH Ed25519 key and manually supplies the resulting one-time envelope to the separate **Apply** workflow. The fixed VPS verifier checks the signature and consumes the nonce before the existing controller performs its verified backup, integrity checks, activation, and rollback handling.

The SSH Apply key is only transport access; it cannot deploy without a valid owner signature accepted by the root-owned VPS verifier. A future Bridge may orchestrate and report workflow runs but cannot hold or invoke the signing key. See [the security model and initial activation steps](docs/mmcrm-github-actions-deployment.md).
