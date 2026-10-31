# MMcrm deployment broker

Public, code-only GitHub Actions orchestration for gated incremental MMcrm deployments.

The application and infrastructure repositories stay private. This repository intentionally contains no application source, source archives, customer data, SSH key material, or generated deployment packages.

The manual **Preflight** workflow validates the pinned application PR and CI, builds an archive only on a hosted runner, checks the read-only controller preflight, and retains a hash-only manifest. The separate **Apply** workflow binds to that successful run, shows its target and hashes before review, waits on the protected `mmcrm-apply` Environment, then rebuilds the archive after approval and requires both hashes to match before invoking the fixed SSH dispatcher.

See [the security model and one-time activation checklist](docs/mmcrm-github-actions-deployment.md). No workflow or secret in this repository is active until the required branch and Environment settings are configured.
