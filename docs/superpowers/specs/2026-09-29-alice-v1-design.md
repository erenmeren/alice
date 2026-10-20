# Alice v1 — Design Specification

- **Date:** 2026-09-29
- **Status:** Draft — awaiting owner review
- **Product:** Alice (working name) — self-hosted SSH key and TLS certificate management platform
- **Coordinator:** main session (final decisions and integration)
- **Section authors (virtual team):** Product Manager, Backend Engineer, Azure/Nginx Integration Engineer, Security Architect, DevOps/Release Engineer + Technical Writer, QA Engineer

This document is the entry point. It summarises the eight initial deliverables and links to the detailed sections. When a detailed section and [`alice-v1/00-decisions.md`](alice-v1/00-decisions.md) disagree, the decisions file (including coordinator rulings R1–R37) wins.

| # | Detailed section | Contents |
|---|---|---|
| 0 | [00-decisions.md](alice-v1/00-decisions.md) | All approved decisions and coordinator rulings |
| 1 | [01-product.md](alice-v1/01-product.md) | §1–4 Product summary, personas, scenarios, scope, release plan |
| 2 | [02-architecture.md](alice-v1/02-architecture.md) | §5–10 Architecture, provider interface, data model, jobs, API, i18n |
| 3 | [03-integrations.md](alice-v1/03-integrations.md) | §11–13 Azure Key Vault, Nginx over SSH, Linux SSH keys |
| 4 | [04-security.md](alice-v1/04-security.md) | §14–17 Threat model, security requirements, license protection, secure SDLC |
| 5 | [05-operations.md](alice-v1/05-operations.md) | §18–21 Packaging, install wizard, licensing flows, upgrade/backup, docs plan |
| 6 | [06-quality.md](alice-v1/06-quality.md) | §22–26 Test strategy, license test matrix, failure modes, security tests, phases and DoD |

---

## D1. Product Summary

Alice is a self-hosted platform that gives an organisation a single place to see and safely manage its TLS certificates and SSH keys. It discovers certificates on Nginx servers and in Azure Key Vault, warns before they expire, deploys renewed certificates to Nginx with automatic rollback, and inventories, deploys, removes and rotates SSH keys on Linux servers. Every sensitive action is recorded in a tamper-evident audit log. It installs with one script on a single Docker host, works fully offline (air-gapped), ships with an English and Turkish UI, and is sold as an annual license limited by the number of managed targets.

Target customers: regulated Turkish enterprises (often air-gapped) and internet-connected mid-size companies and MSPs. Scale target: hundreds of servers, thousands of certificates.

## D2. v1 Scope vs Later

**In v1:** central certificate inventory and expiry alerts (60/30/14/7/1 days, configurable); Nginx certificate discovery and safe deployment; Azure Key Vault certificate/key inventory, KV-renewed certificate auto-deploy to Nginx, certificate import; CSR generation and manual upload; Linux SSH key inventory, generate/deploy/remove, scheduled rotation with overlap; RBAC (Admin, Operator, Auditor); local accounts with mandatory TOTP; OIDC SSO (Phase 7); tamper-evident audit log with optional syslog forwarding; email and webhook alerts; offline signed annual licensing with evaluation mode; install script, setup wizard, encrypted backups, update with rollback; EN/TR UI.

**Later:** ACME/Let's Encrypt, LDAP, online license server, editions, Managed HSM, KV key rotation, App Gateway/Front Door/App Service binding, Azure Gov/China, subscription-wide vault discovery, containerised/Kubernetes Nginx, Nginx Plus API, Apache/IIS/HAProxy, Windows, HA/external database, WebAuthn, dual-approval key download, boot passphrase/TPM/PKCS#11 for the master key, audit pruning. Details and reasons: [01-product.md §3](alice-v1/01-product.md).

## D3. Azure and Nginx Integration Boundaries

- **Azure:** Azure Key Vault only (public cloud). Certificates (full), keys (inventory only), secrets (metadata only; the cert-backing secret is read only to deploy to Nginx). Service Principal (certificate recommended) or Managed Identity. Least privilege: Key Vault Reader → + Key Vault Secrets User (scoped per cert secret) → + Key Vault Certificates Officer. Polling every 15 min, no inbound connectivity needed.
- **Nginx:** Ubuntu 20.04+, Debian 11+, RHEL/Rocky/Alma 8+, over SSH with key auth and a restricted service account. All privileged actions go through the root-owned `alice-helper` binary with fixed subcommands and path validation, allowed via a provided sudoers profile. Alice only replaces certificate and key files, never edits Nginx configuration. Deployment = backup → atomic write → `nginx -t` → reload → TLS handshake verification → automatic rollback on any failure.
- **Linux SSH keys:** same connector; `authorized_keys` and host key inventory; `AuthorizedKeysCommand` hosts are detected and not managed.
- **Why these:** Key Vault is Azure's central store for certificates and keys; SSH needs no agent on customer servers, which security teams approve more easily. Details: [03-integrations.md](alice-v1/03-integrations.md).

## D4. Architecture and Technology Rationale

Two containers: `alice` (single Go binary: HTTPS, REST API with OpenAPI, embedded React/TypeScript + Mantine UI, background jobs) and `postgres` (internal network only). Go was chosen for a small static binary with low CVE surface, strong crypto/SSH/X.509 support, the official Azure SDK, and because compiled code makes license-check removal harder than interpreted languages. Providers (`azurekv`, `nginx`, `linuxssh`) are compile-time plugins behind one interface; no runtime code loading. Secrets use envelope encryption (AES-256-GCM, per-secret DEK wrapped by a master key held in a file outside the database). Details: [02-architecture.md](alice-v1/02-architecture.md).

## D5. Installation and License Activation (outline)

1. `tar xzf alice-1.0.0.tar.gz && cd alice && sudo ./install.sh` (works offline; bundled images).
2. Open `https://<server>` and enter the one-time setup token printed by the installer.
3. Wizard: language → admin account + TOTP → recovery passphrase → HTTPS certificate → SMTP (optional) → license (upload file or start 30-day evaluation) → first target.
4. Licensing: the wizard shows the Installation ID (`ALICE-XXXX-XXXX-XXXX-XXXX`); the customer emails it; the vendor runs `licensectl issue --installation <ID> --customer "X" --targets 100`; the customer uploads the signed file. Renewal is identical and takes effect immediately.

Details: [05-operations.md §18–19](alice-v1/05-operations.md).

## D6. License Expiry, Grace Period and Lock

| State | When | Behaviour |
|---|---|---|
| Evaluation | First 30 days after install, max 5 targets | Full function; warnings at 7/3/1 days; ends directly in LOCK |
| Active | now < `valid_until` | Full function; admin warnings at 60/30/14/7/1 days remaining |
| Grace | `valid_until` ≤ now < `valid_until` + 168 h | Full function; red banner for all users |
| Lock | after grace | See below |

**In lock:** scheduled jobs that change external systems stop; user-initiated external changes are refused; in-flight operations finish or roll back safely; rotations never remove old keys; nothing is deleted, no certificate is revoked, no data is modified. Login, license upload, backup/restore, audit and inventory export remain available. Certificate expiry alert emails continue, marked "license expired". After renewal, read-only recurring jobs resume automatically and pending change jobs need Admin confirmation.

**Continuity window (owner decision 2026-10-20, R44):** for 45 days after a licensed lock begins, the automatic upkeep of what is already managed goes on: ACME renewal of issued certificates, automatic deployment to the locations they are already bound to, and the Key Vault polls that see renewed versions. Nothing a person starts runs in that window (no new certificates or orders, targets, imports, uploads, CSRs, manual deploys, SSH key work or discovery scans). After the 45 days this stops too. The evaluation has no window. Administrators get an email when the lock begins (naming the window's end) and another when the window ends; the banners and the License page say until when certificates keep renewing.

**Renewal after an outage (owner decision 2026-10-20, R45):** a failed ACME renewal is classified as an outage that clears by itself (the certificate authority, its DNS lookups or the DNS hook unreachable or slow, a rate limit, a server error) or a cause that needs a person (a setting, the account, a refused name, a wrong answer to the check). Only five failures that need a person stop automatic renewal; after outages Alice keeps trying by itself, at least once a day and more often in the certificate's last week, until it is renewed or has expired. **Check again and resume** (formerly **Renew now**, an Administrator's act) re-arms and orders at once. While renewal fails, Administrators are reminded 14, 7, 3 and 1 days before the certificate ends, and the certificate's page shows how the last reminder was delivered.

**Target limit:** exceeding it (including after a smaller renewal) only blocks adding new targets.

**Clock:** the license uses the highest trusted time seen (MAC-protected high-water mark, build-time floor), so rolling the clock back never extends a license. Suspicious forward jumps warn first and only count after 24 h of uptime. Certificate dates are used only for warnings, never to lock.

**License server (v2):** the installed signed file is always authoritative; server unreachability will never lock.

## D7. Threat Model and Initial Security Checklist

The top threats are platform compromise (Alice can reach every managed server), theft of the database or backups, a malicious or compromised operator, MITM on SSH/TLS, license bypass, and supply chain. The main mitigations are envelope encryption, host-key pinning, the `alice-helper` allowlist, MFA and step-up authentication, RBAC, the hash-chained audit log with external forwarding, signed releases, and CI scanning (gosec, govulncheck, Trivy, gitleaks, SBOM).

**Known residual risks, stated openly:**
- Root on the Alice host, or a disk snapshot of it, exposes both the database and the master key. Customers must use full-disk encryption.
- A compromised Alice reaches all targets.
- The hash chain alone cannot stop someone who holds the master key from rewriting the audit log. External forwarding is the real protection.
- A cloned installation can run a second copy.

Full STRIDE model, SEC-requirements and the 28-item release checklist: [04-security.md](alice-v1/04-security.md).

## D8. Development Phases and Completion Criteria

| # | Phase | Done when |
|---|---|---|
| 0 | Skeleton and CI | `docker compose up` works, empty EN/TR UI, CI green |
| 1 | Core: local auth + TOTP, RBAC, audit, secret store, wizard basics | Admin created via wizard, TOTP login, three roles behave differently, audit chain verifies |
| 2 | Licensing + `licensectl` | License issued and uploaded; demo clock shows warnings → grace → lock → renewal |
| 3 | Provider framework + Linux/SSH targets + `alice-helper` | Host added, host key confirmed, SSH keys appear in inventory |
| 4 | Nginx certificate discovery and deployment | Certificates listed; deployment works; a broken certificate is rolled back automatically |
| 5 | Azure Key Vault | Vault added; certificates/keys visible; KV renewal auto-deploys to Nginx |
| 6 | SSH key lifecycle and rotation | Generate/deploy/remove; rotation with overlap; lock pauses rotation |
| 7 | Alerts, dashboard and OIDC SSO | Expiry emails, dashboard, filters, SSO login with group → role mapping |
| 8 | Packaging and release | `install.sh`, update with rollback, backup/restore drill, docs, `SECURITY-REPORT.md`, release checklist |

Each phase gets its own implementation plan. At the end of each phase the owner receives what works, how to try it, and known limitations. Full Definition of Done and owner verification steps: [06-quality.md §26](alice-v1/06-quality.md).
