## 18. Packaging and Installation

### 18.1 Release tarball layout

One file per release: `alice-1.0.0.tar.gz` (plus `alice-1.0.0.tar.gz.sha256` and a detached signature `alice-1.0.0.tar.gz.sig`, verified with the vendor release public key; its fingerprint is published on the vendor website and in the license delivery email, and the UI shows a copy-paste verification command). It contains everything needed with no internet access.

```
alice/
  install.sh                 # first-time installer
  alice-update.sh            # upgrade script (section 20)
  alicectl                   # small wrapper: docker compose exec alice alice "$@" (subcommands: section 20.3)
  helper/                    # alice-helper static Go binaries (linux amd64/arm64) + sha256, installed by the admin on target hosts (integrations section)
  docker-compose.yml         # production compose file (section 18.4)
  .env.template              # image tags, ports, timezone (no secrets)
  VERSION                    # e.g. 1.0.0
  images/
    alice-1.0.0.tar          # `docker save` of the alice image
    postgres-16.tar          # `docker save` of the pinned PostgreSQL image (by digest)
    images.sha256            # checksums verified before loading
  sbom/
    alice-1.0.0.spdx.json    # SBOM for security teams
  docs/                      # PDF/Markdown copies of the guides (section 21)
  licenses/                  # third-party open-source notices
  CHANGELOG.md
  RELEASE-CHECKLIST-SIGNED.txt   # confirms gosec/govulncheck/Trivy/gitleaks passed for this build
```

`licensectl` is NOT in the customer tarball. It exists only on the vendor machine.

### 18.2 Host requirements

| Item | Minimum | Recommended (hundreds of servers, thousands of certificates) |
|---|---|---|
| OS | Linux x86_64 (Ubuntu 22.04+, Debian 12+, RHEL/Rocky/Alma 9+) | same |
| Docker | Docker Engine 24+ with the `docker compose` v2 plugin | latest 26.x or newer |
| CPU | 2 vCPU | 4 vCPU |
| RAM | 4 GB | 8 GB |
| Disk | 20 GB free on the partition holding `/opt/alice` | 50 GB (backups, audit log growth, PostgreSQL) |
| Network in | TCP 443 from admin/operator workstations | same |
| Network out | TCP 22 to managed Linux/Nginx hosts; TCP 443 to Azure (`login.microsoftonline.com`, `*.vault.azure.net`) only if Azure Key Vault is used; SMTP host if email alerts are used; OIDC provider if SSO is used | same |
| Time | NTP synchronised clock (licensing and certificate math depend on it) | same |
| Privileges | root (via sudo) for install only | same |

No inbound internet access and no outbound internet access are required for install, update, licensing or normal operation.

(Amendment, ACME issuance 2026-10-13, a deviation recorded in `docs/superpowers/rulings/acme-issuance.md`.) ACME issuance adds outbound connections that exist only after an Admin configures them (no preset is
contacted before; creating a provider or hook contacts nothing):

| Direction | Destination | Protocol / port | When |
|---|---|---|---|
| Out | The ACME directory URL and every URL its answers name (account, nonce, order, authorization, challenge, finalize, certificate, ARI `renewalInfo`) | HTTPS (443 or the URL's port) | Terms preview, registration, key rollover, deactivation, Test run, order, renewal, ARI refresh |
| Out | The DNS hook URL | HTTPS | Every DNS-01 present and cleanup |
| Out | `http://<name>/.well-known/acme-challenge/<token>` | HTTP 80 | HTTP-01 self-check before the CA is asked to validate |
| Out | The HTTP-01 Nginx target | SSH 22 | `alice-helper acme-challenge-put` / `-rm` (protocol 7) |

All of them go through `netaddr` (no link-local/metadata), never through an environment proxy, never follow a
redirect, cap answers at 1 MiB (4 KiB for a hook, 1 KiB for the HTTP-01 check) and are refused in licence lock (the
cleanup of already published records excepted). Air-gapped customers use an internal ACME CA and an internal hook.

### 18.3 What `install.sh` does, step by step

Command: `tar xzf alice-1.0.0.tar.gz && cd alice && sudo ./install.sh`
Options: `--dir /opt/alice` (default), `--port 443`, `--hostname alice.example.com` (used in the certificate and the printed URL), `--non-interactive`, `--restore-mode` (section 20.4), `--uninstall` (with `--purge`, see step 6).

The script is idempotent up to step 6: if it fails, fix the problem and run it again. It refuses to run over an existing installation (it tells the operator to use `alice-update.sh` instead).

**Step 1. Preflight checks.** Every check prints `[ OK ]` or `[FAIL]` with a plain-language cause and fix. The script stops at the first failure after listing all failures found.

| Check | Failure message shown |
|---|---|
| Running as root | "This installer must be run with administrator rights. Run it again as: sudo ./install.sh" |
| Linux x86_64 | "Alice needs a 64-bit Intel/AMD Linux server. This machine is <arch>." |
| Docker installed and running | "Docker is not installed or not running. Install Docker Engine 24 or newer (see docs/install-guide), then run this installer again." |
| Docker version >= 24 and compose plugin present | "Your Docker is too old (found 20.10). Alice needs version 24 or newer." |
| Free disk >= 20 GB on target dir | "Not enough free disk space in /opt: 6 GB free, 20 GB needed." |
| RAM >= 4 GB, CPU >= 2 | "This server has 2 GB of memory. Alice needs at least 4 GB." (warning only if >= 3 GB) |
| Port 443 free | "Another program is already using port 443 (nginx, pid 812). Stop it or run the installer with --port 8443." |
| Clock sanity: system year >= release build year, NTP synchronised | "The server clock looks wrong (it says 2019). Fix the date/time first; licenses depend on it." |
| Tarball integrity: `sha256sum -c` on images and files | "The installation package is damaged or incomplete. Download it again and compare the checksum." |
| No leftover installation in target dir | "Alice is already installed in /opt/alice. To upgrade use ./alice-update.sh." |

**Step 2. Create directory layout** (owner `root`, then per-directory ownership to the container UID/GID `10001`):

```
/opt/alice/
  docker-compose.yml   (0644 root)
  .env                 (0640 root:root)  image tags, port, hostname
  secrets/             (0700 root)       compose secret files
    db_password        (0400, uid 10001 via compose secret mode)
    setup_token        (0400)
  keys/                (0700 uid 10001)
    master.key         (0400 uid 10001)  32 random bytes, base64
    ssh_ed25519        (0400 uid 10001)  platform's own SSH key (generated by app on first start)  (superseded by R37: stored encrypted in the database)
  tls/                 (0700 uid 10001)
    server.crt / server.key   (key 0400)
  data/postgres/       (0700 uid 70 or 999, PostgreSQL image user)
  backups/             (0700 uid 10001)  automatic and manual backups
  logs/                (0750 uid 10001)  only if file logging is enabled; default is docker json-file logs
  install.log          (0600 root)       full log of the installer run
```

**Step 3. Generate secrets.**
- DB password: 32 bytes from `/dev/urandom`, base64url, written to `secrets/db_password` with `umask 077`. It is never printed, never put in `.env` or in an environment variable; the containers read it from a file via Docker secrets.
- Master key: 32 bytes from `/dev/urandom` written to `keys/master.key` with mode `0400`, owner 10001. The path is configurable (`ALICE_MASTER_KEY_PATH`, e.g. a separate mount). Full-disk encryption on the host is REQUIRED by the docs (boot passphrase/TPM/PKCS#11 are deferred to v2; the residual risk is stated in `SECURITY-REPORT.md`). It is never printed. The installer warns: "The master key file is included in encrypted backups. Do not copy it by hand."
- Setup token: 24 random characters (Crockford base32, groups of 6, e.g. `K7QX2M-9TPD4R-WB5H8N-3VZC6A`) written to `secrets/setup_token`; the SHA-256 hash is what the app compares. Printed once on screen at the end and stored in `install.log` only as hash.
- The installer generates nothing that the vendor knows; no value ever leaves the host.

**Step 4. Self-signed TLS certificate.** Using `openssl` inside the alice image (no host dependency): ECDSA P-256, valid 397 days, CN and SAN = given hostname, the host's primary IPs and `localhost`. Written to `tls/`. The wizard later offers to replace it with the customer's own certificate. Browsers will show a warning at first visit; the printed instructions and the wizard page explain this in one sentence.

**Step 5. Load bundled images offline.** `docker load -i images/alice-<v>.tar` and `images/postgres-16.tar` after verifying `images.sha256`. Image tags are pinned in `.env` (`ALICE_IMAGE=alice:1.0.0`, `POSTGRES_IMAGE=postgres@sha256:...`). No `docker pull` is ever executed.

**Step 6. Start the stack.** Copy compose file and `.env` into `/opt/alice`, run `docker compose up -d`, then poll `docker compose ps` until both containers are `healthy` (timeout 3 minutes). On timeout: print the last 30 log lines of each container, and "Alice did not start. Send /opt/alice/install.log to support." The installer does not roll back files (a re-run fixes most problems); `sudo ./install.sh --uninstall` stops and removes the containers but never deletes data or backups; only `--uninstall --purge`, after typing `DELETE`, removes `/opt/alice`.

**Step 7. Print next steps.**

```
Alice 1.0.0 is installed and running.

  Open this address in your web browser:   https://alice.example.com/setup
  (Your browser will warn about the certificate. This is expected until you
   install your own certificate in the setup wizard.)

  One-time setup code (needed once, write it down now, it is not shown again):

       K7QX2M-9TPD4R-WB5H8N-3VZC6A

  The setup code stops working as soon as the first administrator is created.
  Lost the code? Run:  sudo /opt/alice/alicectl setup-token --reset
  Daily backups are stored in /opt/alice/backups. Copy them to another machine.
```

### 18.4 `docker-compose.yml` outline

```yaml
name: alice
services:
  alice:
    image: ${ALICE_IMAGE}
    user: "10001:10001"                 # non-root
    read_only: true                     # read-only root filesystem
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]         # bind 443 as non-root
    security_opt: ["no-new-privileges:true"]
    ports: ["${ALICE_PORT:-443}:8443"]  # only published port
    networks: [frontend, backend]
    depends_on:
      postgres: { condition: service_healthy }
    environment:
      ALICE_DB_HOST: postgres
      ALICE_DB_PASSWORD_FILE: /run/secrets/db_password
      ALICE_TZ: ${TZ:-UTC}
    secrets: [db_password, setup_token]
    volumes:
      - ./keys:/opt/alice/keys:rw       # master.key, ssh key (file mode 0400)
      - ./tls:/opt/alice/tls:rw
      - ./backups:/opt/alice/backups:rw
    healthcheck:
      test: ["CMD", "/alice", "healthcheck"]   # HTTPS GET /healthz on localhost, checks DB connectivity and migrations state
      interval: 15s
      timeout: 5s
      retries: 5
      start_period: 40s
    restart: unless-stopped
    deploy:
      resources:
        limits: { cpus: "2.0", memory: 1g, pids: 512 }
    logging:
      driver: json-file
      options: { max-size: "20m", max-file: "10" }

  postgres:
    image: ${POSTGRES_IMAGE}
    user: "999:999"
    read_only: true
    tmpfs: ["/tmp", "/run/postgresql"]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    # NO "ports:" section. The database is reachable only on the internal network.
    networks: [backend]
    environment:
      POSTGRES_DB: alice
      POSTGRES_USER: alice
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets: [db_password]
    volumes: ["./data/postgres:/var/lib/postgresql/data"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U alice -d alice"]
      interval: 10s
      timeout: 5s
      retries: 10
    restart: unless-stopped
    shm_size: 256m
    deploy:
      resources:
        limits: { cpus: "2.0", memory: 2g, pids: 512 }
    logging:
      driver: json-file
      options: { max-size: "20m", max-file: "5" }

networks:
  frontend: {}
  backend: { internal: true }   # no route to the outside world; postgres cannot call out

secrets:
  db_password: { file: ./secrets/db_password }
  setup_token: { file: ./secrets/setup_token }
```

Notes:
- The `alice` container needs outbound access (SSH, Azure, SMTP, OIDC), so it is on `frontend` (normal bridge) as well as `backend`. PostgreSQL is only on the internal `backend` network. (Amendment, ACME issuance 2026-10-13, a deviation recorded in `docs/superpowers/rulings/acme-issuance.md`.) The same `frontend` network carries the optional ACME connections (CA, DNS hook, HTTP-01 check; see 18.2).
- Compose is always run with the explicit project directory `/opt/alice`; systemd is not required because `restart: unless-stopped` plus the Docker service starting at boot brings Alice back after a reboot.
- Log rotation: Docker `json-file` with size caps, so logs cannot fill the disk. Application logs are JSON on stdout, contain no secrets (guaranteed by the secret-leak-to-log tests). Audit log is in PostgreSQL, not in these logs.
- Optional syslog/SIEM forwarding for audit events is configured in Settings, not in compose.

### 18.5 Setup wizard

The wizard is served at `/setup` only while no admin exists. Every step is one screen with plain-language help text and a "Back" button; the position is saved server-side so a browser refresh does not restart it. (Phase 1: no "Back" button and no server-side position before the administrator exists: a reload returns to the setup-code screen and the code is entered again; once the administrator exists, the signed-in administrator resumes at the first unfinished step. "Back" and full resume arrive with the Phase 8 install wizard; R35 addendum.)

**Protection before the first admin exists.**
1. Until the wizard is finished, the only reachable routes are `/setup`, `/livez`, `/healthz` and static assets; everything else returns a "Setup not finished" page.
2. The very first screen asks for the one-time setup code printed by `install.sh`. Comparison is constant-time against the stored hash. After 5 wrong attempts from one IP the wizard locks for 15 minutes; all attempts are logged.
3. A correct code issues a short-lived wizard session cookie (HttpOnly, Secure, SameSite=Strict, 60 minutes idle).
4. When the admin is created (step 2 below), the setup code is deleted from disk and the database; `/setup` returns 404 from then on. Nobody who reaches the port later can take over the installation. Steps after the admin exists are done from Settings by the logged-in admin. (Phase 1: the setup code stops working when the administrator is created; `/setup` stays reachable for the signed-in administrator to finish the recovery passphrase step, `POST /setup/session` answers 404 and the other setup routes answer `401 setup.session_expired`; there is no Settings screen yet; R35.)
5. Recovery from a lost code: `sudo /opt/alice/alicectl setup-token --reset` (requires root on the host and is possible only while no admin exists).

| # | Wizard step | What it writes |
|---|---|---|
| 0 | Enter setup code | `wizard_session` row (expiry); nothing else (Phase 1: a `setup_sessions` row, cookie `__Host-alice_setup`; R35) |
| 1 | Language (English / Türkçe) | `settings.default_language`; browser cookie for the wizard (Phase 1: setting `locale.default`; R35) |
| 2 | Administrator account: name, e-mail, password (min 12 chars, breach-list check), scan QR code for TOTP and enter a 6-digit code, save 10 recovery codes (must tick "I saved them") | `users` row (role Admin, local, Argon2id hash), TOTP secret (encrypted with a DEK), hashed recovery codes; deletes setup token; audit event `setup.admin_created` (first link of the audit hash chain) |
| 3 | Recovery passphrase (entered twice, strength meter, min 16 chars). Text: "This passphrase protects your backups. If you lose it, backups cannot be opened and nobody, including the vendor, can help." Customer must tick "I stored it safely" | Generates an X25519 backup key pair: the public key is stored on the host (`settings.backup_public_key`); the private key is stored ONLY wrapped by the passphrase (Argon2id salt/parameters in `settings.backup_kdf`) and embedded in every backup file (Phase 1: one setting `backup.key` holds the public key, the KDF parameters and the wrapped private key, and no host file is written; R35). Neither the passphrase nor any passphrase-derived key is stored on the host; scheduled backups encrypt to the public key. Audit event |
| 4 | HTTPS certificate: keep temporary self-signed, or upload certificate chain + private key (PEM/PFX, validated and matched) | if uploaded, replaces `/opt/alice/tls/server.*` atomically, key stored `0400`; the HTTPS listener reloads without restart; certificate metadata in `settings` |
| 5 | Email (SMTP), optional, "Skip" allowed: host, port, TLS mode, username/password, sender, "Send test e-mail" button | `settings.smtp` (password encrypted); test result shown; audit event |
| 6 | License: shows Installation ID (with copy button, and "email this to your vendor" text); either upload a license file, or "Start 30-day evaluation (up to 5 targets)" | `license` row (+ status history), or nothing (evaluation runs from the installation timestamp); installation ID and installation timestamp were created at first start and persisted |
| 7 | Platform SSH key and first target: shows the platform's Ed25519 public key with a ready-to-paste one-line command to authorize it on a server; then add first target (Nginx server, Linux host, or Azure Key Vault) with "Test connection" and host key confirmation (fingerprint shown, admin must click "I trust this server") | `targets`, `credentials` (encrypted), `host_keys` (pinned); may be skipped |
| 8 | Finish: summary page, "Take me to the dashboard", link to the backup section and off-host copy advice | `settings.setup_completed_at`; audit event (Phase 1: setting `setup.completed_at`; the Phase 1 wizard goes from step 3 straight to Finish; R35) |

If the admin closes the browser between steps 2 and 8, they log in normally (password + TOTP) and remaining items appear as a "Finish setting up" checklist on the dashboard (passphrase and TLS are mandatory items that show a red banner until done).

---

## 19. License Activation and Renewal (Customer & Vendor Flow)

### 19.1 Customer flow

**First activation**
1. During the wizard (step 6) or later in Settings → License, the customer sees the **Installation ID**, a code such as `ALICE-7F3K-92QD-M4XT-A81P`. It is generated at first start and is stored in the database. It is preserved by backup/restore, so restoring onto a new host keeps the license valid.
2. The customer clicks "Copy" or "Download request file" (a small text file with installation ID, product version, current number of targets) and emails it to the vendor together with the desired number of targets.
3. The vendor replies with a file named `alice-license-<customer>-<yyyymmdd>.alicelic`.
4. The customer opens Settings → License → "Upload license file" (or the wizard step) and selects the file. Alice validates the signature, checks that the Installation ID matches, and shows a preview: "Licensed to: Example Bank A.S. Up to 100 managed targets. Valid from 2026-10-01 to 2027-10-01. Confirm?" On Confirm it takes effect immediately, with no restart. Messages on failure:
   - "This license file was made for a different installation (ALICE-XXXX). Ask your vendor for a license for ALICE-7F3K-....".
   - "This file is not a valid Alice license. It may be damaged or edited. Download it again from the vendor's email."
   - "This license expired on 2026-01-01. Ask your vendor for a current license."
   - "A newer license is already installed. Uploading an older file is not needed." (only when the new file's `issued_at` is older than the current one, except a correction license, see 19.2).

**Renewal**: identical to activation. About 60 days before expiry the banners start; the customer sends the same Installation ID, vendor issues a new file valid 12 months from issuance, customer uploads; it takes effect immediately. To avoid losing time on an early renewal the vendor may set `--from` to the old license's expiry. A renewal with fewer targets than currently in use is accepted: existing targets keep working with a persistent banner and only adding targets is blocked (no end date).

**Where to see the state**: Settings → License shows customer name, license ID, target usage bar ("37 of 100 targets used"), valid until, current phase, and history of past licenses and status changes.

### 19.2 Vendor flow with `licensectl`

`licensectl` is a separate Go command-line program built from the same repository. It never ships to customers. It runs on a vendor laptop that is not connected to any customer system. No network use.

1. **Generate the signing key pair (once, ever).**
   ```
   licensectl keygen --out ~/alice-vendor/   # creates alice-license-private.pem (Ed25519), alice-license-public.pem
   ```
   The private key is passphrase-protected (Argon2id + AES-256-GCM). Backups: two encrypted USB sticks stored in two places, plus a printed paper copy in a safe. If it is lost, no new licenses can be issued for shipped binaries; if it leaks, anyone can forge licenses. The public key is compiled into the binary (`-ldflags` or embedded file) at build time; the release process checks that the embedded key fingerprint equals the vendor's recorded fingerprint. `keygen` refuses to overwrite an existing key.
2. **Issue a license.**
   ```
   licensectl issue --key ~/alice-vendor/alice-license-private.pem \
       --installation ALICE-7F3K-92QD-M4XT-A81P \
       --customer "Example Bank A.S." --targets 100 \
       [--from 2026-10-01] [--months 12] [--features ""] \
       --out alice-license-examplebank-20261001.alicelic
   ```
   Defaults: `valid_from` = today, `valid_until` = exactly 12 months after `valid_from` (a UTC instant), `features` empty. It asks for the key passphrase, prints a summary, requires typing `yes`, and appends a line to the local ledger `~/alice-vendor/issued.csv` (license_id, customer, installation ID, dates, targets, file SHA-256). The ledger is the vendor's record of who owns what.
3. **Inspect and verify a file** (support calls, before emailing).
   ```
   licensectl inspect alice-license-examplebank-20261001.alicelic
   licensectl verify  --pub ~/alice-vendor/alice-license-public.pem alice-license-examplebank-20261001.alicelic
   ```
   `inspect` prints the payload (license_id, customer, installation_id, issued_at, valid_from, valid_until, max_targets, features, format version). `verify` checks the signature and prints `OK` or `SIGNATURE INVALID`.
4. **Correction license** (customer clock jumped and Alice raised a warning; wrong customer name; customer bought more targets mid-term). Same command with `--replaces <license_id>`; it is valid for the same installation, records the replaced ID in the payload, and may carry an earlier `valid_from` than the installed license. Alice accepts a correction license even if its `issued_at` is later or earlier than the installed one, provided the signature and installation ID are valid. Typical use to unblock a customer after a forward clock jump: issue with the current real date, and Alice clears the "clock changed" warning when the admin uploads it.
5. **Vendor checklist per issuance**: confirm the customer's paid order, confirm the Installation ID characters (the ID includes a check digit, `licensectl` rejects typos), issue, verify, send, record in the ledger.

### 19.3 What the customer sees at each phase

All banners are translated (EN/TR); English wording shown. "Admins" = Admin role; "everyone" = all logged-in users.

| Phase | When | Who sees what | Behavior |
|---|---|---|---|
| **Evaluation** | First 30 days from installation (the installation timestamp is stored with the installation ID; a restore does not reset it), no license | Everyone: blue banner "Evaluation mode: 22 days left, up to 5 targets. To continue after that, add a license in Settings → License." Admins get warnings (banner and e-mail) at 7, 3 and 1 days left. | Fully functional, limit of 5 targets. Adding a 6th: "Evaluation allows 5 targets. Upload a license to add more." |
| **Evaluation ended** | 30 days after installation with no license | Everyone: red banner "The evaluation period has ended. Alice is now read-only for changes. Admins can upload a license in Settings → License." | Behaves as **Lock** (row below); no grace period for evaluation. Data is preserved. |
| **Active** | License valid, more than 60 days left | Admins: Settings → License shows "Active until 2027-10-01. 37 of 100 targets used." No banner. | Normal. |
| **Approaching expiry (warning)** | 60, 30, 14, 7, 1 days remaining, computed from `valid_until` | Admins: yellow banner "Your license expires in 30 days (2027-10-01). Send your Installation ID to your vendor to renew." plus e-mail at each milestone (if SMTP configured). Others do not see it. At 7 and 1 days the banner turns orange. | Normal. |
| **Target limit reached** | targets = `max_targets` | Admins: "You are using all 100 licensed targets. To add more, ask your vendor to increase your license." The "Add target" button shows this text when disabled. | Everything works; only adding new targets is blocked. Never causes lock. A renewal with a smaller `max_targets` than the current count keeps existing targets working with a persistent banner. |
| **Grace** | `valid_until` <= now < `valid_until` + 168 h (ACTIVE while now < `valid_until`; instant-based, UTC) | Everyone: red banner "Your license expired on 2027-10-01. Alice will stop automatic work on 2027-10-08 at 12:00 UTC (168 hours after expiry). Contact your vendor now." Admins also get a daily e-mail. | Everything still works. |
| **Lock** | After grace | Everyone: red full-width banner "License expired. Automatic tasks are paused. Your data is safe and certificate expiry alerts still arrive by e-mail. Admins: upload a new license in Settings → License." User-initiated actions that change external systems (deploy, add/remove key, import) are disabled with a tooltip "Not available while the license is expired." and refused by the API with `license.locked`. | Scheduled discovery, auto-deploy and rotation stop; running operations finish or roll back safely; rotations never remove old keys; no data deleted; no revocation. Available: login, license upload, backup/restore, audit log and inventory export. Certificate-expiry e-mails continue, with the line "Note: Alice's license has expired. Renew it to resume automatic deployment." |
| **Recovery** | Valid license uploaded in any phase | Green message "License activated. All features are available again." | Recurring read-only jobs (discovery, Key Vault polling, expiry checks) resume automatically within one minute. Pending external-change jobs (deploys, rotation removals) wait for Admin confirmation; an overdue old-key removal first re-verifies the new key and sends a fresh dry-run notice. A rotation overlap that ended during lock stays in OVERLAP until a valid license is present. |
| **Clock anomaly** | System clock earlier than the stored high-water mark, or a suspicious forward jump (wall clock advanced more than 48 h beyond monotonic uptime since the last hourly tick), or certificate notBefore evidence suggesting the clock is behind | Admins: orange banner "The server clock changed unexpectedly (it says 2026-03-01, but Alice last saw 2026-09-29). Alice is using the later date for license checks. Please correct the server time or contact your vendor." | A backward clock never extends a license. A suspicious forward jump raises an admin warning; the new time may trigger GRACE/LOCK only after 24 h of monotonic uptime at that time, after which it is accepted. Certificate notBefore values are never used in license math; they only raise the warning "system clock appears to be behind". Vendor can issue a correction license. |

Permitted in lock mode, listed explicitly so support can answer customers: log in, view inventory, view/export audit log, export inventory, create/restore backup, upload license.

---

## 20. Upgrade, Backup and Restore

### 20.1 Upgrade with `alice-update.sh`

Command: `cd /path/to/new/alice-1.1.0 && sudo ./alice-update.sh alice-1.1.0.tar.gz` (the script accepts either the tarball path or the extracted directory; the tarball is the primary documented form). Run it during a quiet period; users are logged out only if the migration needs it.

Flow (all output also written to `/opt/alice/update-<timestamp>.log`):

1. **Preflight.** Root, Docker running, an installation exists at `/opt/alice`, current stack healthy, free disk >= 2x current DB size + 5 GB, checksum and signature of the new tarball verified, `VERSION` is newer than the installed one (downgrade refused: "Going back to an older version is only possible by restoring a backup"), and that the upgrade path is supported (each release lists its minimum source version; jumping over a required intermediate version is refused with the exact version to install first).
2. **Announce.** If an admin is logged in, a banner "Update in progress, back in a few minutes" is shown 60 seconds before the stop (skippable with `--now`). Jobs in flight are given up to 2 minutes to complete (the script asks the node to drain: the job queue stops claiming new jobs; there is no public `maintenance` subcommand). The script also asks for the recovery passphrase up front (or `--passphrase-file`), kept in memory for this run only, because an automatic rollback restores an encrypted backup (step 10c).
3. **Automatic pre-upgrade backup.** `alicectl backup --reason pre-upgrade-1.1.0` produces `/opt/alice/backups/alice-backup-<installid8>-<yyyymmddThhmmssZ>-pre-upgrade-1.0.0.alicebak`. The script verifies the file (`alicectl backup verify`: checks header, size and the `.sha256` file without the passphrase; a full test decrypt uses the passphrase, runs in the CI drill and is available via `--deep`). If the backup fails, the update stops before any change.
4. **Save rollback state.** Copies `docker-compose.yml`, `.env` and the current image tag to `/opt/alice/rollback/<old-version>/`; the old image stays loaded in Docker (it is never pruned until the next successful upgrade).
5. **Load new images.** Verify `images.sha256`, `docker load`. No network.
6. **Stop alice, keep postgres running.** `docker compose stop alice`.
7. **Migrations.** `docker compose run --rm alice alice migrate --to-latest` runs versioned SQL migrations in one transaction each, recorded in `schema_migrations`. Migrations are forward-only; each release tests them against a database dump of the previous release. A migration that cannot be transactional is documented and makes the pre-upgrade backup mandatory (it always is).
8. **Start the new version.** Update `.env` to the new image tag, copy the new compose file, `docker compose up -d`.
9. **Health check.** Wait up to 3 minutes for both containers `healthy`; then run `alicectl selfcheck`: database reachable, migrations at expected version, master key decrypts a test record, audit hash chain verifies, license readable, TLS listener answering, background jobs running. Any failure = upgrade failed.
10. **Automatic rollback on failure** (any step 6 to 9 failing):
    a. Stop the new alice container.
    b. Restore the old compose file, `.env` and old image tag from `rollback/`.
    c. Restore the database from the pre-upgrade backup (drop and recreate the `alice` database, `alicectl restore --db-only`, using the passphrase given at the start), because migrations may have changed the schema.
    d. `docker compose up -d`, repeat the health check on the old version.
    e. Print "The update to 1.1.0 failed and Alice was returned to 1.0.0. Your data is unchanged as of <backup time>. Details: /opt/alice/update-<ts>.log. Please send this file to support." Exit code 1. If even the rollback fails, print the exact manual command to restore from the backup file and stop; the backup file is never deleted.
11. **Success.** Print "Alice is now version 1.1.0". Keep the pre-upgrade backup (excluded from the 14-file rotation until the next successful upgrade). Maintenance mode is cleared, banner removed.

Nothing in an upgrade touches `keys/master.key`, `tls/`, secrets or the installation ID.

### 20.2 Backup contents, schedule, naming, retention

- **Contents of a backup file**: PostgreSQL dump (`pg_dump` custom format via the alice container, consistent snapshot), `master.key`, platform SSH key, TLS certificate and key, installation ID and installation timestamp, backup manifest (Alice version, schema version, timestamp, host name). Everything is encrypted as one blob.
- **Encryption**: hybrid (age-style). Each backup is encrypted to the host's X25519 backup public key (created in the wizard), payload sealed with a chunked AEAD (AES-256-GCM, 1 MiB chunks). The backup private key is embedded in the file wrapped by the recovery passphrase (Argon2id, per-file random salt, memory 256 MB, 3 iterations). The host never stores the passphrase or a passphrase-derived key; restore needs file + passphrase. The clear header holds magic `ALICEBAK`, format version, KDF parameters, salt, and Alice version so the file can be recognised; it contains no customer data.
- **Automatic schedule**: daily at 02:30 server-local time (changeable in Settings → Backups: time and retention count; automatic backups cannot be turned off). A missed run (server was off) runs at next start. The last successful backup age is on the dashboard; a banner turns red after 48 hours without success, and admins get an e-mail.
- **File naming**: `alice-backup-<first8ofInstallationID>-<UTC yyyymmddThhmmssZ>-<kind>.alicebak` where kind is `auto`, `manual` or `pre-upgrade-<version>`. Example: `alice-backup-7F3K92QD-20261001T023000Z-auto.alicebak`. A `.sha256` file is written beside each backup.
- **Retention**: keep the 14 newest `auto` backups (default; range 7 to 60). `manual` and `pre-upgrade` backups are never auto-deleted. Deletion of old files is logged in the audit log. A backup is kept only if the file was fully written and verified.
- **Location**: `/opt/alice/backups/` on the same host. This alone does NOT protect against disk or server loss.
- **Off-host copy (customer responsibility, documented)**: the files are already encrypted, so they can be copied anywhere. Recommended: a nightly job on another machine (`rsync -a --ignore-existing ops@alice:/opt/alice/backups/ /srv/alice-backups/` after granting a read-only account, or an `scp`/SMB/NFS/S3 tool), plus quarterly copy to offline media. The operator guide includes a ready-made cron example, and the UI has a "Download backup" button (Admin, MFA re-prompt, audited) for customers who prefer to copy by hand. Rule of thumb printed in the docs: "3 copies, 2 kinds of storage, 1 off-site; and keep the recovery passphrase in a different place from the backups."
- **Restore point objectives**: RPO = up to 24 hours with default schedule (take a manual backup before risky changes); RTO target = 30 minutes on a prepared host.

### 20.3 `alicectl backup` / `alicectl restore` CLI

All commands run inside the container. Wrapper `/opt/alice/alicectl` (in the tarball) is equivalent to `docker compose -f /opt/alice/docker-compose.yml exec alice alice "$@"` (with `-T` when not on a terminal; if the alice container is not running it uses `docker compose run --rm alice alice`). The v1 subcommands are: `backup`, `backup list`, `backup verify [--deep]`, `restore`, `selfcheck`, `audit verify`, `setup-token --reset`, `support-bundle`. Creating a backup needs no passphrase (it encrypts to the backup public key); `restore` and `backup verify --deep` read the passphrase from the terminal (never from arguments or environment) unless `--passphrase-file` is given.

```
# create a backup now (manual)
sudo /opt/alice/alicectl backup                        # no passphrase needed, writes to /opt/alice/backups/ ..-manual.alicebak
sudo /opt/alice/alicectl backup --out /opt/alice/backups/before-firewall-change.alicebak

# list and verify
sudo /opt/alice/alicectl backup list
sudo /opt/alice/alicectl backup verify FILE [--deep]   # --deep asks for passphrase and test-decrypts everything

# restore (destructive: replaces ALL current data)
sudo /opt/alice/alicectl restore FILE                  # asks passphrase, shows manifest, requires typing RESTORE
sudo /opt/alice/alicectl restore FILE --db-only        # used by the update rollback
```

`restore` steps: read header, ask for passphrase, decrypt and verify MAC (wrong passphrase or damaged file = clear message "The passphrase is wrong or the file is damaged. Nothing was changed."), show manifest ("Backup from 2026-10-01 02:30 UTC, Alice 1.0.0, host alice01") and refuse a backup from a newer Alice version than installed, stop background jobs, write a safety copy of current state as `..-pre-restore.alicebak`, restore database, master key, SSH key and TLS files, run migrations if the backup is from an older schema, restart, run `selfcheck`. After restore all active user sessions are invalidated. The installation ID comes from the backup, so the license stays valid.

The web UI has no restore button in v1, by design: restore replaces the encryption key, so it is a deliberate operator action on the host. Settings → Backups shows list, status, "Back up now" and "Download".

### 20.4 Restoring onto a fresh host

Use after hardware loss, or when moving Alice to a new server.

1. Prepare the new host to the requirements in 18.2; copy the release tarball of the same or a newer Alice version (a restore into a newer version migrates the schema forward).
2. Run `sudo ./install.sh --restore-mode`. This performs steps 1, 2 and 5 of the installer (preflight, directories, load images), generates a temporary DB password and setup token as normal, but starts only `postgres`, not the wizard.
3. Copy the backup file to the new host (`/opt/alice/backups/`).
4. Run `sudo ./alicectl restore /opt/alice/backups/<file>` (with only postgres running, the wrapper runs it via `docker compose run --rm alice`). Enter the recovery passphrase. Type `RESTORE`.
5. `docker compose up -d`; log in with the existing accounts. No wizard appears because the restored database has `setup_completed_at`.
6. Change DNS or IP so users reach the new host. If the DNS name or IP differs from the old TLS certificate's SAN, upload a new certificate in Settings → HTTPS, or accept a re-generated self-signed one (the installer offers `--hostname`).
7. Check: Settings → License (same Installation ID, still valid), Targets → run "Test connection" on all; the platform SSH key was restored, so servers still trust it. Old host must be shut down permanently: two copies of the same installation must not both perform rotations.
8. Take a manual backup on the new host and confirm the off-host copy job points to it.

### 20.5 Disaster-recovery drill (documented, recommended every 6 months; required by many regulators)

1. Pick the newest off-host backup. On a spare VM (no network to production targets, so it cannot change anything) run steps 20.4.1 to 20.4.5.
2. Check: login works with password + TOTP; inventory count equals the production count noted at backup time; `alicectl audit verify` reports "Audit chain OK"; a stored credential decrypts (the "Test connection" button on a non-production target, or `alicectl selfcheck`).
3. Record the time taken (RTO) and backup age (RPO) in a drill log template (in `docs/backup-restore.md`).
4. Destroy the spare VM.

### 20.6 CI test: backup, wipe, restore, verify (every release, blocking)

Runs in CI with real PostgreSQL and the release images:
1. Start a stack from the release tarball via `install.sh --non-interactive`; complete the wizard through the API; seed data: 3 users in each role, TOTP enrolled, 10 targets (dockerized Nginx and SSH containers), 50 certificates with private keys, 20 SSH keys, one rotation in progress, 500 audit events, a test license, settings including SMTP secret.
2. Record facts: row counts per table, SHA-256 of a decrypted sample of secrets, audit chain head hash, installation ID, license status.
3. `alicectl backup`; copy file out; check the file has no plaintext (grep for known secret strings and PEM headers returns nothing) and that restore with a wrong passphrase fails without output of data.
4. **Wipe**: `docker compose down -v`, delete `/opt/alice/*` (including `master.key`), remove images' volumes.
5. Fresh `install.sh --restore-mode`, `alicectl restore` with the passphrase.
6. Verify: row counts equal; decrypted secrets equal the recorded hashes (proves master key restore); audit chain verifies and head hash equals; TOTP login for seeded users works; installation ID and license status are unchanged; platform SSH key still authenticates to the dockerized SSH server; the Nginx deployment job can run; the in-progress rotation continues correctly.
7. Negative cases: corrupted file (one flipped byte) is rejected; backup from a newer schema version is rejected; restore with wrong passphrase leaves the current data untouched.
8. Upgrade variant: install N-1, seed, run `alice-update.sh` to N, verify; then a deliberately broken migration in N proves the automatic rollback returns to N-1 with data intact.

The release is blocked if any step fails.

---

## 21. Documentation Plan

All documents are English, Markdown source in `docs/`, rendered to PDF and included in the release tarball (`docs/`) so air-gapped customers have them. Screenshots are produced by the Playwright E2E suite in EN and TR so images stay in sync with the UI. Language: short sentences, no jargon without explanation, every procedure has numbered steps and an expected result. Every error code shown in the UI (format `ALC-<AREA>-<NNNN>`) links to the troubleshooting guide.

| File | Purpose | Audience |
|---|---|---|
| `docs/install-guide.md` | Preparing the server (Docker install for Ubuntu/Debian/RHEL, offline Docker note, firewall ports, DNS name, NTP), running `install.sh`, understanding each preflight message, verifying the tarball checksum/signature, uninstalling. | IT administrator (may not know Alice), customer procurement/infra team |
| `docs/first-run.md` | Walkthrough of the setup wizard screen by screen, what to prepare beforehand (recovery passphrase, SMTP details, certificate, license request), first target, first alert; 30-minute quick start. Includes a "before you begin" checklist. | Admin performing the first setup; the owner during demos |
| `docs/admin-guide.md` | Day-to-day administration: users and roles (Admin/Operator/Auditor), MFA and recovery codes, OIDC SSO setup (Entra ID, AD FS, Keycloak) and group mapping (MFA for SSO users is delegated to the IdP, a documented customer requirement; the setting "SSO users may be Admin" is OFF by default), targets and credentials, discovery, certificates, deployments, SSH key inventory and rotation policies (dry-run, overlap), notifications, dashboard and alerts, audit log export and SIEM forwarding, API tokens, language settings. | Alice administrators and operators |
| `docs/operator-guide.md` | Running the platform: `alicectl` reference (backup, backup list, backup verify, restore, selfcheck, audit verify, setup-token --reset, support-bundle), the host-root `alice admin reset-mfa` command (audited), logs and log locations, health endpoints, resource sizing, disk usage, replacing the TLS certificate, changing SMTP, host reboot behavior, monitoring recommendations (what to alert on), rotating the recovery passphrase, user offboarding, moving to a new host. | System operators / sysadmins, on-call staff |
| `docs/azure-setup.md` | Step-by-step Azure setup: create an app registration (Service Principal), create client secret or upload a certificate (recommended), assign RBAC roles per use case (monitor-only: Key Vault Reader; deploy to Nginx: + Key Vault Secrets User; upload/import: + Key Vault Certificates Officer), scope the role assignment to one vault (and, for Key Vault Secrets User, preferably to the individual cert-backing secrets), legacy access policy alternative with the equivalent permissions, Managed Identity on an Azure VM, firewall and private endpoint requirements (network reachability from Alice), how to add the vault in Alice, how to test, common errors (403 Forbidden, AADSTS7000215, name not found). Azure Portal and `az` CLI commands for each step. | Azure administrators (Cloud team), assisted by Alice admin |
| `docs/nginx-host-preparation.md` | Preparing an Nginx server: create the `alice-svc` service user, add Alice's public key, install the root-owned `alice-helper` static Go binary (admin installs and updates it from the setup snippet; Alice cannot self-update it), restricted sudoers file with the `nginx` profile allowing only `alice-helper` subcommands, directory permissions, SELinux/AppArmor notes, verifying with the UI "Test connection", how to undo everything. Also covers generic Linux hosts for SSH key management (the `linux` sudoers profile, authorized_keys locations, `AuthorizedKeysCommand` limitation). Supported OS list. | Linux/Nginx administrators |
| `docs/backup-restore.md` | What is backed up, schedule and retention, passphrase handling (what happens when lost), off-host copy recipes (rsync, scp, SMB, S3), restore on the same or a fresh host, disaster-recovery drill template with RTO/RPO log. | Operators, IT managers, auditors who ask for BCP evidence |
| `docs/upgrade.md` | Pre-upgrade checklist, running `alice-update.sh`, what the automatic backup and rollback do, reading the update log, supported upgrade paths, how to roll back manually with a backup, release notes location. | Operators |
| `docs/licensing.md` | Customer-facing: Installation ID, evaluation, activating and renewing (with screenshots), what each phase looks like, what lock mode does and does not do, target counting rules (Nginx servers, Linux hosts, Key Vaults; certificates and keys not counted), moving to new hardware, clock changes, FAQ. Vendor-facing appendix (not shipped to customers, kept in the vendor repo as `docs/vendor/licensing-vendor.md`): `licensectl` usage, key safekeeping, ledger, correction licenses. | Customer admins and purchasing; vendor (appendix) |
| `docs/troubleshooting.md` | Symptom-first guide plus table of all error codes (`ALC-...`): meaning in plain English, likely cause, fix, when to contact support. Sections: install/start problems, cannot log in (lost TOTP device, recovery codes), SSH/host key changed alert, Nginx deploy rolled back, Azure 403/auth errors, license messages, email not sent, backup failed, update rolled back. Includes "how to create a support bundle" (`alicectl support-bundle`: version, health, redacted config, last 1000 log lines; never contains secrets, keys or database content). | Everyone; support desk |
| `docs/security-overview.md` | For customers' security teams: architecture and data flow diagram, trust boundaries, what data is stored and where, encryption design (envelope encryption, master key location, Argon2id, AES-256-GCM), authentication and MFA, RBAC matrix, audit log hash chain, network ports table, container hardening, no telemetry and no outbound calls to the vendor, supply chain (SBOM, signed releases, scanner results), threat model summary, known and residual risks (summary of `SECURITY-REPORT.md`), KVKK/BDDK-oriented control mapping table, vulnerability reporting and patch policy. Ready to attach to a customer security questionnaire. | CISOs, security auditors, procurement security reviews |
| `docs/api.md` + `openapi.yaml` | Generated API reference and how to create scoped API tokens; examples with `curl`. | Integrators, automation engineers |
| `CHANGELOG.md` and per-release notes | What changed, migration notes, known issues, minimum upgrade source version. | All |
| `docs/README.md` | Index: "Which document do I need?" decision table by role and task. | All |

Documentation quality gates (part of the release checklist): every command in the guides is executed by a CI docs-test where feasible (install, backup, restore, update commands run against the test stack); every error code in the code base has an entry in `troubleshooting.md` (checked by script); the first-run guide is tested by someone who has never seen Alice before release 1.0. Documentation is English-only in v1 (no Turkish quick-start document).
