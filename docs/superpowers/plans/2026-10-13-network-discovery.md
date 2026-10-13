# Network Certificate Discovery — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. One review per task, one whole-branch review at the end.

**Goal:** An Admin defines explicit scan scopes (CIDR ranges, hostnames, ports, optional SNI names); Alice connects with TLS, records the presented certificate chain, and shows the certificates Alice does not manage, linked to known targets where it can. Discovery only: nothing on a scanned host is ever changed, no application data is ever sent.

**Architecture:** `internal/discovery` (scope validation and expansion, a rate/concurrency-limited scanner, an isolated `tlsprobe` capture path, ingestion/dedup/retention) runs as job `netdisco.scan` (ReadOnly class) fed by a periodic `netdisco.schedule` task, both on `internal/jobs` (leader, license-lock). Results live in four new tables (migration `00014`), separate from the managed `certificates` inventory so that monitoring, alerts, the Overview horizon and the license counter stay exactly as they are; a read-side query joins by SHA-256 fingerprint to say "managed / known / unmanaged".

**Tech Stack:** Go 1.27.2 (`crypto/tls`, `crypto/x509`, `net/netip`; no new module), PostgreSQL, React/Mantine, Playwright, `cmd/alice-fakefleet` test tool.

**Spec:** alice-v1 specs, rulings, `docs/authz-matrix.md`, `api/openapi.yaml`, `alice-design/IMPLEMENTATION.md`. Facts read from master `f369b83`; each task re-verifies the ones it uses.

**Plan verification:** written on branch `network-discovery` from master `f369b83`. Task 0 has the plan-review gate. **Ordering:** this branch is cut from master and implementation starts after `acme-issuance` is merged to master (migration number, `limit*` classes and `errors.go` would otherwise conflict); the branch is then fast-forwarded by merging nothing: it is re-created from the new master (plan commit cherry-picked, no history rewriting of merged work).

## Global Constraints

- Same repository rules as the ACME plan: fast-forward merges only, no push, `git commit --only`, identity flags, `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`, never touch the untracked review files or `.claude/`, Docker rules (project `alice-e2e` only, `--network host` builds, no testcontainers while Playwright runs), long commands in the background.
- **Air-gap:** no scan exists until an Admin creates a scope and a scan is started by an Operator/Admin or by that scope's own schedule. No default scope, no auto-discovery of "my network", no external lookups (no DNS other than the system resolver for names the Admin listed, no reverse DNS to third parties, no Shodan-like service). No telemetry.
- **Never changes scanned hosts:** the probe performs a TLS handshake, reads the peer chain, closes. It sends no application bytes after the handshake. A source-level test asserts the probe package has no `Write` after the handshake and no `http`/`smtp` import.
- **The one TLS verification bypass.** `InsecureSkipVerify` is used in exactly one function, `tlsprobe.CapturePresentedChain`, because discovery must see expired, self-signed and wrongly chained certificates. It is isolated in `internal/discovery/tlsprobe`, named so, carries `//nolint:gosec // G402: discovery records the presented chain and trusts nothing`, returns only certificates (never a "verified" bit), and a new guard test (`internal/discovery/tlsprobe/guard_test.go`) fails if `InsecureSkipVerify` appears anywhere in the repository outside this file and the three existing allow-listed sites (`notify/pin.go`, `helperproto.go`, `selfcheck.go`) and tests. `TestNoCodeAcceptsAnyHostKey` is untouched and stays green.
- Egress: reuse `internal/platform/netaddr`; add `netaddr.AllowedForScan` (a *stricter* sibling: everything `Allowed` refuses **plus** loopback, unspecified, and Alice's own interface addresses). The scanner dials through a `Control` hook so every resolved address is checked at connect time (DNS-rebinding safe).
- Licensing: discovered endpoints are not targets: `counts_toward_license` is never set; `inventory/counter.go` is untouched; a test asserts `max_targets` accounting is identical before and after discovering 5,000 endpoints. Adopting an endpoint goes through the normal add-target flow and `CheckCanAddTarget`. Scan jobs and the schedule task are `ClassReadOnly`: paused in lock; the start-scan route is `lic: ClassReadOnly` and answers `license.locked` in lock (gated by `guard.go gated()`).
- Secrets: none are stored. The scan stores public certificates only. CSV export uses `csvx` (CSV-injection guard) and the existing export limiter.
- Error codes `ALC-DSC-NNNN`; en/tr strings; authz matrix + tests; OpenAPI; coverage floors **added** for new packages; pincheck green; no lowered floor; Phase 9 UI rules.

## Review Focus

1. **SSRF / pivot:** can any API input reach a loopback, link-local, metadata (169.254.169.254), Alice-own or excluded address — directly, via DNS (including rebinding and a name resolving to both a public and an excluded address), IPv4-mapped IPv6, NAT64/6to4/Teredo forms, decimal/octal IP spellings, or a redirect-like indirection?
2. **Excluded ranges are never dialed** — proven by a dial-counting test, not just filtered after the fact.
3. **Resource abuse:** scope size, ports, SNI names, concurrency, rate, wall-clock, DB growth, response size; a hostile server that trickles bytes, sends a 100 MB chain, or 10,000 certificates.
4. **The bypass is isolated:** the guard test, no verified-bit leaking into the UI as "trusted".
5. **Licensing:** discovery cannot move the target counter; lock mode behaves.
6. **Parsing untrusted certificates:** the fuzz target, no panics, bounded memory.
7. **Honesty of "unmanaged":** definition and its edge cases are explained in the UI.

## Design decisions (answers to the eight questions)

| # | Question | Decision | Trade-off |
|---|----------|----------|-----------|
| 1 | Scope safety | **Explicit scopes only.** A scope = name, list of CIDRs / single IPs / hostnames (max 256 entries), ports (max 16, 1–65535), optional SNI names (max 256), exclusions, enabled flag, optional schedule (every N hours, 1–168, plus optional daily window HH:MM–HH:MM in a chosen time zone), alert-on-expiry flag. **Limits:** ≤ 4,096 addresses per scope after expansion (a /20), ≤ 20,000 endpoints (address × port × sni) per scan; IPv6 only as single addresses or ≤ /120. **Global exclusions** (Admin setting, never overridable by a scope): always-on built-ins (loopback, unspecified, link-local incl. 169.254.169.254 and fe80::/10, multicast, reserved, Alice's own interface addresses and the database host, `fd00:ec2::254`), plus admin-added ranges. **Rate/concurrency:** defaults 20 new connections/s and 32 workers per scan, hard max 100/s and 64; one scan per scope at a time, at most 2 scans at once; connect timeout 3 s, handshake 5 s, whole-scan cap 60 min (then state `timed_out`, partial results kept); cancel at any time (context cancel, workers drain within one timeout). **Who:** Admin creates/edits/deletes scopes and global exclusions (step-up; mirrors `TargetsManage`, Admin-only); Operator and Admin start/cancel scans and read results; Auditor read-only. The API never accepts free-form targets for a scan: only a scope id. | The task text says "admin or operator defines scopes"; Operators can start but not define, because defining is the SSRF-relevant act and adding servers is already Admin-only. Recorded as deviation D1. |
| 2 | Protocol | Direct TLS only in v1 (HTTPS, LDAPS, IMAPS, SMTPS, custom ports). Per endpoint: handshake with `MinVersion TLS10`, `MaxVersion TLS13`, client hello with a broad cipher list; SNI = each listed SNI name; when a scope lists only IPs, one SNI-less handshake. Hostname entries use the hostname as SNI automatically. Capture `PeerCertificates` (full presented chain, max 10 certs, each ≤ 16 KiB, total ≤ 64 KiB, else `chain_too_large`), negotiated TLS version and cipher suite name (free). Close immediately. **STARTTLS is deferred**: `discovery_scope_ports.starttls` enum exists with only `none` so SMTP/IMAP can be added without a migration of meaning. SSL 3.0 and servers offering only legacy suites Go removed cannot be probed (documented limitation L1). | STARTTLS adds protocol state machines with application bytes (violates "never any application data" in spirit), so it is a deliberate follow-up. |
| 3 | Data model | See "Tables". Dedup key is the leaf SHA-256 fingerprint (same definition as `certificates.fingerprint_sha256`). A certificate seen on many endpoints = one `discovery_certificates` row, many `discovery_endpoints` rows pointing at it. **Unmanaged** = fingerprint is not in `certificates`. If it *is* in `certificates` the result shows "Managed by Alice" (with link) and, if that certificate has a live location, "known location". Endpoint→target link: an endpoint whose IP or hostname equals a live target's address/hostname (case-insensitive) shows that target. **Disappearance:** `last_seen_scan_id`, `missed_scans` (incremented when a scan of the owning scope covered the endpoint and it did not answer TLS); after 3 misses state becomes `gone`; `gone` rows older than `retention_days` (default 90, 7–730) are deleted by the scan's cleanup step; `discovery_certificates` with no endpoint and not seen for `retention_days` are deleted; scans keep the last 30 per scope (summary only; per-scan endpoint results are *not* kept, only the endpoint's current state), so growth is O(endpoints + certificates), not O(scans). | No history of "which cert was on this endpoint on 3 March": a ring of the last 5 fingerprints per endpoint (`previous_fingerprints text[]`) is kept to detect rotations. |
| 4 | Licensing | Explicit rule, in code comments, docs and a test (`TestDiscoveryNeverCountsTowardLicense`): the counter reads `targets WHERE counts_toward_license`; discovery writes no `targets` row. "Add as server" opens the existing Add-server dialog prefilled; the existing `CheckCanAddTarget` decides. | |
| 5 | Surfacing | New page **Network discovery** (`/discovery`, tabs Results · Scopes · Scans). Certificates page gets a chip link "Found on the network, not managed (n)" to `/discovery?view=unmanaged`; unmanaged certificates are **not** mixed into the managed inventory table (its counts, exports and alerts are defined by the "monitored" SQL). **Alerts:** new kind `discovered_certificate_expiry` in `internal/alerts`, only for scopes with `alert_on_expiry` (default **off**, because unmanaged findings are noisy), existing thresholds and ledger. **Overview horizon:** decision — *not* included in the managed buckets (it would make "expired: 3" mean something different); a separate quiet metric "Unmanaged certificates expiring within 30 days" shows next to it only when at least one scope exists. Recorded as D2. **CSV:** `GET /discovery/certificates/export` through `reports.export` machinery, `csvx.Writer`, `limitExport`, audit row before first byte. **Audit:** scope create/update/delete, global exclusion change, scan started/cancelled/finished (counts only), export, "adopt" click is not audited (nothing changes). | |
| 6 | Air-gap and budget | Jobs via `internal/jobs` (leader-only scheduler, lock pause). **Budget:** 5,000 endpoints in ≤ 5 min at default 20/s on loopback fleet in `make perf` (`TestPerfNetdiscoScan`: ingest of 5,000 endpoints / 20,000 certificates, list p95 < 300 ms, memory flat); ingestion uses batched `INSERT … ON CONFLICT` (500 rows per statement) and a single transaction per batch; list endpoints are keyset-paginated. "Thousands of certificates on one host" = one IP with up to 256 SNI names × ports; the 20,000-endpoint cap bounds it. | The 20/s default makes a /20 × 1 port take ~3.4 min; documented so admins can raise it to 100/s. |
| 7 | UI | Clarity: Results table (certificate, issuer, expires, found on n endpoints, status chips Unmanaged/Managed/Expired/Self-signed/Wrong name?, "Add as server"), endpoint drawer; Scopes list + form dialog with live size preview ("this scope covers 1,024 addresses × 2 ports") and visible built-in exclusions; Scans table (state, counts, duration, cancel). Empty states explain "nothing is scanned until you add a scope", error states use ALC-DSC codes with plain text. | |
| 8 | Tests | `internal/testutil/fakefleet` + `cmd/alice-fakefleet`: many listeners with: valid chain, expired, not-yet-valid, self-signed, wrong chain order, missing intermediate, SNI-dependent certificates, TLS 1.0/1.2/1.3-only servers, slow-loris, giant chain, resets, non-TLS port, 256-name host. Unit + integration + e2e; fuzz `ParsePresentedChain`; `TestExcludedAddressesAreNeverDialed` (dial-counting `Control` + fleet access log); SSRF table test (spellings, mapped/NAT64, rebinding resolver stub). Tests inject loopback through a test-only constructor that is excluded from the release build (build tag `discoverytest`, checked by `buildtags_test.go` and `release-symcheck`). | |

## Tables (migration 00014)

`discovery_scopes(id, name unique, entries jsonb, ports int[], sni_names text[], exclusions jsonb, enabled, schedule_hours int null, window_start/end time null, window_tz text, alert_on_expiry bool, rate_per_sec, concurrency, created_by, created_at, updated_at, deleted_at)`;
`discovery_scans(id, scope_id, trigger manual|schedule, state queued|running|done|cancelled|timed_out|failed, endpoints_total, endpoints_answered, endpoints_failed, started_at, finished_at, requested_by, error_code)`;
`discovery_certificates(fingerprint_sha256 pk, subject_cn, sans text[], issuer_cn, not_before, not_after, key_algorithm, self_signed, chain_pem, chain_len, first_seen, last_seen)`;
`discovery_endpoints(id, scope_id, address, port, sni, fingerprint_sha256 null, tls_version, cipher, state present|unreachable|gone|no_tls, missed_scans, first_seen, last_seen, last_scan_id, last_error_code, previous_fingerprints text[])` unique `(scope_id, address, port, sni)` with `sni text NOT NULL DEFAULT ''`;
`settings` rows `discovery.exclusions`, `discovery.retention_days`. Down migration drops in dependency order.

## Cross-task contract

**Audit:** `discovery.scope.created|updated|deleted`, `discovery.exclusions.updated`, `discovery.scan.started|cancelled|finished`, `discovery.export`. Details hold ids, names, counts, never certificate bodies.
**Permissions:** `DiscoveryView` (all roles, read token), `DiscoveryOperate` (Admin, Operator; `operate` scope; start/cancel), `DiscoveryManage` (Admin, step-up; scopes, exclusions, retention). **Rate limits:** `limitDiscovery` class (start/cancel 10/min per user) + `limitExport` for the export.
**Error codes (DSC):** 0001 scope too large, 0002 entry not allowed (excluded or reserved address), 0003 invalid entry, 0004 scan already running, 0005 scan cancelled, 0006 scan timed out, 0007 too many scans at once, 0008 scope not found, 0009 invalid schedule, 0010 name does not resolve, 0011 export busy (reuse `ALC-RPT-0004`; not new). Numbers fixed in Task 2.
**API:** `GET/POST /discovery/scopes`, `GET/PATCH/DELETE /discovery/scopes/{id}`, `POST /discovery/scopes/{id}/scans`, `GET /discovery/scans`, `GET /discovery/scans/{id}`, `POST /discovery/scans/{id}/cancel`, `GET /discovery/certificates`, `GET /discovery/certificates/{fingerprint}`, `GET /discovery/endpoints`, `GET /discovery/certificates/export`, `GET/PUT /discovery/settings`. All in OpenAPI with `x-permission`.

## Spec conflicts and deviations (rulings file)

D1 Operators cannot define scopes (task wording allowed it). D2 Overview shows unmanaged expiry as a separate metric. D3 `InsecureSkipVerify` allow-list gains one function (spec `04-security.md:126,254` intends a lint ban; the code relies on gosec + nolint). D4 New outbound destination class (admin-listed scan targets) beyond "managed servers". D5 STARTTLS deferred. D6 Discovery data does not enter the managed `certificates` table (spec has no discovery source "discovered" scanning meaning for this; `certificates.source='discovered'` exists for nginx-config discovery and is untouched). Carries: STARTTLS, scanning from helper nodes, scan history of endpoints, IPv6 ranges larger than /120, adopt-to-bulk-add, SSL 3.0.

## File Structure

```
migrations/00014_discovery.sql
internal/platform/netaddr/scan.go                AllowedForScan, ScanControl
internal/discovery/{scope.go,expand.go,scanner.go,ingest.go,retention.go,link.go}
internal/discovery/tlsprobe/{probe.go,guard_test.go,fuzz_test.go}
internal/jobs/discoveryjobs/                     discovery.scan handler, ScheduleTask, RetentionTask
internal/api/discovery_handlers.go
internal/alerts (discovered_certificate_expiry kind)
internal/testutil/fakefleet  cmd/alice-fakefleet  test/images/fakefleet/Dockerfile
web/src/pages/DiscoveryPage.tsx  web/src/components/discovery/*
web/e2e/phase11.spec.ts
docs/superpowers/rulings/network-discovery.md  docs/security/reviews/network-discovery.md
```

## Tasks

### Task 0: Gate and verification
- [ ] Wait for `acme-issuance` to be merged (or get the owner's ruling). Commit this plan; plan-review subagent against `Review Focus`; record findings in the rulings file.
- [ ] Verify: `netaddr` behaviour for each address class (table test, written first), `alerts` kind registration, `reports.export` reuse, jobs `Task`/`Handle` wiring, `Allow(ClassReadOnly)` meaning in `guard.go`.

### Task 1: netaddr scan policy
- [ ] `AllowedForScan` + `ScanControl` (Alice own addresses injected: interface enumeration at start and per scan). Table test with every spelling in Review Focus 1 (mapped, NAT64, 6to4, Teredo, loopback, 0.0.0.0, 169.254.169.254, `fd00:ec2::254`, own address); `Allowed` unchanged (existing tests untouched).

### Task 2: Migration 00014, error codes, permissions, rate class, job types
- [ ] Failing migration + down + non-superuser tests; error table test and locales and `docs/troubleshooting.md`; rbac + `expectedMatrix` + `make authz-doc`; `jobs.Register("netdisco.scan", ClassReadOnly)`, `netdisco.schedule` and `netdisco.retention` tasks; `limitDiscovery`; license test that the target counter is unaffected.

### Task 3: Scope model and expansion
- [ ] Parsing and validation (CIDR, IP, hostname per RFC 1123, IDNA), size accounting, built-in + global exclusions subtracted *at expansion*, preview computation shared with the API. Table tests, fuzz on entry parsing.

### Task 4: tlsprobe
- [ ] `CapturePresentedChain(ctx, dialer, addr, sni) (Result, error)`; limits (chain size/count, handshake timeout, no application bytes); guard test; fuzz `ParsePresentedChain`; tests against fakefleet: expired, self-signed, wrong order, SNI variants, TLS 1.0/1.2/1.3, non-TLS, slow-loris, giant chain, reset.

### Task 5: fakefleet and alice-fakefleet
- [ ] In-process fleet with access log (used by "never dialed" tests) and the compose container (digest-pinned image, fixed IPs on a dedicated compose network `fleet` plus hostnames as aliases, loopback ctl). Own tests. `testOnlyDirs` entry; release build contains none of it.

### Task 6: Scanner, ingestion, retention
- [ ] Worker pool with token-bucket rate, per-scan context, cancel, wall-clock cap, batch upserts, dedup, `missed_scans`, `gone`, retention cleanup, target linking. `TestExcludedAddressesAreNeverDialed` (dial counter + fleet log), rebinding resolver test, cancel test, timeout test, restart recovery (a `running` scan after a crash is marked `failed` by the leader).

### Task 7: Jobs and schedule
- [ ] `netdisco.scan` handler, `netdisco.schedule` (window and tz aware, leader-only), `netdisco.retention`; lock-mode tests (no dial in lock; manual start → `license.locked`); `wiring_test` passes; not ticked in the e2e build (e2e starts scans manually).

### Task 8: API
- [ ] Routes, OpenAPI, validation, rate limits, authz tests, audit rows, CSV export with `csvx` (CSV-injection test with `=cmd|…` in a CN), pagination, error mapping.

### Task 9: Alerts and Overview metric
- [ ] `discovered_certificate_expiry` kind (only `alert_on_expiry` scopes), email template en/tr, summary metric endpoint field `unmanaged_expiring_30d`; managed counts unchanged (regression test).

### Task 10: UI
- [ ] `/discovery` page with three tabs, scope dialog with live preview, results table and drawer, scans table, certificates-page chip, Overview metric, nav entry for Admin/Operator/Auditor (read-only for Auditor), empty/error states, en/tr, axe, `design-gaps.md` rows. Unit tests.

### Task 11: Perf
- [ ] `TestPerfNetdiscoScan` under `make perf`: 5,000 endpoints / 20,000 certificates; assert budget; record measured numbers in the review document.

### Task 12: E2E
- [ ] `phase11.spec.ts` on all three browsers against `alice-fakefleet`: create scope, preview, scan, results (expired/self-signed/unmanaged), adopt as server (license check), cancel, exclusion refusal, lock mode, export, Turkish, axe, Phase 9 scans.

### Task 13: Documentation
- [ ] Admin guide (scopes, exclusions, rates, retention, what "unmanaged" means), operator guide, `docs/troubleshooting.md`, security overview (SSRF stance, bypass isolation), `docs/security/reviews/network-discovery.md` (method, evidence, **measured** perf, known limitations L1…), rulings file (D1–D6, carries), `CHANGELOG.md`, OpenAPI, authz-matrix.

### Task 14: Final verification and review
- [ ] `make ci` in background and read it; e2e on three browsers; `make perf`; floors added for `internal/discovery`, `…/tlsprobe`, `…/discoveryjobs`; whole-branch review; merge fast-forward; report merge state.

## Not verifiable here

Behaviour on real networks (middleboxes, IDS reactions to scans, real load balancers with SNI routing, IPv6 at scale), real server TLS stacks beyond Go's. Only the fakefleet and loopback performance are measured. Scanning can trip IDS alarms: documented operator warning.

## Amendments after the plan review (binding; they override anything above that disagrees)

Source: adversarial review of this plan against master `f369b83` (blocking B1–B7, important I1–I12, minor M1–M9).

**A1 Job names (B1).** `discovery.schedule` already exists (SSH-key target discovery, `internal/jobs/types.go:73`; `Register` panics on duplicates). This feature uses the namespace `netdisco.*`: `netdisco.scan` (ClassReadOnly, 1 attempt, added to `MaxAttemptsFor`, `maxRunning` cap 2), `netdisco.schedule` (ReadOnly task), `netdisco.retention` (**ClassAlways**, so cleanup also runs in lock). Audit actions keep `discovery.*` only after Task 2 greps the audit allowlist for collisions; otherwise `netdisco.*`. Web job labels are added where the label guard requires it.

**A2 Dynamic policy at dial time (B2, B3, M4).** `netaddr.ScanPolicy` is an interface injected into the scanner; production wires `netaddr.NewScanPolicy(...)` built **per scan** from: built-ins (loopback, unspecified, link-local incl. 169.254.169.254 and `fd00:ec2::254`, multicast, reserved, CGNAT 100.64/10, 198.18/15, documentation ranges), re-enumerated own interface addresses (re-read per batch), the default gateway (`/proc/net/route`), the database host addresses resolved from the DSN, the Admin's global exclusions and the scope's exclusions. NAT64, 6to4, mapped and Teredo forms are unwrapped and the embedded IPv4 is checked against loopback and own addresses too (`64:ff9b::7f00:1`, `2002:7f00:1::` are table cases). `ScanControl(policy)` runs at connect time. **Admin "allowed scan networks"** (setting `discovery.allowed_networks`, default empty = nothing may be scanned) is a positive allowlist: a scope entry outside it is refused at save time and at dial time. This is the stronger control and makes "explicit allow-listed scopes only" true even for a compromised Admin session that has not widened the list (changing the list needs step-up and is audited). Tests inject a permissive `ScanPolicy` from `internal/testutil`; **no build tag** is used (replaces the `discoverytest` tag; I8).

**A3 Hostnames (B5, I7).** A hostname is resolved once at scan start (system resolver, 5 s timeout, ≤ 8 addresses per name). Each resolved IP is its own endpoint (`address`=IP, `host`=name used as SNI), is policy-checked before dialing, and counts against the 4,096/20,000 caps. Excluded IPs are recorded `state='excluded'` and never dialed. Validation-time resolution (`ALC-DSC-0010`) reports only "does not resolve" (never the addresses), with timeout and its own rate limit. Hostname syntax: RFC 1123 LDH, IDNA A-labels, ≤ 253 chars, last label not all-numeric or hex (`2130706433`, `0x7f.1`, `0177.0.0.1` refused), no IP literals, no CR/LF/space. SNI uses the same validator. CIDR parse unmaps `::ffff:` prefixes before size math, rejects zones.

**A4 Data model fixes (B4, I1, I2, I3, M1, M6, M7).** `sni` is `NOT NULL DEFAULT ''` (test: scan twice, row count unchanged). `discovery_certificates` stores the **leaf** PEM and, per endpoint, a chain digest; intermediates are stored once by fingerprint in the same table with `is_leaf=false` and a 16 KiB cap per certificate. Orphan certificates (no endpoint) are purged after **7 days**, not `retention_days`; new fingerprints are capped at 1,000 per scan and 5,000 per scope per day, beyond which only a `cert_churn` counter is recorded. Scope update/delete marks endpoints that left the expansion `gone` immediately and retention removes them; a deleted scope's endpoints are removed by retention. `missed_scans` increments only for endpoints actually attempted, and a scan in which 0 % of attempted endpoints answered while the scope previously had answers does not increment anything (Alice's own network may be down). `last_error_code` is a closed set: `refused|timeout|no_tls|reset|chain_too_large|policy|malformed`; Go error strings are never stored or returned. `previous_fingerprints` trimming is done in SQL; batch upserts de-duplicate in memory first.

**A5 Lock and cancellation (B6, B7, I10).** The scanner calls `license.Allow(ClassReadOnly)` per batch (pattern: `sshkeys/deployreconcile.go:82`) and stops as `cancelled` when locked (test: lock mid-scan, no further dials). Cancellation = `discovery_scans.cancel_requested` polled by the worker; dedupe key `netdisco.scan:<scope>` gives one scan per scope; at most 2 concurrent via the runner's cap table. The cancel route, scope/exclusion/settings routes and reads are `lic: ClassAlways` (a locked install must be able to stop a scan; the start route is `ClassReadOnly`). A scan whose lease is lost is re-queued by the existing reaper; the handler is idempotent (it resumes by marking the scan `failed` if the previous run left it `running` more than one lease ago). Read endpoints (the internal network map) require `DiscoveryView`, granted to Admin, Operator, Auditor; **read API tokens do not get it** (decision D7: the map is sensitive; tokens need `operate`).

**A6 tlsprobe (I4, I5, I6, M2, M3).** Capture raw DER inside `VerifyPeerCertificate` (`rawCerts`) so malformed certificates (e.g. negative serial) are still recorded, then parse in `ParsePresentedChain` (the fuzz target). Wrap the connection in a byte-limiting reader with `SetDeadline` for the whole handshake; map Go's handshake-size error to `chain_too_large`. `CipherSuites` is set explicitly to `tls.CipherSuites()` ∪ `tls.InsecureCipherSuites()`; `MinVersion TLS10`; fakefleet gains an RSA-key-exchange-only server and a SHA-1-signature server (outcome recorded in L1, not assumed). IP-literal SNI sends no SNI (test). The new guard is **AST-based** (like `azurekv/surface_test.go`), skips `_test.go` and `.claude/`, allows `InsecureSkipVerify` in `tlsprobe/probe.go` only plus the existing three production sites by exact file, and forbids `tlsprobe` exporting a `*tls.Config`. D3 is restated as: the repo has no lint ban (gosec G402 + `nolint`); this plan adds the first structural guard.

**A7 Alerts (I11).** `discovered_certificate_expiry` needs: `Kinds()` entry, an `itemsSQL` branch, a ledger object id that is a stable uuid (`uuid_v5` of the fingerprint, since the ledger `object_id` is a uuid), per-kind e-mail template, regression tests that `Items` and Overview counts for managed kinds are byte-identical.

**A8 Perf (I9).** The perf test lives in `internal/api` with tags `integration perf`, named `TestPerfNetdiscoScan` (not `R33`: that ID is taken), and the Makefile `perf` regexp is extended to run it. Numbers corrected: 5,000 endpoints, 5,000 leaf certificates plus 1,000 shared intermediates.

**A9 Task order (I12).** New order: 0 gate · 1 netaddr policy · 2 fakefleet (needed by 3 and 4) · 3 migration + errors · 4 permissions, rate class, job types · 5 scope model · 6 tlsprobe · 7 scanner/ingest/retention · 8 jobs · 9 API · 10 alerts + Overview metric · 11 UI · 12 perf · 13 e2e · 14 docs · 15 final. `testOnlyDirs` gets both `cmd/alice-fakefleet` and `internal/testutil/fakefleet`. Migration number is the next free one **at implementation time** (not hardcoded). Ordering sentence fixed: this branch is deleted and re-created from the new master after `acme-issuance` merges, and the plan commit is cherry-picked (no merged history is rewritten).

**A10 Docs (M2).** The UI's "unmanaged" explanation says: unmanaged means "Alice has no record of this exact certificate"; a certificate in front of Alice-managed hosts via a proxy is unmanaged unless Alice stores its fingerprint. Raw TLS has no redirects, so there is no redirect test (M3).
