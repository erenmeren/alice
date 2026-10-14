# Network discovery — controller rulings

Decisions taken on the owner's behalf during autonomous execution of
docs/superpowers/plans/2026-10-13-network-discovery.md on branch `network-discovery` (re-created from `master` c97b8fd
after the ACME merge; plan 87d7e5d, amendments 0d1d29e; owner instruction: run back to back, merge locally, no
check-ins). Each line: decision — why — cost if wrong — how to reverse it, where that is a file to change. Sources: the
plan's "Spec conflicts and deviations", "Carries" and Amendments A1–A10; every `Ruling:` line, deferred minor and carry
of the ledger `.superpowers/sdd/2026-10-13-network-discovery/progress.md`; the rulings in the task reports
(`task-N-report.md` there). The evidence, the findings and the accepted limitations are in
docs/security/reviews/network-discovery.md.

**Nothing here was checked on a real network**: every scan ran against `fakefleet` (in process, on a private interface
address, and as the `alice-fakefleet` e2e container).

## Deviations from the specification and the task wording

- **D1 — Operators start scans but do not define scopes.** The task text allowed "admin or operator" to define scopes.
  Defining a scope is the SSRF-relevant act, and adding servers is already Administrator-only; Operators start and
  cancel scans and read results — cost: an Operator cannot add a scope — reverse: grant `discovery.manage` to the
  Operator role (rbac + `make authz-doc`).
- **D2 — The Overview shows unmanaged expiry as its own metric.** Not in the managed buckets (it would change what
  "expired: 3" means); a quiet line "Found on the network, not managed by Alice, expiring within 30 days: n", shown
  once a scope exists, counts only unmanaged certificates a place still presents and that are not expired — cost: a
  reader looking for all expiring certificates reads two places — reverse: add the kind to the horizon query.
- **D3 — One more `InsecureSkipVerify` site.** The spec (`04-security.md:126,254`) intends a lint ban; the code relies
  on gosec plus `nolint`. The probe adds one function (`tlsprobe.CapturePresentedChain`) and the first structural
  guard (an AST walk, `guard_test.go`) that allows exactly that function and the three older sites — cost: a fourth
  place to audit — reverse: drop discovery.
- **D4 — A new outbound destination class.** Administrator-listed scan targets, beyond "managed servers". Gated by the
  allowed-networks allowlist (A2) — cost: Alice can be aimed at any network on that list — reverse: empty the list.
- **D5 — STARTTLS is deferred.** The `starttls` enum exists with `none` only. STARTTLS needs application bytes, against
  the "never any application data" rule — cost: SMTP and IMAP ports with STARTTLS show no certificate — reverse: a
  follow-up with a state machine per protocol.
- **D6 — Discovery data does not enter `certificates`.** `certificates.source='discovered'` already means nginx
  configuration discovery and is untouched; monitoring, alerts, the Overview horizon and the license counter stay as
  they were. A read-side join by SHA-256 fingerprint says managed, known or unmanaged — cost: two tables of
  certificates — reverse: none cheap.
- **D7 — Read API tokens do not get `discovery.view`.** The results are a map of the internal network; a token needs
  the operate scope (an Auditor holds read tokens only, so an Auditor reads in the browser) — cost: a read-only
  integration cannot read the map — reverse: add `discovery.view` to the read token scope set.
- **Carries (not built):** STARTTLS, scanning from helper nodes, a history of an endpoint's scan results (only the last
  5 fingerprints are kept), IPv6 ranges larger than /120, bulk "Add as server", SSL 3.0, a trigram index for the search.

## Amendments A1–A10 (plan review: blocking B1–B7, important I1–I12, minor M1–M9)

These override the plan's body. A1 job names `netdisco.*` (`discovery.schedule` exists); `netdisco.retention` is
`ClassAlways`, `netdisco.scan` and `netdisco.schedule` `ClassReadOnly`. A2 a dynamic scan policy built per scan
(built-ins, own addresses re-read per batch, default gateway, database host, global and scope exclusions) applied in
`ScanControl` at connect time, plus the allowed-networks allowlist (default empty), and no build tag: tests inject a
permissive policy from `internal/testutil`. A3 host names resolved once at scan start, one place per address, strict
host syntax. A4 `sni` is `NOT NULL DEFAULT ''`; intermediates stored once; orphan certificates purged after 7 days;
new fingerprints capped; `missed_scans` rules; closed error set. A5 lock per batch, cancel flag, cancel and settings
`ClassAlways`, start `ClassReadOnly`; read endpoints need `DiscoveryView` and D7. A6 probe limits, explicit cipher list,
AST guard, byte-limited connection. A7 the alert kind with a uuid-v5 ledger id. A8 `TestPerfNetdiscoScan` in
`internal/api`. A9 the task order. A10 the "unmanaged" wording.

## Rulings by task

### Tasks 0–1: gate and policy

- Ruling: the gate is satisfied — ACME merged to `master`, the plan was reviewed (A1–A10), per-task re-verification
  happens inside each task — cost: rework in Task 1 if wrong.
- Carry C1 (docs, done): the Docker host reachable through LAN or other bridge addresses must be added to the global
  exclusions by hand; CGNAT `100.64.0.0/10` is always excluded, so Tailscale-style installs cannot scan it; Teredo and
  the IETF protocol range are refused as a whole; only the main routing table's gateways are read.
- Carry C2 (done): the scanner dials through `netaddr.ScanDialContext` only, never a proxy, SOCKS or HTTP transport; an
  AST test fails otherwise.
- Carry C3 (done): the plan text still mentions `AllowedForScan` as the whole rule and a `discoverytest` tag; this
  file and the guides describe what was built.

### Tasks 2–4: fleet, migration, permissions

- The fleet network is `10.89.0.0/24` (Alice `10.89.0.2`, fleet `10.89.0.10`); the e2e journeys set the allowed scan
  networks to it.
- Ruling: A6's "capture raw DER in `VerifyPeerCertificate` so malformed certificates are still recorded" is impossible
  in Go 1.27.2 (the client parses before the callback) — a certificate Go cannot parse is recorded as endpoint state
  with `last_error_code='malformed'` and no certificate body; no `x509negativeserial` debug flag, no wire parsing —
  cost: a malformed-certificate host shows as "Unreadable certificate", not as a certificate (L2) — reverse: parse the
  wire format by hand.
- Extra codes beyond the contract's ten: `ALC-DSC-0011` (name taken; the live-name unique index needs its own refusal),
  `0012` (scan interrupted; restore and crash recovery), `0013` (scope switched off; none of the others fits).
- Ruling: `enabled` gates scheduled and manual scans; a restore switches off scopes with a schedule (the schedule is
  kept) — cost: an Administrator switches them on again — reverse: `endDiscoveryScans` in the restore.
- Ruling: restore warnings are English-only, like ACME's.
- Settings rows (`discovery.allowed_networks`, `.exclusions`, `.retention_days`) are unseeded: an absent row is the
  default, and an absent or unreadable allowed-networks setting means nothing may be scanned (fail closed, tested).
- `limitDiscovery` is 10 a minute, per user for a browser session and per token for a token, one bucket for start and
  cancel; `limitDiscoveryResolve` (30 a minute) sits only on the `discovery.manage` routes that resolve names; the size
  preview has its own limiter (60 a minute, no look-up, nothing dialed).
- `netdisco.*` job types are declared in Task 4 and registered by the handlers in Task 8; no Go comment contains the
  literal register call (a label guard regex scans for it).

### Tasks 5–6: scope model and probe

- Exclusions cannot be host names (a name would need a look-up to mean anything); caps are counted before exclusions
  are subtracted, so excluding most of a big range never makes it legal; host bits in a range are refused; the last
  label of a host name starts with a letter; an IP literal with a trailing dot is not accepted as an SNI name; ports are
  de-duplicated.
- Ruling: `no_tls` is coarse — server alerts, "no common version or suite" and an RSA key over 8192 bits all end there,
  and an unreachable network or host ends as `refused`; the UI and docs say "did not complete a TLS handshake", not
  "plain text" — cost: less precise diagnosis — reverse: more closed-set codes (a migration CHECK each).
- Limitation L2b: a non-leaf certificate Go parses but whose dates Alice cannot store is dropped (`DroppedCerts`);
  ingestion stores the presented chain length honestly.
- Closing right after a TLS 1.3 handshake can reset a server that sent a session ticket; no byte is sent, so this
  satisfies "close immediately" — documented.
- The nightly fuzz job's timeout was raised twice (240, 280, 310 minutes) as targets were added; the release fuzz total
  is about 12 hours (24 targets).
- The guard walk skips only what the go tool ignores (names starting with `.` or `_`, `testdata`) and three exact
  paths (`web/node_modules`, `docs/vendor`, `alice-design/dist`).

### Tasks 7–8: scanner, jobs

- Ruling: **managed** = the fingerprint is in `certificates` and on a live location of a live target; **known** = in
  `certificates` without a live location; **unmanaged** = not in `certificates`. The join stays cheap and meaningful —
  cost: relabel — reverse: one `CASE` (`certificateStatusSQL`).
- Ruling: answered = present, malformed or chain too large (the server spoke TLS); failed = refused, timeout, reset,
  `no_tls`. Only failed ones count as misses, so a plain-text service becomes "no longer found" after 3 scans.
- Ruling: a gone endpoint that still does not answer stays gone with its original `gone_since` (otherwise it would never
  reach retention); an answer brings it back. Endpoints of host names that did not resolve in this scan are not marked
  gone. A scan in which no attempted place answered, in a scope that had answers, counts no misses.
- Ruling: the per-day cap on new fingerprints sums the scan rows of the last 24 hours, so pruning never deletes a scan
  younger than 24 hours (a scope scanned more than 30 times a day keeps up to a day of scan rows).
- Ruling: end reasons — disabled scope: cancelled `discovery.scan_cancelled`; deleted scope: failed
  `discovery.scope_not_found`; the job's context ended: cancelled `discovery.scan_interrupted`; lock: cancelled
  `license.<reason>`.
- Ruling: probes already handed to a worker finish and are recorded when the dispatch stops ("workers drain within one
  timeout"); only the job's own context aborts them.
- Ruling: crash recovery is per scan in the handler (started more than one lease ago); retention ends scans past the
  60-minute cap plus 15 minutes, which cannot be alive. With `max_attempts` 1 a lost lease kills the job, so both
  periodic tasks run `EndOrphanScans` (a queued or running scan with no live job is ended failed
  `discovery.scan_interrupted`) — tested.
- Ruling: a manual start with two scans active is refused with `ALC-DSC-0007` rather than queued — clear feedback; the
  per-scope dedupe key and the runner cap still hold.
- Ruling: with a window, an interval of 24 hours or more counts whole local days; a window closes at its local end
  time; a window lying wholly inside the skipped hour opens at the jump for its usual length — cost: one branch in
  `closing` — documented in the admin guide and the UI help.
- After a lost lease three scans may briefly dial (up to one lease, 45 s). The dead-job e-mail for `netdisco.scan` is
  kept as the only failure notice.
- `Runner.OnEnd`, a generic hook, was added to shared jobs code; `x/net` became a direct dependency (no new module).

### Tasks 9–10: API, alerts

- Ruling: cancel is idempotent (it sets `cancel_requested`; a second cancel or a cancel of a finished scan answers 200
  and writes no audit row). Manual starts are serialised by a transaction advisory lock.
- Ruling: lookups at save time cover only the host names a save adds (at most 16 new names; a spent budget answers 503
  `ALC-SYS-0002`), so editing other fields of a scope whose names stopped resolving is not refused.
- Ruling: the summary's unmanaged counts include only leaves a non-gone endpoint presents or last presented; the list's
  `status=unmanaged` filter without `current` still shows every unmanaged leaf until retention purges it.
- Ruling: the four schedule fields are one group in PATCH; `If-Match` is optional on scope PATCH and DELETE; the settings
  PUT has no version (last write wins).
- Ruling: `discovery.scan.finished` is written in the store's finish hook and the runner's end hook; scans ended by
  crash recovery, the orphan sweep, retention or restore get a finished row too (fix round).
- Ruling: in the API integration stack the scan runs with a permissive test policy on a private non-loopback interface
  (loopback is never scannable); the test skips when the machine has none, or fails with `ALICE_REQUIRE_FLEET=1`
  (`make test-integration`, `make coverage`). A testcontainer for the fleet was not chosen: its image build downloads
  the module set.
- Ruling: a disabled scope does NOT alert; there is no scan-failure alert (no framework; the dead-job e-mail stays).
- Migration `00014` was edited in place to widen the `alerts.kind` CHECK; unreleased, so a development database already
  at 14 must go down to 13 and up again (documented).

### Tasks 11–12: UI, performance

- Ruling: decision 7's "Wrong name?" chip is deferred: Alice does not verify names, so there is no data
  (`docs/design-gaps.md`).
- The Results tab shows certificates still found by default (one `current` filter shared with the summary behind the
  Overview line and the chip), so those numbers match the lists they open; "Expired" is shown by the expiry badge only;
  "Add as server" keeps SSH port 22 and is Administrator-only; the preview never triggers a step-up while typing.
- Bisect note: the first four UI commits of Task 11 are red on their own (their texts are in the fifth); history is
  fast-forward only, so accept `git bisect skip` there.
- Ruling: export budgets 5,000 rows under 3 s and 50,000 rows under 30 s (half the server's 60 s write timeout) — cost:
  retune two constants.
- Ruling: no `pg_trgm` index for `q` (adding an extension is an owner-level change; the inventory search is unindexed
  too; 12.4 ms p95 at 5,000, 65 ms at 50,000) — cost: add the extension and a GIN index in a later migration when
  installations pass about 200,000 leaves.
- Ruling: the scan budget is checked as connect time (computed from `DefaultRate`) plus measured storing, not by a real
  250 s scan; seeding goes through the real store path with synthetic certificates; the 45,000 extra leaves of the
  50,000-row export are written directly and labelled synthetic.
- Ruling: no index or migration change was needed for performance; `status` filters moved inside the paged query.

### Task 13: end-to-end

- Ruling: the cancel journey uses a 15-address slow-loris scope at 1 connection a second (a one-endpoint scan ends
  before the cancel poll); the journey starts scans from the Scan now button because the Scans tab polls only while it
  lists an active scan.
- The Overview journey moves the clock forward 61 days because the summary leaves out expired certificates and the fleet's
  certificates last 90 days; this also exercises lock mode.
- Environment note: `make e2e-up` fails in the build environment at image builds that lack `--network host`; the images were
  built with `docker build --network host` and the stack started with compose.

### Task 14: documentation

- Turkish: the guides are English only (`docs/README.md`); only the UI texts and error code texts are mirrored, and
  they exist in both languages.
- Documented as limitations: the Docker host and CGNAT exclusions (L5), `no_tls` wording (L1), the dropped non-leaf
  certificates (L2b), the deferred chip (L3), the whole-day rounding of window schedules (L7), the lost-lease overlap
  (L8).
