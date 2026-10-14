# Security Review — network certificate discovery

Scope (plan `docs/superpowers/plans/2026-10-13-network-discovery.md`, "Review Focus" 1–7 and amendments A1–A10): Alice
connecting out to addresses an administrator listed, to record the certificate chains servers present: the scan
policy (`internal/platform/netaddr/scan.go`: built-ins, own addresses, gateway, database, exclusions, allowed
networks, checked on the socket); the scope model and expansion (`internal/discovery/scope.go`, `expand.go`); the
isolated probe (`internal/discovery/tlsprobe`, the one TLS verification bypass); the scanner, ingestion, linking and
retention (`internal/discovery`); the jobs `netdisco.scan`, `netdisco.schedule`, `netdisco.retention`
(`internal/jobs/netdiscojobs`); migration `00014`; 17 API routes with three permissions (`discovery.view`,
`discovery.operate`, `discovery.manage`) and two rate classes; the alert kind `discovered_certificate_expiry` and the
Overview metric; the Network discovery page and its dialogs; the test fleet (`internal/testutil/fakefleet`,
`cmd/alice-fakefleet`).

**Nothing in this work was run on a real network.** Every scan ran against `fakefleet` (in process, on loopback or on
a private interface address of the test machine, and as the `alice-fakefleet` container on an internal Docker
network). Middleboxes, intrusion detection reactions, load balancers that route by server name, real server TLS
stacks beyond Go's and IPv6 at scale are not verified. Performance numbers are from one machine with simulated servers
(section "Measured performance").

The controller's rulings, with what each costs if wrong, are in `docs/superpowers/rulings/network-discovery.md`.

## Method

Built in 15 numbered tasks on branch `network-discovery` (re-created from `master` c97b8fd after ACME was merged; plan
87d7e5d, amendments 0d1d29e). Before any code an adversarial plan review ran against `Review Focus` (blocking B1–B7,
important I1–I12, minor M1–M9); its findings became amendments A1–A10, which override the plan's body (the order of
tasks, the job namespace `netdisco.*`, a dynamic policy at dial time, the allowed-networks allowlist, host name
rules, the lock and cancel model, the probe's limits, alerts, the perf test's name and place, the docs rule).
Every task was implemented by an agent and reviewed by another that did not write it; Important findings went back as
fix rounds that were reviewed in scope. Tests were written first and their RED output recorded in the task reports;
implementers and reviewers mutated the code under test (removing a check, a gate or a condition) to see the named
tests turn red. Fuzz targets cover every parser of attacker-controlled bytes (entries, names, expansion, presented
chains). Task 12 measured performance and read the query plans; Task 13 drove the feature through the browser against
the fleet in three browsers. This review was written in Task 14, before Task 15's `make ci`, full e2e and whole-branch
review; their outcome is in the "Final run" column, the findings and the rulings.

## Evidence

"Development runs" are the latest results the implementers recorded in their task reports, with the task named.
"Final run" is Task 15's and is filled in there; until it is, the cell says `PENDING (Task 15)`. `NOT RUN (owner)`
cells are never a pass.

| # | Check | Command | Expected | Development runs | Final run |
|---|---|---|---|---|---|
| 1 | Unit tests, race detector | `go test -race ./...` (touched packages: `internal/platform/netaddr`, `internal/discovery/...`, `internal/jobs/...`, `internal/api`, `internal/alerts`, `internal/archtest`) | ok | ok in every report (Tasks 1–13) | PENDING (Task 15) |
| 2 | Integration tests (PostgreSQL testcontainer, fleet on a private interface) | `ALICE_REQUIRE_FLEET=1 go test -race -tags integration` per package | ok | migrations, backup, discovery, discoverysvc, netdiscojobs, alerts, api ok (Tasks 3–12); `internal/api` 207 s (Task 12) | PENDING (Task 15) |
| 3 | Scan policy for every spelling | `TestScanPolicyEverySpelling` (about 110 addresses: loopback, 0.0.0.0, 169.254.169.254, mapped, NAT64, 6to4, Teredo, `fd00:ec2::254`, CGNAT, own addresses) and the allowlist/exclusion cases | ok | ok (Task 1) | PENDING (Task 15) |
| 4 | Excluded addresses are never dialed | `TestExcludedAddressesAreNeverDialed` (dial counter plus the fleet's access log), the rebinding resolver test (a name that resolves to a public and a refused address: one dial) | ok | ok (Tasks 5, 7) | PENDING (Task 15) |
| 5 | The only egress is the scan policy | `TestDiscoveryDialsOnlyThroughTheScanPolicy` (AST: no HTTP client or transport, proxy or SOCKS dialer, other `net.Dial*`, `Dial/Proxy/Control` hook) | ok | ok, with violation fixtures (Task 7) | PENDING (Task 15) |
| 6 | The bypass is isolated | `internal/discovery/tlsprobe/guard_test.go`: `TestInsecureSkipVerifyOnlyInTheAllowedSites` (AST walk of the repository), `TestTheBypassIsOneLineOfCapturePresentedChain`, `TestProbePackageSurface` (no exported `*tls.Config`, no `Write` after the handshake, no `http`/`smtp` import, every `tls.Client` result used through two methods only), `TestResultCarriesNoVerdict` | ok | ok with fixture trees for each rule (Task 6) | PENDING (Task 15) |
| 7 | Existing host key test untouched | `TestNoCodeAcceptsAnyHostKey` | ok | ok (Task 6) | PENDING (Task 15) |
| 8 | Licensing | `TestDiscoveryNeverCountsTowardLicense` (the target counter before and after thousands of endpoints), `TestLockMidScanStopsDialing`, `TestTheLockCancelsAQueuedScan`, `TestLockPausesTheScheduleButNotTheRetention`; the e2e lock journey (403 `ALC-LIC-0001`, nothing dialed) | ok | ok (Tasks 7, 8, 13) | PENDING (Task 15) |
| 9 | Authorization matrix and route rules | `go test ./internal/api -run 'Authz\|OpenAPI\|Spec\|Discovery'`; `make authz-doc` | ok; no diff | ok; no diff, 202 matrix IDs, 0 gaps (Task 9) | PENDING (Task 15) |
| 10 | Rate limits follow permissions | `TestDiscoveryLimitsFollowTheirPermissions`, `TestDiscoveryRouteTable`, per-user and per-token limit tests | ok | ok (Tasks 4, 9) | PENDING (Task 15) |
| 11 | No internals in errors | `TestDiscoveryErrorsCarryNoInternals`; `last_error_code` is a closed set (`refused timeout no_tls reset chain_too_large policy malformed`), Go error text never stored or returned | ok | ok (Tasks 6, 9) | PENDING (Task 15) |
| 12 | CSV export | `csvx` guard, formula injection test with a `=cmd\|…` common name, audit row before the first byte | ok | ok (Task 9) | PENDING (Task 15) |
| 13 | Fuzzing | `make fuzz-discovery` (`FuzzParseEntry`, `FuzzCanonicalHostname`, `FuzzExpand`), `make fuzz-tlsprobe` (`FuzzParsePresentedChain`: kept plus dropped certificates equal those presented, the leaf is the first) | no crash | ok; `FuzzParsePresentedChain` about 2.77 M executions in 20 s (Task 6); `make fuzz-release`: not run | `make fuzz-release`: NOT RUN (owner) |
| 14 | Performance | `make perf` (`TestPerfNetdiscoScan` and R32) | within budgets | PASS, numbers below (Task 12) | PENDING (Task 15) |
| 15 | Playwright, three browsers | `make e2e-up`, then `npx playwright test e2e/phase11.spec.ts` on chromium, firefox, webkit | all pass | 6 tests (3 journeys, English and Turkish) green on all three browsers, twice; axe checks soft, none reported (Task 13) | PENDING (Task 15) |
| 16 | Coverage floors | `make coverage` | every floor holds | discovery 98 (measured 99.5), tlsprobe 97 (99.3), netdiscojobs 97 (98.2), discoverysvc 85, fakefleet and alice-fakefleet 90; `internal/jobs` 90.6 against its floor; no floor lowered (Tasks 5–9, 12) | PENDING (Task 15) |
| 17 | Lint, docs check, matrix check, pin check, translations | `make lint`, `make i18n-check` | exit 0 | exit 0 in every task | PENDING (Task 15) |
| 18 | No new module, notices unchanged | `make notices` | identical | `golang.org/x/net` became a direct requirement (it was already in the module graph); no new module, no new npm package (Task 5) | PENDING (Task 15) |
| 19 | Behaviour on a real network | — | — | — | NOT RUN (owner) |

Other evidence recorded by the implementers and reviewers:

- Hostile servers (fleet kinds): slow-loris (the handshake deadline holds), a giant chain (a Certificate message claiming 16 MiB, sent in up to 100 MiB) and a huge real chain of many certificates
  (`chain_too_large`, the byte limiter stops the read), a reset during the handshake, a plain-text service,
  256 names on one address, a malformed certificate, a server that depends on the name asked for. No kind caused a panic
  or unbounded memory (Tasks 2, 6).
- "Never any application data": the fleet's access log records bytes after the handshake; the e2e journey asserts zero
  for every scanned kind (Task 13). The probe closes the connection straight after the handshake; a TLS 1.3 server
  that sent a session ticket may log a reset (documented).
- Cancellation, the wall-clock cap, crash recovery (a scan whose job died is ended `discovery.scan_interrupted`;
  `TestTheSweepLeavesScansOfRunningJobsAlone` shows a live scan is left alone), idempotent cancel, one scan per
  scope, two at once (Tasks 7, 8, 9).
- Schedule and window arithmetic with daylight saving time: spring forward and fall back, windows across midnight and
  lying in the skipped hour, intervals of 24 hours or more counting whole days (`TestDueOnTheSpringForwardDay` and
  neighbours, Task 8).
- Retention: gone places, deleted scopes, orphan certificates after 7 days, scans beyond the newest 30, all inside
  one transaction, in lock too, touching only `discovery_*` rows (Tasks 7, 8).
- Restore: in-flight scans ended, scheduled scopes switched off, with a warning; the dump and load round trip covers
  the new tables (Task 3).
- Alerts: managed counts and items byte-identical with and without discovery (regression tests); a switched-off scope
  sends nothing; the e-mail carries addresses, scopes and a link, never a certificate body (Task 10).

## Measured performance

Task 12, `make perf`. Machine: Intel Core Ultra 7 258V (8 cores), 30 GiB RAM, Linux 7.2.9 (CachyOS), Docker 29.9.0,
PostgreSQL 16-alpine (testcontainer), Go 1.27.2; the HTTP handler in process (no network), one client; 10 warm-up and
100 measured requests per row, p95 by nearest rank. Data: 5,000 places, 5,000 leaf certificates and 1,000 shared
intermediates, 20 scopes, 40 scans, 500 servers, 5,000 inventory certificates (500 managed, 250 known, 4,250
unmanaged). The data went through the scanner's own storage path (`CreateScan`, `BeginScan`, `PrepareScan`, `Ingest`,
`FinishScan`) with synthetic certificates, not through TLS handshakes.

| Request (`GET /api/v1/discovery/…`) | p50 ms | p95 ms | Budget | p95 at 50,000 leaves |
|---|---:|---:|---:|---:|
| certificates, default (`status=all&current=true`) | 1.7 | 2.7 | 300 ms | 1.7 |
| … keyset page 14 | 0.9 | 1.3 | 300 ms | 1.4 |
| … `status=unmanaged` | 1.4 | 1.7 | 300 ms | 1.4 |
| … `status=managed` | 1.8 | 2.1 | 300 ms | 4.6 |
| … `status=known` | 3.0 | 3.8 | 300 ms | 6.1 |
| … `status=known`, page 14 | 3.8 | 4.5 | 300 ms | 10.2 |
| … `q=svc-0042` (common name) | 11.6 | 12.2 | 300 ms | 65.6 |
| … `q=alt-1234` (alternative name only) | 11.6 | 12.4 | 300 ms | 65.7 |
| … `q=no-such-name` (walks every leaf) | 11.6 | 12.3 | 300 ms | 67.5 |
| … `expiring_within_days=30` | 0.7 | 1.3 | 300 ms | 1.6 |
| … `expired=true` | 1.9 | 2.9 | 300 ms | 3.3 |
| … `self_signed=true` | 3.7 | 4.6 | 300 ms | 10.1 |
| … `scope_id=` | 2.8 | 3.5 | 300 ms | 3.9 |
| certificates/{fingerprint} | 0.5 | 1.1 | 300 ms | – |
| endpoints | 0.8 | 1.2 | 300 ms | – |
| endpoints, page 14 | 0.6 | 0.8 | 300 ms | – |
| endpoints, `scope_id=` | 0.8 | 1.1 | 300 ms | – |
| endpoints, `scope_id=`, page 2 | 0.7 | 1.1 | 300 ms | – |
| endpoints, `fingerprint=` | 0.2 | 0.3 | 300 ms | – |
| scans | 0.4 | 0.6 | 300 ms | – |
| scopes | 0.7 | 1.2 | 300 ms | – |
| settings | 0.3 | 0.4 | 300 ms | – |
| summary (the Overview metric) | 8.2 | 8.9 | 500 ms | 25.3 |

| Other | Measured | Budget |
|---|---|---|
| CSV export, 5,000 rows, 5 runs | p50 82 ms, max 85 ms | 3 s |
| CSV export, 50,000 rows (synthetic), 2 runs | p50 1,009 ms, max 1,059 ms | 30 s |
| Storing 5,000 places in 20 scans (begin to finish) | 955 ms in total (other runs 707–747 ms); per scan p50 44 ms, p95 62 ms | – |
| A second identical round (every certificate known) | 881 ms | – |
| Scan budget: connect time at the default 20 a second (computed, 250 s) plus storing (measured) | 4 min 11 s, a serial upper bound | under 5 min |
| Live heap before and after the second round | 15.8 → 15.8 MiB, growth +0.00 MiB | under 3 MiB |
| R32 in the same `make perf` | all green, worst p95 51.3 ms (`dashboard/expiring`) | 300 / 500 ms |

What the numbers do and do not say:

- The scan's connect time is **computed** (5,000 places at the default rate of 20 connections a second is 250 s;
  `TestBucketSpacesConnections` pins the spacing on a fake clock), not measured; a real scan would measure little more
  than sleep. The cost of the handshakes themselves (parsing real certificates, at most 64 workers in parallel) is not
  in the store figure. A /20 on one port is about 3.4 minutes at 20 a second.
- The 50,000-row export and the "p95 at 50,000 leaves" column use 45,000 extra leaves written directly by the test, past
  the churn caps and labelled synthetic: reaching them through scans would take nine days of per-scope caps.
- Query plans (`EXPLAIN (ANALYZE, BUFFERS)` of every statement a request sends) found one real problem: the status
  filter was applied to a computed column outside the paged subquery, so `status=unmanaged` read every leaf (176.7 ms at
  50,000, 16.4 ms at 5,000). It is now an anti-join inside the page (0.4 ms at 50,000), checked by an equivalence test
  against the unfiltered list for every status, with limits, cursors, scopes and gone places. The summary became one
  aggregate (36 → 24 ms at 50,000). The target link uses `discovery_targets_host` (asserted by the test). No migration
  change was needed.
- The name search (`q`) is a contains-search with no index, like the inventory's: 12 ms at 5,000, 65 ms at 50,000. A
  trigram index is the follow-up if an installation grows past about 200,000 leaves (ruling in the rulings file).

## Threat notes

### SSRF and pivoting from Alice's position

Anything that can make Alice connect somewhere is a pivot, so the rule is a positive one. An address is dialed only if
it is inside an **allowed scan network** (`discovery.allowed_networks`, default empty = nothing may be scanned), and
not in the built-in refusals (loopback, unspecified, link-local including `169.254.169.254`, multicast, reserved and
special-purpose ranges, documentation and benchmarking ranges, CGNAT `100.64.0.0/10`, the non-link-local cloud
metadata addresses `fd00:ec2::254`, `fd20:ce::254` and `168.63.129.16`, Teredo and the IETF protocol range as a whole,
IPv4-compatible and translated forms), not one of Alice's own interface addresses, a default gateway of the main
routing table, or an address of the database host, and not in the global or scope exclusions. NAT64, 6to4 and mapped
forms are unwrapped and the embedded IPv4 address is checked against the same rules (`64:ff9b::7f00:1` and
`2002:7f00:1::` are table cases). The check runs in the dialer's `Control` hook (`netaddr.ScanDialContext`), on the
socket about to connect and after name resolution, so DNS rebinding and names that resolve to both a public and a
refused address cannot reach a refused address; own addresses and gateways are read again while the scan runs, and a
failed re-read refuses everything. The policy is built per scan and fails closed: an unreadable source, an empty
list and an unreadable setting all mean "nothing may be scanned". The same rule is applied when a scope is saved (a
refusal names the entry or line, never an address), so a dial-time refusal is the second check, not the only one.
Host names are resolved once at scan start (5 s, at most 8 addresses a name, a 60 s budget); each address is its own
place, checked before dialing; an excluded one is recorded as "not scanned" and never dialed
(`TestExcludedAddressesAreNeverDialed`). Hostname syntax refuses what resolvers read as IP addresses in other
spellings (`2130706433`, `0x7f.1`, `0177.0.0.1`). The scanner has exactly one place that dials
(`TestDiscoveryDialsOnlyThroughTheScanPolicy`): no proxy of the environment, no SOCKS, no HTTP client, so raw TLS has
no redirects to follow. An API caller never supplies addresses for a scan, only a scope id. A scope can be written
only by an Administrator with a fresh step-up code, and so can the allowed networks: a compromised session that has
not widened the list can scan only what the list already allows (the residual risk below).

### The one TLS verification bypass

Discovery must see expired, self-signed and wrongly chained certificates, so `tlsprobe.CapturePresentedChain` sets
`InsecureSkipVerify` (D3). It is the only such use added; it carries `//nolint:gosec // G402`, returns certificates
only (never a "verified" bit; `TestResultCarriesNoVerdict`), exports no `*tls.Config` and sends no byte after the
handshake. An AST guard walks the repository and fails if the identifier appears anywhere besides that function and the
three older sites (`notify/pin.go`, `helperproto.go`, `selfcheck.go`), if the field is set by assignment instead of a
literal key, or if the probe package grows an exported `*tls.Config`, a dial, a `Write` or an `http`/`smtp` import. No
screen calls a found certificate "trusted" or "valid", and Alice does not check the name in a found certificate, so a
certificate is either unmanaged, known or managed, never "good".

### Resource abuse by a scanned server

Limits per place: 3 s to connect, 5 s for the whole handshake (one deadline on the connection), at most 10
certificates, 16 KiB each, 64 KiB together (a byte-limiting reader, so a huge chain is cut while it is read and
recorded as `chain_too_large`). Limits per scan: 4,096 addresses, 20,000 places, rate at most 100 a second, at most 64
workers, 60 minutes, and 1,000 new certificates (5,000 a scope a day; beyond them only a counter grows). Limits per
installation: one scan per scope, two at once, 30 scans kept per scope, certificates with no place removed after 7
days. Growth follows places and certificates, not scans.

### Parsing untrusted certificates

The chain parser is fuzzed; Go's parser decides what is a certificate. A certificate Go refuses to parse (for example a
negative serial number) fails the handshake before any callback, so it cannot be captured in Go 1.27.2; the place is
recorded as `malformed` without a certificate (limitation L2). A non-leaf certificate Go parses but whose dates Alice
cannot store (outside years 1–9999, or reversed) is dropped and counted (L2b). Fields from certificates are shown as
text, exported through `csvx` (formula guard) and put in e-mails as text; no certificate body is written to an audit
row, a log or an e-mail.

### A map of the network

The results list every reachable TLS service of the scanned networks. Reading them needs `discovery.view` (all roles in
a browser) and, for an API token, the operate scope: a read token never reads it (D7). Changing scopes and settings
needs an Administrator with step-up and never a token. Every change, every scan and every export is in the audit log
(counts only, never a certificate).

### Licensing and lock

Discovery writes no `targets` row, so the license counter does not move; **Add as server** is the normal add flow and
`CheckCanAddTarget` decides. Starting a scan is `ClassReadOnly`: refused in lock with `ALC-LIC-0001`, scheduled scans
wait, a running scan checks the license per batch and stops as cancelled. Cancelling, scopes, settings and reading stay
available so a locked installation can stop a scan. The cleanup (`netdisco.retention`) runs in lock and deletes or ends
only discovery data.

## Known limitations

- **L1 — What the probe cannot see.** Direct TLS only (STARTTLS is deferred, D5). SSL 3.0, and servers that offer only
  cipher suites Go has removed, cannot complete a handshake and are recorded as "did not complete a TLS handshake"
  (`no_tls`). TLS 1.0 to 1.3, RSA key exchange suites and SHA-1 signed certificates are probed (fleet kinds `tls10`,
  `rsa-kex`, `sha1`). `no_tls` is deliberately coarse: a TLS alert, no common version or suite, an RSA key over 8192 bits
  and a plain-text service all end there, and an unreachable network or host ends as `refused`.
- **L2 — A malformed certificate is not recorded.** Go validates the certificate before the verification callback runs,
  so a certificate it cannot parse (negative serial, an end date before the start) cannot be captured without parsing the
  wire format by hand. The place is recorded as "Unreadable certificate" (`malformed`), with no certificate, so such a
  server is visible but not as a certificate. The mapping depends on Go's error text; a pin test fails loudly when a Go
  upgrade changes it.
- **L2b — Dropped non-leaf certificates.** A non-leaf certificate whose dates Alice cannot store is left out of the stored
  chain; the chain length shown is the presented one. A leaf like that makes the place `malformed`.
- **L3 — No name check ("Wrong name?" chip deferred).** Plan decision 7 asked for a "Wrong name?" chip. Alice does not
  verify a presented certificate against the name it asked for (the probe trusts nothing and computes no verification),
  so the data does not exist; the chip is not built (`docs/design-gaps.md`).
- **L4 — "Unmanaged" means "no record of this exact certificate".** The certificate's SHA-256 fingerprint is not in the
  inventory. A certificate on a proxy in front of a managed server is unmanaged unless Alice stores that certificate.
  **Managed** means in the inventory and on a live location of a live server; **known** means in the inventory without
  one (D6, ruling).
- **L5 — Docker host and carrier-grade NAT.** Alice sees the container's interface addresses and the gateway of its main
  routing table, not the Docker host's other addresses, so those must be added to the global exclusions by hand. CGNAT
  `100.64.0.0/10` is always refused, so installations that use it internally (overlay networks) cannot scan it.
  Only the main routing table is read for gateways.
- **L6 — Counts.** A scan in which no attempted place answered, in a scope that had answers, counts no misses; places of
  host names that did not resolve are not marked gone; a scope's edit marks places that left it gone at once. The
  chip and Overview count only certificates a place still presents (not gone, not excluded, in a scope that is not deleted), so they can be lower than the **Unmanaged** list
  when no-longer-found ones are included; the Overview metric also leaves out expired certificates.
- **L7 — Schedule.** With a window, intervals of 24 hours or more count whole days (36 hours = every 2 days). A window
  across a clock change keeps its local end time (one hour shorter on the spring-forward day). The schedule is checked
  once a minute and queues at most two scans a check.
- **L8 — After a lost lease.** The scan job runs once (no retry). When its lease is lost, the old run may keep connecting
  for up to one lease (45 s), so three scans can briefly dial. Its results are refused once the scan is ended.
- **L9 — Failure notice.** There is no scan-failure e-mail beyond the dead-job e-mail every background job sends.
- **L10 — Search.** `q` has no trigram index (see the measured numbers).
- **L11 — Restore.** A restored copy ends in-flight scans and switches off scheduled scopes; it never continues the
  original's scans.
- **L12 — Load on the scanned network.** A scan is thousands of handshakes from one address; intrusion detection may alarm.
  The guides say so. A TLS 1.3 close right after the handshake can reset a server that sent a session ticket.
- **L13 — Not scanned from elsewhere.** Alice scans from its own server only: no helper nodes, no IPv6 ranges beyond a
  /120, no history of past results beyond the last 5 fingerprints of a place, no bulk **Add as server** (carries).
- **L14 — Add as server keeps SSH port 22.** The dialog is pre-filled with the host; a server on another SSH port is
  corrected by hand.
- **L15 — Scope audit rows record counts only.** `discovery.scope.created`, `.updated` and `.deleted` carry the field
  names that changed and the counts of entries, ports, server names and exclusions, not the entries themselves, so the
  audit log shows that a scope was widened but not to which addresses (the scope itself is readable by whoever may view
  it). Kept on purpose for this release; recording the values is a possible follow-up.
- **L16 — The scan policy protects only the application database's hosts.** The policy built for each scan refuses the
  addresses of Alice's own interfaces, the default gateways and the hosts of the application database URL. The hosts
  of the migration database URL, S3 or other backup storage, SMTP, the identity provider, KMS and the audit syslog
  receiver are not known to it. An administrator who lets a scope reach their network must add those hosts to **Never
  scan these** (global exclusions); the administrator guide says so. Reading those hosts from the settings into the
  policy is a possible follow-up.

## Not verified

Behaviour on real networks (middleboxes, intrusion detection, load balancers that route by name, IPv6 at scale); real
server TLS stacks beyond Go's (only fleet kinds); `make fuzz-release`; a penetration test of the feature. Findings
Task 15 raises are listed under Findings.

## Findings

| # | Source | Finding | Outcome |
|---|---|---|---|
| F1 | Plan review | Job name `discovery.schedule` already exists | Namespace `netdisco.*` (A1) |
| F2 | Plan review | A static list of refused ranges cannot protect Alice's own, gateway and database addresses | Policy built per scan, re-read while it runs; allowlist (A2) |
| F3 | Task 2 | The raw-DER capture of A6 is impossible in Go 1.27.2 | `malformed` state without a certificate (L2) |
| F4 | Task 6 review | Guard walk skipped any directory called `dist`, `vendor` or `node_modules`; context deadline reported as handshake timeout | Walk skips only what the go tool ignores; fixed with tests |
| F5 | Task 7 review | A lost lease with `max_attempts 1` could leave a scan running forever | Orphan sweep in both periodic tasks, tested (Task 8) |
| F6 | Task 8 review | Spring-forward windows were one hour too long | `window.closing`, tests for both clock changes |
| F7 | Task 9 review | Cursor overflow past 2262, `days_left` overflow, missing finished audit rows on crash, sweep and restore ends, scope edit not stopping a running scan, a start race | Fixed in fix round 1 (seven commits) |
| F8 | Task 10 review | A switched-off scope still alerted | It does not alert (ruling) |
| F9 | Task 11 review | Two definitions of "unmanaged and still found"; accessibility gaps; a duplicate "Expired" chip | One `current` filter; fixed |
| F10 | Task 12 | `status=unmanaged` read every leaf | Fixed (see Measured performance) |
| F11 | Task 13 | `make e2e-up` fails here at image builds that lack `--network host` | Environment note in the operator guide |
| F12 | Whole-branch review (M1) | An endpoint whose state became `excluded` kept its old fingerprint: it was still counted, still alerted and never purged | "Still found" is one definition (`discovery.CurrentEndpointSQL`, and the alert query): not `gone`, not `excluded`, of a scope that is not deleted; retention deletes an excluded endpoint not scanned for the retention period; tests |
| F13 | Whole-branch review (M2) | A scope edit during a scan was partly undone by the scan's last batch (it revived endpoints the edit had marked gone) | `Ingest` reads `cancel_requested` under the scan row lock and drops the batch of a scan asked to stop; test |
| F14 | Whole-branch review (L1) | Saving the settings did not ask running scans to stop, against the guide | A change of the allowed networks or the exclusions sets `cancel_requested` on scans in flight in the same transaction (count in the audit row); test |
| F15 | Whole-branch review (L2) | `UpdateScope` locked the endpoints before the scan row, `Ingest` the other way round | `UpdateScope` locks the scope's scans in flight first |
| F16 | Whole-branch review (L3, L4) | A restore could end a scan with `finished_at` before `started_at` (CHECK failure) and switched scopes off without a version bump | `greatest(now, started_at)`; `version = version + 1`; test |
| F17 | Whole-branch review (L5) | A restart or lost lease ended the scan as cancelled, a crash as failed; the guide said failed | Both end as failed with `discovery.scan_interrupted` |
| F18 | Whole-branch review (L6) | The summary and the list counted endpoints of deleted scopes | Both use `CurrentEndpointSQL`; tests |
| F19 | Whole-branch review (L7) | A tampered certificate cursor outside years 1 to 9999 gave a 500 | A validation error (422, like any bad cursor); test |
| F20 | Whole-branch review (L8) | More than 256 entries in the settings lists answered `ALC-DSC-0001` "too large to scan" | A `too_long` validation error naming the field; OpenAPI says so; test |
| F21 | Whole-branch review (L11) | The excluded-endpoint loop of a scan ignored cancellation | It sends under the dispatch context |
| F22 | Whole-branch review (L12) | Scans tab: older pages kept after the first page moved on, "no scopes" shown while scopes load or fail, an empty problem cell, a raw key for an unknown status, no focus return after the scope dialog | Fixed with vitest tests, English and Turkish |
| F23 | Whole-branch review (L9, L10) | Scope audit rows record counts only; the scan policy protects only the application database's hosts | Not changed: Known limitations L15 and L16, and the administrator guide |
| F24 | Whole-branch fix wave | Playwright journeys and the final full run after the fixes | PENDING (e2e and final run) |
