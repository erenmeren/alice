# Rulings: HAProxy provider, discovery only (Phase C)

Spec `docs/superpowers/specs/2026-10-17-web-server-providers-design.md` (§8 binds), plan
`docs/superpowers/plans/2026-10-17-haproxy-provider.md` (13 tasks). The plan's rulings stand as written, except where
an entry below amends them. Branch `haproxy-provider` from main (plan commit f2a5b6fd). The pre-flight rows C1-C16 and
D1-D5 (`.superpowers/sdd/2026-10-17-haproxy-provider/preflight.md`) were all adopted as written; the ones that shape
the product are repeated below.

## Rulings made during execution

Each entry: the decision, why, and the cost if it is wrong.

1. **Root-only helper suite is an owner step.** `sudo -E env "PATH=$PATH" go test -count=1 ./cmd/alice-helper/...` was
   not run: sudo needs a password on the build machine. Why: the Global Constraints allow recording it instead of
   skipping it silently. Cost if wrong: a root-only regression of `haproxy-dump` or of the program pre-check found
   later by the owner.
2. **Plan Ruling 5 amended (Task 4 review).** An unknown escape in the HAProxy lexer is kept as written (backslash and
   character), as HAProxy 2.4 and 2.6 do (probed by the reviewer), not treated as an error; outside double quotes
   `\$` keeps its backslash, and a path with a `$` is `variable` anyway. A carriage return in the middle of a line ends
   the line. A `crt-list` line that starts with a carriage return is skipped (HAProxy skips lines starting with `#`,
   `\n` or `\r`). Why: the plan's `ErrSyntax` for an unknown escape would blank the discovery of every host with a
   regular-expression escape in its configuration. Cost if wrong: a shown path differs in its backslashes.
3. **`MaxListens` and the wire bound (Task 5).** The listens of all binds together are bounded at `MaxListens` =
   1<<16, counted on the wire (a bind's listens are shared by its servers and counted once per server that carries
   them); past it the list is cut with the warning `list_truncated`. The encoded size of all servers is bounded at
   `MaxWire` = 32 MiB (twice the helper's answer); going over it is `ErrTooComplex`, never a truncation. The helper's
   own answer is capped at 16 MiB (`ServerDumpOutput`, `output_too_large`). One word budget (`MaxTokens` = 1<<20)
   covers `haproxy.cfg` and every `crt-list` together. Why: one 1 MiB address argument names about
   200,000 listens, and the bound must hold on the wire, not only in `Parse`. Cost if wrong: some very large
   configurations are cut or refused.
4. **Key settings are used only when stable (Task 5, rounds 2-4).** `ssl-load-extra-files` and
   `ssl-load-extra-del-ext` decide where HAProxy looks for a companion key. They are stable when every such directive
   is in `global`, outside any `.if` block and before the first line that can load a certificate; then the key follows
   from them. Otherwise only a key inside the certificate file is known and every other pair is conditional. Why: a
   per-load cache cannot model HAProxy's first-load-wins with loads Alice cannot see. Cost if wrong: unusual
   configurations show conditional instead of supported.
5. **Fail-closed conditions (Task 5 reviews R1, R3, S1).** Each of these makes every pair conditional: any keyword that
   contains `$` in any section (HAProxy expands it before it reads the keyword, so it may be a `bind`, a key setting
   or a section header); a `crt-store` section anywhere (HAProxy 3.0 on; it can give a certificate a key file of its
   own); key settings that are not stable (Ruling 4). A `$` in a path makes that pair `variable` (pre-flight D4, even
   in single quotes). Cost if wrong: configurations with variable keywords or a `crt-store` show conditional.
6. **Pending pairs (Task 5 review R2, Task 6).** `Parse` returns every pair it can support as pending and conditional;
   `ResolveKeys` decides its key and makes it supported, so a caller that forgets it reports no supported pair.
   `MarkWritable` clears a pending pair's unresolved key; `ResolveKeys` promotes only pairs still pending and
   conditional. Cost if wrong: none.
7. **A writable configuration reads nothing beyond itself (Task 6 reviews I1, R1, R3).** If `haproxy.cfg` can be
   changed by a user other than root, the helper reads no `crt-list`, lists no folder and opens no certificate; each
   `crt` or `crt-list` argument becomes one `config_file_writable` pair carrying only the text as written. The entries
   of a writable `crt-list` are never walked, listed or opened. `MarkWritable` runs instead of `ResolveKeys`, so no
   certificate file is opened to find its key (that answer would tell the writer whether a root-only file holds a
   private key). Every later failure reads `changed`, naming the writable file. Why: the writer's own text is no leak;
   file contents and folder names are. Cost if wrong: writable configurations show coarse places.
8. **A `crt-list` that cannot be read (Task 6 review I2, R2).** One that is absent (ENOENT) or not a regular file, and
   whose every naming lies in an uncertain region, gives conditional pairs (or none) and the warning
   `config_file_not_read`, never a whole-dump error. An untrusted one (not root-controlled), a masked failure and a
   bound stay hard. Cost if wrong: none.
9. **`conf.d` warning widened (pre-flight C14, D2).** `config_dir_not_read` is raised whenever `/etc/haproxy/conf.d`
   holds a regular `*.cfg` entry (or a link to one) or exists as a directory that cannot be listed safely (not root's,
   writable by group or others, on a pseudo file system, too many entries); no warning when it is absent or holds no
   `*.cfg`. Why: on Rocky 9 a writable `conf.d` with frontends is exactly the silent-empty case. Cost if wrong: an
   HAProxy page without websites and without a reason.
10. **`-c` exit 2 is valid; a missing certificate, a missing key or an unresolvable server is `syntax` (pre-flight D3).**
    Verified on 2.4, 2.6 and 2.8. Consequence, documented in the guide and in troubleshooting: whether `haproxy -c`
    passes depends on DNS and on the environment at the moment of the discovery (server addresses are resolved at
    check time; the service's environment is not set). Cost if wrong: hosts reported invalid because of DNS.
11. **Extension-less and `w.pem.rsa` certificate names are `bad_name` (pre-flight C15).** The helper's `certName` rule
    stays (it guards against reading `/etc/shadow` through links, and is checked on the resolved name, so a link does
    not help); a `w.pem.rsa` entry is listed with the problem `bad_name` and `keyInCert` answers false for it. Listed
    in the guide, in troubleshooting and in KI-41. Cost if wrong: customers' extension-less HAProxy certificates show a
    file problem.
12. **Duplicate `crt-base` is rejected by HAProxy 2.4 and 2.6 (Task 10).** `'crt-base' already specified`; the plan
    (Ruling 9) assumed a later `crt-base` could override. The parser is last-wins in read order (`parse.go`: each `crt-base` in `global` replaces the previous one; a relative
    path read before any is `path_not_allowed`), and the real-matrix fixture has exactly one `crt-base`, in the
    distribution's `global`, because 2.4 and 2.6 reject a second. Nothing is claimed about 2.8: unverified. Cost if wrong: a relative path before a `crt-base` is
    unsupported although a newer HAProxy would resolve it.
13. **`defaults` is sticky (Task 5 carry M8).** Once a `defaults` section has a `disabled` or `enabled` line, every
    later frontend or `listen` that sets neither itself is conditional; the flag is never reset by a later `defaults`.
    Cost if wrong: a few more conditional places.
14. **Program pre-check (plan Ruling 15, Task 3; Phase B carry of Apache Ruling 7).** `nginx`, `apache2ctl` (with
    `/etc/apache2/envvars` and `apache2`), `httpd` and `haproxy` run only after the program and every directory above
    it are root-controlled (regular file owned by root, no group or other write bit, directories not writable by
    group or others, no pseudo or FUSE file system; hard links allowed; a missing or non-directory parent passes so the
    "not installed" logic is unchanged). Beyond the brief, the file's own file system is checked too (FUSE over the
    file). `systemctl` is not covered (KI-40). The `nginx-test` answer is `untrusted`, which the connection test shows
    as the generic "configuration has an error" text; the dumps carry the reason and file. Documented in
    `docs/nginx-host-preparation.md`. Cost if wrong: a deployment-tool-managed binary under `/opt` owned by a deploy
    user is refused until it is root-owned.
15. **Writable-configuration existence oracle (plan ruling 16, KI-41).** Server names of a writable configuration are
    still listed, as for Apache (KI-40). The remaining channel is `haproxy -c` itself, which runs before anything is
    read: a writer who names a root-only path learns from the check's verdict whether it is a loadable certificate.
    Accepted, Low. Cost if wrong: none beyond KI-29.
16. **Known limitation (Task 6 review M4).** A path on a FUSE-backed file system can stall the root-control check until
    the helper's time limit; documented in the guide and in KI-41.
17. **Rocky 9 prints a conf.d warning from `haproxy -c` on the main file.** It is harmless: the helper uses only the
    exit status. Documented in the guide and in troubleshooting.
18. **Wording.** The docs and `SECURITY-REPORT.md` say "the helper of this release (1.8.0, protocol 9)" and never name
    a bare version as the latest. The Apache and Nginx guides were updated from "1.7.0" to this wording.
19. **A fifth plain `-t` run for Apache stays an owner option.** Apache Ruling 8 (version-dependent verdict on a missing
    certificate file) is unchanged; no run was added in Phase C. Cost if wrong: an extra run added later.

## Accepted deviations from the plan

- **Task 3:** an additional file-system check of the program file itself (FUSE) beyond the brief; kept after review.
- **Task 7:** trailer of commit 2de14bec says "Claude Sonnet 5.5" instead of the rules file's trailer (the subagent's own
  attribution reminder); it cannot be amended on a shared branch. Emulator limits (one crt-list shared by SNI frontends
  was fixed in round 1; the fidelity renderer keeps simple port handling).
- **Task 8:** the brief's POST-target and 422 API tests were first skipped, then added in fix round 1 (two route tests;
  the 422 values list is pinned by the inventory integration test).
- **Task 11:** the hardening check missed `/etc/apache2/ssl` and `/etc/haproxy/certs`; the controller extended it with
  `find -mindepth 1` and verified 0 findings on the `alice-e2e-sshtarget` image.
- **Task 13 (gates):** a subset of `make ci`, as in Phase B, plus `make e2e-hardening-check vuln secrets-scan`
  (pre-flight C16); the rest is recorded as an accepted deviation with the gate results below.
- **Commit trailers:** commits of tasks run by Sonnet carry "Claude Sonnet 5.5" instead of "Claude Opus 5.5".

## Deferred minors

### Fix later

- `haproxyconf` lexer: memory is about 28-30 times the input (Task 4 M3); an empty quoted word at the end of a line is
  returned although HAProxy drops it (Task 4 M4).
- `haproxyconf` / helper: no streaming of the answer; peak memory 62-98 MiB on the largest accepted input (Task 5, Task 6
  concern 3).
- Task 7: the fidelity renderer has a row for a non-root `crt-list`; `hasPrivateKeyLine` is copied into the fidelity
  oracle.
- Task 10: the Nginx owner step does not assert on a deployment; `a.pem` is reused, which hides the all-supported case; a
  Makefile orphan line; `require` inside defers; the root-owner check for `/usr/sbin/nginx` is covered outside the
  root-only suite only by the `chown 65534` step.
- Task 11: the e2e 2.4 regular expression, Enter-without-dialog immediacy, `restoreNginx` is skipped on an early
  failure, tabs in the e2e `haproxy.cfg`.
- Task 9: six minors recorded in its review (two cheap ones fixed by the implementer).
- Known unrelated flakes: `internal/backup` `TestStopLeavesNoSession` under load; e2e `phase9:225`, `phase5:610` (tr
  colour contrast), SavedViews.

### Dropped (with reason)

- Streaming JSON per server (Task 6 consideration): accepted as is, the test ceiling is documented.
- Cap of 4096 directory entries (Task 6 concern 4): accepted.

## Carried items

- A fifth plain `-t` run for Apache (Ruling 19): owner option.
- Deploy to HAProxy (certificate write, `haproxy -c` before the reload, reload) is a later phase; the capability set,
  the disabled controls and the note follow `can(target, 'deploy_certificate')`.
- The multi-approval ("four eyes") idea is deferred until after Phase C.
- A hardening of the `systemctl` calls (reload after a deployment) is not covered by the program pre-check.

## Owner steps

1. Run the root-only helper suite on a machine where sudo works:
   `sudo -E env "PATH=$PATH" go test -count=1 ./cmd/alice-helper/...` (Ruling 1), if it was not run.
2. Review a real customer HAProxy configuration with `haproxy-dump`: compare the frontends and certificates Alice lists
   with what the running HAProxy serves, especially `crt-list` options, `.if` use, `$` in paths, `crt-store`,
   `ssl-load-extra-files`, certificate folders with extension-less names, and `conf.d` on Red Hat.
3. Reinstall `alice-helper` 1.8.0 on servers that will be HAProxy servers (CHANGELOG upgrade notes); other servers keep
   working with 1.6.x and 1.7.x but get the program pre-check only with 1.8.0.

## Final gates (Task 13)

To be filled by Task 13 with the results of the static, unit, integration, `make test-ssh`, fuzz, web, e2e and docs
gates, the helper checksums and the grep checks.
