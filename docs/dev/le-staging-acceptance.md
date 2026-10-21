# Let's Encrypt staging acceptance

`make le-staging` runs Alice's real ACME code against the real Let's Encrypt **staging** service
(`https://acme-staging-v02.api.letsencrypt.org/directory`) for a domain you control. It checks that what the tests
prove against the fake CA also holds against a real one. Staging certificates are not trusted by browsers and
staging's request limits are generous. The harness is `test/lestaging`. Nothing in `make ci` runs it: without its
variables it skips.

## What it checks

Each step prints one line, `[PASS]`, `[FAIL]`, `[WARN]` or `[SKIP]`, and the run ends with `RESULT: PASS` or
`RESULT: FAIL`.

| Step | What runs (Alice's own code unless noted) |
|---|---|
| `preflight` | Settings, the state directory, the account key (made once and kept), the CA's earlier "wait until" time |
| `directory` | Reads the directory: renewal information (ARI), revocation, key change, terms of service |
| `roots` | Downloads the staging roots from letsencrypt.org at run time (Pretend Pear X1, Bogus Broccoli X2, Yearning Yucca YE, Yonder Yam YR). Let's Encrypt asks for them not to be pinned |
| `account` | Registers the account, without an external account binding. Later runs get the same account back |
| `leftovers` | Revokes the certificates that an earlier, interrupted run issued and did not revoke |
| `order` | A new key and CSR (`internal/acme/keygen`), the order, the challenge through the real solver, finalize and the chain download |
| `chain` | The chain leads to a staging root, the issuer is a `(STAGING)` CA, the leaf holds exactly the ordered names and is valid now for server authentication |
| `ari` | Fetches renewal information (RFC 9773) for the certificate |
| `renewal` | A second order with `replaces` naming the first certificate. It must report `replaces sent`, and the new chain is checked as in `chain` |
| `revoke` | Revokes both certificates, then revokes the first one again (the CA answers `alreadyRevoked`, which Alice treats as done) |
| `cleanup` | Every challenge that was presented was removed, nothing is left to revoke and, if you asked for it, the account is deactivated |

A run issues two certificates and revokes both. It is safe to run again. The account is reused, so new
registrations stay well under the limit of 50 per address per 3 hours. Certificates that a failed run left behind are
revoked first. When the CA answers with a rate limit, the time it gives (`Retry-After`) is stored, and no later run
sends anything before then.

## Prerequisites

- A Go toolchain and this repository (no Docker, no database).
- A DNS name in a public zone you control, for example `le-test.example.com`. Let's Encrypt refuses
  `example.com`, `.test`, `.local` and other reserved names.
- One of the two proofs:
  - **Web proof (HTTP-01)**: the name's A or AAAA record points at the machine that runs the harness (or at a web
    server it can write to), and port 80 on that address is reachable from the internet.
  - **DNS proof (DNS-01)**: a way to put a TXT record `_acme-challenge.<name>` into the zone. You can use your DNS
    hook (the HTTPS service described in [the admin guide](../admin-guide.md#dns-hooks-dns-proof)), or add the record
    by hand when the harness asks for it (`manual`). A wildcard needs the DNS proof.
- Read the Let's Encrypt terms of service. The `directory` line prints their address. Setting
  `ALICE_LE_ACCEPT_TOS=yes` means you agree to them.

## Variables

| Variable | Required | Meaning |
|---|---|---|
| `ALICE_LE_DOMAIN` | yes | The name to order, without `*.` |
| `ALICE_LE_ACCEPT_TOS` | yes | `yes`: you accept the CA's terms of service |
| `ALICE_LE_CHALLENGE` | no | `http-01` (default) or `dns-01` |
| `ALICE_LE_WILDCARD` | no | `yes` also orders `*.<domain>` (needs `dns-01`) |
| `ALICE_LE_EMAIL` | no | The account's contact address (none by default) |
| `ALICE_LE_KEY_TYPE` | no | `ecdsa_p256` (default), `ecdsa_p384`, `rsa_2048`, `rsa_3072` or `rsa_4096` |
| `ALICE_LE_STATE_DIR` | no | Where the account key, the issued certificates and the state are kept (`make le-staging`: `bin/le-staging`; the binary on its own: your cache directory, `alice-le-staging`). One subdirectory per CA |
| `ALICE_LE_DEACTIVATE` | no | `yes` deactivates the account at the end and deletes its key |
| `ALICE_LE_HTTP01_LISTEN` | no | Address the harness serves the token files on (default `:80`) |
| `ALICE_LE_HTTP01_WEBROOT` | no | Instead of listening: the document root of a web server that already answers on port 80; files go to `<root>/.well-known/acme-challenge/` |
| `ALICE_LE_DNS_PROVIDER` | for `dns-01` | `hook` (the default when `ALICE_LE_DNS_HOOK_URL` is set) or `manual` |
| `ALICE_LE_DNS_HOOK_URL`, `ALICE_LE_DNS_HOOK_SECRET` | for `hook` | The hook's `https://` address and its secret, exactly as you would enter them in Alice |
| `ALICE_LE_DNS_HOOK_CA_FILE` | no | PEM file with the root of the hook's HTTPS certificate, if a private CA signed it |
| `ALICE_LE_DNS_WAIT` | no | Seconds to wait after the hook added the record (default 5, at most 120; `0` means no wait) |
| `ALICE_LE_DNS_POLL_TIMEOUT` | no | Seconds the hook may answer `{"ready":false}` (default 60, at most 100) |
| `ALICE_LE_DNS_MANUAL_TIMEOUT` | no | `manual`: how long to wait for each record to become visible (default 10 minutes) |
| `ALICE_LE_DNS_RESOLVER` | no | `manual`: the resolver that checks for the record, `host:port` (for example `1.1.1.1:53`; default the system resolver) |
| `ALICE_LE_ROOTS_FILE` | no | PEM roots to verify the chain against, instead of downloading them (needed for any directory other than Let's Encrypt's) |
| `ALICE_LE_CA_FILE` | no | Extra PEM roots for the CA's own HTTPS (not needed for Let's Encrypt) |
| `ALICE_LE_DIRECTORY` | no | Another staging directory (default Let's Encrypt staging) |
| `ALICE_LE_ALLOW_PRODUCTION` | no | The production Let's Encrypt directory is refused unless this is `yes`. Do not set it for acceptance: production limits are strict and its certificates are real |

## Running it

Web proof, with the harness listening on port 80 itself. Port 80 needs root, so build the binary first and run it
with `sudo`:

```bash
make le-staging-build
sudo ALICE_LE_DOMAIN=le-test.example.com ALICE_LE_ACCEPT_TOS=yes \
  ALICE_LE_STATE_DIR="$PWD/bin/le-staging" \
  ./bin/le-staging.test -test.v -test.count=1 -test.timeout 2h -test.run '^TestLetsEncryptStaging$'
```

Web proof through a web server that already serves the name on port 80 (no root needed if you can write to its
document root):

```bash
ALICE_LE_DOMAIN=le-test.example.com ALICE_LE_ACCEPT_TOS=yes \
  ALICE_LE_HTTP01_WEBROOT=/var/www/html make le-staging
```

DNS proof through your DNS hook, with a wildcard:

```bash
ALICE_LE_DOMAIN=le-test.example.com ALICE_LE_ACCEPT_TOS=yes ALICE_LE_CHALLENGE=dns-01 ALICE_LE_WILDCARD=yes \
  ALICE_LE_DNS_HOOK_URL=https://dns-hook.example.com/alice ALICE_LE_DNS_HOOK_SECRET="$(cat ~/hook-secret)" \
  make le-staging
```

DNS proof by hand. The harness prints each TXT record and waits until the resolver sees it. With a wildcard there
are two values for the same name; keep both.

```bash
ALICE_LE_DOMAIN=le-test.example.com ALICE_LE_ACCEPT_TOS=yes ALICE_LE_CHALLENGE=dns-01 ALICE_LE_DNS_PROVIDER=manual \
  ALICE_LE_DNS_RESOLVER=1.1.1.1:53 make le-staging
```

## Expected output

```
Let's Encrypt staging acceptance: https://acme-staging-v02.api.letsencrypt.org/directory, dns-01, names le-test.example.com *.le-test.example.com
[PASS] preflight  state …/bin/le-staging/acme-staging-v02.api.letsencrypt.org, a new account key, 0 certificate(s) of earlier runs to revoke
[PASS] directory  renewalInfo yes, revokeCert yes, keyChange yes, external account binding required NO, terms https://letsencrypt.org/documents/…
[PASS] roots      (STAGING) Pretend Pear X1; (STAGING) Bogus Broccoli X2; (STAGING) Yearning Yucca Root YE; (STAGING) Yonder Yam Root YR
[PASS] account    registered a new account https://acme-staging-v02.api.letsencrypt.org/acme/acct/…
[PASS] leftovers  nothing left by earlier runs
[PASS] order      issued serial … for le-test.example.com *.le-test.example.com, valid until …, 2 certificate(s) in the chain, 2 challenge(s) presented
[PASS] chain      le-test.example.com -> (STAGING) … -> (STAGING) …
[PASS] ari        suggested window … .. …, ask again after …
[PASS] renewal    issued serial … replacing …, replaces sent
[PASS] revoke     revoked 2 certificate(s); a second revocation answered as done
[PASS] cleanup    4 challenge(s) presented and removed, nothing left to revoke
RESULT: PASS (11 passed, 0 failed, 0 warnings, 0 skipped)
```

The exact intermediates and roots change over time (Let's Encrypt rotates them). Any `(STAGING)` names are fine.
Without the variables the test skips and names what is missing:
`--- SKIP: TestLetsEncryptStaging … set ALICE_LE_DOMAIN, ALICE_LE_ACCEPT_TOS=yes …`. The binary exits non-zero
when any step fails.

Record the result in row 1.41 of the [release checklist](../release-checklist.md) (with the owner table of
[acme-issuance.md](../security/reviews/acme-issuance.md#owner-verification), steps 1, 2 and 5 at the ACME level).

## Troubleshooting

- **`order` fails with `acme.validation_failed_http`.** The CA, or Alice's own check before it, could not fetch
  `http://<name>/.well-known/acme-challenge/<token>`. Check the A/AAAA record, the firewall and port forwarding for
  port 80, and that nothing else is listening there. Alice fetches the URL itself before it asks the CA. Behind a
  NAT router without hairpin NAT that fetch fails even though the CA would succeed: add a line
  `127.0.0.1 le-test.example.com` to `/etc/hosts` while you use `ALICE_LE_HTTP01_LISTEN`.
- **`cannot listen on :80`.** Run the binary with `sudo` as shown, or use `ALICE_LE_HTTP01_WEBROOT`, or listen on a
  high port (`ALICE_LE_HTTP01_LISTEN=:8080`) and forward port 80 to it.
- **`order` fails with `acme.validation_failed_dns`.** The CA asks the zone's authoritative servers. Raise
  `ALICE_LE_DNS_WAIT` (up to 120) or have the hook answer `{"ready":true}` only once every authoritative server
  serves the record. Check with `dig TXT _acme-challenge.le-test.example.com @<authoritative server>`.
- **`order` fails with `acme.hook_refused`.** The hook refused the call (status shown), or could not be reached, or
  its certificate is not trusted (`ALICE_LE_DNS_HOOK_CA_FILE`). If `cleanup` then reports a challenge "with an
  error", remove the TXT record by hand.
- **`acme.identifier_refused` (`rejectedIdentifier`).** The CA does not issue for that name (reserved or blocked
  names, or a CAA record that does not allow `letsencrypt.org`).
- **`acme.ca_rate_limited`.** The line says until when the CA asked Alice to wait. The next run stops at
  `preflight` before then. To override (only if you know the limit has passed), remove `ca_not_before` from
  `<state dir>/state.json`. The staging limits are listed at https://letsencrypt.org/docs/staging-environment/.
- **`roots` fails.** letsencrypt.org could not be reached. Download the four PEM files listed there yourself, put them
  in one file and set `ALICE_LE_ROOTS_FILE`.
- **`renewal` reports `replaces already_replaced` or `refused`.** The CA did not take the `replaces` field. That is
  a finding: keep the output.
- **`ari` is `WARN`.** The suggested window lies outside the certificate's validity. Alice ignores such a window and
  uses its own rule. Keep the output.
- **A damaged state.** Delete `<state dir>/state.json`. Delete `account-key.pem` as well to register a new account.
  The `certificates/` folder holds the PEM chains of every certificate issued, for inspection.

## For developers

The untagged tests in `test/lestaging` run the same code against the fake CA (`internal/testutil/fakeacme`) in
`make test` and `make coverage`. The HTTP-01 path with the real solver runs under the integration tag. The built-in
DNS providers plug in with `RegisterDNSProvider` (in `test/lestaging/solvers.go`): a provider registers the
`solver.Solver` it builds under its name, reads its credentials through `DNSParams.Getenv` from
`ALICE_LE_DNS_<NAME>_*` variables, and is then chosen with `ALICE_LE_DNS_PROVIDER=<name>`.
