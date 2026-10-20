# API Guide

This guide is for integrators and automation engineers. Alice has a JSON API over HTTPS; the web interface uses the
same API.

## Base URL and description

All operations are under `https://<Alice's address>/api/v1/`, for example
`https://alice.example.com/api/v1/certificates`. Times are UTC in RFC 3339 form.

Every operation, its parameters, its answer and the permission it needs are described in the OpenAPI 3.1 file
`api/openapi.yaml` of the Alice source (each operation's `x-permission`). The release package does not contain it;
ask your vendor for the file of your Alice version. Which role and token scope may use which operation is listed in
[authz-matrix.md](authz-matrix.md).

## Authentication with API tokens

Scripts authenticate with a personal API token:

1. Sign in to Alice and open **API tokens**.
2. Choose **Create token**, a **Name**, the **Access** and how many days the token is valid (at most 365). Alice may
   first ask for a fresh 6-digit code.
3. Copy the token (it starts with `alice_`); it is shown once.

Send it in every request:

```
Authorization: Bearer alice_…
```

| Access | Scope | What the token may do |
|---|---|---|
| **Read only** | `read` | Read what its owner may read (inventory, deployments, audit log for administrators and auditors). |
| **Read and operate** | `operate` | Also the everyday changes its owner's role allows (for example deploy a certificate, add or remove an SSH key). |

A token never has more rights than its owner's current role: when the owner's role changes or the owner is disabled,
the token follows. Auditors can only create read-only tokens. People who sign in through single sign-on cannot
create tokens; a script then uses a token of a local account. Revoking a token on **API tokens** stops it at once.
Tokens have no idle timeout.

**What tokens cannot do.** Tokens are refused (`ALC-AUTH-0002`), whatever their scope, for every action that asks a
person to confirm with a fresh code (**Confirm it's you**): user and role administration, creating API tokens,
settings (mail, single sign-on, HTTPS certificate, audit forwarding, backup schedule), license upload, private-key
download, re-pinning a server's host key, adding a Key Vault and its credentials, enabling a rotation policy and the
decisions in a rotation run, **backups** (list, back up now, download), and for certificate authorities (ACME) adding
authorities, accounts and DNS hooks, defining which certificates Alice gets and switching their automatic renewal or
automatic deployment on, revoking a certificate at its authority, every action of a key compromise incident, and for
network discovery defining scan scopes, the allowed scan networks, the exclusions and the retention. A few other actions need a person too,
such as confirming a server's fingerprint and confirming or discarding a waiting job. The exact list, operation by
operation, is the "API token" column of [authz-matrix.md](authz-matrix.md). Backups and restores are done by an
administrator in the web interface or by the operator on the server ([backup-restore.md](backup-restore.md)).

Keep tokens out of shell history and process lists, for example:

```
read -rs ALICE_TOKEN && export ALICE_TOKEN
curl -fsS -H "Authorization: Bearer $ALICE_TOKEN" https://alice.example.com/api/v1/version
```

If Alice still uses its temporary certificate, tell `curl` which certificate to trust (`--cacert`), never `-k`.

## Requests from a browser: CSRF rules

The web interface signs in with a session cookie (`SameSite=Strict`). A browser request that changes something
(anything but `GET`) must:

- come from Alice's own origin: the `Origin` header, when present, must be Alice's address, and the browser's
  `Sec-Fetch-Site` must be `same-origin`;
- carry the header `X-CSRF-Token` with the `csrf_token` of `GET /api/v1/auth/session`.

Otherwise it is refused with `ALC-AUTH-0004`. Requests with an `Authorization: Bearer` token are not subject to
these two checks, because no browser sends a token by itself.

## Errors

Every error is JSON with a stable code:

```
{
  "error": {
    "code": "ALC-SYS-0001",
    "reason": "system.not_found",
    "message_key": "errors.system.not_found",
    "message": "Not found",
    "request_id": "01J…",
    "retryable": false
  }
}
```

- `code` is stable across versions and documented in [troubleshooting.md](troubleshooting.md).
- `retryable` says whether the same request may succeed later; such answers often carry `Retry-After` (seconds).
- Validation errors (`ALC-SYS-0006`, HTTP 422) add `details`: one entry per field with `field` and `code`.
- Quote `code` and `request_id` when asking for help.

Common answers: 401 `ALC-AUTH-0001` (no valid session or token), 403 `ALC-AUTH-0002` (not allowed), 404
`ALC-SYS-0001`, 409 (a conflict, see the code), 412 `ALC-SYS-0008` (changed meanwhile: read again and retry), 429
`ALC-SYS-0005` (too many requests, see `Retry-After`), 403 `ALC-LIC-0001` and 503 `ALC-LIC-0009` (license).

## Pagination

Long lists (certificates, SSH keys, deployments, the audit log and others) return one page at a time:

```
{"items": [ … ], "next_cursor": "…"}
```

Pass `limit` (1 to 200, default 50) and, for the next page, `cursor=<next_cursor of the previous page>`. The last
page has `"next_cursor": null`. Cursors are opaque: pass them back unchanged. Short lists, such as servers, return
everything with `"next_cursor": null`.

## Examples

**List the certificates that expire within 30 days** (expired ones included), soonest first:

```
curl -fsS -H "Authorization: Bearer $ALICE_TOKEN" "https://alice.example.com/api/v1/certificates?expiry=30&limit=200"
```

Then the next page, until `next_cursor` is `null`:

```
curl -fsS -H "Authorization: Bearer $ALICE_TOKEN" "https://alice.example.com/api/v1/certificates?expiry=30&limit=200&cursor=<next_cursor>"
```

**List the managed servers and Key Vaults** (one kind with `type=linux`, `nginx` or `azure_key_vault`):

```
curl -fsS -H "Authorization: Bearer $ALICE_TOKEN" "https://alice.example.com/api/v1/targets?type=nginx"
```

**Renew a certificate from a certificate authority now** (an administrator's or operator's **Read and operate**
token), then follow the order:

```
curl -fsS -X POST -H "Authorization: Bearer $ALICE_TOKEN" "https://alice.example.com/api/v1/acme/certificates/<id>/order"
curl -fsS -H "Authorization: Bearer $ALICE_TOKEN" "https://alice.example.com/api/v1/acme/certificates/<id>/orders?limit=5"
```

`POST …/test` runs a Test run instead and `POST …/deploy` with `{"location_ids": [...]}` (at most 20) deploys the
current certificate. These ACME actions share one limit of 10 a minute per person or token (429 `ALC-SYS-0005`); an
authority that limits Alice answers 503 `ALC-ACM-0005` with `Retry-After`, and so does every order or Test run of
that certificate until the time the authority named (`ca_not_before` on the certificate; up to 7 days). The ids and
states are in `GET /api/v1/acme/certificates`.

**Scan a scope and list the unmanaged certificates found on the network** (an administrator's or operator's **Read and
operate** token; a read-only token is refused, because the results are a map of your network):

```
curl -fsS -X POST -H "Authorization: Bearer $ALICE_TOKEN" "https://alice.example.com/api/v1/discovery/scopes/<scope id>/scans"
curl -fsS -H "Authorization: Bearer $ALICE_TOKEN" "https://alice.example.com/api/v1/discovery/scans?limit=5"
curl -fsS -H "Authorization: Bearer $ALICE_TOKEN" "https://alice.example.com/api/v1/discovery/certificates?status=unmanaged&current=true"
```

A scan is started only for a scope an administrator wrote in the web interface; the API never takes addresses.
Starting and cancelling scans share a limit of 10 a minute per person or token. Scopes, the allowed scan networks and
the exclusions cannot be changed with a token. In lock mode starting a scan is refused (`ALC-LIC-0001`); the rest
works. `GET /api/v1/discovery/certificates/export` downloads the same list as CSV. Lists page by cursor like the others.

**Export the audit log** (administrators and auditors, a read-only token is enough):

```
curl -fsS -D headers.txt -o audit.json -H "Authorization: Bearer $ALICE_TOKEN" "https://alice.example.com/api/v1/audit/export?format=json"
grep -i '^X-Alice-Audit-Intact' headers.txt
```

The file holds the verification result and every entry; it can be re-checked outside Alice
([operator-guide.md](operator-guide.md#checking-an-audit-export-outside-alice)). Alice runs one export or check at a
time; while another runs the answer is 503 `ALC-AUD-0001` with `Retry-After`. Every export is recorded in the audit
log.

## Limits

- Requests with a token or session Alice does not know (wrong, expired, revoked) are limited to 60 a minute per
  client address.
- Some operations have their own limits (downloads, uploads); the answer is 429 `ALC-SYS-0005` with `Retry-After`.
- Request bodies have size limits per operation (413 `ALC-SYS-0007`).
- `/livez` and `/healthz` need no authentication ([operator-guide.md](operator-guide.md#health-endpoints-and-request-limits)).
