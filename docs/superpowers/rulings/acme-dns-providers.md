# Rulings: built-in DNS providers for DNS-01 (Cloudflare, Azure DNS, Amazon Route 53)

Owner approval of the work 2026-10-21; the details below were chosen by the implementer and are recorded for review
(items marked **owner to confirm** are the ones that change what an administrator sees or must grant). Spec: R57 in
`docs/superpowers/specs/alice-v1/00-decisions.md`; user text in `docs/admin-guide.md` ("Built-in DNS providers (DNS
proof)"), `docs/troubleshooting.md` (ALC-ACM-0042 to ALC-ACM-0044). Before this work Alice published a DNS-01 record
only through an administrator's DNS hook (`internal/acme/solver/dns01`, Task 9 of the ACME plan); this adds three DNS
services Alice drives through their API itself.

## The design as built

- **One publisher table, a kind per row** (migration `00030`). A DNS publisher stays an `acme_hooks` row; the new
  `kind` is `webhook` (every row before 00030, the hook as before), `cloudflare`, `azure_dns` or `route53`, fixed at
  creation (no UPDATE grant on it: the sealed secret's format depends on it). A provider has no URL and no CA bundle
  (CHECKs) and has `settings` (jsonb, the non-secret settings); a hook has `settings = '{}'`. A certificate keeps naming
  its publisher by `hook_id`, so the certificates, orders, presented records, the R55 service policy (`challenges:
  dns01` covers every kind), the scoped access rules (publishers are platform resources, as before) and the cleanup
  job are unchanged. The Down refuses while a provider exists (SQLSTATE Z1030), deleted ones included: their rows and
  credentials still clean up what they published.
- **Credentials** are one JSON document sealed in the row's existing secret columns (AAD `acme_hooks/<id>/secret`, the
  hook secret's), written field by field into a buffer Alice owns and clears (`dnsCredentialDoc.encode`): the
  Cloudflare API token; the Azure client secret, or the sign-in certificate's DER with its PKCS #8 RSA key; the AWS
  secret access key. A managed identity's document is `{}`. Write-only like the hook secret (`secret_configured`). On a
  change an empty credential keeps the stored one; credentials are required again when what they belong to changes
  (the Azure sign-in method, the AWS access key ID).
- **Settings**: Azure `auth`, `tenant_id`, `client_id`, `subscription_id`, `resource_group` and, for a certificate,
  Alice's reading of it (`cert_thumbprint`, `cert_not_after`); Route 53 `access_key_id`, `role_arn`, `external_id`;
  Cloudflare none. The Azure sign-in rules are the Key Vault credential's (`validateVaultCredential`,
  `vaultIdentity`): one rule for both Azure sign-ins.
- **The solver** (`internal/acme/solver/dnsapi`): a `Provider` interface (FindZone, AddTXT, RemoveTXT, ChangeDone) and
  one `Solver` over it: the shared name rule and allow-list (`solver.NormalizeDomain`, `solver.Suffixes`, now also used
  by the hook solver), the zone looked up once per name and order, the wait for the provider's change (Route 53's
  INSYNC; poll every 2 s, bounded by the publisher's poll time and 100 polls), then the publisher's propagation wait,
  and a clean-up under its own 30 s context. `dnssolver` maps a publisher's kind to its solver; the inventory fills its
  `Config` (secrets opened, zeroed by the caller) and the jobs build and close it.
- **Zone discovery**: the longest zone name of the account that the record name `_acme-challenge.<name>` ends in on a
  label boundary (a zone of the challenge label itself, `_acme-challenge.example.com`, is admitted). Public zones only
  (a Route 53 private zone and an Azure zone listed as Private are skipped). Cloudflare and Route 53 look a candidate
  name up (one call per candidate, longest first: a zone-scoped token works); Azure lists the zones of the resource
  group (at most 10 pages, a nextLink to another host, path or scheme refused).
- **The record**: every value of a name is kept (a wildcard and its base name share the record); only the given value
  is removed; adding a value that is there and removing one that is gone succeed. Cloudflare: one record per value,
  content sent as a quoted string, TTL at least 60 (its minimum; 1 would mean automatic), code 81058 (identical
  record) is success. Azure: the record set read and written with `If-None-Match: *` / `If-Match: <etag>`, a 412 read
  again (3 times, then transient). Route 53: the set read, UPSERT of the union, DELETE of the exact set for the last
  value (no conditional write exists: the package comment and the admin guide say so).
- **HTTP**: `dnsapi.NewHTTPClient`, one per provider: https to the provider's fixed hosts on 443 only
  (`api.cloudflare.com`; `management.azure.com` and `login.microsoftonline.com`; `route53.amazonaws.com` and
  `sts.amazonaws.com`), TLS 1.2+, every dial through netaddr, no environment proxy, no redirect, 1 MiB answers, 30 s per
  exchange. The Azure managed identity's metadata transport reaches `169.254.169.254:80` only (the Key Vault
  provider's exception, copied). The e2e build's trust (`ACMERoots`) is the providers' roots too.
- **Azure sign-in**: azidentity with the Key Vault provider's guards, re-implemented in `azuredns/identity.go` (the
  package may not import `providers/azurekv`): public cloud, instance discovery off, no SDK retries or telemetry, a
  token for `https://management.azure.com/.default` and the configured tenant only, refused while
  `AZURE_REGIONAL_AUTHORITY_NAME`, `MSAL_FORCE_REGION` or `AZURE_SDK_GO_LOGGING` is set. `TestAzureSDKSurface` admits
  that one file. As for Key Vault, the SDK keeps its own copy of the secret or key for the solver's life.
- **Route 53 signing**: an own SigV4 (`route53/sigv4.go`, no SDK) checked against eight vectors of the AWS SigV4 test
  suite; the canonical URI encodes each segment once more (the rule of every service but S3). An assumed role: STS
  AssumeRole (Version 2011-06-15), session `alice-acme-<8 hex>`, 900 s, renewed with less than 2 minutes left, dropped
  on a refused token.
- **Errors**: three new closed reasons (`internal/acme`): `acme.dns_zone_not_found` (ALC-ACM-0042, 422, permanent),
  `acme.dns_auth_failed` (ALC-ACM-0043, 502, permanent: a 401/403, Cloudflare's auth codes on a 400, AWS's auth codes,
  a refused sign-in), `acme.dns_provider_error` (ALC-ACM-0044, 502, retryable; transient for no answer, 408, 429, 5xx,
  Route 53 Throttling and PriorRequestNotComplete; permanent otherwise). No provider answer text, URL, header,
  signature or credential is ever in an error (each provider's leak tests, `TestDNSProviderCredentialsNeverLeak`).
- **API**: the same `/api/v1/acme/hooks` routes (permissions, scopes, licence classes, step-up and token rules
  unchanged). The request body is flat with the Key Vault credential's names (`auth`, `tenant_id`, `client_id`,
  `client_secret`, `certificate_pem`, `private_key_pem`, `pfx_base64`, `pfx_password`) and `kind`, `subscription_id`,
  `resource_group`, `api_token`, `access_key_id`, `secret_access_key`, `role_arn`, `external_id`; `kind` is refused on
  a PATCH (400). The view adds `kind` and a `settings` object. Audit: a hook's rows are unchanged (no `kind` key, for
  existing readers of the log); a provider's add `kind` and its identifiers (`external_id_set` instead of the value).
- **UI**: Settings → Certificate authorities → **DNS publishing** (was "DNS hooks") with **Add DNS provider** beside
  **Add DNS hook**; the provider dialog per kind with what the credentials need; the certificate wizard names each
  publisher's kind; the proof method reads "DNS proof (DNS record)". The UI takes the Azure certificate as PEM (a PFX
  through the API).

## Departures and defaults (owner to confirm)

1. **CNAME delegation is not followed** (**owner to confirm**): the existing hook does not follow one either, so the
   record goes into the zone that holds `_acme-challenge.<name>` itself; a dedicated zone named for the challenge label
   works. Following a CNAME needs DNS lookups Alice does not make today (a resolver choice, split-horizon DNS).
2. **Public zones only** (**owner to confirm**): a private zone answers resolvers inside its network, never a public CA.
3. **The API host names are fixed** (public clouds only, no Azure Government/China, no AWS GovCloud/China); a proxy is
   never used. Alice's server needs outbound https to the hosts above.
4. **No zone pinning**: the zone is always discovered; a credential that cannot list or look up zones does not work
   (Cloudflare: a token needs Zone Read; Route 53: `ListHostedZonesByName` on `*`; Azure: Reader on the resource group).
5. **The waits are the hook's** (propagation 0..120 s, default 5; poll 1..100 s, default 60; together at most 120 s);
   the poll time bounds the provider's change (Route 53 INSYNC).
6. **TTL 60 s**, as for the hook (not configurable).
7. **No Azure client-secret expiry** is recorded (the Key Vault form has one): the admin guide asks to renew the secret
   in time. The certificate's expiry is shown.
8. **A connection test** ("check the credentials now") is not built: saving contacts no one, as for the hook; the first
   Test run is the check.
9. Route 53's credentials may be a role's temporary credentials only through AssumeRole; instance profiles, web
   identity and SSO profiles are not read (no environment or file credentials, by design).

## Tests

Unit and in-process integration tests per provider against its fake (`internal/testutil/fakecloudflare`,
`fakeroute53`, and Azure DNS in `fakekv`), each with fault injection (status, code, canary body, connection reset,
delay); a full issuance with the real ACME client and the fake CA for each (the fakes mirror their records into the
fake CA's DNS); the job path (`internal/jobs/acmejobs/dnsproviders_integration_test.go`: issue through each, failure
classes, the cleanup through a deleted provider); the inventory lifecycle per kind; the API handlers and the leak suite
(`internal/api/dnsprovider_leak_integration_test.go`); migration 00030 and its Down; the UI dialogs (EN and TR).
Matrix rows F-98 to F-103 and S-12 (`docs/superpowers/specs/alice-v1/06-quality.md`).

## What the owner must do against real accounts

See the report of this work: a Cloudflare zone with a scoped token, an Azure DNS zone with a service principal (secret
and certificate) and, on an Azure VM, a managed identity, and a Route 53 public hosted zone with an access key (and a
role), each used for a Test run against Let's Encrypt staging.
