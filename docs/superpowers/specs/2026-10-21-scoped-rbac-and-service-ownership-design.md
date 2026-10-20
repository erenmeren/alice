# Scoped access and service ownership: design

Status: draft for the owner's review. Date: 2026-10-21. Written against `main` at `bdbf9b3b` (migrations up to
`00021`, decisions up to R46). Numbers reserved here: migration `00024` (Phase 1 creates the whole schema of §4, so the
later phases need no migration; one that does after review takes the next free number at merge time) and decision
**R49**. When accepted, R49 amends `alice-v1/04-security.md` §15.4 (SEC-014, SEC-016,
SEC-017, the role table), §15.5 (SEC-025, SEC-026) and `alice-v1/02-architecture.md` (data model, route groups).

The owner approved on 2026-10-20 that work proceeds on the recommended defaults of §14 while the questions stay open.

## 1. Purpose and agreed understanding

Two outside reviews ask for the same missing layer:

1. "Resource groups, environments, role bindings, scoped service accounts" (as Sectigo SCM and ManageEngine KMP have).
   Today Alice has three global roles (`internal/rbac/rbac.go`: Admin, Operator, Auditor). Every Operator can act on
   every server, certificate, Key Vault, SSH key and discovery scope.
2. "Service policy": each service has an owner team, a scope (domains and a group of servers), a certificate source, a
   validation method and its renewal, deployment and incident behaviour, versioned; notifications go to the service's
   owners.

Both are designed here together so the data model is done once:

| Decision | Choice |
|---|---|
| One grouping concept | A **service** (table `services`). It owns servers, Key Vaults, certificates, ACME certificates, signing requests, SSH keys and discovery scopes. It carries an optional **environment** label (production, staging, ...). The same service is the unit of access (role bindings), ownership (owner team, notifications) and policy. |
| Roles | The three existing roles, unchanged in meaning. No new roles, no custom permission sets, no deny rules. |
| Bindings | A person, an automation account or a directory group (LDAP or OIDC) holds a role **globally** (today's `users.role` and group mappings, unchanged) or **on a service** or **on an environment** (every service with that label, now and later). Rights are the union. |
| Existing installations | Every existing resource moves to the service **Default**; every existing user keeps exactly today's rights (they are all global). Nothing changes until an Administrator creates a second service and a scoped binding. |
| Who manages access | Global Administrators only, with step-up, never an API token. |
| Licensing | Not a licensed feature (§14 Q1). |

## 2. Goals and non-goals

Goals (v1 of this feature):

- G1. An Operator or Auditor (person, automation account or directory group) can be limited to one or more services
  or environments, and then sees and acts on only those resources, on every route, list, count, export and e-mail.
- G2. An Administrator can be limited the same way ("service Administrator"): every resource-level Administrator
  action inside the service, none of the platform ones (users, settings, license, SSO, backups, audit, ACME providers,
  discovery networks).
- G3. Automation (API tokens) can be limited to services, and can belong to an automation account instead of a person.
- G4. Each service has an owner team that receives the service's e-mails, and a versioned policy that constrains what
  enters the service (domain names, certificate sources, ACME challenge and providers, automatic deployment) and sets
  defaults (renewal window, incident revocation).
- G5. Moving a private key across services is an explicit, two-sided decision (a **trust**), checked again by every
  background job that deploys.
- G6. Zero behaviour change for an installation that never creates a second service.

Non-goals (not in this design; some get hooks, §7.4):

- Deny rules, negative bindings, custom roles or per-permission grants.
- Nested services, service hierarchies, folders.
- Delegated administration: a service Administrator cannot grant access, create services, or change the service's
  domains.
- Audit log reading by scoped principals (global only in v1; new audit rows carry the service so it can come later).
- Drift detection, canary deployments, deployment windows, post-deploy verification policy (hooks only).
- Per-service SMTP, per-service alert thresholds, per-service ACME providers or hooks (providers stay platform objects).
- Scoping the vendor console (`internal/vconsole`): unrelated.

## 3. Vocabulary

- **Service**: a named group of resources with an optional environment, an owner team and a policy. Exactly one
  service is the **Default** service (`is_default`); it cannot be deleted.
- **Environment**: an Administrator-managed label (seeded: `production`, `staging`, `test`, `development`).
- **Owning service** of a resource: the service in its `service_id` column, or derived (§4.5).
- **Grant**: (role, where) where `where` is *global* or a set of services. A principal's grants come from its global
  role, its own bindings and the bindings of its directory groups.
- **Reach** of a principal for a permission: *all* (some global grant allows it) or the set of services where some
  grant allows it. Computed per request (SEC-017).
- **Platform permission**: only a global grant satisfies it. **Resource permission**: a grant on the resource's
  service satisfies it.
- **Trust** (`service_trusts`): "service B accepts certificates and SSH keys owned by service A on its servers and Key
  Vaults". Directed.
- **Automation account**: a non-person user that cannot sign in and only holds API tokens. (Not "service account":
  that term is the LDAP bind account on the directory form, `Hizmet hesabı DN'si`.)

## 4. Data model

### 4.1 New tables (migration `00024`)

```sql
CREATE TABLE environments (
    id         uuid PRIMARY KEY,
    key        text NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9-]{0,31}$'),
    name       text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60 AND name = btrim(name) AND name !~ '[[:cntrl:]]'),
    sort       smallint NOT NULL DEFAULT 0,
    version    integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
-- seeded: production (sort 10), staging (20), test (30), development (40); names localized in the UI by key,
-- an Administrator-renamed one shows its stored name.

CREATE TABLE services (
    id             uuid PRIMARY KEY,
    name           citext NOT NULL CHECK (char_length(name::text) BETWEEN 1 AND 100 AND name::text = btrim(name::text)
                                          AND name::text !~ '[[:cntrl:]]'),
    description    text NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
    environment_id uuid REFERENCES environments (id),          -- NULL: no environment
    is_default     boolean NOT NULL DEFAULT false,
    policy_version integer NOT NULL DEFAULT 1 CHECK (policy_version >= 1),
    version        integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by     uuid REFERENCES users (id),
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL
);
CREATE UNIQUE INDEX services_name ON services (name);
CREATE UNIQUE INDEX services_one_default ON services (is_default) WHERE is_default;
CREATE INDEX services_environment ON services (environment_id);

-- Append-only policy history (§7.3). Version 1 of every service is the empty policy {"schema":1}.
CREATE TABLE service_policies (
    service_id uuid NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    version    integer NOT NULL CHECK (version >= 1),
    body       jsonb NOT NULL CHECK (jsonb_typeof(body) = 'object' AND octet_length(body::text) <= 65536),
    created_by uuid REFERENCES users (id),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (service_id, version)
);
-- the application role gets SELECT, INSERT only (no UPDATE/DELETE), like license_files

-- A directory group Alice refers to (bindings, owner teams). value is exactly what the group claim (OIDC) or the group
-- search (LDAP) returns, with the rules of oidc_group_mappings / ldap_group_mappings (case-sensitive for LDAP).
CREATE TABLE directory_groups (
    id                uuid PRIMARY KEY,
    source            text NOT NULL CHECK (source IN ('oidc', 'ldap')),
    oidc_provider_id  uuid REFERENCES oidc_providers (id) ON DELETE CASCADE,
    ldap_directory_id uuid REFERENCES ldap_directories (id) ON DELETE CASCADE,
    value             text NOT NULL CHECK (char_length(value) BETWEEN 1 AND 1024 AND value = btrim(value) AND value !~ '[[:cntrl:]]'),
    label             text NOT NULL DEFAULT '' CHECK (char_length(label) <= 100),
    created_by        uuid REFERENCES users (id),
    created_at        timestamptz NOT NULL,
    CHECK ((source = 'oidc') = (oidc_provider_id IS NOT NULL) AND (source = 'ldap') = (ldap_directory_id IS NOT NULL)),
    UNIQUE NULLS NOT DISTINCT (source, oidc_provider_id, ldap_directory_id, value)
);

-- The groups a directory or SSO user had at the last sign-in or step-up (rewritten there in the same transaction as
-- the role; at most 1000 per user, see §6.1). The provider or directory is the user's own.
CREATE TABLE user_directory_groups (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    value   text NOT NULL CHECK (char_length(value) BETWEEN 1 AND 1024),
    seen_at timestamptz NOT NULL,
    PRIMARY KEY (user_id, value)
);

CREATE TABLE role_bindings (
    id                 uuid PRIMARY KEY,
    user_id            uuid REFERENCES users (id) ON DELETE CASCADE,            -- a person or an automation account
    directory_group_id uuid REFERENCES directory_groups (id) ON DELETE CASCADE,
    role               text NOT NULL CHECK (role IN ('admin', 'operator', 'auditor')),
    service_id         uuid REFERENCES services (id) ON DELETE CASCADE,
    environment_id     uuid REFERENCES environments (id) ON DELETE RESTRICT,
    created_by         uuid REFERENCES users (id),
    created_at         timestamptz NOT NULL,
    CHECK (num_nonnulls(user_id, directory_group_id) = 1),
    CHECK (num_nonnulls(service_id, environment_id) = 1),
    UNIQUE NULLS NOT DISTINCT (user_id, directory_group_id, role, service_id, environment_id)
);
CREATE INDEX role_bindings_user ON role_bindings (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX role_bindings_group ON role_bindings (directory_group_id) WHERE directory_group_id IS NOT NULL;

-- target_service accepts certificates and SSH keys owned by source_service (§5.6).
CREATE TABLE service_trusts (
    id                uuid PRIMARY KEY,
    source_service_id uuid NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    target_service_id uuid NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    created_by        uuid REFERENCES users (id),
    created_at        timestamptz NOT NULL,
    CHECK (source_service_id <> target_service_id),
    UNIQUE (source_service_id, target_service_id)
);

CREATE TABLE service_owners (
    id                 uuid PRIMARY KEY,
    service_id         uuid NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    user_id            uuid REFERENCES users (id) ON DELETE CASCADE,
    directory_group_id uuid REFERENCES directory_groups (id) ON DELETE CASCADE,
    created_by         uuid REFERENCES users (id),
    created_at         timestamptz NOT NULL,
    CHECK (num_nonnulls(user_id, directory_group_id) = 1),
    UNIQUE NULLS NOT DISTINCT (service_id, user_id, directory_group_id)
);
```

Global role bindings are **not** moved into `role_bindings`. They stay where they are and mean what they mean today:
`users.role` for a person (manual or written at sign-in from `oidc_group_mappings` / `ldap_group_mappings`). Reason:
`users.role` is read by session and token lookup, the last-administrator rule, the SSO Admin cap
(`DemoteSSOAdmins`), the notification recipients and the token scope check; moving it would touch all of them for no
change in meaning. In the UI the global role is shown as the first binding, "All services".

Bounds (application, refused with `validation.out_of_range`): at most 500 services, 50 environments, 200 bindings per
subject, 50 owners per service, 200 trusts per service.

### 4.2 Columns added to existing tables

| Table | Column | Rule |
|---|---|---|
| `users` | `role` becomes nullable | NULL = no global role. New CHECK `NOT is_break_glass OR role = 'admin'`. |
| `users` | `auth_source` gains `automation` | CHECK: `automation` has no password, no OIDC/LDAP columns, `is_break_glass = false`, `role IS NULL OR role IN ('operator','auditor')`, `role_source = 'manual'`. No `user_mfa` row is ever created for it. |
| `users` | `description text NOT NULL DEFAULT ''` (≤ 500) | for automation accounts |
| `targets` | `service_id uuid NOT NULL REFERENCES services` | servers and Key Vaults alike |
| `certificates` | `service_id uuid NOT NULL REFERENCES services` | owning service (§4.5) |
| `csr_requests` | `service_id uuid NOT NULL REFERENCES services` | holds a private key |
| `ssh_keys` | `service_id uuid NOT NULL REFERENCES services` | owning service (§4.5) |
| `acme_certificates` | `service_id uuid NOT NULL REFERENCES services` | |
| `discovery_scopes` | `service_id uuid NOT NULL REFERENCES services` | |
| `jobs` | `service_id uuid REFERENCES services` | set at enqueue; NULL for platform jobs (backup, license tick, audit verify, ...) |
| `alerts` | `service_id uuid REFERENCES services` | set when the alert row is written (history: the service at that time) |
| `certificate_incidents` | `service_ids uuid[] NOT NULL DEFAULT '{}'` | every service that held an affected location at start (§5.6) |
| `rotation_policies` | `approved_service_ids uuid[] NOT NULL DEFAULT '{}'` | the services a person with rights on all of them approved at enable / Run now (§5.7) |
| `api_tokens` | `service_ids uuid[]` | NULL = the owner's whole reach; otherwise a narrowing (§6.3) |

Each `service_id` gets an index (`(service_id)`; for `certificates` also `(service_id, not_after, id)` for the
expiry lists). Derived resources get no column: host keys, certificate locations, SSH key locations, deployments,
Key Vault certificates/keys/secrets/imports, KV bindings, ACME bindings, ACME orders, rotation policies (through their
key), rotation runs, discovery scans and endpoints, incident locations.

### 4.3 Migration `00024` and backfill

In one transaction (goose default):

1. Create the tables of §4.1; seed the four environments; insert the Default service (`name 'Default'`,
   `environment_id NULL`, `is_default true`, `gen_random_uuid()`) and its policy version 1 `{"schema":1}`.
2. For each table of §4.2 with `NOT NULL service_id`: `ADD COLUMN service_id uuid REFERENCES services (id)`,
   `UPDATE ... SET service_id = (SELECT id FROM services WHERE is_default)`, `ALTER ... SET NOT NULL`, index.
   `jobs.service_id` is backfilled from `target_id` (→ Default) for rows with a target and left NULL otherwise;
   `alerts.service_id` → Default; `certificate_incidents.service_ids` → `{Default}`;
   `rotation_policies.approved_service_ids` → `{Default}` for enabled policies.
3. `users.role DROP NOT NULL`; replace the `auth_source` and OIDC/LDAP CHECKs to admit `automation`; add the
   break-glass CHECK (every existing row passes: the wizard administrator is `admin`).
4. Grants for `alice_app` as the other tables (`service_policies`: SELECT, INSERT).

Down migration drops everything added; it refuses (RAISE) when a second service, a binding or an automation account
exists, so a down never silently widens access. `migrations/frozen_test.go` gains `00024` once Phase 1 merges.

Effect: every user keeps its `users.role`; every resource is in Default; no binding exists. Every route answers as
before (asserted by the unchanged authorization matrix, §12 Phase 1).

### 4.4 How new resources get a service

Every create route accepts an optional `service_id`:

- Given: the caller needs the route's permission on that service (403 `ALC-SVC-0006` otherwise; the body field is
  named in `fields`).
- Omitted, caller has a global grant for the permission: the Default service.
- Omitted, scoped caller: the only service where it holds the permission; 422 `ALC-SVC-0005` (`service.required`)
  when there are several or none.

Resources created by Alice itself inherit:

| Created by | Owning service |
|---|---|
| Discovery on a server (a certificate or SSH key seen for the first time) | the server's service |
| Key Vault sync (a `certificates` row of source `azure_kv`) | the vault's service |
| ACME order (each issued `certificates` row) | the ACME certificate's service |
| Signing request completed | the request's service |
| Upload of a certificate whose fingerprint already exists | unchanged; the caller needs `certificates.operate` on the existing owning service too (§5.6) |
| Generated SSH key, rotation's new key | the generating request's service / the rotated key's service |
| Discovery scan results | none of their own: visible through their scope (§4.5) |

### 4.5 Owning and visible services per resource

Certificates and SSH keys are de-duplicated installation-wide by fingerprint, so one row can be on servers of several
services. They therefore have an **owning** service (writes) and a set of **visible-from** services (reads).

| Resource | Owning service (writes) | Visible to readers of |
|---|---|---|
| Server, Key Vault (`targets`) | `targets.service_id` | owning |
| Host key, certificate location, SSH key location, KV certificate/key/secret/import | the target's | the target's |
| Certificate | `certificates.service_id` | owning ∪ services of targets with a live location of it ∪ the vault's service of a KV certificate holding it ∪ the service of an ACME certificate whose current or past certificate it is |
| Signing request | `csr_requests.service_id` | owning |
| SSH key | `ssh_keys.service_id` | owning ∪ services of targets with a live location |
| Rotation policy, rotation run | the key's | the key's ∪ services in `approved_service_ids` |
| ACME certificate (and its orders, bindings) | `acme_certificates.service_id` | owning ∪ services of bound locations' targets |
| KV binding | the vault's service | the vault's ∪ services of bound locations' targets |
| Deployment | the location's target's | that ∪ the certificate's owning service |
| Incident | `certificates.service_id` of its certificate | `service_ids` |
| Discovery scope, scan, endpoint | the scope's | the scope's |
| Discovery certificate (`discovery_certificates`) | none (read-only) | services of scopes with an endpoint presenting it (leaf or chain) |
| Job | `jobs.service_id` (NULL: platform) | same |
| Alert | `alerts.service_id` | same |

## 5. Authorization semantics

### 5.1 Grants and reach

A principal's grants, loaded at every request together with the session or token lookup (no cache beyond the
request, SEC-017):

1. `users.role` if not NULL → (role, global).
2. Each `role_bindings` row with `user_id` = the user → (role, {service} or {services with that environment}).
3. For an OIDC or LDAP user, each `role_bindings` row whose `directory_group_id` names a group of the user's own
   provider or directory whose `value` is in `user_directory_groups` for the user → as 2.
4. **SSO Admin cap**: for an OIDC or LDAP user, while the setting "SSO users may be Admin" is off, every `admin` from
   2 and 3 counts as `operator` (as SEC-014 already caps the global role).
5. An environment binding is expanded to the services that have the environment **now** (a service created later in
   production is in reach at once; relabelling a service changes reach at once, which is why relabelling is a global
   Administrator's act, §10).

Reach for permission *p* = *all* if a global grant's role is in *p*'s policy roles, else the set of services of the
scoped grants whose role is. Token scope (`read`/`operate`) and step-up apply to every grant exactly as today.

`internal/rbac` stays pure: it gains `Grants`, `ScopedGrant{Role, Services []uuid.UUID}` and
`Reach(p, subject) (all bool, services []uuid.UUID)`, `DecideIn(p, subject, serviceID)`. The loading, resolving and
SQL live in a new package `internal/authz` (archtest: `authz` may import `rbac`, `platform/db`; `inventory`,
`sshkeys`, `discovery`, `reports`, `alerts`, `notify` may import `authz`'s value types only, not its loader).

### 5.2 Platform and resource permissions

| Permission | Kind | Note |
|---|---|---|
| `public`, `setup`, `mfa_pending`, `session`, `session.stepup` | unchanged | self or anonymous |
| `users.read`, `users.manage`, `settings.manage`, `license.read`, `license.manage`, `sso.manage`, `backup.manage`, `audit.read`, `acme.preview`, `discovery.manage` | platform | |
| `read`, `acme.view`, `discovery.view` | resource, or *any* on routes without a resource | §5.3 |
| `targets.manage`, `hostkeys.confirm`, `hostkeys.repin`, `inventory.operate`, `jobs.confirm`, `certificates.operate`, `credentials.manage`, `sshkeys.download`, `rotation.manage`, `rotation.operate`, `acme.operate`, `certificates.incident` | resource | |
| `acme.manage` | resource on `/acme/certificates/...`; platform on providers, accounts, hooks | decided per route (§11) |
| new `services.manage` | platform | Admin, step-up, never a token. Services, environments, owner teams. |
| new `access.manage` | platform | Admin, step-up, never a token. Role bindings, directory groups, automation accounts and their tokens. |
| new `services.policy` | resource | Admin, step-up, never a token. Except `domains`, which needs a global grant (§7.3). |
| new `services.assign` | cross (source and destination) | Admin, step-up, never a token. Moving resources between services. |
| new `services.trust` | cross (both services) | Admin, step-up, never a token. Creating needs it on both, removing on either. |

All five new permissions are `ClassAlways` (they change Alice's own records, not a managed system) with the default
rate limit.

### 5.3 Route classes

The route table (`internal/api/server.go`, `type route`) gains two fields:

```go
scope    routeScope   // scopePlatform | scopeAny | scopeSelf | scopeResource | scopeList | scopeCreate | scopeCross
resolver resolverFunc // scopeResource (and the path part of scopeCross): which resource the path names
```

`register` refuses to start when a route has no `scope`, when a `scopeResource` route has no resolver, or when a path
with `{id}`-like parameters is not `scopeResource`/`scopeCross`/`scopeSelf`/`scopePlatform` (deny by default, as
SEC-016). The generated `docs/authz-matrix.md` gains a **Scope** column.

| Class | Route-level check in `guard` | Then |
|---|---|---|
| `scopePlatform` | `Decide` with the global grant only; a token with `service_ids` is refused | handler as today |
| `scopeAny` | allowed when some grant allows the permission | handler; the answer is filtered as §5.8 says |
| `scopeSelf` | as today | the caller's own records |
| `scopeResource` | allowed when some grant allows it | `guard` resolves the resource and checks it (§5.4) before the handler |
| `scopeList` | allowed when some grant allows it | the service function filters by reach (§5.8) |
| `scopeCreate` | allowed when some grant allows it | the handler resolves `service_id` (§4.4) and checks it |
| `scopeCross` | allowed when some grant allows it | path resource as `scopeResource`, then the cross rule of §5.6 in the service function |

### 5.4 Checking a resource (and IDOR)

For `scopeResource` and `scopeCross` routes `guard` calls the route's resolver (`byTarget("id")`,
`byCertificate("id")`, `byBinding("id")`, ... one per row of §4.5), which returns the owning service and the
visible-from set with one indexed query, then:

- the resource does not exist **or** no visible-from service is in the caller's `read` reach (and the reach is not
  *all*) → the route's own not-found error (each resolver carries it: `ErrTargetNotFound`, `ErrCertificateNotFound`,
  ...), and an audit `authz.denied` row with reason `out_of_scope` (deduplicated like other refusals, SEC-070/R39 item 4).
  Existence is never revealed.
- visible, the route's permission is a read → allowed.
- visible, the permission is a write and the owning service is not in the permission's reach → 403
  `ALC-AUTH-0002` (`auth.forbidden`), audit reason `scope`.

Resolvers check path parents too: `/targets/{id}/kv/certificates/{certificate_id}` resolves the vault and keeps the
existing check that the certificate belongs to it; `/targets/{id}/host-keys/{key_id}/...` likewise.

**Time of check vs time of use.** A resource can be moved between services after `guard` checked it. Every service
function behind a `ClassChange` or `ClassAlways` write route already locks its row (`FOR UPDATE`); it re-checks the
owning service against the reach carried in its `Actor` under that lock (`authz.Assert`). Moves (`services.assign`)
lock the same rows, so a write and a move serialize.

### 5.5 Conditional permissions inside handlers

The conditional rules of the matrix notes (`credentials.manage` for `DELETE /targets/{id}?remove_bindings=true`, for
adding locations to an automatic KV binding, for deploying a held version; `acme.manage` for switching an ACME
binding's automatic deployment on) are evaluated **on the owning service of the source** (the vault, the ACME
certificate) with the same step-up rule as today.

### 5.6 Cross-service actions: the rule

> An action that places a certificate's private key or an SSH key's public key on a server or into a Key Vault needs
> (a) the action's permission on the **source's owning service**, (b) the destination permission on **each
> destination target's service**, and (c) when the two services differ, a **trust** from the destination service to
> the source service. (c) is checked again by the deployment engine at the first send and by every background job
> that deploys.

Applied:

| Action | (a) source | (b) destination | (c) |
|---|---|---|---|
| `POST /certificates/{id}/deploy` | `certificates.operate` on the certificate's service | `certificates.operate` on each location's target's service | yes |
| `POST /bindings` (KV), `PATCH /bindings/{id}` adding locations | `certificates.operate` on the vault's service | same on each added location's service | yes |
| `PUT /acme/certificates/{id}/bindings/{location_id}` | `acme.operate` on the ACME certificate's service (`acme.manage` when switching automatic deployment on) | `acme.operate` on the location's service | yes |
| `POST /certificates/{id}/actions/import-to-key-vault` | `credentials.manage` on the certificate's service | `credentials.manage` on the vault's service | yes |
| `POST /ssh-keys/{id}/actions/deploy` | `inventory.operate` on the key's service | `inventory.operate` on each target's service | yes |
| `POST /bindings/{id}/actions/deploy`, `POST /acme/certificates/{id}/deploy` | the source permission only: the bindings were approved on both sides when made | — | re-checked at the first send |
| Removing a binding or one of its locations | **either** side's permission: the receiving service can always detach its own server | — | no |
| `POST /certificates/{id}/incidents` and the incident actions | `certificates.incident` on **every** service in the incident's `service_ids` (computed at start: the certificate's service and every service holding an affected location) | — | no: an incident replaces a key that is already there |
| `POST /rotation/policies/{id}/actions/enable`, `.../run`, run decisions | `rotation.operate` on the key's service and every service holding a live location; stored in `approved_service_ids` | — | no: the key is already there |
| HTTP-01 server of an ACME certificate (`http_target_id`) | `acme.manage` on the ACME certificate's service | `certificates.operate` on the server's service (Alice writes a challenge file there) | no (no key moves) |
| `POST /services/{id}/actions/assign` | `services.assign` (Admin) on each resource's current service | `services.assign` on the destination | no |

A refusal for missing rights on a service the caller cannot see says only "outside your services"
(`ALC-SVC-0012`, `service.spans_services`, with a count, never a name). A missing trust is `ALC-SVC-0007`
(`service.untrusted`, 409) naming both services (the caller sees both, having rights on both).

Trusts are created with `services.trust` on both services (a global Administrator trivially) and removed with it on
either. Removing a trust does not undo deployments; it stops later ones: the engine's first send and the automatic
deployment plans of ACME and Key Vault bindings refuse a cross-service location without a trust, mark the binding
location with the attention code `service.untrusted` and send the binding's usual "automatic deployment stopped"
e-mail (routed per §7.2).

Where (c) is enforced in code: `inventory.(*Service).checkDeployLocation` (every deploy request: manual, KV, ACME,
incident is exempted by its source), the engine's first send (next to the revoked/compromised refusal of R46),
`planACMEAutoDeploy` / the KV auto-deploy plan, `kv_imports` before the vault call, `sshkeys` `checkDeploy`.

### 5.7 Background work acting across services

Jobs run as the system (`audit.ActorSystem`). They are not re-authorized against the person who caused them (people
change role, leave, are disabled; work must not stall or flip). Instead, every background step that crosses a service
boundary re-checks a **structural** fact recorded when a person with the rights approved it:

- deployments: a trust exists (§5.6), or the deployment belongs to an incident;
- rotation: the services now holding live locations of the key ⊆ `approved_service_ids`; otherwise the run does not
  start (or does not continue to the next step) and the policy goes to its existing "needs attention" state with
  the code `service.spans_services`; an Administrator with rights on all of them enables it again;
- incidents: the affected locations are fixed at start (`certificate_incident_locations`); `incident.advance`
  touches no other location;
- moving a target to another service leaves its bindings in place; the next automatic deployment to it is checked by
  (c) like any other.

Jobs queued by a person carry `jobs.service_id` (the target's service, the ACME certificate's, the key's, the
scope's). `jobs.confirm` (work held by the license) is checked on that service; a job with `service_id` NULL is
platform work and needs a global grant.

### 5.8 Lists, counts, dashboard, reports, discovery, audit

- **Lists** (`scopeList`): the inventory/sshkeys/discovery list functions take an `authz.Reach`; *all* adds no
  condition; otherwise `service_id = ANY($n)` on owned rows, and for certificates and SSH keys the visible-from rule of
  §4.5 as `EXISTS` sub-queries on locations, KV certificates and ACME bindings. Cursor pagination is unchanged (the
  filter applies before the cursor). Totals and facet counts are computed over the filtered set.
- **Filters**: every list gains `service_id` (repeatable) and `environment_id` (repeatable) query filters, intersected
  with the reach.
- **Detail answers** list only the related rows in reach: a certificate's locations, an SSH key's locations, a
  binding's locations, an incident's locations, the impact of a certificate (`GET /certificate-impact/{id}`). Each
  such list gains `hidden_count` (rows outside the caller's reach): an operator of service B must know that the
  compromised key is also elsewhere, but not where.
- **Owning service of a row seen from another service**: shown as `{"id": ..., "name": ...}` when in reach, as
  `{"outside": true}` otherwise.
- **Dashboard** (`/dashboard/summary`, `/dashboard/expiring`) and `GET /alerts`: computed over the caller's `read`
  reach; the audit head stays Administrators' and Auditors' with a **global** grant.
  `GET /notifications/status` answers the delivery state to global Administrators only.
- **Exports** (certificates, SSH keys, discovery CSV): filtered like the list; the `*.export` audit row records the
  reach (`"reach":"all"` or the service ids).
- **Network discovery**: a scope belongs to a service; its scans, endpoints and the certificates its endpoints
  present are visible to readers of that service (`discovery.view`, still operate scope for tokens, D7). Creating,
  changing and deleting scopes, the allowed networks, global exclusions and retention stay `discovery.manage`
  (platform: what may be dialed is the SSRF decision, D1). `GET /discovery/settings` becomes platform (it shows the
  allowed networks). Starting and cancelling a scan is `discovery.operate` on the scope's service.
- **Audit log**: platform (`audit.read` with a global grant) in v1. From Phase 2 on, every audit row about a resource
  carries `details.service_id` (the owning service at that time), so a scoped audit view can be added later without
  a migration of the chain.
- **Jobs list**: filtered by `jobs.service_id`; platform jobs (NULL) only with a global grant.
- **Saved views**: the person's own, unchanged; a view's filters that name services outside the reach simply match
  nothing.

### 5.9 Step-up, tokens and the rest that stays

Step-up rules, the five-minute window, "never a token" permissions, rate limits, the license lock classes and the
CSRF/origin checks are unchanged. A scoped grant never makes a step-up permission token-usable.

### 5.10 Error shape

| Situation | Answer |
|---|---|
| By-id resource outside the read reach, or absent | the route's 404 code |
| Visible, write not allowed on its service | 403 `ALC-AUTH-0002` |
| Platform route, only scoped grants (or a service-restricted token) | 403 `ALC-AUTH-0002` |
| Create in a service outside the reach | 403 `ALC-SVC-0006` |
| Cross action, a destination outside the reach | 403 `ALC-SVC-0012` (count only) |
| Cross action, no trust | 409 `ALC-SVC-0007` |

## 6. Directory groups, automation accounts and API tokens

### 6.1 Directory groups

- At every OIDC or LDAP sign-in and step-up, the API already has the user's group list (it computes the highest mapped
  role from it). It now also passes the list to `auth.SignInOIDC` / `SignInLDAP` / `StepUpOIDC` / `StepUpLDAP`, which
  rewrite `user_directory_groups` for the user in the same transaction as the role (first 1000 values in the order
  received; when more were returned, an audit detail `groups_truncated` — fewer rights, never more).
- **Sign-in refusal changes**: today a directory or SSO user with no mapped group is refused (`no_access`). Now the
  user is refused when it has no mapped group **and** no scoped binding of its own and none through any of its groups.
  A user with only scoped bindings signs in with `users.role` NULL.
- A group removed in the directory takes effect at the user's next sign-in or step-up (as role changes do today);
  **Disable** on People & access stops the sessions at once (unchanged).
- Bindings and owner teams name a `directory_groups` row (source, provider or directory, value). An Administrator
  declares the group (free text, or picked from the values seen at sign-ins of that provider/directory:
  `SELECT DISTINCT value FROM user_directory_groups JOIN users ...`, shown with the number of users).
- Deleting an OIDC provider or LDAP directory cascades its groups, their bindings and owner entries (the provider or
  directory delete already refuses while users exist, so only unused groups go).

### 6.2 Automation accounts

- A user with `auth_source = 'automation'`: a name (the user name rule), a display name, a description. It cannot sign
  in (no password, no MFA, no session is ever created; the local sign-in query excludes it), it is never the
  break-glass account, its global role is NULL, Operator or Auditor (never Admin), and it can hold scoped bindings of
  any role (an Admin binding on a service lets its operate tokens do that service's `targets.manage` and
  `rotation.manage`, which accept operate tokens today).
- Created, changed and disabled by a global Administrator (`access.manage`, step-up). Disabling revokes its tokens
  (as for a person, SEC-019 / R39 item 5). Never deleted (audit references); the name stays taken.
- Its tokens are created and revoked by a global Administrator on its page (`access.manage`, step-up), shown once,
  with the rules of SEC-026 (expiry ≤ 365 days, scopes, prefix). The audit row names the Administrator and the account.

### 6.3 API tokens limited to services

- `POST /tokens` and `POST /automation-accounts/{id}/tokens` take an optional `service_ids` (1 to 50 services; each
  must be in the owner's reach for some role at creation, 422 `ALC-TOK-0002` otherwise).
- Effective rights of a token = the owner's grants **now** ∩ the token scope (`read`/`operate`, as today) ∩
  `service_ids` (when set). A token with `service_ids` never passes a platform route, even when its owner is a global
  Administrator.
- The token-scope check at creation (`AllowsScope`) passes when some grant of the owner allows the scope.
- An SSO or directory user still cannot create tokens (R42); automation accounts are the answer for them.

## 7. Service ownership and policy

### 7.1 Owner team

`service_owners` lists people, automation accounts are refused (422), and directory groups. Ownership gives **no
access**: it decides who receives the service's e-mails and who is shown as responsible. The Owners editor warns when an
owner has no binding that reaches the service ("Receives e-mails but cannot open this service"). Edited by a global
Administrator (`services.manage`, step-up), replaced as a whole list with the service's `version` (409 on a stale one).

### 7.2 Notification routing

Recipients of a **service e-mail** for services *S*:

1. the Administrator recipients of today (`notify.recipientsFor`: enabled users with a **global** `admin` role and an
   address, plus the extra addresses of the notification settings) — **only if** some service in *S* has
   `notifications.administrators` true in its policy (default true; Default service true);
2. for each service in *S*: its owners that are enabled people with an address, and the enabled members (by
   `user_directory_groups`) of its owner groups;
3. for each service in *S*: its policy's extra addresses (`notifications.addresses`, ≤ 20, with locale).

Deduplicated by mailbox (`sameMailbox`), each in its own locale, one outbox row per recipient (as today).

| E-mail (template keys of `locales/common`) | *S* |
|---|---|
| `alert.certificate_expiring/expired` | the certificate's owning service ∪ services of its live locations |
| `alert.kv_certificate_*`, `alert.kv_key_*`, `alert.kv_credential_*`, `kv.*` | the vault's service |
| `alert.discovered_certificate_*` | the services of the scopes that saw it |
| `alert.more`, `alert.more_discovered` (digests) | built **per recipient**: each recipient's digest lists only the items whose *S* made it a recipient |
| `deployment.*` | the destination target's service ∪ the certificate's owning service |
| `target.host_key_changed`, `target.auth_failed` | the target's service |
| `acme.*` | the ACME certificate's service |
| `rotation.*` | the key's service ∪ `approved_service_ids` |
| incident e-mails (R46) | the incident's `service_ids` |
| `job.dead` | `jobs.service_id` (NULL: Administrators only) |
| `backup.*`, `license.*`, `auth.lockout`, `audit.broken`, `job.tampered`, `notify.test` | **platform**: Administrators only, as today |

Ruling: the rotation notice gate ("a scheduled run starts only after its notice e-mail was delivered") counts a
delivered copy to any recipient of the notice, owners included: they are the people responsible for the key.

An installation with only the Default service, no owners and the default policy sends exactly today's e-mails to
exactly today's recipients.

### 7.3 Policy (versioned)

The policy is a JSON document, validated by a Go struct decoded with `DisallowUnknownFields`, saved as a new
`service_policies` row (`version = services.policy_version + 1`) with `If-Match`-style `version` in the body (409
`ALC-SVC-0010` on a stale one), audited with the changed top-level keys. Schema 1:

```json
{
  "schema": 1,
  "domains": ["pay.example.com", "*.pay.example.com", "10.20.0.0/16"],
  "certificate_sources": ["acme", "uploaded", "csr"],
  "acme": {
    "providers": ["<acme_providers.id>"],
    "challenges": ["dns01", "http01"],
    "key_types": ["ecdsa_p256", "rsa_3072"],
    "renew_before_days": 30
  },
  "deployment": { "auto_deploy": "allowed" },
  "incident": { "revoke_mode": "after_verified" },
  "notifications": { "administrators": true, "addresses": [{ "email": "pay-team@example.com", "locale": "en" }] }
}
```

Every field is optional; absent means "no constraint" or "today's default". Phase 5 builds exactly these:

| Field | Meaning | Enforced at |
|---|---|---|
| `domains` (≤ 200; a DNS name matches itself; `*.suffix` matches any name ending in `.suffix` at any depth, wildcard names included; an IP or CIDR matches IP SANs inside it) | every name of a certificate entering the service must match an entry; empty list = no constraint | ACME certificate create/edit (names), CSR create, upload (CN and SANs), assign of a certificate, ACME certificate or CSR into the service. 422 `ALC-SVC-0008` naming the first name outside. Changing it needs a **global** grant (403 `ALC-SVC-0011`). |
| `certificate_sources` (`acme`, `uploaded`, `csr`) | how new certificates may enter | upload, CSR create, ACME certificate create. 422 `ALC-SVC-0009`. |
| `acme.providers`, `acme.challenges`, `acme.key_types` | allowed values for the service's ACME certificates (validation method = challenge) | ACME certificate create/edit. 422 `ALC-SVC-0014`. |
| `acme.renew_before_days` (1–60) | default for new ACME certificates of the service | create form default; not a constraint |
| `deployment.auto_deploy` (`allowed` \| `forbidden`) | whether automatic deployment may be on for the service's KV bindings and ACME certificates/bindings | switching it on: 422 `ALC-SVC-0013`; the ACME/KV automatic deployment plans hold with attention `service.auto_deploy_forbidden` while the policy forbids it (existing automatic bindings stop deploying, they are not switched off) |
| `incident.revoke_mode` (`after_verified` \| `now`) | default of an incident started on the service's certificates | incident start form default |
| `notifications.administrators`, `notifications.addresses` | §7.2 | outbox |

A policy is evaluated when an action happens; it is never applied retroactively to existing objects (except the
auto-deploy hold above, which only stops work). Who edits: `services.policy` (Admin of that service, step-up);
the `domains` field additionally needs a global grant, because a service Administrator widening its own domains would
defeat the guard. Global Administrators are not exempt from a policy; they change it.

### 7.4 Later work and its hooks

Reserved top-level keys, refused now with 422 `ALC-SVC-0015` ("not available yet"), so adding them later is not a
breaking change: `verification` (post-deploy TLS check policy), `drift` (detect and act on a server whose file no
longer matches), `canary` (deploy to a subset first), `windows` (deployment windows), `thresholds` (per-service expiry
alert days). The UI shows them nowhere in v1. Also later: a scoped audit view (rows already carry
`details.service_id`), a per-service "outside policy" flag on discovered certificates, per-service ACME providers.

## 8. API changes

### 8.1 New routes

| Method | Path | Permission | Scope | Lock class |
|---|---|---|---|---|
| GET | `/api/v1/environments` | `read` | any | — |
| POST | `/api/v1/environments` | `services.manage` | platform | always |
| PATCH | `/api/v1/environments/{id}` | `services.manage` | platform | always |
| DELETE | `/api/v1/environments/{id}` | `services.manage` | platform (409 `ALC-SVC-0016` while a service or binding uses it) | always |
| GET | `/api/v1/services` | `read` | list (services in reach; global: all) | — |
| POST | `/api/v1/services` | `services.manage` | platform | always |
| GET | `/api/v1/services/{id}` | `read` | resource: service | — |
| PATCH | `/api/v1/services/{id}` | `services.manage` | platform (name, description, environment) | always |
| DELETE | `/api/v1/services/{id}` | `services.manage` | platform (409 `ALC-SVC-0003` unless empty; Default: 409 `ALC-SVC-0004`) | always |
| GET | `/api/v1/services/{id}/policy` | `read` | resource: service | — |
| GET | `/api/v1/services/{id}/policy/versions` | `read` | resource: service | — |
| PUT | `/api/v1/services/{id}/policy` | `services.policy` | resource: service (+ global for `domains`) | always |
| GET | `/api/v1/services/{id}/owners` | `read` | resource: service | — |
| PUT | `/api/v1/services/{id}/owners` | `services.manage` | platform | always |
| POST | `/api/v1/services/{id}/actions/assign` | `services.assign` | cross: destination `{id}`, sources from the body (`resources: [{type, id}]`, ≤ 500; types `target`, `certificate`, `csr`, `ssh_key`, `acme_certificate`, `discovery_scope`) | always |
| GET | `/api/v1/service-trusts` | `read` | list (either side in reach) | — |
| POST | `/api/v1/service-trusts` | `services.trust` | cross: both services | always |
| DELETE | `/api/v1/service-trusts/{id}` | `services.trust` | cross: either service | always |
| GET | `/api/v1/role-bindings` | `users.read` | platform (filters `user_id`, `directory_group_id`, `service_id`, `environment_id`) | — |
| POST | `/api/v1/role-bindings` | `access.manage` | platform | always |
| DELETE | `/api/v1/role-bindings/{id}` | `access.manage` | platform | always |
| GET | `/api/v1/users/{id}/access` | `users.read` | platform: the effective grants and where each comes from | — |
| GET | `/api/v1/directory-groups` | `users.read` | platform (with values seen at sign-in) | — |
| POST | `/api/v1/directory-groups` | `access.manage` | platform | always |
| DELETE | `/api/v1/directory-groups/{id}` | `access.manage` | platform (cascades its bindings and owner entries; the answer counts them) | always |
| GET | `/api/v1/automation-accounts` | `users.read` | platform | — |
| POST | `/api/v1/automation-accounts` | `access.manage` | platform | always |
| PATCH | `/api/v1/automation-accounts/{id}` | `access.manage` | platform (display name, description, global role, disable) | always |
| GET | `/api/v1/automation-accounts/{id}/tokens` | `users.read` | platform | — |
| POST | `/api/v1/automation-accounts/{id}/tokens` | `access.manage` | platform | always |
| DELETE | `/api/v1/automation-accounts/{id}/tokens/{token_id}` | `access.manage` | platform | always |

`assign` answers a preview with `?dry_run=true`: per resource, the move, and the bindings that become cross-service
without a trust (they will stop deploying; §5.6).

### 8.2 Changed answers and bodies

- `GET /auth/session` gains `access`: `{"global_role": "operator"|null, "services": [{"id","name","environment",
  "roles":[...]}], "permissions_anywhere": [...]}` (for navigation).
- Every DTO of a row in §4.5 (lists and details) gains `service` (`{id, name, environment}` or `{"outside": true}`)
  and `allowed_actions`: the permissions the caller holds on that row (computed in Go from the row's owning service
  and the request's reach; step-up not considered: the UI still asks for it).
- Create bodies gain optional `service_id` (§4.4): `POST /targets`, `POST /key-vaults`, `POST /certificates/upload`,
  `POST /certificates/csr`, `POST /ssh-keys/generate`, `POST /acme/certificates`, `POST /discovery/scopes`.
  `PATCH` bodies do **not** accept `service_id` (unknown field): moving is `assign`.
- `POST /tokens` gains `service_ids`; token answers show it.
- `POST /role-bindings`: `{"user_id"|"directory_group_id", "role", "service_id"|"environment_id"}`.
- The impact, incident, certificate, SSH key and binding detail lists gain `hidden_count` (§5.8).
- OpenAPI (`internal/api/openapi.yaml`): every new route with `x-permission` and the new `x-scope` extension; the
  OpenAPI test asserts `x-scope` equals the route table's.

### 8.3 Error codes

New area `ALC-SVC` (services) and `ALC-ACC` (access), each with EN and TR texts in `locales/common` and the error
catalogue test:

| Code | Reason | Status |
|---|---|---|
| `ALC-SVC-0001` | `service.not_found` | 404 |
| `ALC-SVC-0002` | `service.name_taken` | 409 |
| `ALC-SVC-0003` | `service.not_empty` | 409 |
| `ALC-SVC-0004` | `service.default_protected` | 409 |
| `ALC-SVC-0005` | `service.required` | 422 |
| `ALC-SVC-0006` | `service.not_allowed` (create or assign into a service outside the reach) | 403 |
| `ALC-SVC-0007` | `service.untrusted` | 409 |
| `ALC-SVC-0008` | `service.domain_not_allowed` | 422 |
| `ALC-SVC-0009` | `service.source_not_allowed` | 422 |
| `ALC-SVC-0010` | `service.version_conflict` | 409 |
| `ALC-SVC-0011` | `service.domains_global_only` | 403 |
| `ALC-SVC-0012` | `service.spans_services` | 403 |
| `ALC-SVC-0013` | `service.auto_deploy_forbidden` | 422 |
| `ALC-SVC-0014` | `service.acme_not_allowed` (provider, challenge or key type) | 422 |
| `ALC-SVC-0015` | `service.policy_field_unavailable` | 422 |
| `ALC-SVC-0016` | `environment.in_use` | 409 |
| `ALC-SVC-0017` | `environment.key_taken` | 409 |
| `ALC-ACC-0001` | `binding.duplicate` | 409 |
| `ALC-ACC-0002` | `binding.role_not_allowed` (an automation account's global Admin) | 422 |
| `ALC-ACC-0003` | `directory_group.not_found` | 404 |
| `ALC-ACC-0004` | `automation.cannot_sign_in` (never shown to the person; audit reason) | — |
| `ALC-ACC-0005` | `binding.limit` | 422 |
| `ALC-TOK-0002` | `token.service_not_allowed` | 422 |

## 9. User interface and i18n

Screens (React, `web/src/pages`; every role check `role === 'admin'` (37 places today) is replaced by
`can(session, perm)` for platform actions and `canOn(row, perm)` from `allowed_actions` for resource actions):

- **Services** (new top-level page under the administration group, visible to everyone with a grant; global
  Administrators see all, others their own): list with name, environment badge, owners, counts of servers, Key Vaults,
  certificates, ACME certificates, SSH keys, scopes, policy version. Create, edit, delete (when empty).
- **Service page**, tabs: *Overview* (environment, description, owners, policy summary); *Resources* (servers, Key
  Vaults, certificates, ACME certificates, SSH keys, scopes, each linking to the existing pages; **Move here**
  dialog with the dry-run warnings); *Access* (bindings that reach the service: direct, through its environment,
  through groups, plus "All services" holders as a note; add/remove for global Administrators with step-up);
  *Policy* (form for §7.3 fields, version history with who and when, `domains` read-only for non-global
  Administrators); *Trusts* ("Accepts certificates and keys from", "Sends certificates and keys to").
- **People & access**: a person's page gains *Access* (global role as the first row "All services", service and
  environment bindings, rights through groups read-only, "Explain" from `GET /users/{id}/access`); new tabs
  **Groups** (directory groups, their bindings and members seen) and **Automation accounts** (list, create, disable,
  tokens).
- **Every resource list** (servers, Key Vaults, certificates, ACME certificates, SSH keys, deployments, discovery,
  rotations, incidents, jobs): a Service column with the environment badge and Service/Environment filters; every
  create dialog a Service picker (preselected when only one is possible); every detail page a service badge and, for
  holders of `services.assign`, **Move to service**.
- **Dashboard**: a service filter ("All my services" by default).
- **Tokens**: a "Limit to services" multi-select.
- **Settings → Environments**: list, add, rename, reorder, delete when unused.
- A person with no grant at all sees one page: "You do not have access to anything yet. Ask an Administrator."
- Hidden rows: detail lists show "and N more outside your services" when `hidden_count > 0`.

Terms (EN / TR), added to `web/src/locales/*.json` and `locales/common/*.json`, with a `terms.test.ts` rule that
"service account" is never used for automation accounts:

| EN | TR |
|---|---|
| Service | Hizmet |
| Environment | Ortam |
| Production / Staging / Test / Development | Üretim / Hazırlık / Test / Geliştirme |
| Owners | Sorumlular |
| Access | Erişim |
| All services | Tüm hizmetler |
| Automation account | Otomasyon hesabı |
| Accepts certificates and keys from | Şu hizmetten sertifika ve anahtar kabul eder |
| Service policy | Hizmet ilkesi |
| Move to service | Hizmete taşı |
| outside your services | hizmetlerinizin dışında |

`make i18n-check` covers both catalogues.

## 10. Security analysis

| Threat | Mitigation |
|---|---|
| **IDOR on by-id routes** | One resolver per resource kind in `guard`, mandatory for every route with a path id (startup refusal otherwise); out-of-reach = the route's 404; a generated test (`TestScopedIDOR`) iterates the route table with a scoped identity and fixtures in another service (§12 Phase 2). Service functions re-check under their row lock (§5.4). |
| **List, count and search leaks** | Reach filter inside the SQL, never after paging; totals over the filtered set; exports filtered; `hidden_count` gives numbers, never names; owning service shown as `outside`. Name-uniqueness refusals (server, scope, service names are unique installation-wide) can reveal that a name exists: accepted and documented (names are not secrets; the alternative, per-service names, breaks the existing unique indexes and the audit wording). |
| **Error texts naming foreign objects** | Conflict errors that today name another object (a location bound to another ACME certificate, a file used by another binding) say "another certificate outside your services" when the object is not visible. Review item for every `ErrorCode` with params in Phase 2. |
| **Confused deputy: background jobs** | Jobs act as the system on approved structures; cross-service steps re-check trusts and `approved_service_ids` (§5.7); a person's later loss of rights stops nothing they already approved, a removed trust stops further deliveries. |
| **Confused deputy: Alice's own credentials** | The platform SSH key and Key Vault credentials are per target; scoped principals reach them only through targets in reach. `GET /ssh-keys/platform-key` returns the public key only (unchanged). |
| **Key exfiltration across services** | §5.6: rights on both sides plus a two-sided trust; private key download needs `sshkeys.download` on the key's own service; KV import needs both sides. |
| **Privilege escalation through bindings** | Only global Administrators manage bindings, groups and automation accounts, with step-up, never a token; every change audited (`access.binding_added/removed` with subject, role, scope). A service Administrator cannot grant, cannot create services, cannot change domains or environments. |
| **Escalation through group membership** | A directory administrator can add a person to a bound group: inherent, as for global mappings today; documented. The SSO Admin cap applies to scoped Admin bindings too (§5.1 step 4). Membership changes take effect at the next sign-in or step-up. |
| **Escalation through environment relabel** | Changing a service's environment changes every environment binding's reach: `services.manage` (global), step-up, audited with the old and new environment. |
| **Escalation through assignment** | Moving a resource needs Admin on its current service **and** on the destination; nobody can pull another service's resource into their own. Domain policy is checked on certificates moved in. |
| **Escalation through ownership** | Ownership grants no access; owners are edited by global Administrators. |
| **Escalation through tokens** | Token rights are always the owner's current grants ∩ scope ∩ `service_ids`; narrowing only. Automation accounts never hold a global Admin. |
| **Last global Administrator lockout** | Unchanged rule (SEC-015): the last enabled local user with global `admin` cannot be disabled, deleted or demoted; scoped bindings never count. New CHECK: the break-glass account is always a global `admin`. Deleting a service or binding cannot touch global roles. |
| **Stale authorization** | Grants loaded per request (SEC-017); environment expansion per request; a binding removed takes effect on the next request; group membership at next sign-in/step-up. |
| **Audit of access decisions** | `authz.denied` with reasons `scope` and `out_of_scope` (deduplicated, R39 item 4); binding, service, owner, trust, policy, assignment, environment and automation-account changes each audited with before/after. |
| **Down-migration widening access** | The down refuses when scoped state exists (§4.3). |
| **Performance as availability** | Two indexed queries per request for grants; reach filters on indexed `service_id`; budget: p95 overhead < 2 ms on the perf suite fixture. |

## 11. Every route and how it is scoped

The 225 operations of the route table at `bdbf9b3b` (every row of `docs/authz-matrix.md`, `/livez` and `/healthz`
included). Classes as §5.3: **P** platform, **A** any, **S** self, **R:x** resource resolved by `x`, **L** list,
**C** create, **X** cross (§5.6), **—** unchanged (public, wizard, pending).

**Health, setup, sign-in, own session** — `/livez`, `/healthz`, `GET /i18n/locales`, `GET /setup/status`,
`POST /setup/session`, `PUT /setup/language`, `POST /setup/admin/enrollment`, `POST /setup/admin`,
`POST /auth/login`, `POST /auth/mfa/enroll`, `POST /auth/mfa/verify`, `GET /auth/oidc/providers`,
`POST /auth/oidc/{id}/start`, `GET /auth/oidc/{id}/callback`, `GET /auth/ldap/directories`,
`POST /auth/ldap/{id}/login`: **—**. `GET /auth/session` (+`access`), `POST /auth/logout`, `POST /auth/stepup`,
`POST /auth/password`, `POST /auth/recovery-codes`, `PUT /auth/locale`, `POST /auth/oidc/stepup`,
`POST /auth/ldap/stepup`: **S**. `GET /version`: **A**. `POST /setup/recovery-passphrase`, `/setup/evaluation`,
`/setup/complete`, `/setup/https/keep-temporary`, `/setup/mail/skip`: **P**.

**People, tokens, audit, license** — `GET /users`, `POST /users`, `GET /users/{id}`, `PATCH /users/{id}`,
`POST /users/{id}/actions/reset-mfa`, `.../reset-password`, `.../revoke-sessions`, `.../unlock-directory-sign-in`: **P**.
`GET /tokens`, `POST /tokens` (+`service_ids`), `DELETE /tokens/{id}`: **S**. `GET /audit`, `GET /audit/export`,
`POST /audit/verify`: **P**. `GET /license/status`: **A**. `GET /license`, `POST /license/preview`,
`POST /license`: **P**.

**Servers and Key Vaults** — `GET /providers`: **A**. `GET /targets`: **L**. `POST /targets`: **C**
(`targets.manage`). `GET /targets/{id}`, `PATCH /targets/{id}`, `DELETE /targets/{id}` (conditional
`credentials.manage` on the vault's service), `POST /targets/{id}/actions/test`, `.../discover`,
`GET /targets/{id}/host-keys`, `POST /targets/{id}/host-keys/{key_id}/actions/confirm`, `.../repin`,
`GET /targets/{id}/ssh-keys`, `GET /targets/{id}/certificate-locations`, `GET /targets/{id}/key-files`:
**R:target**. `PATCH /locations/{id}`: **R:location**. `POST /key-vaults`: **C** (`credentials.manage`).
`PUT /targets/{id}/vault-credentials`, `GET /targets/{id}/kv/certificates`,
`GET /targets/{id}/kv/certificates/{certificate_id}`,
`POST /targets/{id}/kv/certificates/{certificate_id}/versions/{version_id}/actions/release`,
`GET /targets/{id}/kv/keys`, `GET /targets/{id}/kv/secrets`, `GET /targets/{id}/kv/imports`,
`GET /targets/{id}/kv/imports/{import_id}`: **R:target** (the vault).

**SSH keys and rotation** — `GET /ssh-keys`, `GET /ssh-keys/export`: **L**. `GET /ssh-keys/platform-key`: **A**.
`GET /ssh-keys/{id}`: **R:ssh_key** (locations filtered, `hidden_count`).
`POST /ssh-keys/{id}/actions/download-private-key`: **R:ssh_key** (owning service). `POST /ssh-keys/generate`: **C**.
`POST /ssh-keys/{id}/actions/deploy`: **X**. `POST /ssh-keys/locations/{id}/actions/remove`: **R:ssh_key_location**.
`GET /rotation/policies`, `GET /rotation/runs`: **L**. `POST /rotation/policies`: **C** (the key's service; the key
must be in reach). `GET /rotation/policies/{id}`, `PATCH`, `DELETE`, `.../actions/disable`, `.../actions/preview`:
**R:rotation_policy**. `.../actions/enable`, `.../actions/run`: **X** (§5.6). `GET /rotation/runs/{id}`,
`.../actions/abort`: **R:rotation_run**. `.../actions/continue`, `.../finish-now`, `.../keep-old`: **X**
(`approved_service_ids`).

**Jobs** — `GET /jobs`: **L**. `GET /jobs/{id}`, `POST /jobs/{id}/actions/confirm`, `.../discard`: **R:job** (NULL
service → global only).

**Certificates, signing requests, deployments, Key Vault bindings, incidents** — `GET /certificates`,
`GET /certificates/export`, `GET /certificates/csr`, `GET /certificate-locations`, `GET /deployments`,
`GET /incidents`: **L**. `GET /certificates/{id}`, `GET /certificate-impact/{id}`: **R:certificate** (filtered,
`hidden_count`). `GET /certificates/capabilities`: **A**. `POST /certificates/upload`, `POST /certificates/csr`: **C**.
`GET /certificates/csr/{id}`, `.../actions/complete`, `.../actions/cancel`: **R:csr**.
`POST /certificates/{id}/deploy`, `POST /certificates/{id}/actions/import-to-key-vault`,
`POST /certificates/{id}/incidents`: **X**. `GET /deployments/{id}`: **R:deployment**. `POST /bindings`: **X**.
`GET /bindings/{id}`: **R:binding**. `PATCH /bindings/{id}`: **X** (adding locations; releasing needs either side).
`PUT /bindings/{id}/auto-deploy`: **R:binding** (`credentials.manage` on the vault's service; switching on also
needs `certificates.operate` on every bound location's service and is refused by policy `forbidden`).
`DELETE /bindings/{id}`: **R:binding** (vault side). `POST /bindings/{id}/actions/deploy`: **R:binding** (+ trust at
first send). `GET /incidents/{id}`: **R:incident** (locations filtered). `POST /incidents/{id}/retry`,
`.../revoke-now`, `.../replacement`, `.../close`: **X** (`service_ids`).

**Settings, dashboard, alerts, views** — every `/settings/...` route (SMTP and its test/trust/untrust,
notifications, alerts, general, backups, HTTPS, audit forwarding and its test; 19 operations): **P**.
`GET /dashboard/summary`, `GET /dashboard/expiring`: **A** (computed over reach). `GET /alerts`: **L**.
`GET /notifications/status`: **A** (state for global Administrators only). `GET /views`, `POST /views`,
`DELETE /views/{id}`: **S**.

**SSO, directories, backups** — every `/sso/...` (11), `/ldap/...` (10) and `/backups...` (3) operation: **P**.

**ACME** — `GET /acme/providers`, `GET /acme/providers/{id}`, `GET /acme/hooks`, `GET /acme/hooks/{id}`: **A**
(platform objects, readable by every holder of `acme.view`). `POST /acme/providers`, `PATCH`/`DELETE
/acme/providers/{id}`, `POST /acme/providers/{id}/account`, `POST /acme/providers/{id}/preview`,
`POST /acme/accounts/{id}/rollover`, `.../rollover/recover`, `.../deactivate`, `POST /acme/hooks`,
`PATCH`/`DELETE /acme/hooks/{id}`: **P**. `GET /acme/certificates`: **L**. `POST /acme/certificates`: **C**
(+ HTTP-01 server rule, + policy). `GET /acme/certificates/{id}`, `PATCH`, `DELETE`, `.../order`, `.../test`,
`.../orders`, `.../rearm`, `.../release-hold`, `.../revoke`, `GET .../bindings`, `DELETE .../bindings/{location_id}`
(either side), `POST .../deploy`: **R:acme_certificate**. `PUT .../bindings/{location_id}`: **X**.

**Network discovery** — `GET /discovery/summary`: **A** (over reach). `GET /discovery/scopes`, `GET /discovery/scans`,
`GET /discovery/certificates`, `GET /discovery/certificates/export`, `GET /discovery/endpoints`: **L**.
`POST /discovery/scopes`, `POST /discovery/scopes/preview`, `PATCH`/`DELETE /discovery/scopes/{id}`,
`GET /discovery/settings`, `PUT /discovery/settings`: **P**. `GET /discovery/scopes/{id}`,
`POST /discovery/scopes/{id}/scans`: **R:discovery_scope**. `GET /discovery/scans/{id}`,
`POST /discovery/scans/{id}/cancel`: **R:discovery_scan**. `GET /discovery/certificates/{fingerprint}`:
**R:discovery_certificate** (endpoints filtered).

Totals (counted from the matrix rows with the rules above): P 79, R 61, L 19, X 16, — 16, S 14, A 13, C 7 = 225.
The implementation regenerates them with the matrix; a mismatch is a review finding, not a design change. No existing
route changes its answer for an existing user: the one route whose class tightens, `GET /discovery/settings` (to P),
is read today only by people who all hold a global grant after the migration.

## 12. Implementation phases

Each phase is its own branch, fully green (`make ci` stages, e2e), fast-forward merged into `main` before the next,
behind no flag: every phase is inert until an Administrator creates a second service (Phase 1) or a binding (Phase 2+).

### Phase 1 — Services, environments, assignment, trusts (size L, ~9 tasks)

Migration `00024` (§4.1–4.3 except it leaves `role_bindings`, `directory_groups`, `user_directory_groups`,
`service_owners` empty and unused); `internal/authz` resolvers (read/owning service per §4.5) used by the new routes;
services, environments, policy read (version 1 only), assignment with dry run, trusts; `service_id` on create bodies
and `service` on DTOs; the cross-service trust check (§5.6 (c)) in `checkDeployLocation`, the engine's first send, the
ACME/KV automatic deployment plans, KV import and SSH key deploy; `jobs.service_id` and `alerts.service_id` written;
route table `scope` field on every route (values per §11; only `scopePlatform`/`scopeSelf`/`—` change nothing yet)
and the matrix doc's Scope column; UI: Services page, service page (Overview, Resources, Trusts), service column and
filters, Move to service, Environments settings.

Acceptance:
- Migration up on a populated fixture: every owned row in Default, counts equal; down works without scoped state and
  refuses with it.
- `docs/authz-matrix.md` diff: only the Scope column and the new routes; `TestAuthzMatrix` expectations unchanged for
  every existing route.
- Create without `service_id` → Default; with one → that service; unknown → 422.
- Assign: moves each type; dry run lists cross-service bindings without trust; audited once per call with ids.
- Deploy of a certificate in A to a server in B: refused `ALC-SVC-0007` before any SSH (fake provider records no
  call); with a trust → deploys; trust removed → the next ACME/KV automatic deployment holds with
  `service.untrusted` and the e-mail is queued.
- Startup refuses a route without `scope` (unit test with a bad table, like `authz_test.go`'s `bad` routes).
- e2e: create a service in production, move a server and its certificate, see the badges and filters.

### Phase 2 — Scoped role bindings for people (size XL, ~14 tasks)

`role_bindings` for `user_id` subjects; grants loading in session and token lookup; `rbac` reach; `guard` per §5.3–5.4;
reach filters in every list/count/export/dashboard/alerts/jobs/discovery function (§5.8); cross rules (§5.6) in the
service functions; `allowed_actions` and `hidden_count` in DTOs; `details.service_id` in audit rows; a person
without a global role (`users.role` NULL, nullable since `00024`; every read of the column handles NULL); bindings API and People & access *Access* section; service
page *Access* tab; UI gating moved from roles to `can`/`canOn`; no-access page.

Acceptance:
- `TestScopedIDOR` (generated from the route table): identity `operator@B` (and `auditor@B`, `admin@B`, token
  `operate` of `operator@B`) against fixtures of every resource kind in A: every **R** read → the route's 404;
  every **R**/**X** write → 404; every **L** → no A rows and totals without them; every **C** with `service_id` A
  → 403 `ALC-SVC-0006`; every **P** → 403. A new route without a resolver fails the test.
- The same identities on fixtures in B: everything their role allows today works.
- A certificate owned by A with a location on a B server: `operator@B` sees it, its B location and `hidden_count`
  for A's; cannot deploy it anywhere (no rights on A); can detach the B location from its binding.
- Environment binding `operator@production`: a service created in production afterwards is in reach on the next
  request; relabelling it to test removes it.
- `admin@B` cannot open People & access, Settings, Audit, Backups, License, SSO, ACME providers, discovery settings
  (403), can repin a host key on a B server with step-up and download a B key's private key with step-up.
- Last-admin rule unchanged; a person whose only right is `admin@B` never counts.
- Binding add/remove: global Administrator with step-up only; token refused; audited with subject, role, scope.
- Dashboard numbers, exports, alerts, jobs equal to a hand-filtered fixture.
- Perf suite: p95 overhead of grants loading < 2 ms.
- Error texts: no foreign object name in any error answer to `operator@B` (leak-style test over the fixtures, like
  the secret-leak suite).
- e2e: a scoped Operator signs in, sees only B, deploys within B, is refused in A.

### Phase 3 — Directory groups, automation accounts, limited tokens (size L, ~8 tasks)

`directory_groups`, `user_directory_groups`, group-subject bindings, the sign-in refusal change and the SSO Admin
cap on scoped bindings (§6.1); automation accounts (§6.2); `api_tokens.service_ids` (§6.3); Groups and Automation
accounts tabs; Tokens page limit.

Acceptance:
- OpenLDAP (testcontainers, as the LDAP suite) and the fake OIDC IdP: a user in group G bound `operator@B` signs in
  with no global mapping and reaches B only; removed from G → after the next sign-in no access and refused
  `no_access`; a user with neither mapping nor binding is refused as today.
- `admin@B` through a group with "SSO users may be Admin" off acts as Operator on B.
- Groups truncated at 1000: fewer rights, audit detail present.
- Automation account: every sign-in path refuses it (local form, LDAP, OIDC) with the generic answer; token made by
  an Administrator with step-up works within its bindings; disabling revokes its tokens; it cannot get a global Admin
  (`ALC-ACC-0002`).
- A global Administrator's token limited to B: platform routes 403, A resources 404, B resources work.
- A token's rights shrink when its owner's binding is removed (next request).

### Phase 4 — Owners and notification routing (size M, ~5 tasks)

`service_owners`, owners API and editor; recipient resolution of §7.2 in `internal/notify` (a `ServiceNotifier` beside
`AdminNotifier`; every enqueue site of the service e-mails of §7.2 passes its services); per-recipient digests;
policy `notifications` fields read (written in Phase 5; until then the defaults).

Acceptance:
- Only Default, no owners: the outbox rows of the whole notify test suite are byte-identical to before (golden).
- Owner of A gets A's expiry alert, not B's; a digest to the owner of A lists only A's items while the
  Administrators' digest lists all.
- Group owner: the enabled members seen at sign-in with an address get it; disabled ones do not.
- Platform e-mails (license, backup, lockout, audit) never go to owners.
- Rotation notice delivered only to an owner opens the gate (ruling §7.2).

### Phase 5 — Service policy v1 (size L, ~7 tasks)

The §7.3 struct, validation, versioning, history API and UI; enforcement points of §7.3; `domains` global-only;
auto-deploy hold; reserved keys refused.

Acceptance:
- Each field: an action inside the policy works, one outside is refused with its code before any outside call (no
  ACME order created, no CSR key generated, nothing uploaded).
- `domains`: wildcard depth, wildcard names, IP/CIDR, empty list = no constraint; `admin@B` changing it → 403
  `ALC-SVC-0011`, changing other fields works with step-up.
- `auto_deploy: forbidden`: switching on refused; existing automatic bindings hold with attention, resume when allowed.
- Stale version → 409; history lists every version with author; audit shows changed keys.
- Reserved keys → 422 `ALC-SVC-0015`.

### Documents per phase

`alice-v1/00-decisions.md` (R49, Phase 1), `04-security.md` §15.4 (amended role table: "on a service or
environment", SEC-027 scoped reach, SEC-028 resolvers and 404, SEC-029 cross-service trust; Phase 2),
`02-architecture.md` (tables and route groups), `06-quality.md` §25 new subsection "Scoped access" with test IDs
`SR-01..` and `test/matrix/traceability.json` entries (`make matrix-check`), `docs/authz-matrix.md` (generated),
`docs/admin-guide.md` "Services and access", `docs/operator-guide.md` (what a scoped Operator sees),
`docs/security-overview.md`, `SECURITY-REPORT.md` threat delta, rulings file
`docs/superpowers/rulings/scoped-access.md` per phase.

## 13. Interactions with other work

- License lock (R9, R44): unchanged; the new administration routes are `ClassAlways`; the continuity window does not
  care about services.
- Revocation and incidents (R46): `certificate_incidents.service_ids` and the X rule; the impact answer filters.
- Web server providers: none (services are orthogonal to target types).
- Vendor console: none.

## 14. Open questions for the owner (the implementation proceeds on the default)

| # | Question | Recommended default |
|---|---|---|
| Q1 | Is scoped access a licensed feature (the license `features` field, unused in v1)? | **No.** Authorization must never depend on license state: a lapsed or edition-less license would either widen access (security bug) or lock people out of their own servers. If editions come, gate only the *creation* of a second service, never the evaluation of bindings. |
| Q2 | Name of the concept: "Service" or "Group" (or "Application")? | **Service / Hizmet**, as the second review uses it; one service per (application, environment), e.g. "Payments (production)". |
| Q3 | May a service carry several environments, or is environment a label per resource? | **One optional environment per service.** Per-resource labels make bindings and policy ambiguous. |
| Q4 | Can a service Administrator manage bindings of their own service (delegation)? | **No in v1**: global Administrators only, with step-up. Revisit after customers use it. |
| Q5 | Do scoped Auditors (and Administrators) read the audit log of their services? | **No in v1**: audit stays global; rows carry `details.service_id` from Phase 2 so a filtered view can follow. |
| Q6 | Cross-service deployment: allowed with a two-sided trust, or never? | **Allowed with a trust** created by Administrators of both services; checked again by every background deployment. |
| Q7 | Does being an owner grant access? | **No**: ownership routes e-mails; access is bindings. The editor warns about owners without access. |
| Q8 | May automation accounts hold Admin? | **On a service: yes; globally: no.** |
| Q9 | Out-of-reach by-id answers: 404 or 403? | **404** (no existence oracle); 403 only when the caller can see the resource but not change it. |
| Q10 | Store all directory groups of a user, or only those Alice refers to? | **All, up to 1000**: a new binding to an existing group works without waiting for everyone's next sign-in, and the binding form can show who is in a group. |
| Q11 | Are Administrators still e-mailed about every service? | **Yes by default** (`notifications.administrators: true`); a service can turn it off for its own e-mails; platform e-mails always go to Administrators. |
| Q12 | Does a global Administrator bypass a service policy? | **No**: they change the policy (audited, versioned) instead. |
| Q13 | Owning service of a discovered certificate or SSH key? | **The service of the server it was first seen on**; it is visible from every service holding it; an Administrator can move it. |
| Q14 | Can a directory or SSO user with only scoped bindings (no global group mapping) sign in? | **Yes**. A local person with no grant at all can sign in and sees the "no access yet" page; a directory or SSO user with no grant at all is refused as today. |
| Q15 | Seeded environments? | `production`, `staging`, `test`, `development`; Administrators rename, add, reorder, delete unused ones. |
