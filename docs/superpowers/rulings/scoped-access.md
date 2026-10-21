# Rulings: scoped access and service ownership

Owner approval 2026-10-20: work proceeds on the recommended defaults of the design
(`docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md`, §14) while its questions stay open.
Spec: R49 in `docs/superpowers/specs/alice-v1/00-decisions.md`; SEC-029 in `alice-v1/04-security.md`; the data model in
`alice-v1/02-architecture.md`; SR-01 to SR-10 in `alice-v1/06-quality.md`; user text in `docs/admin-guide.md`
("Services") and `docs/troubleshooting.md`.

## Phase 1: services, environments, assignment, trusts (2026-10-21)

### The design as built

- Migration `00026` creates the whole schema of §4. Every existing owned row (servers, Key Vaults, certificates,
  signing requests, SSH keys, ACME certificates, scan scopes) is in the protected **Default** service; jobs with a target
  and every alert take Default; enabled rotation policies are approved for Default; every user keeps `users.role`.
- `internal/authz` holds the value types and the two checks other modules run in their own transactions:
  `ResolveService` (the service a new row goes to: the one named, key-share locked, or Default) and `CheckTrust`
  (design §5.6 (c), the trust row key-share locked so a removal waits for a deployment being queued under it).
  `internal/authz/services` keeps services, environments, the policy history, trusts, the assignment with its dry run and
  the resolvers of §4.5; only the API reaches it (archtest).
- Permissions `services.manage`, `services.assign`, `services.trust`: Administrator, step-up, never a token, every
  route ClassAlways. Reads are `read`.
- Every route declares a scope class; `register` panics without one; the matrix and `x-scope` show it. The totals of
  §11 hold (platform 79, resource 61, list 19, cross 16, none 16, self 14, any 13, create 7) plus the 15 service routes.

### Rulings made during execution

1. **The owning-service columns keep a column default** (`default_service_id()`). The design says "backfill, then SET
   NOT NULL". `ALTER TABLE ... ADD COLUMN ... DEFAULT <non-constant>` fills every row by rewriting the table, and no
   `UPDATE` trigger fires: the finished incidents (Z1023) and finished deployments are frozen against updates, so an
   `UPDATE` backfill would fail on any installation that has one. Keeping the default afterwards puts a row inserted by
   other means (a test fixture, the restore of a dump taken before 00026 and migrated up) in Default, which is the
   design's own "omitted" rule. Every create path of the application names its service explicitly (tested).
2. **Deleting a service** refuses while it owns a live resource; certificates, signing requests and SSH keys count
   whatever their state (they are never deleted). Its soft-deleted servers, ACME certificates and scan scopes are
   history: they move to the Default service in the same transaction (audited count). `jobs.service_id` and
   `alerts.service_id` reference services `ON DELETE SET NULL`.
3. **The Down refuses (Z1026)** also while a user has no global role (it could not restore `users.role NOT NULL`).
4. **Trust checks.** `checkDeployLocation` checks the trust for every deploy path (a person's deployment, a Key Vault
   binding's and an ACME certificate's Deploy now, both planners); `CreateBinding` and a binding's added websites, and a
   new ACME binding, check it too (§5.6 table, rows 2 and 3); an existing ACME binding whose server moved keeps working
   until it deploys. The source is the certificate's own service for a person's deployment, the vault's for a Key Vault
   deployment and the ACME certificate's for Deploy now and the ACME planner. At the first send the engine accepts any of
   the deployment's sources (the certificate's service, or the ACME certificate's for a certificate an ACME order
   issued; the vault's for a Key Vault deployment). The replacement deployments of a key-compromise incident are exempt
   (the request carries the exemption; the first send recognises a replacement at one of the incident's locations).
5. **The planners hold, they do not stop.** A website across services without a trust is not deployed to and gets the
   mark `service.untrusted` (ACME: `acme_bindings.attention_code`; Key Vault: the new
   `certificate_locations.binding_attention_code`); a newly marked set sends one e-mail (`acme.auto_deploy_untrusted`,
   `kv.auto_deploy_untrusted`) and one audit row; a trust (or both in one service) clears the mark at the next run and the
   website is deployed to. The wave's stop is unaffected: `service.untrusted` is a neutral reason.
6. **Error codes.** Only the codes Phase 1 produces are registered (`ALC-SVC-0001` to `0004`, `0007`, `0016`, `0017`)
   plus `ALC-SVC-0018` `service.trust_exists` (409; the design has no code for a duplicate trust). An unknown
   `service_id` or `environment_id` in a body is 422 `validation.required` on the field, as an unknown reference
   elsewhere. A stale `If-Match` on a service or an environment is `ALC-SYS-0008` (412), as for servers.
7. **Audit rows are unchanged** before Phase 2 (§5.8): create rows do not gain `service_id`. The assignment is audited
   once with `details.resources` = `kind:id,...` (the audit log refuses a details key such as `ssh_key_ids`).
8. **Rows show their service** as `{id, name, environment}` (`service`) on the six owned kinds, lists and details, and
   the lists of servers, certificates (and the export), signing requests, SSH keys (and the export), ACME certificates
   and scan scopes filter by `service_id` and `environment_id`. Without the services module (a test build) a row shows
   the id alone. Derived rows (deployments, bindings, jobs, incidents) gain their service with Phase 2.
9. **`certificate_incidents.service_ids`** is filled when an incident starts; Phase 2 enforces it.
10. **E-mail recipients are unchanged** (Phase 4 routes by owners).
11. **No break-glass CHECK yet.** §4.2's `NOT is_break_glass OR role = 'admin'` would refuse demoting the break-glass
    account, which another Administrator may do today (SEC-015 keeps only the last enabled Administrator); Phase 1 changes
    nobody's rights, so the CHECK waits for the phase that lets a person hold no global role.

## Phase 2: scoped role bindings for people (2026-10-21, R53)

### The design as built

- A person holds a role globally (`users.role`; `null` now means no global role) and, through `role_bindings` rows
  with a `user_id`, on one service or on an environment. `authz.LoadGrants` reads them with every session and token
  lookup (one indexed query beside the user row, SEC-017): one grant per role with the union of its services, an
  environment binding expanded to the services that carry the environment at that request. A new or removed binding,
  and a service relabelled to or from an environment, change the reach at the next request.
- `rbac`: `Subject.Grants`; `Decide` stays the decision of a global grant; `DecideAnywhere` (a grant on any service),
  `DecideIn` (a grant on one service), `Reach` (every service, or the services of the grants whose role allows the
  permission; the token scope applies, the step-up window does not). `session` and `session.stepup` hold for any
  signed-in person (`SignedIn`), so a person without any grant still reads and ends their own session.
- `guard`: platform, self and none routes use `Decide`; every other class `DecideAnywhere`. Every resource route, and
  every cross route with a path resource, declares a resolver (`route.resolve`; `register` refuses one without, and a
  list or create route with a path parameter). The resolver kinds are those of design §4.5 plus `location`,
  `ssh_key_location`, `discovery_scan`, `discovery_cert` (by fingerprint), `deployment`, `kv_binding`, `incident`,
  `job`, `rotation_policy`, `rotation_run`, `service`, `service_trust`, `acme_binding_place`, `incident_reach`,
  `rotation_reach` and `kv_certificate`.
- Lists and counts filter inside their queries with the conditions of `internal/authz/sql.go` (one definition of
  "visible from" per kind, shared with the resolvers' semantics).
- New routes: `GET/POST /api/v1/role-bindings`, `DELETE /api/v1/role-bindings/{id}`, `GET /api/v1/users/{id}/access`;
  `GET /api/v1/auth/session` gains `access`. Permission `access.manage`.
- The scoped IDOR suite (`internal/api:TestScopedIDOR`) is generated from the route table: every kind planted in
  service A, an Operator, an Auditor and an Administrator of service B and an operate token of the Operator call every
  route; every answer is compared with the answer for an absent resource, every list body is searched for A's ids and
  names, every answer (refusals included) is searched for A's ids and names.

### Rulings made during execution

1. **A caller with a global grant is never looked up.** When the route's permission reaches every service and the
   caller holds no role binding, `guard` resolves nothing: an installation without bindings answers exactly as before
   (the unchanged authorization matrix proves it). A caller with bindings is resolved even when a global grant covers
   the route, so that the conditional permissions inside the handlers (design §5.5) are judged on the resource's own
   service (`roleOn`, `decideOn`).
2. **The break-glass CHECK is `NOT is_break_glass OR role IS NOT NULL`, not `role = 'admin'`.** The design's rule would
   refuse demoting the wizard's administrator, which SEC-015 allows today (only the last enabled Administrator is kept),
   and migration `00028` would fail on an installation that did. What the new freedom (a person without a global role)
   could break is that the emergency account depends on role bindings: that is refused, by the application first
   (`ALC-USR-0004`, audited `break_glass_global_role`) and by the CHECK. **Owner to confirm.**
3. **Absent and out of sight are one answer.** For a caller with bindings the guard answers an absent resource itself
   with the route's 404 (the kind's code: `ALC-SVC-0001` for a service, `ALC-DSC-0008` for a scan scope, `ALC-SYS-0001`
   otherwise) and audits both as `out_of_scope`; a caller with a global grant still gets the handler's own answer for an
   absent resource, as before. A malformed id is the handler's answer for everyone.
4. **Writes on a visible resource are judged on its owning service**, with three exceptions that the route table names:
   removing an ACME binding's website is either side's (`byEither`), removing a trust either service's, and a Key Vault
   binding's change of websites any visible side's at the guard, then the handler decides: the vault's side may add
   (each added website needs `certificates.operate` on its own service) and release any; a website's side may release
   its own websites only. The websites the caller cannot see are kept, whatever the list names, because the caller cannot
   name them. An incident's actions need `certificates.incident` on every service in its `service_ids` and its
   certificate's; switching a rotation on and Run now need `rotation.operate` on the key's service and every service of
   a server holding a live location; Continue, Finish now and Keep the old key every service the run is visible from.
5. **Switching a rotation on or running it records `approved_service_ids`** (the key's service and the services of its
   live locations). The background check of design §5.7 (a run does not start while the key is on servers of a service
   not approved) is **not** built yet: see "What remains".
6. **Creates are checked before their fields.** `service_id` naming a service outside the caller's reach is 403
   `ALC-SVC-0006` with the field named, before any other validation; without `service_id` a global grant gets the
   Default service and a person with role bindings their only service for the permission, or 422 `ALC-SVC-0005` when
   there are several. A new rotation policy belongs to its key's service: a key the caller cannot see is 404, one it
   sees without `rotation.manage` on its service 403 `ALC-SVC-0006` on `ssh_key_id`. An ACME certificate's HTTP-01
   server needs `certificates.operate` on the server's service (`ALC-SVC-0012`).
7. **Cross-service destinations** (a certificate's websites, a Key Vault binding's websites, an ACME binding's website,
   an import's vault, an SSH key deploy's server, the resources of an assignment, both services of a trust) are checked
   in the handler before the service function is called; the refusal `ALC-SVC-0012` counts the services outside the
   reach (`params.count`) and names none. The re-check under the row lock of design §5.4 (`authz.Assert` inside the
   service functions) is **not** built: a move between the check and the write is a global Administrator's act and the
   trust check (SEC-029) still runs under its lock. See "What remains".
8. **Jobs without a service are platform work**: a job with `service_id` NULL is in no list, count or resolver answer
   for a person with role bindings only.
9. **Audit rows carry their service.** The audit log adds `details.service_id` itself, in the row's transaction, for
   every object type that has an owning service (servers, Key Vaults, certificates, signing requests, SSH keys, ACME
   certificates, scan scopes and scans, locations, host keys, deployments, Key Vault bindings, certificates, versions and
   imports, rotation policies and runs, incidents, jobs), unless the event names one. Module tests that compare a row's
   details leave it out; `internal/inventory:TestCreatePathsNameAService` checks it.
10. **Exports record a limited reach** (`details.reach` = the service ids) and nothing for a global reach, so the export
    rows of an installation without bindings are unchanged.
11. **A service outside the reach** shows as `{"outside": true}` in every row's `service`, in the service lists and on
    the other side of a trust; the services list and the trusts list hold the caller's services (a trust: either
    side). An untrusted refusal names only the services the caller sees.
12. **Rows carry `allowed_actions`** (omitted when empty) on the six owned kinds: the resource permissions the caller
    holds on the row's owning service, with the token scope and without the step-up window.
13. **`hidden_count`** on a certificate's, an SSH key's, a Key Vault binding's and an incident's locations, on a
    certificate's impact (certificates with the key, locations and vault versions) and on an ACME certificate's
    bindings. The impact's network endpoints are shown to a global `discovery.view` only; a discovered certificate's
    detail lists the endpoints of the caller's scopes.
14. **The dashboard** counts, lists and warns over the caller's read reach (certificates by visibility, Key Vault
    objects by their vault, deployments by server or certificate, servers, rotations by their policy); the backup state,
    the setup checklist, the audit head, the license detail and the delivery state stay a global grant's.
15. **The platform class is enforced**: `GET /api/v1/discovery/settings` (classed platform in Phase 1, permission
    `discovery.view`) now needs a global grant, as every platform route; nobody loses it, since every role is global
    without role bindings.
16. **SSO and directory users** may hold role bindings; the SSO Admin cap applies to them at every request. Their
    sign-in still needs a mapped group (the refusal change of design §6.1 is Phase 3).

### What remains (Phase 2 as built)

- The re-check under the row lock inside the service functions (design §5.4, `authz.Assert`); today the guard and the
  handlers check before the call.
- The rotation background check of design §5.7 (`approved_service_ids` is recorded, not yet enforced by the runner).
- Derived rows (deployments, bindings, jobs, incidents) do not show their `service` yet, and their lists have no
  `service_id`/`environment_id` filters (they are filtered by reach).
- The perf budget is measured for the grants read only (`internal/api:TestR53GrantsReadBudget`, perf build tag: p95 about 1 ms
  at 500 services and 200 bindings, budget 2 ms); the lists of a person with role bindings are not in the R32 suite yet.
- Conflict errors that name another object (design §10, "Error texts naming foreign objects"): the error parameters
  were reviewed (they name what the caller sent, a refused location's id, or what it holds rights on, a destination
  vault's certificate name, and an untrusted refusal names only the services the caller sees), and the leak check covers
  every route-level answer; no body-dependent conflict is exercised against a resource of another service yet.

## Phase 5: service policy v1 (2026-10-21, R55)

### The design as built

- The policy is `authz.Policy` (schema 1, design §7.3), parsed by `authz.ParsePolicy` with every unknown field refused
  and the reserved keys of §7.4 refused (`ALC-SVC-0015`, field `body.<key>`); `authz.LoadPolicy` reads the current
  version in the caller's transaction and the checks (`CheckNames`, `CheckSource`, `CheckACME`/`CheckACMEChanges`,
  `CheckAutoDeploy`) are pure. `services.Store.SetPolicy` saves a version; the API's `PUT /api/v1/services/{id}/policy`
  takes `{"version": <the version read>, "body": <the whole document>}`.
- New permission `services.policy`: Administrator, step-up, never a token, resource scope (resolved by the service),
  ClassAlways. The domains need it with a global grant (`rbac.Reach(...).All()`), checked by the store under the service's
  row lock against the version the caller read.
- Enforcement points, each before anything is stored, ordered or generated: `CreateACMECertificate` and
  `UpdateACMECertificate`, `CreateCSR` (before the key is generated and again in the transaction), `UploadCertificate`
  (after the file is read, before it is stored), `services.Store.Assign` (the destination's domains), `SetAutoDeploy`
  (Key Vault), `AddACMEBindingStrict`, and the planners `planACMEDeploy` / `planBinding`. `StartIncident` and
  `CreateACMECertificate` take the policy's defaults.
- No migration: `00026` made `service_policies` (append-only) and `services.policy_version`. `00030`, set aside for this
  phase, is not used.
- Tests: SR-30 to SR-34 (`internal/authz:TestParsePolicy*`, `TestPolicyDomains`, `TestPolicyChecks`,
  `internal/authz/services:TestSetPolicyVersionsAndAudit`, `TestAssignChecksTheDestinationsDomains`,
  `internal/inventory:TestPolicy*`, `internal/api:TestPutServicePolicy`, `TestServicePolicyThroughTheAPI`,
  `TestScopedIDOR` (the new route), the web `PolicyPanel` tests and `web/e2e/service-policy.spec.ts`). The numbers start at
  SR-30 so that Phases 3 and 4, built in parallel, keep SR-17 onwards.

### Rulings made during execution

1. **Every list: empty is no constraint.** §7.3 says so for `domains`; the same holds for `certificate_sources`,
   `acme.providers`, `acme.challenges`, `acme.key_types` and `notifications.addresses` (a service that admits nothing
   would be a deletion in disguise). The stored document drops empty lists and objects, so equal policies are equal
   documents and the history's "what changed" is exact.
2. **`schema` is required and is 1.** An unknown field (at any depth) or a wrong type is the generic 400
   (`ALC-SYS-0004`), as for every other body; a reserved key is 422 `ALC-SVC-0015`; an invalid value is 422 validation
   on `body.<path>` (`body.domains.2`, `body.acme.renew_before_days`). **Owner to confirm** the 400 for an unknown field
   (the design names no code).
3. **Domains.** An entry is a lower-case DNS name, `*.suffix` over at least two labels, an IP address or a CIDR block
   written with its network address (host bits set, or IPv4 written as IPv6, are refused: say what is meant). A
   certificate's names are its SANs and its CN when the CN is a DNS name or an IP address ("My server" names no host);
   comparison ignores case and a trailing dot. A wildcard entry never admits its own suffix (`*.pay.example.com` does
   not admit `pay.example.com`), an exact entry no name below it.
4. **The domains rule for a service Administrator** compares sets: saving a document whose domains are the current ones
   in another order is allowed; any other change is `ALC-SVC-0011`.
5. **The same document stores nothing**: no version, no audit row; the answer is the current version.
6. **Audit**: `service.policy_changed` with `details.fields` (the changed top-level keys; the audit log refuses a details
   key named `keys`), `version`, `old_version` and the service's name.
7. **An ACME provider named by the policy must exist** when the policy is saved (422 on `body.acme.providers.N`, the
   provider key-share locked); one deleted later simply matches no certificate.
8. **A change is judged in what it changes.** An ACME certificate's change checks the names only when they change, the
   provider, challenge and key type only those that change, automatic deployment only when it is switched on: a policy
   made stricter afterwards refuses no unrelated change (§7.3: never retroactive).
9. **The policy is read, not locked**, in the action's own transaction: a policy saved while an action runs applies from
   the next action (as an Administrator's change of a role does).
10. **Automatic deployment is judged on the source's service**: the Key Vault's for its bindings, the ACME certificate's
    for it and its websites (§7.3: "the service's KV bindings and ACME certificates/bindings"). A destination service
    cannot forbid automatic deployments to its servers by policy (it can refuse the trust). **Owner to confirm.**
11. **The hold.** The ACME planner marks every binding of the certificate with automatic deployment on
    (`acme_bindings.attention_code`), the Key Vault planner the websites it would have deployed to
    (`certificate_locations.binding_attention_code`), with `service.auto_deploy_forbidden`; the mark takes precedence over
    `service.untrusted`; nothing else is planned for that certificate or binding while it lasts (no deployment, no hold,
    no stop, no notice). A newly marked set is audited once (`acme.auto_deploy.forbidden`, `kv.auto_deploy.forbidden`)
    and sends no e-mail: the policy change is the cause and is audited with its author. When the policy allows it again
    the marks clear and the next run deploys. Deployments queued before the policy changed are not stopped (the engine's
    first send does not read the policy), and Deploy now is never held. Switching automatic deployment off (the ACME
    certificate, one of its websites, a Key Vault binding) clears its marks: the planner does not visit it again. **Owner
    to confirm** "no e-mail".
12. **Defaults.** `acme.renew_before_days` is used when a new ACME certificate names no window; `incident.revoke_mode`
    when an incident is started without a mode; the incident dialog starts with "revoke at once" as the policy says.
13. **Upload refusals** are audited like every refused upload (`certificate.upload_rejected`, reason `policy`).
14. **What is not judged**: certificates Alice finds (server scans, Key Vault syncs, network discovery), the completion of
    a signing request (its names were judged at creation), renewals and incident replacements of an ACME certificate (its
    names were judged when set), and the sources and ACME rules on a move (only the destination's domains, §7.3).
15. **`notifications` is stored** with the policy and validated (at most 20 addresses, bare `local@domain`, locale `en`
    or `tr`, no address twice); nothing reads it until Phase 4. The Policy tab says so.

### What remains (Phase 5 as built)

- The ACME certificate dialog has no service picker (no create dialog has one yet): it still proposes 30 days, and the
  policy's renewal window applies to API calls that give none. The policy-aware hints in the create dialogs (allowed
  names, sources) are not built; the refusal names the rule.
- The engine's first send does not re-check `deployment.auto_deploy`; a deployment queued before the policy forbade it
  still goes.
- `notifications` is read by the routing of Phase 4.

