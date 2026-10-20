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
