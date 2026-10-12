# Alice production integration

Reference: `erenmeren/alice@44521f52ce02fc92e02a89c9d5a2011f3b95c4a9`.

## 1. Theme foundation

Apply the semantic light/dark variables in `dist/tokens.css` through the existing Mantine provider. Replace `defaultColorScheme="light"` with a persisted `auto` preference and provide light/dark/system controls. Retain `getStyleNonce={readCspNonce}`. Do not use the current black foreground override for both themes: map light/subtle variants and errors to scheme-aware semantic tokens. Replace direct `c="gray.7"` and `c="black"` uses throughout the components before declaring dark mode complete.

Bundle font files locally in the production web assets; the application is designed to work offline. Keep system-font fallbacks for failed font loading. Do not request fonts or icons from CDNs.

## 2. Shared shell and components

Refactor `web/src/layout/AppLayout.tsx` into inventory, operations and administration groups without changing route guards. Preserve mobile close-on-navigation behavior. Keep the account and API-token surfaces available to each permitted role. Add icon labels, current-page semantics and the existing focusable scroll-region behavior.

Implement reusable `PageHeader`, `ResourceTable`, `StatusBadge`, `FactList`, `OperationTimeline`, `AttentionItem`, `EmptyState` and `AppearanceControl` using Mantine primitives. Controls should use translated strings, semantic tokens and consistent error messages. Dark mode, long Turkish labels, long fingerprints and narrow tables are first-class states.

## 3. Dashboard

Reuse `/dashboard/summary`, `/dashboard/expiring` and `/alerts`. The existing summary is role-filtered: operators must not receive or see detailed license, audit, backup or notification administration data.

Expiry windows are cumulative and include expired certificates. For mutually exclusive totals use `expired`, `within_7 - expired`, `within_30 - within_7`, and `within_60 - within_30`. Do not add the cumulative counts together.

The 5-day histogram in the prototype requires all relevant certificate expiration rows or a server-side aggregate. The existing ten-row dashboard preview is insufficient for a complete distribution. Add an explicit aggregate endpoint only if a fully paged read would be too expensive. Group resources by stable IDs and avoid counting the same certificate twice across Key Vault and general inventory.

“Assurance” is a new presentation of existing audit and backup summary fields, not a new security score or compliance claim. A matching checksum does not establish restore readiness. Hash-chain continuity is not independent proof against a compromised host; preserve external forwarding context.

## 4. Inventories and detail screens

Retain `useUrlFilters`, debounced search, server-side filtering, saved views and `next_cursor` pagination. Exports must use exactly the active filters. The prototype uses small local arrays and numbered pages for visual exploration, not as the production pagination implementation.

Use `CertificateDetail.locations` for certificate-to-server relationships, and Key Vault bindings for source-to-destination relationships. Do not infer relationships from resource names. Unassociated uploaded certificates must be deployed from an eligible server location; the details page should link to that workflow.

Preserve missing-location, unsupported-target, read-only, incomplete-chain, expired and private-key-unavailable states. A discovered certificate does not imply that Alice holds its private key. Never return a TLS private key to the browser.

## 5. Deployments and rotation

Continue to use `deploymentView`, `isSettled`, polling backoff, unknown-state handling and the existing outcome components. Keep these distinct: succeeded, unchanged, failed, cancelled before sending, rolled back, rollback failed, recovering, license-held, finishing, stopped and unknown. A queued job or a green UI step is not proof of a completed remote change.

Show remote, local and skipped verification accurately. Keep backup paths and fingerprints as evidence. Never label rollback as generic success; say what was restored and whether the previous endpoint was verified.

The standalone rotation policy page is an information-architecture change over existing `/rotation/policies` and `/rotation/runs` resources. Decisions must use `actions_allowed` intersected with the role. Preserve overlap, old-key retention, unverifiable locations, paused-license behavior, one-location removal and step-up. Do not offer Azure Key Vault key rotation; v1 provides inventory only for those keys.

## 6. Role and license gates

- Admin: installation, targets, credentials, people, policies, license and sensitive operations as currently permitted.
- Operator: allowed discovery, certificate and SSH-key operations; no audit access, no credential administration or private-key download.
- Auditor: read inventory, license and audit; export; no changes to managed systems.

Use `docs/authz-matrix.md` and server RBAC as authoritative. The UI is not an authorization boundary. Sensitive settings reads also require step-up in the existing implementation; do not merely challenge on save.

License lock pauses external mutations. Inventory, exports, audit and backups remain available. Already-started operations complete or recover safely. After renewal, read-only recurring jobs may resume; pending external mutations require administrator review. The prototype's “active” switch is only a visual-state selector.

## 7. Additional UI proposals

Global search currently searches the local prototype. No unified search endpoint was identified in the reviewed route table. A production implementation needs an explicitly scoped aggregation API or bounded per-resource queries with RBAC and rate limits.

Theme/density are user preferences. Organization labeling and an explicit display-time-zone preference in this prototype are presentation proposals; do not silently add a new tenancy model or confuse display time zone with the existing per-schedule time zone.

The first-run design walkthrough is not a working installer. Preserve the real setup-token, admin/TOTP enrollment, one-time recovery-code display, recovery passphrase, HTTPS, SMTP, license and first-target checks. Never allow visual progress controls to bypass them.

## Acceptance checks

1. Check every primary route at 1440, 1024, 768 and 390 px in both themes and both languages.
2. Verify full keyboard operation, visible focus, dialog containment and focus return, table scrolling, screen-reader names and live status updates.
3. Test empty, filtered-empty, loading, partial error, stale data and retry separately.
4. Exercise all three roles, expired evaluation, annual grace, license lock and renewal recovery against the real API.
5. Verify deployment outcomes including ambiguous remote state, partial rollback and skipped TLS verification.
6. Verify filters and exports agree, pagination cannot misrepresent totals, and no aggregate derives from a truncated list.
7. Recheck actual rendered contrast; token arithmetic alone is not a full accessibility audit.
