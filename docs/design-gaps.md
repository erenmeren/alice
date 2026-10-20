# Design gaps: where Alice differs from the Clarity design, and why

## Source

The Clarity product design in `alice-design/` (reviewed at `erenmeren/alice@44521f5`, committed 2026-10-12) is the
reference for the web interface since Phase 9. It is a prototype with synthetic data: it does not draw every state the
product has, and some of its elements need data or endpoints Alice does not have. This file records every place
where the product differs from the design, what was built instead and why. Phase 9 changed only the web interface:
no API, permission, data or setup-check change.

Status values used below: **filled** (the design is silent; built from the design's components and tokens),
**differs** (deliberately not as drawn, for the reason given), **not built** (left out, see the reason),
**to verify** (built; a browser check of Task 18 or 19 confirms it), **follow-up** (see the last section).

## Rulings

The plan (`docs/superpowers/plans/2026-10-12-phase-9-design.md`, "Design rulings") settled these conflicts between the
design, the product and the tests:

- **R1 Stack.** React and Mantine stay, with the CSP nonce, catalogs, query semantics, RBAC, step-up, cursor paging and
  server-derived action eligibility; the design's HTML/CSS becomes theme overrides, CSS modules and small components.
- **R2 Vendored assets.** Geist, Geist Mono and the design's 75-icon Lucide subset are copied into `web/src/design/`;
  icons render as React SVG from data; their licenses reach `THIRD_PARTY_NOTICES.md` through `tools/notices -vendored`.
- **R3 Tokens.** The design's tokens are `--alice-*` variables for light and dark, plus hover and `on-strong` tokens
  the design implies; Mantine's variables map to them.
- **R4 Color mode and density** are per-device preferences (`alice.colorScheme`, `alice.density`), applied before the
  bundle runs; the language stays per account.
- **R5 Shell.** Mantine `AppShell` restyled: 222 px sidebar, grouped navigation (Inventory, Operations,
  Administration), installation card without an organization name, visible Your account / API tokens links and a
  visible Sign out button instead of the design's account dialog.
- **R6 Top bar.** Burger, a plain-text breadcrumb (not a landmark), the page palette, theme and language toggles and
  the attention bell; the "DESIGN PREVIEW" label is dropped.
- **R7 Command palette = pages only.** It lists the destinations the role may open; there is no resource search.
- **R8 Attention bell.** A popover that reads `/alerts` only while open; no polling, no unread dot.
- **R9 Language toggle.** With two languages the top bar shows the other language's code (TR/EN), named by that
  language's own name; Your account has the language select.
- **R10 Overview.** The dashboard becomes the design's Overview with Operations and Assurance tabs; the "Welcome"
  heading is removed; the metric strip shows Key rotations instead of the SSH key total.
- **R11 Copy.** Navigation and page titles take the design's names; body text with a security or legal meaning keeps
  the product's wording; TR "API anahtarları" stays; `locales/common` is not edited.
- **R12 Expiry horizon.** Four exclusive buckets from the summary instead of twelve five-day bars; the count links
  stay cumulative.
- **R13 Tables.** `ResourceTable` keeps the focusable, named scroll region; a cursor footer ("N shown" + Load more)
  replaces numbered pagination.
- **R14 Status badges stay Mantine `Badge`**, rendered through `StatusBadge`; existing badge components keep their
  names, props and texts.
- **R15 Alerts are Notices.** Mantine `Alert` keeps its roles and test ids with the design's look; `ErrorAlert` shows
  the `ALC-*` code.
- **R16 Settings** keeps the product's eight tabs, order and `?tab=` addresses as the design's vertical section
  navigation; Appearance lives on Your account.
- **R17 Sign-in** uses the design's split layout with the product's heading "Sign in to Alice".
- **R18 Wizard** uses the design's setup shell and a non-interactive progress rail over the real steps and checks.
- **R19 Rotations page** (`/rotations`) is read-only; decisions stay on the run page, policies on the key's page.
- **R20 No numbers from paged lists**: no mini-stats or totals that would be counted from cursor-paged lists.
- **R21 No settings the product lacks** (organization name, display time zone), no "Upload replacement", no Azure key
  rotation, no "Renew everything".
- **R22 Design-system page.** Not added; new components and filled gaps are recorded here.

## Gaps filled in the design's language

### All screens (tokens, theme, shared components)

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| all (tokens) | hover tokens for filled semantic buttons | `--alice-{brand,success,warning,danger,info,neutral}-hover`, contrast-tested at 4.5:1 in both schemes | 1 | filled |
| all (tokens) | a foreground for filled semantic buttons | `--alice-on-strong` (white in light, `#13291d` in dark), tested | 1 | filled |
| all (tokens) | a neutral tone | `--alice-neutral`, `-hover`, `-soft` (from the text-secondary and surface-subtle values) | 1 | filled |
| sign-in (tokens) | named tokens for the brand side | `--alice-auth-brand-{bg,text,muted,line}` (light values; dark inherits) | 1 | filled |
| all tables | the design's 3 px focus ring on the table scroll region | stays 2 px inside (`outline-offset: -2px`, `--alice-focus`): e2e contract, and the scroll root clips outside rings | 1 | differs |
| all (fields) | `--alice-border-strong` is 2.99:1 on `surface-subtle` (light) and 2.98:1 on `surface-hover` (dark) | kept the design's value; fields sit on `surface`/`canvas` (≥ 3:1, tested); no input is placed on the two lower-contrast surfaces | 1 | differs |
| all (dark) | Mantine-only surfaces (popover and menu dropdowns, segmented control, close button, select chevron, disabled controls) | Mantine's dark palette, disabled variables and primary-color variables mapped onto `--alice-*` tokens in `theme.ts`; a guard test and an ESLint rule keep palette shades and inline colors out | 17 | filled |
| all (dark) | text selection contrast: the design's dark `::selection` (text on `--alice-brand-line`) is 3.96:1 | kept the design's value (selection is outside WCAG text contrast) | 1, 17 | differs |
| all tables | numbered pagination and "x–y of N results" (the cursor API gives no totals) | `CursorFooter`: "N shown" (`ui.table.shown`) + the existing Load more / Show more button | 3 | differs |
| all pages (notices) | the design's `notice()` has no ARIA role | `Notice` defaults to `role="note"`; `alert`/`status` only when passed | 3 | filled |
| notices | ShieldCheck for every tone except warning/danger | info and neutral notices use `CircleDot`: a shield with a check reads as "secure/OK" | 3 | differs |
| all empty states | the design's `empty()` title is an `<h2>` | `EmptyState` title is a `<p>` with the h2 look: an empty table adds no heading to the outline | 3 | differs |
| all tables (toolbar) | the design's toolbar centers its controls | `align-items: flex-end`: the inputs carry visible labels, so the fields align on their baseline | 3 | differs |
| errors | a stable error code (the design requires one but draws none) | "Error code: `ALC-…`" line in `ErrorAlert` (`Code translate="no"`), above the request ID | 3 | filled |
| deploy dialogs | a style for the website a refusal names, and for separating several runs | `deploy.module.css`: `.refused` (2 px `--alice-danger`, `--alice-radius-sm`), `.separated` (`--alice-border` rule) | 17 | filled |
| dialogs | focus after a dialog removes its own trigger (repin, key removal, certificate dialogs) | unchanged pre-Phase 9 behaviour | 6, 7 | follow-up |

### Shell (sidebar, top bar, banners)

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| sidebar | the installation card names an organization | "Self-hosted installation" + "Version x" from `GET /version`: no tenancy model, and operators cannot read the license customer | 4 | differs |
| sidebar | the account menu dialog | visible Your account / API tokens links and a Sign out button (R5; the e2e needs a visible Sign out) | 4 | differs |
| top bar | search that finds resources | page palette over the role's destinations only (R7), hint "Only pages you can open" | 4 | differs |
| top bar | the bell's unread dot | no dot: there is no unread state on the server (R8) | 4 | differs |
| top bar | the palette shortcut label | `⌘K` on Apple platforms, `Ctrl K` elsewhere (the design's `.kbd` style) | 4 | filled |
| top bar | the TR/EN toggle's visible text "TR" is not part of its accessible name "Türkçe" (WCAG 2.5.3) | kept: R9 and the e2e pin the native language name, clearer to a screen-reader user than a code | 3 | differs |
| mobile | the design's 222 px drawer | Mantine AppShell's full-width off-canvas navbar under the top bar (e2e contract); Escape closes it and returns focus to the menu button | 4 | differs |
| banners | product banners (setup, 12 license kinds, notifications failing, 48-hour backup alarm, SSO step-up refusal, sign-out failure) | Mantine Alerts as status lines with the design's icons per severity (ShieldAlert / CircleAlert / CircleDot); link text inherits the alert's color, bold | 4 | filled |
| popover | the notifications dialog layout | 340 px popover with `AttentionItem` rows, title, loading/error/empty states and "Open the overview" | 4 | filled |

### Overview

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| Overview (horizon) | 12 five-day bars need every certificate row or a server aggregate | 4 exclusive buckets from the summary (R12), bar heights ∝ the largest bucket, 3 px baseline; 7/30/60 selects the cumulative headline; cumulative links kept with a note | 5 | differs |
| Overview (metrics) | the "SSH keys" total needs a count the paged API lacks | "Key rotations" = rotations in progress (`MetricStrip`) | 5 | differs |
| Overview (attention metric) | the "1 expiry · 3 operational events" breakdown | `summary.attention` with "Conditions to resolve"; no link (the list is on the same page) | 5 | differs |
| Overview (attention) | conditions of a kind this web version cannot show | counted in the "N open" badge (the server's number, equal to the metric) and named in a muted line under the list | 5 | filled |
| Overview (deployments) | "Recent deployments" shows successes too | the summary carries only failures: title "Failed deployments (last 7 days)", design subtitle and activity rows, `failed_7d` badge | 5 | differs |
| Overview (connectivity) | one tick per target and a per-platform note | one segment per status (flex-grow = count, tone tokens, `role=img` label lists the states), per-status links | 5 | differs |
| Overview (rotation panel) | one run's phase path | the summary has no run phases: upcoming rotations + running / needs-attention badges + link to `/rotations` | 5 | differs |
| Overview (setup checklist) | "Finish setting up" | `Panel` with attention-row list, Required (danger) / Done (success) `StatusBadge`s | 5 | filled |
| Overview (empty panels) | empty states for attention, renewals, connectivity, deployments, rotations, evidence | `EmptyState` with the existing texts | 5 | filled |
| Overview (header) | the admin "Add target" button | not built: servers and Key Vaults are added on their own pages; Managed targets links to Servers | 5 | not built |
| Overview (header) | what Refresh refreshes | default button (RefreshCw) refetching the summary, evidence trail, renewals and conditions, beside the 60 s polling | 5 | filled |
| Overview (status line) | "Sample snapshot · 09:42 UTC" | `server-status` (server version / checking / unreachable) · "Updated <generated_at>" | 5 | filled |
| Overview (deep link) | loading state of a view the role may not have | no tab panel until the summary settles; a disallowed `?view=assurance` is removed from the address | 5 | filled |
| Assurance (audit) | broken-chain and never-verified states | danger badge "Integrity problem" + `role=alert` Notice; "Not verified yet" fact | 5 | filled |
| Assurance (audit) | the forwarding state ("Configure and verify in Settings") | Administrators: a fact row linking to Settings → Audit forwarding, no state (reading it needs step-up); Auditors: no row; the scope sentence says "where configured" | 5 | differs |
| Assurance (backup) | alarm, failing, never and not-configured states | alarm and failing as Notices, never/not-configured lines, "Latest backup available" badge only when healthy | 5 | filled |
| Assurance (license) | a license panel | `LicenseCard` (administrator/auditor detail); Operators see the license only through the shell's banners | 5 | filled |
| Assurance (evidence trail) | the audit table with details and resource column | the 5 newest entries (time, actor, action, result badge), nothing on a 403, link to `/audit` | 5 | differs |

### Certificates

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| Certificates | a count on the "All certificates" chip; chip counts under other filters | no count on All (R20); Expired/7/30 counts (from the summary, whole inventory) only while no other filter is set; All pressed only when nothing is filtered | 6 | differs |
| Certificates | the expiry select beside the chips | the native Expiry select (7/14/30/60/90, expired) stays in the toolbar; chips and select write the same `expiry` filter | 6 | filled |
| Certificates | pending signing requests, Create signing request, PEM/PFX upload fields, saved views, export with the active filters | `Panel` (`pending-csrs`), header buttons, existing dialogs with `DialogActions`, `SavedViews`, `ExportButton` | 6 | filled |
| Certificates | "Create signing request" as a ghost button at the chip row's end | kept in the page header (default button) | 6 | differs |
| Certificates | the row "Open ↗" column | not built: the name link opens the certificate; a second link would repeat its name | 6 | not built |
| Certificates | the `.expiry-track` bar under each expiry date | not built: the `Expiry` badge and the date carry the state | 6 | not built |
| Certificates | "Used on" as a text link; 10 px secondary row text | plain count; secondary text 9 px | 6 | to verify |
| Certificates (empty) | Upload in the empty state; Clear filters in the no-match state | the header Upload and the toolbar Clear filters (button names stay unique) | 6 | differs |
| Certificate detail | Overview / Locations / Deployment history tabs | one page of sections (topology, details, locations table, deployments, import history) | 6 | differs |
| Certificate detail | a vault name in the source node | "Azure Key Vault" (the certificate detail carries no vault name) | 6 | differs |
| Certificate detail | import into Key Vault, import history, truncated locations, deploy hint, chain-completion hint | Next action panel buttons and Notices, `ImportHistory` as a `Panel`, truncation notes in the footers | 6 | filled |
| Certificate detail | "Upload replacement" on an expired certificate | text only (R21); the upload dialog is on the list page | 6 | differs |
| Certificate detail | Deploy disabled with a reason tooltip | hidden as before (tests pin it absent); the reasons are the notices | 6 | differs |
| Certificate detail | next action for read-only roles and expired certificates | role/state-specific text | 6 | filled |
| Certificate detail | the validity bar's scale (days/365) | the share of the certificate's own validity period left | 6 | differs |
| Certificate detail | the site port when a server block has several listens | 443 if listed, else the first non-80 listen (the API has no TLS flag) | 6 | filled |
| Certificate detail | a renewal due in under a day | "Renewal due today" | 6 | filled |

### Servers

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| Servers | held jobs "Waiting for an administrator" | `Panel` (`blocked-jobs`) above the table, Show more in the footer | 7 | filled |
| Servers | Alice's platform public key and the preparation script | `Panel` with labelled `Code` blocks, native profile select, Copy button, below the table | 7 | filled |
| Servers | empty inventory | `EmptyState` (Server icon) in a `Panel` | 7 | filled |
| Servers | the last problem of a server | secondary text under the Connection badge | 7 | filled |
| Servers | "Last checked" (the API has no last-attempt time) | "Last connected" column; "Never" when null | 7 | differs |
| Servers | the toolbar (search, "Connection state" select) | not built: the list API has no server-side search or status filter | 7 | not built |
| Servers | mini-stat buckets for refused sign-ins, pending fingerprints and other states | extra mini-stats when above 0, so the buckets add up to the total (the list is read completely) | 7 | filled |
| Servers | footer "N servers · …" | only "Azure Key Vaults are listed separately." (the count is the first mini-stat) | 7 | differs |
| Servers | header text of the open-link column | visually hidden "Open" | 7 | filled |
| Server detail | host-key confirmation of a pending server | `Panel` "Is this your server?" first in the left column | 7 | filled |
| Server detail | repin / keep the previous fingerprint with reason and step-up | the existing dialog with `DialogActions`; Review as the danger Notice's action | 7 | filled |
| Server detail | websites with verification settings ("Certificates on this server") | `WebsitesPanel` as a named `Panel` region, `StatusBadge`s, `EmptyState` | 7 | filled |
| Server detail | SSH keys with remove ("SSH access" facts) | "SSH keys on this server" `Panel` with the `target-keys` table, `KeyFlags` as `StatusBadge`s | 7 | filled |
| Server detail | job progress, finished, still working, held, stopped and job-error alerts; helper scan warnings | Mantine Alerts under the identity notice (R15) | 7 | filled |
| Server detail | sign-in user, helper version, Nginx version, last scan, last problem | extra `FactList` rows in "Connection details" | 7 | filled |
| Server detail | delete server | header action + confirmation dialog with `DialogActions` | 7 | filled |
| Server detail | a status line for every state | Notices for verified, identity changed, unreachable, sign-in refused and pending fingerprint; none for checking, partly working and disabled (never "verified" for them) | 7 | differs |
| Server detail | discovery as the primary button | default variant (Test connection and Discover weigh the same) | 7 | differs |
| Server detail | operations text on a Linux server (the design speaks of Nginx) | a Linux variant about SSH keys | 7 | filled |
| Server detail | "Edit server" | not built: there is no update-server API | 7 | not built |

### Key Vaults

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| Key Vaults | vault cards in a 3-column grid | `ResourceTable` with the card's content per row (Cloud tile, name link, URL line, status, sign-in method, last check) | 8 | differs |
| Key Vaults | certificate / key / secret counts per vault | not shown: the vault list carries none and the vault lists are cursor-paged (R20) | 8 | not built |
| Key Vaults | "Open vault" per card | the name link opens the vault | 8 | differs |
| Key Vaults | last problem, empty inventory, held jobs | secondary text, `EmptyState` in a `Panel`, `BlockedJobsPanel` above the table | 8 | filled |
| Key Vault detail | the "Website connections" tab | not built: connections are per certificate; each certificate page has its Connected websites panel | 8 | not built |
| Key Vault detail | state explanations, firewall address, throttling | status `Notice`, `JobErrorAlert` with the `ALC-*` code, firewall address as a one-fact `FactList` | 8 | filled |
| Key Vault detail | sign-in facts and the credentials-expiry warning | "Vault details" `Panel` with `FactList`; `credentials-expiry` Notice | 8 | filled |
| Key Vault detail | the check interval (design: fixed "Polling every 15 minutes") | "Check interval" `Panel` with the administrator's form | 8 | filled |
| Key Vault detail | access check and role guide; replace credentials, remove vault, remove with connections; job feedback | `AccessCheckPanel` and `RoleGuide` panels; header actions with existing dialogs; Alerts (R15) | 8 | filled |
| Key Vault detail | empty tabs, paging, inventory row chips | `EmptyState` per tab, `CursorFooter`; chips as `StatusBadge`s | 8 | filled |
| Key Vault certificate | "Deploy version" header button | not built: Deploy now is in Connected websites and per version (a connection is required) | 8 | not built |
| Key Vault certificate | held versions, release with step-up, versions table, monitor-only and pending states | "Version history" `Panel`, Held badge + `held-text`, Release dialog with `DialogActions`, Notices | 8 | filled |
| Key Vault certificate | connected websites with state, auto-deploy, add/delete connection, stopped after 3 failures | `BindingPanel` as a `Panel`, state `StatusBadge`, `stopped-help` Notice, existing dialogs | 8 | filled |
| Key Vault certificate | "Vault" fact in the policy | not shown (the certificate detail has no vault name); the back link leads to the vault | 8 | differs |
| Key Vault pages | long Turkish state badges at narrow widths (Mantine badge labels do not wrap) | `StatusBadge` with `maxWidth: 100%` in tables that scroll in their region | 8 | to verify |

### SSH keys

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| SSH keys | the weak-key count ("1 weak key requires review") | no count (R20): a warning Notice with "Show weak keys" (`?flag=weak`), hidden on an empty inventory and while that filter is on | 9 | differs |
| SSH keys | tab counts | no counts (R20); `LinkTabs` labels only | 9 | differs |
| SSH keys | the Rotation column | not built: the list API has no rotation state | 9 | not built |
| SSH keys | key label as the row name, the row "open" chevron | the fingerprint link is the name, the comment the secondary line; one link per row | 9 | differs |
| SSH keys | server, user and finding filters, missing-keys switch, saved views, Clear | toolbar with native selects, a text box, a `Switch`, `SavedViews` and Clear | 9 | filled |
| SSH keys | Alice's connection key, keys no longer found; empty inventory vs no match | brand / neutral `StatusBadge`s; two `EmptyState`s | 9 | filled |
| SSH key detail | key name as h1 | h1 "SSH key" (e2e); the label is in the "Managed by Alice" panel | 9 | differs |
| SSH key detail | deploy to a server, private-key download with step-up, remove one location | header buttons (Deploy, then Download) + existing dialogs with `DialogActions`; Remove per row | 9 | filled |
| SSH key detail | line number, options, last seen and flags per location; retired, destroyed and rotated-from states; Alice's own key | the 9-column `key-locations` table; neutral badges and the "Replaces an earlier key" link; brand Notice | 9 | filled |
| SSH key detail | the rotation policy lifecycle (switch with step-up, preview, run, edit, delete, history) | `RotationPolicyPanel` as a `Panel` with sentence list, history table and `StatusBadge` states | 9 | filled |
| Generate key dialog | ECDSA P-256, the radio choice | the existing radio group; the design's note as an info Notice | 9 | filled |

### Key rotations and the rotation run

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| Key rotations | "Create policy" button | not built (R19): a policy needs a key, step-up and a preview; the empty state says where | 10 | not built |
| Key rotations | per-row "Preview" | not built (R19); Preview and Run now stay on the key's page | 10 | not built |
| Key rotations | tab counts | no count (R20) | 10 | differs |
| Key rotations | the SSH keys tab named "Key rotations" | named "Rotation policies" (the design's own tab label) so it does not repeat the navigation link's name | 10 | differs |
| Key rotations | a single "Active rotation" panel | "Active rotations": one entry per running run, cursor-paged; "No rotation is running." only when no further page exists | 10 | filled |
| Key rotations | a run whose policy was deleted; a run paused by the license | named by the old fingerprint; danger "Paused" badge and the on-hold sentence | 10 | filled |
| Key rotations | policy on/off, last result, run links | On/Off `StatusBadge`, "Last run: …" line, a Runs column | 10 | filled |
| Key rotations | key type under the policy name; location count and "Started …" per active run | not shown: the name links to the key page; the run summary has no counts | 10 | not built |
| Key rotations / run | descriptive phase-state texts ("Both keys remain valid") | generic Complete / In progress / Not started (Paused when paused) in `RotationPath`; status badge and notices carry the specifics | 10 | differs |
| Rotation run | the progress path for stopped or failed runs | no path; the status badge and the reason say what happened | 10 | differs |
| Rotation run | license pause, decision deadline, notice pending/failed, kept locations | danger Notice (`role=alert`), warning Notice, the existing `ReasonAlert`, warning Notice under the results | 10 | filled |
| Rotation run | skipped, cancelled, failed and undone locations; step history | "Location results" panel with `run-counts` and `StatusBadge`s; "Steps" panel | 10 | filled |
| Rotation run | the design's fixed decision buttons | "Available decisions" panel with exactly `actions_allowed`, administrators only, step-up | 10 | differs |
| Rotation run | "Notice sent" / "Notice delivered" | "Announced" (`notified_at` is the announcement time), hidden while the notice failed or is pending | 10 | differs |
| Rotation run | back link "Key rotations" | "Back to the SSH key" (existing; a "Key rotations" link would repeat the navigation link's name) | 10 | differs |

### Deployments

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| Deployments | outcome mini-stats; "N deployments in this sample" | not built (R20; a test pins no totals); `CursorFooter` | 11 | not built |
| Deployments | search and outcome filter in the toolbar | not built: no text or status filter in the list today; no toolbar | 11 | not built |
| Deployments | Duration and "Started" columns | "When" = request time (queued or held rows have no start); timestamps on the detail page | 11 | differs |
| Deployments | certificate file, recovering/held state, Key Vault source, an automatic deployment | secondary lines; "Alice (automatic)" in Triggered by | 11 | filled |
| Deployments | a qualifier for a success that was not verified | warning tone on the "Succeeded" badge + "Verification: Skipped / Not done" | 11 | filled |
| Deployments | empty history | `EmptyState` (Rocket) in a `Panel` | 11 | filled |
| Deployment detail | the "Operation log" panel | not built: the API has no raw log; the steps carry the evidence | 11 | not built |
| Deployment detail | eleven outcome states (held, finishing, stopped, unknown, cancelled before sending, restored, rollback failed, local/skipped/no verification, …) | `DeploymentOutcome` Alerts toned through the theme with the design's notice icons; `DeploymentErrorAlert` with cause, action, operation id and `ALC-*` code | 11 | filled |
| Deployment detail | recovery card; step states waiting, not run, skipped, unknown; step details | "Recovery" `Panel`; `OperationTimeline` markers (not run = empty circle, never a tick) and detail lines | 11 | filled |
| Deployment detail | Key Vault facts, key file, requested/finished time, requested by; failed and cause step | `FactList` rows in Operation details; "Technical details" `Panel` | 11 | filled |
| Deployment detail | the served fingerprint when the verification did not report it | the Served line is omitted; the Verification fact says Skipped / Not done | 11 | follow-up |
| Deployment detail | "Inspect audit record" link | not built: the audit trail has no per-deployment filter | 11 | not built |

### Audit trail and License

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| Audit trail | Export JSON beside the single "Export log" | two download buttons (CSV, JSON), both the whole log, with a line saying so | 12 | filled |
| Audit trail | the integrity notice before any verification | not built: the page does not read the last verification; Verify shows the result Notice (intact: status, broken: alert) with "verified through entry #N", the head hash, the scope sentence and, for Administrators, a link to Audit forwarding | 12 | differs |
| Audit trail | search over actor, action and resource | the server's action-prefix field and Result select + Apply (no free-text search in the API) | 12 | differs |
| Audit trail | "Details" opening a modal | the in-row disclosure (`button[aria-expanded]`) | 12 | differs |
| Audit trail | IP address, unknown actions, system actors | IP as a mono line under the actor; raw action in `<Code>`; Settings2 avatar + "System (name)" | 12 | filled |
| Audit trail | "UTC" label; "N events in this sample" | times in the reader's zone; `CursorFooter` and "Newest first" | 12 | differs |
| Audit trail | failure and denied share danger | failure warning, denied danger (the product's distinction) | 12 | differs |
| Audit trail | empty result | `EmptyState` inside the table panel; the filters stay | 12 | filled |
| License | evaluation, evaluation ended, grace (the design has active/locked) | a Notice per phase; grace is danger (as the server's banner and `licensing.md`) | 12 | filled |
| License | damaged license file; Installation ID; pending license; no target limit | danger Notice (`role=alert`); Installation ID fact with Copy; pending line; usage bar only with a limit | 12 | filled |
| License | usage over the limit (the design's bar stops at 84 %) | full bar in `--alice-warning`, `aria-valuetext` "N of M targets used" | 12 | filled |
| License | uploaded files list; upload as a dialog with sample facts | "Uploaded licenses" `Panel`; "Upload license" focuses the administrator's "Upload a license" panel with the product's upload flow | 12 | differs |
| License | history as an activity list | the product's history table in a titled `Panel` | 12 | differs |
| License | the "Activation: Signed offline license file" fact | not added (License end and Installation ID only) | 12 | not built |
| License | TR header button "Lisans yükle" | "Lisans dosyası yükle": the upload panel is already titled "Lisans yükle" | 12 | differs |

### People & access, API tokens, Your account

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| API tokens | Turkish "API belirteçleri" | "API anahtarları" kept (R11) | 13 | differs |
| People & access | the manage dialog actions (edit, new password, sign out everywhere, reset two-factor, disable/enable) and refusals | existing dialogs with `DialogActions`; `ErrorAlert` with the code | 13 | filled |
| People & access | SSO users, their provider, roles from groups | `StatusBadge` "Single sign-on" + provider name + "At the identity provider"; no role choice for them | 13 | filled |
| People & access | authenticator state of a local account; disabled users | "Local account" badge (success/warning) + "Authenticator app set up / not set up yet"; Disabled badge | 13 | filled |
| People & access | user name next to name and e-mail | mono username line | 13 | filled |
| People & access | role-card headings are h3 under h1 | `<h2>` with the micro-card style (no skipped level) | 13 | differs |
| People & access | role cards in two columns at 761–1200 px | one column below 1020 px, three from 1020 px | 13 | to verify |
| API tokens | the new token shown once; SSO users cannot create tokens; empty list; access icons | warning Alert with `new-token`, Copy and Done (component state only); info Notice; `EmptyState`; `StatusBadge`s | 13 | filled |
| API tokens | Revoke as a neutral ghost button | subtle danger button with the X icon (revoking is destructive) | 13 | differs |
| Your account | change password and recovery codes in dialogs | the existing inline form and recovery-code flow as sections of the profile panel | 13 | differs |
| Your account | an SSO account | "Single sign-on" fact, "At the identity provider" badge, a line that the identity provider manages password and second factor; no password form and no recovery codes (the server refuses both) | 13 | filled |
| Your account | an authenticator not set up | "Not set up" badge (warning); the Sign-in fact says "Local account" | 13 | filled |
| Your account | Appearance in Settings (design) | the Appearance panel on Your account (R16) | 13 | differs |
| Your account (appearance) | the language select is device-only in the design | the select also saves to the account (help text says so) | 3 | differs |
| Your account (appearance) | color cards as `aria-pressed` buttons | visually hidden native radios in a fieldset ("Color mode"), 3 px focus ring on the card | 3 | differs |

### Settings

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| Settings | the product's eight tabs with a separate Recipients tab (the design's: Appearance, General, Notifications, Alerts, SSO, Backups, HTTPS, Forwarding) | the product's eight tabs, order and addresses as the vertical section navigation with icons (R16); the ACME work adds a ninth, Certificate authorities (`?tab=acme`, after HTTPS certificate) | 14, ACME 14 | differs |
| Settings | Appearance, organization name, display time zone, default language, idle timeout | not built (R16, R21): Appearance is on Your account; the rest has no backend | 14 | not built |
| Settings → Email | untrusted-certificate dialog, trusted fingerprint, test e-mail, write-only password | `AppModal` + `DialogActions`, micro-card, sub-section row | 14 | filled |
| Settings → Alerts | threshold rows instead of a comma list and switches | number rows with remove buttons, Add threshold, Save in `.formActions` | 14 | differs |
| Settings → General | public URL, retired-key retention | fields + `.formActions` | 14 | filled |
| Settings → Backups | alarm, not configured, failing, free space, next run, download with step-up, unreadable files, kinds | Notices, "Last backup" and "Schedule" micro-cards with the product's sentences, off-host Notice, `ResourceTable` with `StatusBadge` checks, `EmptyState`, Back up now in `.formActions` | 14 | filled |
| Settings → Backups | the "Details" row action | not built: there is no backup detail | 14 | not built |
| Settings → HTTPS | temporary certificate, PEM/PFX upload, wrong PFX password, warnings | warning/success Notice, `FactList`, `.checkOption` radio rows, `ErrorAlert`, warning list Notice | 14 | filled |
| Settings → Audit forwarding | enable, write-only CA with remove, test message, refused address, backlog and cursor | `.checkOption` checkbox, CA line + remove checkbox, Test + Save, delivery micro-card of whole sentences (not a `FactList`: the e2e reads the sentences) | 14 | filled |
| Settings → SSO | "SSO users may be Admin" and its confirmation, providers, refresh/edit/delete, mappings, empty states | `.switchRow` + dialog; providers as named sections with the design's usage-node head, `StatusBadge` On/Off, mappings `ResourceTable`; break-glass brand Notice | 14 | filled |
| Settings | form fields at 11 px on `--surface` | Mantine inputs with the theme's field styles | 14 | differs |
| Settings → Certificate authorities (ACME) | the whole screen family: the design predates ACME issuance and has no certificate authority, account or DNS hook screen | built from the SSO tab's pattern: a sub-section per list (h3), each authority and hook as a named section with the usage-node head (icon tile, h4 name, host as `Code`, `StatusBadge`s with icon + text: preset, account state, external account key, secret), allowed names as `Code` chips or a warning badge, the account as a `FactList` with its actions; `EmptyState`s with an explanation; an info `Notice` that nothing is contacted until an account is registered | ACME 14 | follow-up |
| Settings → Certificate authorities (ACME) | dialogs: add/edit authority (preset select, CA bundle, external account binding with write-only secret key, allowed names), register account (terms checkbox), rotate key / check key change, deactivate (affected certificate count), add/edit DNS hook (write-only secret, bounded waits), removals | `AppModal` + `DialogActions` + `ErrorAlert` + field errors, as the SSO provider dialog; allowed names as removable chips (`.chips`, a `CloseButton` per entry) with the rules told before the save | ACME 14 | follow-up |
| Settings → Certificate authorities (ACME) | the DNS hook's wire contract for its author | a native `<details>` disclosure ("How does the hook work?") with a 3 px `--alice-focus` ring on its summary | ACME 14 | follow-up |
| Settings → Certificate authorities (ACME) | the terms of service before registration | the register dialog reads the CA's directory when it opens (preview: "Contacting {host}…"), shows the terms as an external link above a checkbox that is disabled until then, registers for exactly those terms (`accepted_terms_url`), refuses unsafe terms, retries a failed read, warns when an external account binding is required | ACME 14 | follow-up |

### Issued certificates (ACME)

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| Navigation | an entry for certificates Alice gets from a certificate authority | "Issued certificates" (`/acme`, ShieldCheck icon) in the Inventory group after Certificates, for every role (Auditors read only); the name is the one the renewal e-mails use | ACME 15 | follow-up |
| Issued certificates | the whole list: the design predates ACME issuance | `PageHeader` + the inventory table panel (`ResourceTable` look): names (first name as `Code` link, "and N more names"), authority, `StatusBadge` with icon + text per state (pending neutral, issuing info, active success, failing warning, stopped danger), proof method, `Expiry` badge and date, next renewal (the scheduled attempt, else the server's rule before expiry or the authority's earlier ARI window), automation badges; native-select filters (status, authority) in the address, Clear filters, `CursorFooter`; an `EmptyState` with the explanation, the link to Settings → Certificate authorities when no authority exists and the one Get a certificate button (Administrators) | ACME 15 | follow-up |
| Issued certificate status page | the status page: definition, current certificate, renewal, orders, websites | the Key Vault certificate page's grid: main column with Renewal (`FactList`, Administrator `Switch`, failing/stopped `Notice`s with Check again and resume (formerly Renew now), the last problem as title + "What to do" + code), Orders (table, polled while an order runs) and "Websites using this certificate"; side column with What is ordered and Current certificate (`FactList`, short fingerprint, link to the certificate); Test run and Get certificate now / Order now in the header; license-lock `Notice` and disabled buttons | ACME 15 | follow-up |
| Issued certificate status page | websites, automatic deployment, holds | a table per website (server link, file as `Code`, state badge, what it serves, attention as plain text), a per-website automatic-deployment `Switch` (Operators may only switch off), the certificate's own switch, license/chain hold and stop `Notice`s with Release, the "change by hand" guidance `Notice`; Add websites, Deploy now (at most 20, chain confirmation) and Remove as `AppModal` dialogs like ConnectWebsitesDialog / DeployDialog | ACME 15 | follow-up |
| Get a certificate | a multi-step dialog | `AppModal` with a local state machine (AddKeyVaultDialog), a numbered step rail (`ol`, `aria-current="step"`, the setup rail's states laid out across), a focusable `h2` per step that takes the focus, Back/Next in `DialogActions` with "Step n of 5"; chips for names; early allow-list warnings as warning `Notice`s; the Nginx snippet in a native `<details>`; the done step offers Run a test first / Get certificate now | ACME 15 | follow-up |
| Get a certificate | websites in the wizard (design row 8: "locations") | not in the wizard: the server binds a website only to an issued certificate (409 ALC-ACM-0027), so the last step says that websites are connected on the status page after the first issuance; the wizard sets the certificate's automatic deployment | ACME 15 | differs |

### Network discovery

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| Navigation | an entry for certificates found on the network | "Network discovery" (`/discovery`, Network icon) in the Inventory group after Issued certificates, for every role (Auditors read only) | ND 11 | follow-up |
| Network discovery | the whole screen family: the design predates discovery | `PageHeader` + Mantine `Tabs` (Results, Scopes, Scans) as on the Overview, the tab in `?tab=`; `?view=unmanaged` (the Overview's and the alert e-mails' link) starts the Results at Unmanaged; a license-lock `Notice` and the Auditor's read-only `Notice` | ND 11 | follow-up |
| Network discovery → Results | the results table | the inventory table panel (`ResourceTable` look): the name as a button that opens the detail (`Code`, `aria-haspopup="dialog"`; the whole row is a pointer target too), other names as secondary text, issuer, the managed inventory's `Expiry` badge and date, "N endpoints", `StatusBadge`s with icon + text (Unmanaged warning, Managed success, Known info, No longer found neutral, Self-signed neutral; an expired certificate is shown by the `Expiry` badge alone, the Expired filter stays); "Found on" counts the endpoints that are not gone; native-select filters (status, expiry, signed by, still found / include no longer found, scope) and a debounced search in the address, Clear filters, Export, `CursorFooter`; a neutral `Notice` explaining what "unmanaged" means (A10). The list shows the certificates still found by default: the same definition as the summary behind the Overview line and the Certificates link, so their numbers match the lists they open | ND 11 | follow-up |
| Network discovery → Results | decision 7's "Wrong name?" chip | not built: Alice does not verify a presented certificate against the name it asked for (the probe trusts nothing and returns no verification), so there is no data to compute it; deferred | ND 11 | not built |
| Network discovery → Results | a detail view of one certificate and the places it was found | a right-hand Mantine `Drawer` (the first drawer in Alice; titled with the certificate's name, translated close button, a row click first focuses the name, so focus returns there): status chips and their meaning, a `FactList`, then one bordered card per endpoint (`address:port` as `Code`, state badge, SNI, plain-language last problem, TLS version and cipher, first/last seen, earlier fingerprints, the server in Alice as a link); "Add as server" opens the existing Add server dialog pre-filled with the host (Administrators only; the SSH port stays 22) | ND 11 | differs |
| Network discovery → Scopes | discovery settings, the empty allowed-networks state | an info `Notice` (`role="status"`) "Nothing is scanned until you list the networks Alice may scan" with the Administrator's button, then a `Panel` with a `FactList` (allowed networks and exclusions as `Code` lists, retention, the built-in exclusions) and Change settings | ND 11 | follow-up |
| Network discovery → Scopes | the scopes list and its dialogs | a `Panel` with a table (name with the size summary, ports, the schedule in words with the whole-days note, the Administrator's `Switch` named by the scope with the On/Off state as visible text beside it, or an On/Off badge, e-mail badge, last scan badge, Scan now with its disabled reason as visible described-by text, Edit/Delete); `AppModal` dialogs with `DialogActions`: the scope form (one entry per line, per-line refusals "Line n: …", pace with the hard limits, schedule hours, optional daily window with a native time zone select and the DST note), the live size box (`aria-busy` while asking, one `aria-live` line that changes only on an answer, debounced 800 ms, the previous request cancelled and a late answer ignored, nothing asked beyond 256 lines, "Too many size checks" on a 429 and asked again after the wait; a step-up only on a click), the daily window's two times in a fieldset described by its error and the time zone refusal on the select, settings, and a delete confirmation that says what happens to the results | ND 11 | follow-up |
| Network discovery → Scans | the scans table | a `Panel` with a table (scope, started by, state badge, "answered · not answering · in total", started/finished/duration, the reason a scan ended early as title + what to do + code, Cancel scan); Start a scan opens a dialog that lists every scope and disables the ones that cannot start with their reason; only the first page reads itself again, while a scan on it is queued or running; "The scan has started" goes when that scan is over or after a few seconds | ND 11 | follow-up |
| Certificates | a link to unmanaged certificates found on the network | a default `Button` link at the end of the chip row, "Found on the network, not managed (n)", only when a scan scope exists (`/discovery/summary`) | ND 11 | filled |

### Sign-in, step-up, error pages

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| sign-in | the heading "Welcome to Alice / Sign in to your Atlas workspace" (a tenant the product does not have) | h1 "Sign in to Alice" + "Sign in with your Alice account." (R17) | 15 | differs |
| sign-in | MFA code, recovery code, first-sign-in TOTP enrollment and recovery codes | the same form side under the one h1; the phase title as h2 (focused); enrollment widens the form to 420 px | 15 | filled |
| sign-in | session-ended notice, SSO refusals, lockout and rate-limit errors | the existing Alerts above the form; CircleAlert on the SSO refusal | 15 | filled |
| sign-in | one demo SSO button | one full-width button per public provider under "or"; the MFA note sits under the password form, not under the SSO buttons (Alice does not enforce MFA for single sign-on) | 15 | differs |
| sign-in | the brand dot color (`--brand` is invisible on the brand side) | `--alice-auth-brand-muted` (decorative) | 15 | differs |
| sign-in (enrollment) | the QR code tile in dark mode | `.qrTile`: fixed `#ffffff` in both schemes (authenticator apps scan dark on light); the color guard allows exactly this line | 15, 17 | filled |
| sign-in (recovery codes) | a recovery-code list | two-column mono grid on `--alice-surface-subtle`, Copy/Download buttons | 15 | filled |
| step-up | the SSO variant; the subtitle in the dialog head | same dialog with Cancel and the focused continue button; the subtitle is the body's first paragraph (keeps it out of the dialog's name) | 15 | filled |
| route error, not found, no access | no design for a render error; not-found outside the shell; the design's denied wording | `AuthLayout` without the brand side + `AuthMessage` (icon tile, h1, text, actions); product text `ui.noAccess` in `role="alert"` | 15 | filled |

### Setup wizard

| Screen | What the design lacks | How it was filled (components / tokens) | Task | Status |
|---|---|---|---|---|
| setup wizard | the language choice as a select in step 1 | the real language step stays separate; it shares rail item 1 with the setup code | 16 | differs |
| setup wizard | TOTP QR + manual key and one-time recovery codes (the design only mentions them) | `TotpEnrollment` and `RecoveryCodes` in the content panel, h2 styled as the step title | 16 | filled |
| setup wizard | passphrase strength meter, too-weak text, `ALC-SET-0010`, done state after Back | product fields, `Progress` in semantic tokens, `ErrorAlert`, the "stored" checkbox as a `.check-option` row | 16 | filled |
| setup wizard | HTTPS upload with warnings, keep temporary, done state (design: two radio rows) | two bordered `.choice` boxes (upload first, "or", keep temporary with "Replace it before production use."); Continue once a choice is made | 16 | differs |
| setup wizard | mail save/test/skip | the Settings mail form; Skip and Continue in the actions row; one separator line | 16, 14 | filled |
| setup wizard | license upload preview, Installation ID, evaluation help (design: two radio rows) | Installation ID, two bordered `.choice` boxes, preview dialog with `DialogActions` | 16 | differs |
| setup wizard | the platform key, server preparation, optional add server | `PlatformKeyPanel` and the add-server dialog | 16 | filled |
| setup wizard | completion with step-up; the 404 "setup is over" path | `DoneStep` ("Go to the dashboard", step-up); back to sign-in; the rail shows every item done | 16 | filled |
| setup wizard | Back on every step after the first | Back only where the wizard allows it (never before HTTPS: recovery codes are shown once); the rail never navigates and has nothing focusable | 16 | differs |
| setup wizard | the "Visual walkthrough only" note and "Exit preview" | dropped: this is the real installer | 16 | differs |
| setup wizard | step change announcement | focus on the new step's h2 and a polite live region "Step n of 7" | 16 | filled |
| setup wizard (phone) | only the current rail item | the same, plus "Step n of 7" | 16 | filled |
| setup wizard | whole-row clicks on the bordered choice rows (language, passphrase) | the Settings rows toggle on the whole row; the wizard's own `.checkOption` rows do not yet | 14, 16 | follow-up |

## Design elements not built, and why

1. **Numbered pagination** and "x–y of N results": the API pages with cursors and gives no totals (R13).
2. **The 5-day expiry histogram**: it needs every certificate row or a server-side aggregate; Phase 9 added no
   endpoint (R12).
3. **The "SSH keys" total** on the Overview: the SSH key list is cursor-paged (R10, R20).
4. **Deployment outcome counts and weak-key counts**: counted from paged lists they would lie (R20).
5. **Resource search** in the command palette: there is no bounded, RBAC-scoped search endpoint (R7).
6. **Organization name** in the sidebar and in Settings: the product has no tenancy model (R5, R21).
7. **Display time zone** in Settings: no backend (R16, R21).
8. **Appearance in Settings**: it is a per-person preference; Settings is for administrators only (R16).
9. **Vault cards**: a table scales past a few vaults and keeps the e2e row contract.
10. **The Operation log** on a deployment: the API has no raw log; the steps carry the evidence.
11. **The design-system and product-review pages**: review tools of the prototype; this file records their
    content instead (R22).
12. **The "Atlas workspace" sign-in copy**: it names a tenant the product does not have (R17).

## Tokens and components added beyond the design

Tokens (`web/src/design/tokens.css`, light and dark, contrast-tested in `tokens.test.ts`):

- `--alice-{brand,success,warning,danger,info,neutral}-hover`: hover of filled semantic buttons.
- `--alice-on-strong`: text on filled semantic buttons.
- `--alice-neutral`, `--alice-neutral-hover`, `--alice-neutral-soft`: the neutral tone.
- `--alice-auth-brand-{bg,text,muted,line}`: the sign-in brand side.
- Mantine's own variables (`--mantine-color-body`, `-text`, `-error`, `-disabled*`, the primary color's variables
  and the dark palette) mapped onto the tokens in `web/src/theme.ts`.

Components (`web/src/components/ui` unless noted):

- `CursorFooter`: "N shown" and Load more for cursor-paged tables.
- `Notice`: a page-level status line with `role="note"` by default.
- `LinkTabs`: tabs that are plain links (`aria-current="page"`), not a tablist and not a landmark.
- `DialogActions`: the design's dialog action bar.
- `ThemeToggle`, `LanguageToggle`, `AppearanceControl`: color mode, compact tables and language.
- `UsageTopology` (`components/certificates`): where a certificate is used, source to locations.
- `RotationPath` (`components/rotation`): the four rotation phases, only for runs that are progressing.
- `SetupRail`, `SetupShell`, `StepHeading`, `StepActions` (`pages/setup`): the wizard's shell and rail.
- `AuthLayout`, `AuthMessage` (`components/auth`): the sign-in split layout and the one-heading message block.
- `ExpiryHorizon` (`components/dashboard`): the exclusive expiry buckets.
- `components/deploy.module.css` (`.refused`, `.separated`) and `components/settings/settings.module.css`
  (form actions rows, micro-cards, choice rows).

## Follow-ups (not in Phase 9)

- A bounded, RBAC-scoped search endpoint, so the command palette can find resources.
- A server-side expiry histogram aggregate, for the design's five-day bars.
- Total counts for paged lists (deployments, SSH keys, Key Vault contents), if wanted, from the server.
- `locales/common` texts (server errors and e-mails) that still say "Dashboard" or "Audit log".
- The Turkish term for API tokens ("API anahtarları" or the design's "API belirteçleri").
- Mobile navigation width (the design's 222 px drawer instead of the full-width off-canvas menu).
- An explicit "Not reported by the verification" line for the served fingerprint on a deployment.
- Focus after a dialog removes its own trigger (repin, key removal, certificate dialogs).
- Whole-row clicks on the wizard's own choice rows, as in Settings.
- A design for the ACME screens (Settings → Certificate authorities and the Issued certificates pages): they were built
  from the existing components and tokens, without a counterpart in `alice-design/`.
- Issued certificate status page: refresh the websites' states while a deployment of the certificate is queued or
  running (today only orders are polled; after **Deploy now** the page must be reloaded), and one combined automatic
  deployment control instead of the certificate's and each website's switch.
- Restored installations: a banner on **Issued certificates** while automatic renewal was switched off by a restore
  (today only the restore's warning and the "Off" state say so).
- Switching a website's automatic deployment off while the license is locked (the route is refused in lock; removing
  the website is the way today).
- A design for the Network discovery screens (Results, the certificate drawer, Scopes and its dialogs, Scans): they were
  built from the existing components and tokens, without a counterpart in `alice-design/`.
