# Phase 9: The Clarity Design in the Web Interface — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every screen of the Alice web interface — sign-in and verification, the first-run wizard, the application shell and all routed pages — follows the committed "Clarity" product design (`alice-design/`): its semantic light and dark tokens, the local Geist fonts and Lucide icons, grouped navigation, page headers, resource tables, status badges, fact lists, operation timelines and attention items, with a light / dark / system color mode and a compact table density. Where the design is a prototype with synthetic data and does not draw a state the product has (held jobs "Waiting for an administrator", license phases and banners, step-up, `ALC-*` error codes, recovery codes and passphrase, HTTPS, backups, audit forwarding, SSO, rotation decisions, deployment outcomes, Key Vault bindings and imports, CSRs, API tokens, discovery), that state is built from the same components and tokens. No security behaviour, permission, query semantic or setup check changes.

**Architecture:** A token layer (`web/src/design/tokens.css`: `--alice-*` CSS variables for both schemes, selected by Mantine's `data-mantine-color-scheme`) feeds Mantine through `cssVariablesResolver` and a semantic `variantColorResolver`, so every existing Mantine component (Alert, Badge, Button, Modal, Table, Tabs, inputs) takes the design's look in both schemes without per-call colors. A small set of presentational components in `web/src/components/ui/` gives pages the design's structures (PageHeader, Panel, ResourceTable, StatusBadge, FactList, OperationTimeline, AttentionItem, EmptyState, Notice, MetricStrip, LinkTabs, AppearanceControl). Each page task re-composes its page from them while keeping its data hooks, guards, `data-testid`s and accessible names. Web-only: no API, route permission, migration or Go server change; one new client route (`/rotations`) reads two existing endpoints (`GET /api/v1/rotation/policies`, `GET /api/v1/rotation/runs`).

**Tech Stack:** React 18.3, Mantine 8.3 (`@mantine/core`, `@mantine/hooks`), TanStack Query 5, react-router 7, i18next 26 / react-i18next 17, Vite 8, TypeScript 6, Vitest 5 + Testing Library + msw 2, Playwright 1.63 + `@axe-core/playwright` 4.13. **No new npm dependency**: Geist and Geist Mono (SIL OFL 1.1) and the Lucide icon subset (ISC) are vendored from `alice-design/dist/assets` and `alice-design/dist/icons.js`.

**Spec:** `alice-design/README.md` and `alice-design/IMPLEMENTATION.md` (binding production rules), the screens in `alice-design/dist/{pages.js,admin.js,app.js,ui.js,guide.js}` with `tokens.css` and `styles.css`, and `alice-design/validation-report.json`. The owner's request (2026-10-12): use alice-design as **the** design and stay faithful to it; rearrange the first-run screens (wizard and sign-in) according to it; where the design lacks something the product has, add it in the same visual language. Executors read the spec files of their screens before writing code (the brief names the functions).

## Global Constraints

- Web-only phase. Changed paths: `web/**`, `tools/notices/**` and the `notices` line of `Makefile` (Task 2, vendored-asset licenses), `docs/**` UI-label references, `docs/design-gaps.md` (new), `CHANGELOG.md`. **No** change to `internal/**`, `cmd/**`, `migrations/**`, `api/openapi.yaml`, `docs/authz-matrix.md`, `locales/common/**` or `alice-helper`. **`alice-design/` is read-only.**
- Go toolchain `go 1.27.2` (`export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"`, repository root as working directory) for `make i18n-check`, `tools/notices` and `make docs-check`.
- All code, identifiers, comments, file names, commit messages and technical docs are in English. Turkish appears only as translation values in `web/src/locales/tr.json`; formal-polite ("siz").
- **Commits:** Conventional Commits, made with `git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "<message>" -m "Co-Authored-By: <the model that wrote the commit> <noreply@anthropic.com>" -- <paths>` (`-m` before `--`). Several agents share one working tree and one git index: stage new files with `git add -- <paths>` and commit **only** your paths; never `git add -A`, `git add .`, `git commit -a`, a bare `git commit`, `git stash`, `git reset` of paths you did not write. Never squash, rebase or amend (`.gitleaksignore` is pinned to commit hashes; the branch merges fast-forward only). The commit snippets below show `Claude Opus 5.5` in the trailer; substitute the model that wrote the commit.
- **Never read, edit, move, add or commit** `docs/security/reviews/independent-audit-2026-10-04.md`, `docs/security/reviews/independent-audit-2026-10-04-poc/` or `.claude/` (add `--exclude-dir=.claude` to recursive greps).
- **Docker safety:** the owner's compose project `alice` (image `alice:dev`, volumes `alice_*`) and the containers `pt-footbar-pg`, `slaveofai-postgres`, `alice-demo*` are never touched: no `make up/down/reset/logs/setup-token/unlock/hardening-check`, no `docker compose` without `-p alice-e2e`, no prune, no `docker rm/stop/image rm` of anything you did not create. Only the tasks marked **Docker alone** (18 and 19) run Docker or Playwright (`make e2e-up`, `make e2e`, `make e2e-browsers`, `make e2e-down`; project `alice-e2e`, 127.0.0.1:9443), with no other agent using Docker. `make lint` runs ShellCheck in a container: no agent runs it while Playwright runs; web tasks use `make web-lint`.
- **Shared-file lock.** `web/src/locales/en.json`, `web/src/locales/tr.json` and `web/src/test/screens.ts` are edited by many tasks. An agent edits them only while holding the lock: `until mkdir /home/meren/projects/alice-secrets/.superpowers/sdd/2026-10-12-phase-9-design/locale.lock 2>/dev/null; do sleep 20; done`, then re-read the files, make one minimal edit (keys only in the namespaces your task owns, see C9; never reformat the file), run `make i18n-check`, commit **only** these files (`i18n(web): …`), and release with `rmdir …/locale.lock` — also on failure. Hold the lock for minutes, not for the whole task. Adding keys before the code that uses them is fine. A task's own commits never list these three files: another agent may hold uncommitted keys in them, and `commit --only` would take those too.
- No new npm dependency, no CDN (fonts, icons, scripts), no inline `<script>` or `<style>`: the SPA's CSP is `default-src 'none'; script-src 'self'; style-src 'self' 'nonce-…'; img-src 'self' data:; font-src 'self'` (`internal/api/spa.go`). Mantine keeps `getStyleNonce={readCspNonce}`; CSS lives in `.css` / `*.module.css` files that Vite emits as `<link>`; the e2e CSP guard fails any violation.
- Frontend rules kept: no `dangerouslySetInnerHTML`; no `toUpperCase`/`toLowerCase` (ESLint) — uppercase eyebrows and group labels use CSS `text-transform: uppercase` (which respects `lang` for Turkish İ); native `<select>` (`NativeSelect`) everywhere the e2e drives `selectOption` (C10).
- **Secrets** (password, TOTP secret, recovery codes, recovery passphrase, private keys, PFX passwords, CA PEM, API tokens) never reach `localStorage`, a query key, the query cache, a URL, a log or a test artefact; the screenshot evidence of Task 19 is never committed. The only new `localStorage` values are `alice.colorScheme` and `alice.density` (per device, like the design's "Your preference stays on this device"); `alice.lang` stays as it is.
- i18n: every user-visible string is a key in `web/src/locales/en.json` and `tr.json` (`make i18n-check`: same keys, same `{{placeholders}}`, no empty value, identical values only if allowlisted in `.i18n-identical.json`); plural `_one`/`_other`; no sentence assembly; fingerprints, paths, host names, user names and `ALC-*` codes are never translated (rendered in `<Code>` or the mono token). Copy comes from the design (EN and TR as written in `alice-design/dist/*.js`) unless C10 or a ruling says the product's wording stays.
- **Accessibility:** status = text + icon + color, never color alone; a 3 px focus ring (`--alice-focus`) on every control except the table scroll region (2 px inside, an e2e contract); one `<h1>` per page; exactly one `navigation` landmark (named `t('nav.label')`) and one `main`; dialogs trap focus, close on Escape and return focus. No serious or critical axe finding and no horizontal page scroll at 390, 640, 768, 1024, 1280, 1440 and 1920 px, in light and dark, in English and Turkish.
- **Coverage floors are never lowered:** `web/vite.config.ts` thresholds statements 93, branches 90, functions 93, lines 95 (`make web-coverage`); new code carries its tests. `coverage-floors.json` (Go) is untouched; `tools/notices` tests must pass.
- **Verification before every commit:** `cd web && npx tsc --noEmit`, `make web-test`, `make web-lint`, `make i18n-check`; `make web-coverage` where the task says so; `make web` (production build) in Tasks 1, 4, 16 and 20. Playwright only in Tasks 18 and 19.
- **The 122 Playwright tests × 3 browsers stay green.** Accessible names, roles, `data-testid`s, URLs and texts in the "E2E contract" section are kept. The only deliberate breaks are the label changes of the "Label changes" table; Task 4 makes them and edits the specs in the same commit (Task 5 edits one spec for the Assurance tab); Task 18 proves the suite.
- **Security semantics never weaken:** route guards and nav role lists stay as in `docs/authz-matrix.md`; buttons that act on a run, a job or a deployment come only from server data (`actions_allowed`, `deploymentView`, `isSettled`, job state); step-up flows, license-lock behaviour, cursor pagination (`next_cursor`, "Load more"), URL filters (`useUrlFilters`), saved views and exports with exactly the active filters, cumulative expiry windows (`expired ⊂ within_7 ⊂ within_30 ⊂ within_60`), the wizard's order and checks: all unchanged. No count or chart is computed from a paged or truncated list. No "security score".
- Report honestly: failing tests, skipped steps and deviations go in the task report; gap rows go to Task 20 through the reports.

## Review Focus

1. **Dark mode on real screens** — every page, dialog, banner and table in the dark scheme (and "system" while the OS is dark): text on tinted alerts and badges, disabled controls, `<Code>` blocks, focus rings, the table striping and hover, the wizard's QR code and the auth brand side. Expected: no text below 4.5:1, no element still light (white panel on dark canvas), no black link text. Tests: Task 1 `tokens.test.ts` (every text/background token pair ≥ 4.5:1 in both schemes, non-text ≥ 3:1), Task 17 `colorRules.test.ts` (no hard-coded `c=`/`color=` shade, `black` or `--mantine-color-<name>-<n>` left), Task 18 axe on every route in dark (`phase9.spec.ts`).
2. **Role and license gates through the new shell** — an Operator, an Auditor, an SSO user, a locked license, an Administrator with unfinished setup. Expected: the grouped sidebar shows exactly the destinations of `NAV_ITEMS` for the role (Operator: no Audit trail, People & access, Settings, License; Auditor: no People & access, Settings), the Assurance tab only when the summary carries `audit`/`backup`, the command palette lists only permitted pages, the setup and license banners keep their texts and test ids, and nothing is offered that the server would refuse. Tests: Task 4 `AppLayout.test.tsx` (`renders the destinations of each role, in the design’s groups`) and `shell.test.tsx` (`opens with Ctrl+K and lists only the pages the role may open`), Task 5 `DashboardPage.test.tsx` (`hides the Assurance tab for an Operator…`).
3. **The wizard cannot be skipped by its new progress rail** — clicking or keyboarding the rail, a reload at every step, Back from every step, a session that ends mid-wizard, a 404 from a setup route. Expected: the rail is a non-interactive `<ol>` with `aria-current="step"`, Back exists only where `BACK` allows it, the resume rules of `startOf` are unchanged, every check (setup code, TOTP, one-time recovery codes, passphrase strength, HTTPS choice, mail save-or-skip, license choice) still gates Continue. Tests: Task 16 `SetupRail.test.tsx` (`is not interactive: no links, no buttons, nothing focusable`) and `SetupPage.test.tsx` (`rail marks the step resumed from next_step…`, the existing resume and Back tests kept).
4. **Numbers that could lie** — the expiry horizon, chips and metric strip; deployment and SSH-key lists that load page by page. Expected: horizon bars use mutually exclusive buckets derived from the summary (`expired`, `within_7 − expired`, `within_30 − within_7`, `within_60 − within_30`), every count link opens exactly its rows (cumulative), Key Vault key and secret counts are never added to certificate counts, no "of N results" total and no outcome counts from loaded rows. Tests: Task 5 `ExpiryHorizon.test.tsx` (`derives exclusive buckets from cumulative counts`, `never adds Key Vault keys`), Task 6 `CertificatesPage.test.tsx` (`shows the design header, chips with the summary’s cumulative counts and none on All`), Task 11 `DeploymentsPage.test.tsx` (`shows no outcome totals`).
5. **Long Turkish labels, long fingerprints and narrow tables** — Turkish nav and button labels, SHA-256 fingerprints, Key Vault URLs and file paths at 390 px, compact density, 200 % text zoom. Expected: no horizontal page scroll (tables scroll inside their focusable region), labels wrap instead of overflowing, fingerprints break anywhere (`overflow-wrap: anywhere`). Tests: Task 3 `ui.test.tsx` (`FactList values break long tokens`), Task 18 `phase9.spec.ts` (every route at 390/768/1024/1440 in both languages and schemes, overflow check of `expectAccessibleAt`).

---

## Design rulings (R1–R22)

These settle every place where the design, the product and the tests pull in different directions. Executors follow them; a reviewer checks against them.

- **R1 Stack.** Keep React/Mantine, the CSP nonce, i18n catalogs, query semantics, RBAC, step-up, cursor pagination and server-derived action eligibility (IMPLEMENTATION §§1–6). The design's HTML/CSS is translated into Mantine theme overrides, CSS modules and small components — never copied as `innerHTML`.
- **R2 Vendored assets, no new dependency.** Fonts (`geist.woff`, `geist-mono.woff`, `OFL.txt`) and the 76-icon Lucide subset (`icons.js`, `LUCIDE-LICENSE`) are copied into `web/src/design/`. Icons render as React SVG elements from data (no `innerHTML`). Their licenses enter `THIRD_PARTY_NOTICES.md` through a `-vendored` manifest in `tools/notices` (Task 2). System-font fallbacks stay in the stacks.
- **R3 Tokens.** The design's tokens become `--alice-*` CSS variables (C1) for `data-mantine-color-scheme="light"` and `"dark"`, plus hover tokens and `--alice-on-strong` that the design implies but does not name (needed for filled semantic buttons). Mantine's own variables map to them (C2). Light/subtle variants use the semantic `*-soft` background with the semantic foreground — this replaces the old "black text" override (IMPLEMENTATION §1); `--mantine-color-error` is `--alice-danger` in both schemes.
- **R4 Color mode and density are per-device preferences.** `MantineProvider` gets `defaultColorScheme="auto"` and `localStorageColorSchemeManager({ key: 'alice.colorScheme' })`; density is `alice.density` (`comfortable` 67 px rows / `compact` 48 px). `web/public/theme-init.js` (a same-origin script, allowed by `script-src 'self'`) applies both before the bundle runs, so a dark-mode user never sees a light flash. Language keeps its existing account-level persistence (`PUT /auth/locale` + `alice.lang`). A blocked `localStorage` changes nothing but persistence.
- **R5 Shell.** Mantine `AppShell` stays (its mobile off-canvas behaviour and `Burger` are e2e contract), restyled: a 222 px sidebar (202 px between 768 and 1199 px), 65 px top bar, breakpoint `sm` (768 px; the design's 760). DOM order: skip link → navbar → header → main (keeps the 25-Tab budget to the People & access link). Sidebar: brand, installation card ("Self-hosted installation" + Alice version — no organization name: the product has no tenancy model and operators cannot read the license customer), one `<nav aria-label={t('nav.label')}>` with an ungrouped Overview and the groups **Inventory** (Certificates, SSH keys, Servers, Key Vaults), **Operations** (Deployments, Key rotations, Audit trail), **Administration** (People & access, Settings, License) — group labels are plain text, not headings, not links; then the account block (avatar initials, `data-testid="current-user"` with the display name only, role) with visible links **Your account** and **API tokens** and a visible **Sign out** button. The design's account dialog is not used: the e2e needs a visible Sign out button and plain links.
- **R6 Top bar.** Burger (mobile), a breadcrumb of plain text (`Workspace › <page>` — a `<div>`, never a `nav` landmark or links, so page-wide link and navigation queries stay unique), the command palette trigger (⌘K / Ctrl+K), the theme toggle, the language toggle and the attention bell. The design's "DESIGN PREVIEW" label is dropped.
- **R7 Command palette = pages only.** There is no unified search endpoint (IMPLEMENTATION §7). The palette searches the destinations the role may open (the same `NAV_ITEMS` filter) and never queries resources. Resource search is a recorded gap.
- **R8 Attention bell.** Opens a popover that reads `GET /alerts` (`ALERTS_KEY`) only while open and shows the conditions with `AttentionItem` (the dashboard's mapping, C6); no polling from the shell, no unread dot (no "unread" exists server-side).
- **R9 Language toggle.** With exactly two languages the top bar shows the design's toggle button: visible text is the other language's code (`TR` / `EN`), its accessible name is the other language's native name (`Türkçe` / `English`); it calls the existing `setLanguage` + `setMyLocale`. With more languages it falls back to a `Menu` (not built now, `LANGUAGES` has two entries; a test pins the two-language behaviour). The Account page's Appearance panel shows the language as a `NativeSelect`.
- **R10 Overview.** The dashboard follows `overviewPage()`: eyebrow = today's date (`Intl` long weekday, day, month, year in the UI language), `<h1>` **Overview**, the design's description, tabs **Operations | Assurance** (`?view=assurance`; Assurance only when the summary carries `audit` or `backup`). The personal "Welcome, <name>" heading is removed; the signed-in identity is the sidebar's `current-user` (the e2e moves to it, Label changes table). Metric strip: Monitored certificates, Managed targets, **Key rotations** (the design's "SSH keys" count needs a total the paged API does not give — gap), Needs attention (`summary.attention`). Panels: Expiration horizon (4 exclusive buckets, R12), Needs attention (`/alerts`), Upcoming renewals (`/dashboard/expiring`, 10 rows, never totalled), Target connectivity (`targets.by_status`), Recent deployments (`deployments.recent`, `failed_7d`), Key rotation (`rotation.*`). Assurance: Audit integrity (`audit`), Recovery readiness (`backup`, with the design's "Not established by a backup checksum" line), License (`license`, admin/auditor detail) and the evidence trail link to `/audit`. The setup checklist stays at the top when present.
- **R11 Copy.** Navigation and page titles take the design's names (Label changes table). Body copy keeps the product's wording where it carries a security or legal meaning (wizard, sign-in, step-up, error texts, license texts) and where tests or docs pin it; descriptive one-liners under page titles and panel subtitles come from the design. The Turkish product term "API anahtarları" for API tokens stays (the design's "API belirteçleri" would change 21 established strings and the docs; recorded gap). `locales/common` (server texts: errors, e-mails) is not edited; its "Dashboard"/"Audit log" mentions are a recorded follow-up.
- **R12 Expiry horizon.** The design's 12 five-day bars need every certificate row or a server aggregate (IMPLEMENTATION §3); Phase 9 adds no endpoint. The horizon shows the four exclusive buckets the summary allows, the 7/30/60 segmented control selects which cumulative window the big number states ("N expiring within X days, expired included"), and the `dashboard-counts` links stay cumulative (each opens exactly its rows). Recorded gap: per-5-day distribution.
- **R13 Tables.** `ResourceTable` wraps Mantine `Table.ScrollContainer` + `Table` (the theme keeps the focusable, named scroll region with its 2 px inside focus ring — an e2e CSS contract) and adds the design's toolbar and footer slots. The footer shows "N shown" and the existing "Load more" button; the design's numbered pagination and "x–y of N results" are not built (cursor API). Every table keeps one header row, `tbody tr` rows, its `data-testid`, its `aria-label`, and native selects in its toolbar.
- **R14 Status badges stay Mantine `Badge`.** `StatusBadge` renders `<Badge variant="light">` with a dot or icon (the rotation run page's e2e locates `.mantine-Badge-root`). Existing badge components (`TargetStatusBadge`, `VaultStatusBadge`, `Expiry`, `DeploymentStatusBadge`, `KeyFlags`) keep their names, props, texts and data attributes and render through `StatusBadge`.
- **R15 Alerts are Notices.** Mantine `Alert` stays (roles `alert`/`status` and test ids are contract); the theme gives it the design's status-line look. `Notice` is a thin wrapper for new page-level notices. `ErrorAlert` additionally shows `ALC-*` codes (`ApiError.code`) as "Error code: <code>" like `JobErrorAlert` does — the design's state table requires "a stable error code" for failures.
- **R16 Settings.** The product's eight tabs keep their order, names and `?tab=` URLs (e2e pins the tablist): mail, recipients, alerts, general, backups, https, forwarding, sso. They render as the design's vertical settings navigation (`Tabs orientation="vertical"` ≥ 768 px, horizontal scroll below) with each tab's body in a panel with the design's heading + description. **Appearance lives on Your account**, not in Settings (it is a per-user preference, and Settings is Administrator-only). The design's General fields "Organization name" and "Display time zone" are not added (no backend; IMPLEMENTATION §7).
- **R17 Sign-in.** The design's split layout (`loginPage()`): brand side (hidden below 768 px) with the design's tagline as a styled paragraph (not a heading) and footer; form side with the theme and language toggles top right, the shield icon tile, `<h1>` **Sign in to Alice** (product text; the design's "Welcome to Alice / Atlas workspace" names a tenant the product does not have), the product's fields and **Sign in** button, the SSO buttons under the "or" divider when providers exist, and the "Protected with multi-factor authentication" note. MFA, recovery-code and first-sign-in enrollment phases use the same form side.
- **R18 Wizard.** The design's `setupPage()` shell: brand row with the "Set up Alice" `<h1>` and a "Setup" badge; a left rail (`<ol aria-label>` of 7 non-interactive items: Setup code & language; Administrator & MFA; Recovery passphrase; HTTPS certificate; Mail server; License; First server) with done/current/upcoming markers and `aria-current="step"`; the content panel with the step's `<h2>` (styled like the design's step title), its form and a `form-actions` footer (Back left where `BACK` allows, primary action right). Mobile shows only the current rail item. Every real step, check, test id and text is kept; the rail never navigates; the design's "Visual walkthrough only" note is not shown (this is the real installer).
- **R19 Rotations page.** `/rotations` (new, read permission, all roles) shows the design's `rotationsPage()`: an "Active rotations" panel for runs that are not final (from `listRuns`, first page, with a "Load more"), and the policies table (`GET /rotation/policies`, every live policy) linking to each key and its open/last run. No "Create policy" button here: a policy is created on its key's page (needs `ssh_key_id`, step-up and a preview). Decision buttons stay on `/rotation/runs/:id` (from `actions_allowed`, Administrators only). SSH keys and Key rotations share `LinkTabs` (plain links with `aria-current="page"`, not a tablist, not a landmark).
- **R20 No numbers from paged lists.** The design's mini-stats on Deployments ("12 verified · 1 rolled back") and SSH keys ("1 weak key") are not built: those lists are cursor-paged. Servers keeps its mini-stats (its list is read completely, `listAllServers`). Weak keys get a filter link ("Show weak keys", `?flag=weak`) without a count.
- **R21 No settings in the design that the product lacks** (organization name, display time zone), no "Upload replacement" on discovered certificates without a private key flow change, no Azure key rotation, no "Renew everything" (README product boundaries).
- **R22 Design-system page.** The product has no design-system route and none is added (the prototype's page is a review tool). New components and every filled gap are recorded in `docs/design-gaps.md` (Task 20) with the tokens and components used.

## Design → product coverage

| Design screen (function in `alice-design/dist`) | Product route / component | What changes | What the product has that the design lacks (built in the design's language) | Task |
|---|---|---|---|---|
| Shell: `renderSidebar`, `renderTopbar`, `app.js` nav (inventory/operations/administration) | `layout/AppLayout.tsx`, `NAV_ITEMS` | Grouped sidebar, installation card, account block, top bar with breadcrumb, palette, theme/language toggles, bell; banners as status lines; footer | Setup banner (`setup-banner`), license banners (12 kinds), notifications-failing banner, 48-hour backup banner, SSO step-up refusal alert, sign-out failure alert, role-filtered destinations, mobile close-on-navigate | 4 |
| `footer()` | AppLayout footer | "Self-hosted · Alice v<version>" from `GET /version` | Server unreachable/version states (`home.server*`) | 4 |
| Global search (⌘K) | new `components/shell/CommandPalette.tsx` | Pages only (R7) | — (resource search = gap) | 4 |
| `appearance()` (design system + account + settings) | new `components/ui/AppearanceControl.tsx`, `ThemeToggle`, `LanguageToggle`; Your account | Light/dark/system cards, compact tables switch, language select | Account-level language persistence, per-device storage note | 3, 13 |
| `overviewPage()` operations tab | `pages/DashboardPage.tsx`, `components/dashboard/*` | Page header, tabs, metric strip, horizon, attention, renewals, connectivity, recent deployments, rotation panels | Setup checklist (`setup-checklist`), partial errors per query, `dashboard-counts` cumulative links, KV keys/secrets line, notifications failing condition, audit-broken condition | 5 |
| `assuranceDashboard()` | DashboardPage `?view=assurance`, `AuditHead`, `BackupCard`, `LicenseCard` | Audit integrity, recovery readiness, license, evidence link | Backup alarm/never/not configured states, license phases for admin/auditor, operator gets no tab | 5 |
| `certificatesPage()` | `pages/CertificatesPage.tsx` | Chips, toolbar, resource table, footer, cumulative note | Pending CSRs (`pending-csrs`), Create CSR, upload dialog, saved views menu, export, native filter selects (7/14/30/60/90), cursor Load more, server filter | 6 |
| `certificateDetail(id)` | `pages/CertificateDetailPage.tsx` | Detail header, validity panel, topology "where used", facts, locations table, next action, data handling | Deploy dialog and its steps, `deploy-hint`, `chain-hint`, import into Key Vault (admin), import history, unassociated upload → deploy from an eligible location | 6 |
| `serversPage()` / `serverDetail(id)` | `pages/TargetsPage.tsx`, `pages/TargetDetailPage.tsx` | Mini-stats, table, detail header, identity notice, connection facts, operations panel | Add server dialog + host-key confirmation, platform public key panel, held jobs panel "Waiting for an administrator" (`blocked-jobs`), repin dialog, delete, SSH key table with remove, websites (Nginx locations, verify settings), job progress/stopped/still-working alerts, discovery | 7 |
| `vaultsPage()` / `vaultDetail(id)` / `vaultCertificateDetail()` | `KeyVaultsPage`, `KeyVaultDetailPage`, `KVCertificatePage` | Vault cards or table, boundary notice, tabs, facts, versions table, connected websites | Access check panel (monitor/deploy/import), firewall/throttled states, replace credentials, polling interval, delete with bindings, release of held versions (admin + step-up), bindings and auto-deploy confirm, KV deploy dialog, role guide | 8 |
| `sshKeysPage()` / `sshKeyDetail(id)` | `SSHKeysPage`, `SSHKeyDetailPage`, `RotationPolicyPanel` | Link tabs (Inventory / Key rotations), weak-key filter link, table, detail panels | Generate key, deploy key dialog, download private key (admin, step-up, protect), remove one location (last root key confirm), missing keys switch, saved views, export, Alice connection key flag | 9 |
| `rotationsPage()` / `rotationDetail()` | new `pages/RotationsPage.tsx`; `pages/RotationRunPage.tsx` | Active rotations, policies table; run header, progress path, location results, key transition, decisions panel | `actions_allowed` decisions (continue, finish now, keep old, stop and undo) with step-up, license-paused run, decision deadline, notice pending/failed, kept count, skipped locations | 10 |
| `deploymentsPage()` / `deploymentDetail(id)` | `DeploymentsPage`, `DeploymentDetailPage`, `DeploymentView`, `DeploymentSteps` | Table, outcome badges, detail header, outcome notice, OperationTimeline, operation details, evidence | 11 outcome states (succeeded verified/unverified/local/skipped, unchanged, failed, cancelled before sending, rolled back, pending change restored, rollback failed, recovering, held, finishing, stopped, unknown), recovery card, KV source, polling backoff | 11 |
| `auditPage()` | `pages/AuditPage.tsx` | Integrity notice, toolbar, table, details | Export CSV and JSON, details disclosure per row, verify result states (intact/broken), forwarding link | 12 |
| `licensePage()` | `pages/LicensePage.tsx` | License card, usage, renewal rules, history | Phases evaluation/grace/locked/expired, Installation ID, preview dialog, pending/duplicate/correction states, upload errors | 12 |
| `usersPage()` | `pages/UsersPage.tsx` ("People & access") | Role cards, people table | Manage dialog (edit, set password, revoke sessions, reset MFA), SSO users and provider names, last-admin protection errors | 13 |
| `tokensPage()` | `pages/TokensPage.tsx` | Notice, table | New token reveal once (`new-token`), SSO users note, auditor read-only scope, revoke dialog | 13 |
| `accountPage()` | `pages/AccountPage.tsx` ("Your account") | Profile panel + Appearance panel | Regenerate recovery codes (step-up, shown once), change password, SSO account (no password) | 13 |
| `settingsPage(tab)` | `pages/SettingsPage.tsx`, `components/settings/*`, `components/sso/*` | Vertical settings nav, panel per tab with design heading + description | Separate Recipients tab, SMTP untrusted certificate dialog, test e-mail, alert threshold rows, public URL, backups list/download/schedule/free space, HTTPS upload PEM/PFX + warnings, forwarding CA write-only, SSO providers/mappings/allow-admin, step-up on read | 14 |
| `loginPage()` | `pages/LoginPage.tsx` | Split auth layout, toggles, form styling | MFA code, recovery code, first-sign-in TOTP enrollment + recovery codes, session-ended notice, SSO errors (`sso-error`), rate limiting | 15 |
| `stepUp()` dialog | `components/StepUpProvider.tsx`, `AppModal.tsx` | Design dialog (head, content, actions bar) | SSO step-up variant ("Confirm at your identity provider") | 15 |
| `notFound()` / `deniedPage()` | `NotFoundPage`, `RouteErrorPage`, `RequireRole` no-access | EmptyState style | Render error with reload, no-access text `ui.noAccess` | 15 |
| `setupPage()` (7-step walkthrough) | `pages/SetupPage.tsx`, `pages/setup/*`, `TotpEnrollment`, `RecoveryCodes`, `LicenseUpload` | Setup shell, rail, step panel, actions | Language step, TOTP QR + manual key, one-time recovery codes, passphrase strength meter + server-side strength, HTTPS upload or keep temporary, mail save/test/skip, license upload preview or evaluation + Installation ID, platform key + optional add server, done/complete with step-up, Back and resume, gone (404) | 16 |
| `designSystemPage()` / `reviewPage()` | — (R22) | Not built | `docs/design-gaps.md` | 20 |
| Theme, tokens, density | `theme.ts`, `ThemeProvider.tsx`, `design/*` | Everything | Danger hover contrast, error color, scroll-region focus | 1, 17 |

## Label changes (the only deliberate breaks of the e2e contract)

All are made by Task 4 in the catalogs and in `web/e2e` in the same commit, except row 9 (Task 5).

| # | Key(s) | Before EN / TR | After EN / TR | Why | e2e places |
|---|---|---|---|---|---|
| 1 | `nav.dashboard`, `dashboard.title` | Dashboard / Pano | Overview / Genel bakış | design IA (`pageNames()`) | none by name |
| 2 | `dashboard.welcome` h1 | "Welcome, <name>" (h1) | removed; `<h1>` is `dashboard.title` | R10 | `helpers.ts:152,304,603`, `phase1.spec.ts:158,183`, `phase7.spec.ts:268,471,618,645,716` → new helper `expectSignedInAs(page, name)` = h1 `t('dashboard.title')` visible and `getByTestId('current-user')` has text `name` |
| 3 | `nav.users`, `users.title` | Users / Kullanıcılar | People & access / Kişiler ve erişim | design | `COPY.navUsers`, `COPY.usersHeading` (EN+TR) |
| 4 | `nav.audit`, `audit.title` | Audit log / Denetim kaydı | Audit trail / Denetim kaydı | design | `COPY.navAudit` EN |
| 5 | `nav.account`, `account.title` | My account / Hesabım | Your account / Hesabınız | design | `COPY.navAccount` EN+TR |
| 6 | `nav.deployments`, `deployments.title` | Deployment history / Dağıtım geçmişi | Deployments / Dağıtımlar | design | read through `t()`: none |
| 7 | language switch | SegmentedControl "English \| Türkçe" (`getByText(...).click()`) | toggle button named by the other language | R9 | `phase3.spec.ts:116`, `phase4.spec.ts:109`, `phase6.spec.ts:347` → `page.getByRole('button', { name: 'Türkçe', exact: true }).click()` (or `'English'`) |
| 8 | capitalized page references in `web/src/locales/*.json` values ("the Users page", "Audit log", "My account", "Dashboard", "Deployment history" used as page names) | old names | new names | consistency | none |
| 9 | Assurance tab | `backup-card`, `audit-head`, `license-card` on the dashboard | inside the Assurance tab (`?view=assurance`) | R10 | `phase8.spec.ts:348-352,373,383,396`: click `getByRole('tab', { name: t('dashboard.tabs.assurance') })` first (Task 5) |

## E2E contract (keep; condensed from `web/e2e`, read the specs for detail)

- Landmarks: one `main`; one `navigation` named `t('nav.label')` (unnamed `getByRole('navigation')` must stay unique); exactly one visible `<h1>` per page; no headings or links in the breadcrumb or sidebar group labels.
- Nav links: accessible name exactly the label (no counts, no badges in the link); page-wide link names stay unique.
- Sign out: a visible button named `nav.signOut` right after sign-in at 1280 px. `current-user` contains only the display name.
- Mobile at 640 px: nav off-canvas (`not.toBeInViewport`), buttons "Open navigation"/"Close navigation" with `aria-expanded`, a nav link click closes it, main stays clickable.
- Tab budget: ≤ 25 Tab presses from the dashboard to the People & access link; other budgets 60/80/6/4 in dialogs (do not add focusable elements before existing controls in those dialogs).
- `field()` = `getByLabel(/^<label>( \*)?$/)`: input labels are exactly the copy; descriptions are separate.
- Native selects (`NativeSelect`) for: certificate expiry and server filters, users Role, deploy certificate, SSH deploy server/user/file, target type and profile, SSO role, recipient language.
- Mantine specifics kept: `.mantine-Badge-root` in the rotation run's `role=status aria-live=polite` region, `data-invalid` on PasswordInput, Switch track (`click({force:true})`), dialog close X plus footer button with the same name (`.last()`).
- Tables: `targets-table` rows = 1 header + N; `target-keys` first cell = OS user; `backups-table` cell 1 = kind, cell 4 = check; `expiring-list`/`certificates-table` `tbody tr` with the name in the first `code`; audit rows contain their own `button[aria-expanded]`.
- Scroll region: `getByRole('group', { name: t('ui.scrollRegion') })`, `:focus-visible` outline `2px solid`, offset `-2px`, scrolls sideways at 375 px.
- Every `data-testid` listed in the e2e inventory is kept on the element with the same role and text (examples: `server-status`, `dashboard-counts`, `expiring-list`, `attention-list`, `setup-checklist`, `backup-card`, `license-banner-<kind>`, `notifications-banner`, `backup-alarm-banner`, `setup-banner`, `totp-secret`, `recovery-codes`, `passphrase-strength`, `https-keep-temporary`, `https-done`, `https-upload-form`, `setup-skip`, `setup-back`, `installation-id`, `platform-public-key`, `target-status`, `target-keys`, `host-key-changed`, `repin-new-fingerprint`, `blocked-jobs`, `vault-status`, `kv-version-row`, `held-text`, `binding-panel`, `deployment-row`, `deployment-status`, `deployment-state`, `recovery`, `ssh-keys-table`, `managed-key`, `key-locations`, `rotation-panel`, `run-location`, `run-counts`, `new-token`, `account-summary`, `license-phase`, `license-summary`, `license-installed`, `backups-table`, `backup-now`, `forwarding-form`, `forwarding-ca-set`, `https-temporary`, `sso-error`).
- Headings and texts the specs read through `t()` keep their keys; literal `COPY` strings in `helpers.ts` change only per the Label changes table.
- Existing empty-state texts (`targets.empty`, `targets.noKeys`, `vaults.empty`, `certificates.empty`, `deployments.empty`, `sshKeys.empty`, `tokens.empty`, `audit.empty`, `dashboard.noneExpiring`, `dashboard.noAttention`, `backups.empty`, `sso.noProviders`) keep their keys and appear verbatim, as the `EmptyState` title or description.

## File Structure

New (all under `web/` unless stated):

| Path | Responsibility | Task |
|---|---|---|
| `src/design/fonts/geist.woff`, `geist-mono.woff`, `OFL.txt` | Vendored Geist fonts and their license (copied byte for byte from `alice-design/dist/assets`) | 1 |
| `src/design/icons.ts`, `src/design/LUCIDE-LICENSE` | Generated Lucide icon data (76 icons) and its license | 1 |
| `src/design/Icon.tsx` (+ test) | `Icon` component: SVG from icon data, decorative (`aria-hidden`) | 1 |
| `src/design/tokens.css` (+ `tokens.test.ts`) | `--alice-*` tokens for light and dark, density, `@font-face` | 1 |
| `src/design/mantine.module.css` | Mantine component classes in the design's look (Alert, Badge, Button, Paper/Card, Code, Modal, Table, Tabs, Title, inputs) | 1 |
| `src/design/base.css` | Global rules: focus ring, selection, body smoothing | 1 |
| `src/design/THIRD_PARTY.json` | Manifest of vendored assets for `tools/notices -vendored` | 1 |
| `src/preferences.ts` (+ test) | Density preference (`alice.density`), color-scheme storage key | 1 |
| `public/theme-init.js` (+ `src/themeInit.test.ts`) | Pre-paint scheme and density from storage | 1 |
| `../tools/notices/vendored.go` (+ test) | `-vendored` manifest section in `THIRD_PARTY_NOTICES.md` | 2 |
| `src/components/ui/{PageHeader,Panel,ResourceTable,CursorFooter,StatusBadge,FactList,OperationTimeline,AttentionItem,EmptyState,Notice,MetricStrip,LinkTabs,DialogActions,AppearanceControl,ThemeToggle,LanguageToggle}.tsx`, `ui.module.css`, `status.ts`, `cx.ts`, `index.ts`, `ui.test.tsx`, `appearance.test.tsx`, `status.test.ts` | The design's shared building blocks | 3 |
| `src/layout/AppLayout.module.css`, `src/components/shell/{CommandPalette,AttentionBell}.tsx` (+ tests), `src/components/dashboard/conditions.ts` (+ test) | Shell styling, page palette, attention popover, the condition → item mapping shared with the dashboard | 4 |
| `src/pages/DashboardPage.module.css`, `src/components/dashboard/{ExpiryHorizon,TargetConnectivity,RecentDeployments,AssurancePanels}.tsx` (+ tests) | Overview panels | 5 |
| `src/pages/CertificateDetailPage.module.css`, `src/components/certificates/UsageTopology.tsx` (+ test) | Certificate detail layout and source → locations view | 6 |
| `src/pages/RotationsPage.tsx` (+ test), `src/pages/RotationsPage.module.css` | `/rotations` | 10 |
| `src/pages/LoginPage.module.css`, `src/components/auth/AuthLayout.tsx` (+ test) | Split sign-in layout | 15 |
| `src/pages/setup/SetupShell.tsx`, `SetupRail.tsx`, `setup.module.css` (+ tests) | Wizard shell and rail | 16 |
| `src/design/colorRules.test.ts` | Guard: no hard-coded color shades left | 17 |
| `e2e/phase9.spec.ts`, `e2e/design-evidence.spec.ts` | Axe on every route (both schemes and languages) and the screenshot evidence | 18, 19 |
| `../docs/design-gaps.md` | Every gap and how it was filled | 20 |

Modified: `src/theme.ts`, `src/theme.test.ts`, `src/theme.css`, `src/ThemeProvider.tsx`, `src/main.tsx`, `index.html`, `src/test/render.tsx`, `src/test/setup.ts` (1); `src/layout/AppLayout.tsx` (+ test), `src/components/{BackupBanner,LicenseBanners,NotificationsBanner}.tsx`, `src/pages/DashboardPage.tsx` (h1 only), `src/locales/*.json`, `e2e/helpers.ts`, `e2e/phase1.spec.ts`, `phase3.spec.ts`, `phase4.spec.ts`, `phase6.spec.ts`, `phase7.spec.ts` (4); each page and its components in Tasks 5–16; `Makefile` `notices` line (2), `Makefile` `e2e-design-evidence` target (19); `docs/*.md` label references, `CHANGELOG.md` (20).

## Task index and schedule

1. Design foundation: vendored fonts and icons, tokens, the scheme-aware Mantine theme, density and color-mode preferences, pre-paint script, test providers — **no Docker**
2. Third-party notices for the vendored fonts and icons (`tools/notices -vendored`) — **no Docker**
3. Shared UI components (PageHeader, Panel, ResourceTable, CursorFooter, StatusBadge, FactList, OperationTimeline, AttentionItem, EmptyState, Notice, MetricStrip, LinkTabs, DialogActions, AppearanceControl, ThemeToggle, LanguageToggle) — **no Docker**
4. Application shell, navigation groups, command palette, attention bell, banners, footer; the label changes and their e2e edits — **no Docker** (edits e2e)
5. Overview (dashboard) with Operations and Assurance — **no Docker** (edits `phase8.spec.ts` only)
6. Certificates list and detail — **no Docker**
7. Servers list and detail — **no Docker**
8. Key Vaults list, detail and Key Vault certificate — **no Docker**
9. SSH keys list and detail (with the rotation policy panel) — **no Docker**
10. Key rotations page (`/rotations`) and the rotation run page — **no Docker**
11. Deployments list and detail (outcomes and the operation timeline) — **no Docker**
12. Audit trail and License — **no Docker**
13. People & access, API tokens, Your account (Appearance) — **no Docker**
14. Settings (eight tabs, vertical navigation) and SSO settings — **no Docker**
15. Sign-in, MFA, first-sign-in enrollment, step-up dialog, not-found and error pages — **no Docker**
16. First-run wizard in the design's setup shell — **no Docker**
17. Dark-mode sweep and the color-rule guard — **no Docker**
18. Responsive and accessibility sweep with Playwright (`phase9.spec.ts`), full Chromium suite — **Docker alone**
19. Three-browser suite and the visual evidence (screenshots of every primary route, light/dark, EN/TR, 1440/1024/768/390; not committed) — **Docker alone**
20. Documentation: `docs/design-gaps.md`, UI label references in the guides, appearance section, CHANGELOG; final coverage and build — **no Docker**

**Schedule (at most three agents at once; tasks that share files are in different waves):**

| Wave | Agent A | Agent B | Agent C | Docker |
|---|---|---|---|---|
| 1 | Task 1 (`web/src/design/*`, `theme*`, `ThemeProvider.tsx`, `main.tsx`, `index.html`, `public/theme-init.js`, `preferences.ts`, `test/render.tsx`, `test/setup.ts`) | Task 2 (`tools/notices`, `Makefile` `notices` line) | — | none |
| 2 | Task 3 (`web/src/components/ui/*`, locale lock for `ui.*`/`appearance.*`) | — | — | none |
| 3 | Task 4 (`layout/*`, `components/shell/*`, `components/dashboard/conditions.ts`, banners, `DashboardPage.tsx` h1 line, `LanguageSwitcher.tsx`, `web/e2e/*`) | Task 15 (`LoginPage`, `components/auth/*`, `StepUpProvider`, `AppModal`, `TotpEnrollment`, `RecoveryCodes`, `SSOErrorAlert`, `NotFoundPage`, `RouteErrorPage`, `auth/guards.tsx` no-access view) | Task 16 (`SetupPage`, `pages/setup/*`, `LicenseUpload`) — uses Task 15's `TotpEnrollment`/`RecoveryCodes` as they are on disk; restyles only its own files | none |
| 4 | Task 5 (`DashboardPage*`, `components/dashboard/*` except `conditions.ts`, `e2e/phase8.spec.ts`) | Task 6 (`Certificates*`, `CertificateDetail*`, `PendingCSRs`, `SavedViews`, `ExportButton`, `UploadCertificateDialog`, `CreateCSRDialog`, `CSRPem`, `DeployDialog`, `ImportHistory`, `ImportToKeyVaultDialog`, `UploadWarnings`, `Expiry`, `components/certificates/*`) | Task 7 (`Targets*`, `TargetDetail*`, `AddServerModal`, `HostKeyConfirm`, `BlockedJobsPanel`, `PlatformKeyPanel`, `WebsitesPanel`, `LocationSettingsDialog`, `LocationWarning`, `TargetStatusBadge`, `JobErrorAlert`, `RemoveKeyDialog`, `KeyFlags`) | none |
| 5 | Task 8 (`KeyVault*`, `KVCertificatePage*`, `VaultInventory`, `VaultStatusBadge`, `AccessCheckPanel`, `AddKeyVaultDialog`, `ReplaceCredentialsDialog`, `BindingPanel`, `ConnectWebsitesDialog`, `KVDeployDialog`, `AutoDeploySwitch`, `RoleGuide`, `SignInFields`) | Task 9 (`SSHKeys*`, `SSHKeyDetail*`, `RotationPolicyPanel`, `RotationPolicyDialog`, `RotationPreviewDialog`, `GenerateKeyDialog`, `DeployKeyDialog`, `DownloadKeyDialog`) | Task 11 (`Deployments*`, `DeploymentDetail*`, `DeploymentView`, `DeploymentSteps`, `LabelledCode`, `CodeText`) | none |
| 6 | Task 10 (`RotationsPage*`, `RotationRunPage*`, `rotationText.tsx`, `api/rotation.ts` `listPolicies`, `router.tsx`, `NAV_ITEMS` line in `AppLayout.tsx`, `test/screens.ts` under the lock) | Task 12 (`AuditPage*`, `LicensePage*`) | Task 13 (`UsersPage*`, `TokensPage*`, `AccountPage*`) | none |
| 7 | Task 14 (`SettingsPage*`, `components/settings/*`, `components/sso/*`) | — | — | none |
| 8 | Task 17 (any file with a remaining hard-coded color; `eslint.config.js`; `theme.ts`) | — | — | none |
| 9 | Task 18 | — | — | **Docker alone** (Playwright) |
| 10 | Task 19 | Task 20 (docs only; no `make lint`, no Docker) | — | **Docker alone** for Task 19 |

Dependencies: 3 needs 1; 4–16 need 3 (and 1); 5 needs 4 (`conditions.ts`, the h1 change); 10 needs 4 (`NAV_ITEMS`) and 9 (`LinkTabs` on the SSH keys page); 17 needs 4–16; 18 needs 17; 19 needs 18; 20 needs the reports of 1–19. Locale files and `test/screens.ts` are shared through the lock (Global Constraints). Recommended execution: subagent-driven, one reviewer per task; Tasks 4 and 16 get an additional security-minded reviewer (role-filtered shell, wizard checks).

## Cross-task contract

### C1. Tokens (`web/src/design/tokens.css`, Task 1)

The design's `tokens.css` values, prefixed `--alice-`, keyed on Mantine's scheme attribute, plus the hover and `on-strong` tokens filled buttons need (R3). Exact file:

```css
/* The Clarity design's semantic tokens (alice-design/dist/tokens.css), for the light and the dark scheme. Mantine sets
   data-mantine-color-scheme on <html>; public/theme-init.js sets it before the app runs. Components read only these
   variables (and Mantine's, which theme.ts maps onto them): never a hex value or a palette shade. */
@font-face {
  font-family: 'Geist';
  src: url('./fonts/geist.woff') format('woff');
  font-style: normal;
  font-weight: 100 900;
  font-display: swap;
}
@font-face {
  font-family: 'Geist Mono';
  src: url('./fonts/geist-mono.woff') format('woff');
  font-style: normal;
  font-weight: 100 900;
  font-display: swap;
}
:root,
:root[data-mantine-color-scheme='light'] {
  color-scheme: light;
  --alice-canvas: #f6f7f5;
  --alice-surface: #ffffff;
  --alice-surface-raised: #ffffff;
  --alice-surface-subtle: #f0f3ef;
  --alice-surface-hover: #f0f5f1;
  --alice-text: #1b2b27;
  --alice-text-secondary: #53645e;
  --alice-text-muted: #5d6d64;
  --alice-border: #dce3dc;
  --alice-border-strong: #7e9184;
  --alice-brand: #145f50;
  --alice-brand-hover: #104c40;
  --alice-on-brand: #ffffff;
  --alice-brand-soft: #e9f2ed;
  --alice-brand-line: #a7c9b9;
  --alice-success: #216447;
  --alice-success-hover: #1a5038;
  --alice-success-soft: #eaf5ee;
  --alice-warning: #8b4b0b;
  --alice-warning-hover: #6e3b08;
  --alice-warning-soft: #fff3df;
  --alice-danger: #b03939;
  --alice-danger-hover: #8f2c2c;
  --alice-danger-soft: #fff0ef;
  --alice-info: #305eb1;
  --alice-info-hover: #264b8e;
  --alice-info-soft: #edf2fc;
  --alice-neutral: #53645e;
  --alice-neutral-hover: #43534d;
  --alice-neutral-soft: #f0f3ef;
  --alice-on-strong: #ffffff;
  --alice-accent: #d9eea1;
  --alice-on-accent: #29472d;
  --alice-chart: #4b9077;
  --alice-chart-muted: #bbd4c6;
  --alice-chart-urgent: #d39750;
  --alice-chart-expired: #c36a65;
  --alice-shadow: 0 6px 24px #18392b08;
  --alice-overlay: #0719117a;
  --alice-focus: #2563b0;
  --alice-auth-brand-bg: #163b30;
  --alice-auth-brand-text: #edf3e9;
  --alice-auth-brand-muted: #bfd1c4;
  --alice-auth-brand-line: #476b5838;
}
:root[data-mantine-color-scheme='dark'] {
  color-scheme: dark;
  --alice-canvas: #111816;
  --alice-surface: #19221e;
  --alice-surface-raised: #202c25;
  --alice-surface-subtle: #202c25;
  --alice-surface-hover: #24352b;
  --alice-text: #e8eee8;
  --alice-text-secondary: #b3c1b6;
  --alice-text-muted: #9cae9f;
  --alice-border: #34473b;
  --alice-border-strong: #697e70;
  --alice-brand: #9cd7b5;
  --alice-brand-hover: #b6e6ca;
  --alice-on-brand: #13291d;
  --alice-brand-soft: #263e30;
  --alice-brand-line: #507e62;
  --alice-success: #9ed9b6;
  --alice-success-hover: #b8e6ca;
  --alice-success-soft: #233e2e;
  --alice-warning: #f0c07e;
  --alice-warning-hover: #f4d09e;
  --alice-warning-soft: #3a3021;
  --alice-danger: #f2a2a0;
  --alice-danger-hover: #f6bab8;
  --alice-danger-soft: #402a2a;
  --alice-info: #adc7ff;
  --alice-info-hover: #c5d7ff;
  --alice-info-soft: #283549;
  --alice-neutral: #b3c1b6;
  --alice-neutral-hover: #c9d4cb;
  --alice-neutral-soft: #202c25;
  --alice-on-strong: #13291d;
  --alice-chart: #83bb9c;
  --alice-chart-muted: #466452;
  --alice-shadow: 0 6px 24px #00000012;
  --alice-overlay: #020805b8;
  --alice-focus: #99bcff;
}
:root {
  --alice-radius-sm: 6px;
  --alice-radius-md: 10px;
  --alice-radius-lg: 14px;
  --alice-radius-xl: 20px;
  --alice-sidebar: 222px;
  --alice-header: 65px;
  --alice-row-height: 67px;
  --alice-duration: 160ms;
}
:root[data-density='compact'] {
  --alice-row-height: 48px;
}
@media (max-width: 1199px) {
  :root {
    --alice-sidebar: 202px;
  }
}
@media (prefers-reduced-motion: reduce) {
  :root {
    --alice-duration: 0ms;
  }
}
```

Tone names used everywhere: `brand`, `success`, `warning`, `danger`, `info`, `neutral` (each has `--alice-<tone>`, `-hover`, `-soft`).

### C2. Theme (`web/src/theme.ts`, Task 1)

Exports (other tasks import these names): `SCROLL_REGION_CLASS` (unchanged `'alice-scroll-region'`), `type Tone`, `toneOf(color?: string): Tone`, `TONE_COLOR: Record<Tone, string>` (the Mantine color name per tone: brand `forest`, success `green`, warning `yellow`, danger `red`, info `blue`, neutral `gray`), `variantColorResolver`, `cssVariablesResolver`, `appTheme(scrollRegionLabel: string): MantineThemeOverride`. `DANGER_HOVER` is removed (the danger tone has `--alice-danger-hover`). Exact code is in Task 1.

### C3. Preferences, provider and pre-paint (Task 1)

- `web/src/preferences.ts`: `COLOR_SCHEME_KEY = 'alice.colorScheme'`, `DENSITY_KEY = 'alice.density'`, `type Density = 'comfortable' | 'compact'`, `readDensity(): Density`, `applyDensity(d: Density): void` (sets `document.documentElement.dataset.density`), `saveDensity(d: Density): void`, `useDensity(): [Density, (d: Density) => void]`.
- `ThemeProvider`: `MantineProvider` with `theme`, `cssVariablesResolver`, `getStyleNonce={readCspNonce}`, `colorSchemeManager={localStorageColorSchemeManager({ key: COLOR_SCHEME_KEY })}`, `defaultColorScheme="auto"`.
- `web/public/theme-init.js` loaded by `<script src="/theme-init.js"></script>` in `index.html` `<head>`.
- Color mode in components: `useMantineColorScheme()` (`'light' | 'dark' | 'auto'`) and `useComputedColorScheme('light')`.

### C4. Icons (Task 1)

`import { Icon, type IconName } from '../design/Icon'` — `<Icon name="ShieldCheck" size={18} className?={…} />`. Always decorative (`aria-hidden="true"`, `focusable="false"`); the text next to it carries the meaning. `IconName` is the union of the 76 names in `alice-design/dist/icons.js` (there is no `X`: use `CircleX`; no `Sun`/`Moon` substitutes needed — both exist).

### C5. Shared UI components (`web/src/components/ui`, Task 3; import from `../components/ui` via `index.ts`)

```ts
export interface PageHeaderProps {
  title: ReactNode;               // rendered as the page's only <h1>
  description?: ReactNode;
  eyebrow?: ReactNode;            // uppercase via CSS, mono, muted
  actions?: ReactNode;            // buttons, right-aligned; wraps under the title below 1020 px
  back?: { to: string; label: string };
  icon?: IconName;                // detail pages: the resource tile left of the title
  status?: ReactNode;             // a StatusBadge next to the title (callers keep their own live region)
}
export interface PanelProps {
  title?: ReactNode; description?: ReactNode; action?: ReactNode; footer?: ReactNode;
  children: ReactNode; padded?: boolean /* default true */; headingOrder?: 2 | 3 /* default 2 */;
  testId?: string; className?: string; 'aria-label'?: string;  // aria-label makes it a named region: only where a test or a screen reader needs one
}
export interface ResourceTableProps {
  label: string; minWidth?: number /* default 640 */; toolbar?: ReactNode; footer?: ReactNode;
  testId?: string /* on <table> */; striped?: boolean; children: ReactNode /* Table.Thead + Table.Tbody */;
}
export interface CursorFooterProps { shown: number; hasMore: boolean; loading: boolean; onMore: () => void; moreLabel: string }
export type Tone = 'brand' | 'success' | 'warning' | 'danger' | 'info' | 'neutral';   // re-exported from theme.ts
export interface StatusBadgeProps { tone: Tone; icon?: IconName; children: ReactNode; testId?: string; size?: 'sm' | 'md' | 'lg' }
  // plus any data-* / aria-* attribute, passed to the Mantine Badge root
export interface Fact { label: ReactNode; value: ReactNode; testId?: string; key?: string }
export interface FactListProps { facts: Fact[]; label?: string }
export type StepState = 'done' | 'failed' | 'running' | 'waiting' | 'skipped' | 'notRun' | 'unknown';
export interface TimelineStep { id: string; title: ReactNode; detail?: ReactNode; state: StepState; stateLabel: string; time?: ReactNode; dataAttrs?: Record<string, string> }
export interface OperationTimelineProps { steps: TimelineStep[]; label: string }
export interface AttentionItemProps { tone: 'warning' | 'danger' | 'info'; icon: IconName; title: ReactNode; detail?: ReactNode; meta?: ReactNode; to?: string; onClick?: () => void; testId?: string }
export interface EmptyStateProps { title: ReactNode; description?: ReactNode; action?: ReactNode; icon?: IconName /* default 'Search' */; testId?: string }
export interface NoticeProps { tone: Tone; title: ReactNode; children?: ReactNode; action?: ReactNode; role?: 'alert' | 'status'; testId?: string }
export interface Metric { label: ReactNode; value: ReactNode; foot?: ReactNode; icon: IconName; to?: string; tone?: 'warning' | 'danger'; testId?: string }
export interface MetricStripProps { items: Metric[]; label: string }
export interface LinkTab { to: string; label: ReactNode; match?: string[] }
export interface LinkTabsProps { items: LinkTab[]; label: string }   // a <div role="group" aria-label> of links, aria-current="page" on the active one
export interface DialogActionsProps { children: ReactNode; note?: ReactNode }   // the design's dialog footer bar
export interface AppearanceControlProps { signedIn: boolean }       // color mode cards, compact tables switch, language select
export function ThemeToggle(): JSX.Element                           // ActionIcon, aria-label t('appearance.toggle')
export function LanguageToggle(props: { signedIn: boolean }): JSX.Element   // R9
export function cx(...names: (string | false | null | undefined)[]): string
```

Tone helpers (`components/ui/status.ts`): `TARGET_TONE: Record<TargetStatus, Tone>` (ok success, checking info, degraded warning, pending_host_key warning, unreachable warning, host_key_changed danger, auth_failed danger, disabled neutral), `TARGET_ICON: Partial<Record<TargetStatus, IconName>>` (host_key_changed Fingerprint, unreachable Unplug, auth_failed ShieldAlert, checking RefreshCw, ok CircleCheck), `deploymentTone(d: Pick<Deployment,'status'|'error'>): Tone` (succeeded success; unchanged neutral; pending/running info; rolled_back/needs_attention warning; failed/rollback_failed danger; cancelled neutral), `expiryTone(state: ExpiryState): Tone` (expired danger, within30 warning, within60 info, ok success), `expiryIcon(state): IconName` (expired CircleAlert, otherwise Clock3).

### C6. Conditions (`web/src/components/dashboard/conditions.ts`, Task 4)

Moved out of `AttentionList.tsx` unchanged in meaning: `conditionTarget(c: Condition, vaultIds: ReadonlySet<string>): string | null`, `conditionLabel(c: Condition, t: TFunction): string | null`, plus `CONDITION_ICON: Record<string, IconName>` (host_key_changed Fingerprint, auth_failed ShieldAlert, deployment_failed Rocket, audit_broken ScrollText, notifications_failing Mail), `conditionTone(c): 'danger' | 'warning'` (host_key_changed, auth_failed, audit_broken danger; others warning) and the hook `useConditionItems(items: Condition[]): { key: string; tone; icon; title: string; name: string; since: string; to: string | null }[]` (reads the vaults only when an `auth_failed` item is listed, exactly as today). Used by the dashboard (Task 5) and the bell (Task 4).

### C7. Shell (Task 4)

`NAV_ITEMS` gains `icon: IconName`, `group: 'none' | 'inventory' | 'operations' | 'administration'` and optional `match?: string[]` (extra path prefixes that mark the item active). Order: Overview; Certificates, SSH keys, Servers, Key Vaults; Deployments, (Key rotations — Task 10), Audit trail; People & access, Settings, License. `ACCOUNT_ITEMS`: Your account (`/account`), API tokens (`/tokens`). Roles unchanged. Group label keys: `nav.groups.inventory|operations|administration`. Breadcrumb key `shell.workspace`. Footer `shell.footer` ("Self-hosted · Alice {{version}}"). The `<main>` has `id="main"` and `tabIndex={-1}`; the skip link `shell.skip` targets it.

### C8. Test helpers (Task 1)

`renderApp(ui, languages?, opts?: { colorScheme?: 'light' | 'dark' })`, `renderRoute(path, { languages?, strict?, colorScheme? })`, `renderWithAuth`, `renderWithStepUp` keep their signatures and render inside the **app** theme (`appTheme`, `cssVariablesResolver`, `forceColorScheme` when `colorScheme` is given). `src/test/setup.ts` keeps `matchMedia` returning `matches: false` and clears `alice.colorScheme`/`alice.density` with the rest of `localStorage` and removes `data-density` from `<html>` before each test.

### C9. Translation namespaces (who adds which keys)

Existing keys keep their names. New keys only in these namespaces, each owned by one task (others read them): `ui.table.*`, `ui.empty.*`, `appearance.*` (Task 3); `shell.*`, `nav.groups.*`, `nav.rotations` (value only; Task 10 adds the item), and the Label changes values (Task 4); `dashboard.tabs.*`, `dashboard.metrics.*`, `dashboard.horizon.*`, `dashboard.panels.*`, `dashboard.assurance.*`, `dashboard.description` (Task 5); `certificates.page.*` (6); `targets.page.*` (7); `vaults.page.*` (8); `sshKeys.page.*` (9); `rotation.page.*` (10); `deployments.page.*` (11); `audit.page.*`, `license.page.*` (12); `users.page.*`, `tokens.page.*`, `account.page.*` (13); `settings.page.*` (14); `login.brand.*`, `login.mfaNote` (15); `setup.rail.*`, `setup.shell.*` (16). TR values come from the design where it has them; otherwise formal Turkish in the catalog's terminology.

### C10. Kept names and controls

Everything in "E2E contract" plus: the `ErrorAlert`, `JobErrorAlert`, `DeploymentErrorAlert`, `StillWorkingAlert`, `BlockedJobAlert`, `StoppedJobAlert`, `DeploymentStatusBadge`, `DeploymentOutcome`, `TargetStatusBadge`, `VaultStatusBadge`, `Expiry`, `KeyFlags`, `SavedViews`, `ExportButton`, `AppModal`, `LoadingIndicator`, `PageLoader`, `Widget` exports keep their names and props (their internals may change); `useUrlFilters`, `useDebouncedParam`, query keys, `api/*` functions are not changed except Task 10's added `listPolicies`.

---

### Task 1: Design foundation: vendored fonts and icons, tokens, the scheme-aware Mantine theme, density and color-mode preferences, pre-paint script, test providers

**Design source:** `alice-design/dist/tokens.css`, `styles.css` lines for `body`, `h1–h3`, `code`, `:focus-visible`, `.btn`, `.pill`, `.panel`, `.data-table`, `.tabs`, `dialog`, `.field`, `.status-line`; `theme-init.js`; `guide.js` `tokens` (typography, radius, motion); `IMPLEMENTATION.md` §1.

**Files:**
- Create: `web/src/design/fonts/geist.woff`, `web/src/design/fonts/geist-mono.woff`, `web/src/design/fonts/OFL.txt`, `web/src/design/LUCIDE-LICENSE`, `web/src/design/icons.ts`, `web/src/design/Icon.tsx`, `web/src/design/Icon.test.tsx`, `web/src/design/tokens.css`, `web/src/design/tokens.test.ts`, `web/src/design/mantine.module.css`, `web/src/design/base.css`, `web/src/design/THIRD_PARTY.json`, `web/src/preferences.ts`, `web/src/preferences.test.ts`, `web/public/theme-init.js`, `web/src/themeInit.test.ts`
- Modify: `web/src/theme.ts`, `web/src/theme.test.ts`, `web/src/theme.css`, `web/src/ThemeProvider.tsx`, `web/src/main.tsx`, `web/index.html`, `web/src/test/render.tsx`, `web/src/test/setup.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces: C1, C2, C3, C4, C8 exactly.

- [ ] **Step 1: Vendor the assets**

```bash
cd /home/meren/projects/alice-secrets
mkdir -p web/src/design/fonts
cp alice-design/dist/assets/geist.woff alice-design/dist/assets/geist-mono.woff alice-design/dist/assets/OFL.txt web/src/design/fonts/
cp alice-design/dist/assets/LUCIDE-LICENSE web/src/design/LUCIDE-LICENSE
{ printf '%s\n' '// Lucide icons (ISC license: LUCIDE-LICENSE beside this file): the subset the Clarity design uses, generated from' \
                '// alice-design/dist/icons.js by Task 1 of docs/superpowers/plans/2026-10-12-phase-9-design.md. Do not edit by hand.' \
                '// Each icon is a list of [SVG element, attributes] drawn on a 24 x 24 grid with stroke="currentColor".';
  sed -e 's/^export const icons = /export const ICONS = /' \
      -e 's/};$/} as const satisfies Record<string, readonly (readonly [string, Readonly<Record<string, string>>])[]>;/' alice-design/dist/icons.js;
  printf '\n%s\n' 'export type IconName = keyof typeof ICONS;'; } > web/src/design/icons.ts
cmp alice-design/dist/assets/geist.woff web/src/design/fonts/geist.woff && grep -c '"ShieldCheck"' web/src/design/icons.ts
```

Expected: no `cmp` output, then `1`.

`web/src/design/THIRD_PARTY.json` (read by Task 2's `tools/notices -vendored`):

```json
[
  {
    "name": "Geist and Geist Mono",
    "source": "https://github.com/vercel/geist-font",
    "license": "OFL-1.1",
    "files": ["web/src/design/fonts/geist.woff", "web/src/design/fonts/geist-mono.woff"],
    "licenseFile": "web/src/design/fonts/OFL.txt"
  },
  {
    "name": "Lucide icons (subset)",
    "source": "https://lucide.dev",
    "license": "ISC",
    "files": ["web/src/design/icons.ts"],
    "licenseFile": "web/src/design/LUCIDE-LICENSE"
  }
]
```

- [ ] **Step 2: Write the failing tests**

`web/src/design/tokens.test.ts` — parses `tokens.css` and checks every text/background pair of both schemes (the pairs of `alice-design/validation-report.json` plus the ones the theme creates):

```ts
import { readFileSync } from 'node:fs';

const css = readFileSync('src/design/tokens.css', 'utf8');

// tokensOf reads the custom properties of the first rule whose selector list contains selector.
function tokensOf(selector: string): Record<string, string> {
  const rule = [...css.matchAll(/([^{}]+)\{([^}]*)\}/g)].find(([, sel]) => sel.split(',').map((s) => s.trim()).includes(selector));
  if (!rule) throw new Error(`no rule for ${selector}`);
  return Object.fromEntries([...rule[2].matchAll(/--alice-([a-z-]+):\s*(#[0-9a-f]{6})\b/g)].map(([, k, v]) => [k, v]));
}

function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}
// mix is CSS color-mix(in srgb, a p%, b): the light variants' hover background (theme.ts).
function mix(a: string, b: string, p: number): string {
  const ch = (h: string, i: number) => parseInt(h.slice(i, i + 2), 16);
  return '#' + [1, 3, 5].map((i) => Math.round(ch(a, i) * p + ch(b, i) * (1 - p)).toString(16).padStart(2, '0')).join('');
}

const TONES = ['success', 'warning', 'danger', 'info', 'neutral'] as const;
const TEXT_PAIRS: [string, string][] = [
  ['text', 'canvas'], ['text', 'surface'], ['text', 'surface-hover'],
  ['text-secondary', 'surface'], ['text-secondary', 'canvas'], ['text-secondary', 'surface-subtle'],
  ['text-muted', 'canvas'], ['text-muted', 'surface'], ['text-muted', 'surface-subtle'],
  ['on-brand', 'brand'], ['on-brand', 'brand-hover'], ['brand', 'brand-soft'], ['brand', 'surface'], ['brand', 'canvas'], ['brand', 'surface-hover'],
  ...TONES.flatMap((t): [string, string][] => [[t, `${t}-soft`], ['on-strong', t], ['on-strong', `${t}-hover`], [t, 'surface']]),
];

describe.each([
  ['light', ':root[data-mantine-color-scheme=\'light\']'],
  ['dark', ':root[data-mantine-color-scheme=\'dark\']'],
])('the %s scheme', (_name, selector) => {
  const light = tokensOf(':root[data-mantine-color-scheme=\'light\']');
  const tokens = { ...light, ...tokensOf(selector) };

  it.each(TEXT_PAIRS)('%s on %s reaches 4.5:1', (fg, bg) => {
    expect(contrast(tokens[fg], tokens[bg])).toBeGreaterThanOrEqual(4.5);
  });

  it.each(TONES)('%s text stays at 4.5:1 on its hovered light variant', (t) => {
    expect(contrast(tokens[t], mix(tokens[t], tokens[`${t}-soft`], 0.1))).toBeGreaterThanOrEqual(4.5);
  });

  it('draws field borders and the focus ring at 3:1 (non-text contrast)', () => {
    for (const bg of ['surface', 'canvas']) {
      expect(contrast(tokens['border-strong'], tokens[bg])).toBeGreaterThanOrEqual(3);
      expect(contrast(tokens.focus, tokens[bg])).toBeGreaterThanOrEqual(3);
    }
  });
});

it('has the same token names in both schemes and a compact density row', () => {
  const light = Object.keys(tokensOf(':root[data-mantine-color-scheme=\'light\']')).sort();
  const dark = Object.keys(tokensOf(':root[data-mantine-color-scheme=\'dark\']'));
  for (const k of dark) expect(light).toContain(k);
  for (const k of ['canvas', 'surface', 'text', 'brand', 'danger', 'focus', 'on-strong']) expect(dark).toContain(k);
  expect(css).toMatch(/:root\[data-density='compact'\]\s*\{\s*--alice-row-height:\s*48px;/);
  expect(css).not.toMatch(/https?:\/\//); // fonts are local (CSP font-src 'self', offline installations)
});
```

`web/src/design/Icon.test.tsx`:

```tsx
import { render } from '@testing-library/react';
import { Icon } from './Icon';
import { ICONS } from './icons';

describe('Icon', () => {
  it('draws the icon from its data, hidden from assistive technology', () => {
    const { container } = render(<Icon name="ShieldCheck" size={16} className="x" />);
    const svg = container.querySelector('svg')!;
    expect(svg).toHaveAttribute('aria-hidden', 'true');
    expect(svg).toHaveAttribute('focusable', 'false');
    expect(svg).toHaveAttribute('width', '16');
    expect(svg).toHaveAttribute('stroke', 'currentColor');
    expect(svg).toHaveClass('x');
    expect(svg.children).toHaveLength(ICONS.ShieldCheck.length);
  });
  it('carries the 76 icons of the design and nothing that needs innerHTML', () => {
    expect(Object.keys(ICONS)).toHaveLength(76);
    for (const parts of Object.values(ICONS)) for (const [tag] of parts) expect(['path', 'circle', 'rect', 'line', 'ellipse', 'polyline', 'polygon']).toContain(tag);
  });
});
```

`web/src/preferences.test.ts`:

```ts
import { act, renderHook } from '@testing-library/react';
import { DENSITY_KEY, applyDensity, readDensity, saveDensity, useDensity } from './preferences';

describe('density preference', () => {
  it('defaults to comfortable and remembers compact on this device', () => {
    expect(readDensity()).toBe('comfortable');
    saveDensity('compact');
    expect(localStorage.getItem(DENSITY_KEY)).toBe('compact');
    expect(document.documentElement.dataset.density).toBe('compact');
    expect(readDensity()).toBe('compact');
  });
  it('ignores an unknown stored value', () => {
    localStorage.setItem(DENSITY_KEY, 'tiny');
    expect(readDensity()).toBe('comfortable');
  });
  it('still applies the choice when storage is blocked (private window, policy)', () => {
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new DOMException('blocked'); });
    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new DOMException('blocked'); });
    expect(readDensity()).toBe('comfortable');
    expect(() => saveDensity('compact')).not.toThrow();
    expect(document.documentElement.dataset.density).toBe('compact');
    set.mockRestore();
    get.mockRestore();
  });
  it('useDensity updates the page and the hook state', () => {
    applyDensity('comfortable');
    const { result } = renderHook(() => useDensity());
    act(() => result.current[1]('compact'));
    expect(result.current[0]).toBe('compact');
    expect(document.documentElement.dataset.density).toBe('compact');
  });
});
```

`web/src/themeInit.test.ts` — runs the real `public/theme-init.js` in jsdom:

```ts
import { readFileSync } from 'node:fs';

const source = readFileSync('public/theme-init.js', 'utf8');
const run = () => new Function(source)();
const root = document.documentElement;

function media(dark: boolean) {
  window.matchMedia = ((q: string) => ({ matches: dark && q.includes('dark'), media: q, addEventListener() {}, removeEventListener() {} })) as unknown as typeof window.matchMedia;
}

describe('theme-init.js (runs before the app, CSP script-src self)', () => {
  const original = window.matchMedia;
  afterEach(() => {
    window.matchMedia = original;
    root.removeAttribute('data-mantine-color-scheme');
    root.removeAttribute('data-density');
  });
  it('follows the system when nothing is stored', () => {
    media(true);
    run();
    expect(root.getAttribute('data-mantine-color-scheme')).toBe('dark');
  });
  it('follows the system for the stored "auto"', () => {
    media(false);
    localStorage.setItem('alice.colorScheme', 'auto');
    run();
    expect(root.getAttribute('data-mantine-color-scheme')).toBe('light');
  });
  it('applies a stored explicit scheme and compact density', () => {
    media(false);
    localStorage.setItem('alice.colorScheme', 'dark');
    localStorage.setItem('alice.density', 'compact');
    run();
    expect(root.getAttribute('data-mantine-color-scheme')).toBe('dark');
    expect(root.getAttribute('data-density')).toBe('compact');
  });
  it('never throws when storage is blocked', () => {
    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new DOMException('blocked'); });
    expect(run).not.toThrow();
    get.mockRestore();
  });
  it('is loaded from index.html as a same-origin script, not inline', () => {
    expect(readFileSync('index.html', 'utf8')).toMatch(/<script src="\/theme-init\.js"><\/script>/);
    expect(source).not.toMatch(/innerHTML|document\.write|eval\(/);
  });
});
```

Rewrite `web/src/theme.test.ts`: keep the scroll-region tests (`makes the scrolling part…`, `names the region in the language of the app` — its error-color line becomes `/--mantine-color-error:\s*var\(--alice-danger\)/`), keep `relies on Mantine drawing the field message … from that variable`, change the focus-ring assertion to `outline:\s*2px solid var\(--alice-focus\)` with `outline-offset:\s*-2px`, and replace the red/indigo tests with:

```ts
import { DEFAULT_THEME, mergeMantineTheme } from '@mantine/core';
import { TONE_COLOR, appTheme, cssVariablesResolver, toneOf, variantColorResolver } from './theme';

const full = mergeMantineTheme(DEFAULT_THEME, appTheme('Table, scrolls sideways'));

describe('semantic colors', () => {
  it('maps Mantine colors, with or without a shade, to the design tones', () => {
    expect(toneOf('red.9')).toBe('danger');
    expect(toneOf('yellow')).toBe('warning');
    expect(toneOf('orange')).toBe('warning');
    expect(toneOf('green')).toBe('success');
    expect(toneOf('teal.9')).toBe('success');
    expect(toneOf('blue')).toBe('info');
    expect(toneOf('gray')).toBe('neutral');
    expect(toneOf('indigo')).toBe('brand');
    expect(toneOf(undefined)).toBe('brand');
    expect(TONE_COLOR.danger).toBe('red');
  });
  it('draws light and subtle variants with the tone on its soft background, never black text', () => {
    const light = variantColorResolver({ color: 'yellow', theme: full, variant: 'light' });
    expect(light.background).toBe('var(--alice-warning-soft)');
    expect(light.color).toBe('var(--alice-warning)');
    expect(JSON.stringify(light)).not.toContain('black');
    expect(variantColorResolver({ color: 'red', theme: full, variant: 'subtle' }).color).toBe('var(--alice-danger)');
  });
  it('fills buttons with the strong tone and its readable foreground, hovering the hover token', () => {
    const danger = variantColorResolver({ color: 'red.9', theme: full, variant: 'filled' });
    expect(danger).toMatchObject({ background: 'var(--alice-danger)', hover: 'var(--alice-danger-hover)', color: 'var(--alice-on-strong)' });
    const primary = variantColorResolver({ color: full.primaryColor, theme: full, variant: 'filled' });
    expect(primary).toMatchObject({ background: 'var(--alice-brand)', color: 'var(--alice-on-brand)' });
  });
  it('maps Mantine’s own variables onto the tokens in both schemes', () => {
    const vars = cssVariablesResolver(full);
    for (const scheme of [vars.light, vars.dark]) {
      expect(scheme['--mantine-color-body']).toBe('var(--alice-canvas)');
      expect(scheme['--mantine-color-text']).toBe('var(--alice-text)');
      expect(scheme['--mantine-color-dimmed']).toBe('var(--alice-text-secondary)');
      expect(scheme['--mantine-color-error']).toBe('var(--alice-danger)');
      expect(scheme['--mantine-primary-color-filled']).toBe('var(--alice-brand)');
      expect(scheme['--mantine-color-default-border']).toBe('var(--alice-border)');
    }
  });
  it('uses the bundled Geist fonts with system fallbacks', () => {
    expect(full.fontFamily).toMatch(/^Geist, /);
    expect(full.fontFamilyMonospace).toMatch(/^'Geist Mono', /);
    expect(full.headings.sizes.h1.fontSize).toBe('32px');
  });
});
```

Also add to `theme.test.ts`: rendering `<ThemeProvider>` sets `data-mantine-color-scheme` to `light` when `matchMedia` reports light and nothing is stored, and to `dark` after `localStorage.setItem('alice.colorScheme', 'dark')` (the manager reads the key), and `readFileSync('src/main.tsx')` imports `./design/tokens.css` and `./design/base.css` after `@mantine/core/styles.css`.

Run: `cd web && npx vitest run src/design src/preferences.test.ts src/themeInit.test.ts src/theme.test.ts`
Expected: FAIL (`Cannot find module './preferences'`, `./Icon`, missing `tokens.css`, the old theme exports).

- [ ] **Step 3: Implement**

`web/src/design/tokens.css`: exactly C1.

`web/src/design/Icon.tsx`:

```tsx
import { createElement } from 'react';
import { ICONS, type IconName } from './icons';

export type { IconName };

export interface IconProps {
  name: IconName;
  size?: number;
  className?: string;
}

// Icon draws one Lucide icon of the design (1.7 px stroke, round caps). It is decorative: the text next to it carries
// the meaning (design rule "Status = label + icon + color"), so it is hidden from assistive technology.
export function Icon({ name, size = 18, className }: IconProps) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {ICONS[name].map(([tag, attrs], i) => createElement(tag, { key: i, ...attrs }))}
    </svg>
  );
}
```

`web/src/theme.ts` (replaces the file; keep the comment style of the repository):

```ts
import {
  Alert, Badge, Button, Card, Code, Input, InputWrapper, Modal, Paper, Table, TableScrollContainer, Tabs, Title,
  createTheme, defaultVariantColorsResolver,
  type CSSVariablesResolver, type MantineColorsTuple, type MantineThemeOverride, type VariantColorsResolver,
} from '@mantine/core';
import classes from './design/mantine.module.css';

// SCROLL_REGION_CLASS marks the scrolling part of every table scroll container; theme.css draws its keyboard focus ring
// inside it (the ScrollArea root clips anything drawn outside, overflow: hidden).
export const SCROLL_REGION_CLASS = 'alice-scroll-region';

// The design's forest accent as a palette; shade 7 is the light brand. Components that read a palette shade directly
// (Loader, Progress, Switch, Checkbox) get the brand; everything scheme-dependent comes from the variables below.
const forest: MantineColorsTuple = ['#e9f2ed', '#d3e6db', '#a7c9b9', '#83bb9c', '#5a9479', '#3d7d64', '#24695a', '#145f50', '#104c40', '#0b3a31'];

export type Tone = 'brand' | 'success' | 'warning' | 'danger' | 'info' | 'neutral';

// The Mantine color a component passes, by the design's semantic tone it stands for. Pages keep saying color="red" or
// color="yellow"; the resolver turns that into the tone's tokens, in both schemes.
const TONE_OF: Record<string, Tone> = {
  forest: 'brand', indigo: 'brand', violet: 'brand', grape: 'brand',
  green: 'success', teal: 'success', lime: 'success',
  yellow: 'warning', orange: 'warning',
  red: 'danger', pink: 'danger',
  blue: 'info', cyan: 'info',
  gray: 'neutral', dark: 'neutral',
};

export const TONE_COLOR: Record<Tone, string> = { brand: 'forest', success: 'green', warning: 'yellow', danger: 'red', info: 'blue', neutral: 'gray' };

// toneOf maps "red", "red.9" or a missing color (the primary color) to its tone; anything unknown is neutral.
export function toneOf(color: string | undefined): Tone {
  if (!color) return 'brand';
  return TONE_OF[color.split('.')[0]] ?? 'neutral';
}

const strong = (t: Tone) => `var(--alice-${t})`;
const onStrong = (t: Tone) => (t === 'brand' ? 'var(--alice-on-brand)' : 'var(--alice-on-strong)');

// variantColorResolver replaces the light-only overrides of earlier phases (black text on light variants, a darker red
// hover): every variant draws from the semantic tokens, whose pairs tokens.test.ts holds at 4.5:1 in both schemes.
export const variantColorResolver: VariantColorsResolver = (input) => {
  const tone = toneOf(input.color ?? input.theme.primaryColor);
  const soft = `var(--alice-${tone}-soft)`;
  switch (input.variant) {
    case 'filled':
      return { background: strong(tone), hover: `var(--alice-${tone}-hover)`, color: onStrong(tone), hoverColor: onStrong(tone), border: '1px solid transparent' };
    case 'light':
      return {
        background: soft,
        hover: `color-mix(in srgb, ${strong(tone)} 10%, ${soft})`,
        color: strong(tone),
        hoverColor: strong(tone),
        border: `1px solid color-mix(in srgb, ${strong(tone)} 30%, transparent)`,
      };
    case 'subtle':
      return { background: 'transparent', hover: soft, color: strong(tone), hoverColor: strong(tone), border: '1px solid transparent' };
    case 'outline':
      return { background: 'transparent', hover: soft, color: strong(tone), hoverColor: strong(tone), border: `1px solid ${strong(tone)}` };
    default:
      return defaultVariantColorsResolver(input);
  }
};

// Mantine's own variables, mapped onto the tokens. The tokens change with data-mantine-color-scheme, so both schemes
// use the same mapping.
const SCHEME: Record<string, string> = {
  '--mantine-color-body': 'var(--alice-canvas)',
  '--mantine-color-text': 'var(--alice-text)',
  '--mantine-color-dimmed': 'var(--alice-text-secondary)',
  '--mantine-color-placeholder': 'var(--alice-text-muted)',
  '--mantine-color-anchor': 'var(--alice-brand)',
  '--mantine-color-default': 'var(--alice-surface)',
  '--mantine-color-default-hover': 'var(--alice-surface-hover)',
  '--mantine-color-default-color': 'var(--alice-text)',
  '--mantine-color-default-border': 'var(--alice-border)',
  '--mantine-color-error': 'var(--alice-danger)',
  '--mantine-primary-color-filled': 'var(--alice-brand)',
  '--mantine-primary-color-filled-hover': 'var(--alice-brand-hover)',
  '--mantine-primary-color-light': 'var(--alice-brand-soft)',
  '--mantine-primary-color-light-hover': 'var(--alice-surface-hover)',
  '--mantine-primary-color-light-color': 'var(--alice-brand)',
  '--mantine-primary-color-contrast': 'var(--alice-on-brand)',
};

// cssVariablesResolver goes to the MantineProvider (it is not part of the theme).
export const cssVariablesResolver: CSSVariablesResolver = () => ({ variables: {}, light: SCHEME, dark: SCHEME });

const SANS = "Geist, system-ui, -apple-system, 'Segoe UI', Arial, sans-serif";
const MONO = "'Geist Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

// appTheme is the app's theme. scrollRegionLabel names the scrolling part of a table (the caller's translated
// "ui.scrollRegion"), so the theme is made again when the language changes.
export function appTheme(scrollRegionLabel: string): MantineThemeOverride {
  return createTheme({
    colors: { forest },
    primaryColor: 'forest',
    primaryShade: { light: 7, dark: 3 },
    variantColorResolver,
    fontFamily: SANS,
    fontFamilyMonospace: MONO,
    headings: {
      fontFamily: SANS,
      fontWeight: '600',
      sizes: {
        h1: { fontSize: '32px', lineHeight: '1.2', fontWeight: '590' },
        h2: { fontSize: '16px', lineHeight: '1.5', fontWeight: '600' },
        h3: { fontSize: '14px', lineHeight: '1.5', fontWeight: '600' },
        h4: { fontSize: '13px', lineHeight: '1.5', fontWeight: '600' },
        h5: { fontSize: '12px', lineHeight: '1.5', fontWeight: '600' },
        h6: { fontSize: '11px', lineHeight: '1.5', fontWeight: '600' },
      },
    },
    fontSizes: { xs: '11px', sm: '12px', md: '14px', lg: '16px', xl: '20px' },
    radius: { xs: '4px', sm: '6px', md: '10px', lg: '14px', xl: '20px' },
    defaultRadius: 'sm',
    spacing: { xs: '8px', sm: '12px', md: '16px', lg: '24px', xl: '32px' },
    cursorType: 'pointer',
    components: {
      Alert: Alert.extend({ defaultProps: { variant: 'light', radius: 'md' }, classNames: { root: classes.alert, title: classes.alertTitle, message: classes.alertMessage } }),
      Badge: Badge.extend({ defaultProps: { radius: 'sm', tt: 'none', variant: 'light' }, classNames: { root: classes.badge } }),
      Button: Button.extend({ defaultProps: { radius: 'sm' }, classNames: { root: classes.button } }),
      Card: Card.extend({ defaultProps: { radius: 'md' }, classNames: { root: classes.panel } }),
      Paper: Paper.extend({ defaultProps: { radius: 'md' }, classNames: { root: classes.panel } }),
      Code: Code.extend({ classNames: { root: classes.code } }),
      Modal: Modal.extend({
        defaultProps: { radius: 'lg', overlayProps: { blur: 3 } },
        classNames: { content: classes.dialog, header: classes.dialogHeader, title: classes.dialogTitle, body: classes.dialogBody, overlay: classes.dialogOverlay },
      }),
      Table: Table.extend({ classNames: { table: classes.table } }),
      Tabs: Tabs.extend({ classNames: { list: classes.tabsList, tab: classes.tab } }),
      Title: Title.extend({ classNames: { root: classes.title } }),
      Input: Input.extend({ classNames: { input: classes.input } }),
      InputWrapper: InputWrapper.extend({ classNames: { label: classes.inputLabel, description: classes.inputDescription } }),
      // A table that scrolls sideways on a narrow screen must be reachable with the keyboard (axe
      // scrollable-region-focusable); a table without a link or button in it has nothing else to focus.
      // The stop is a named group (not a landmark) with a focus ring drawn inside it (theme.css).
      TableScrollContainer: TableScrollContainer.extend({
        defaultProps: {
          scrollAreaProps: {
            classNames: { viewport: SCROLL_REGION_CLASS },
            viewportProps: { tabIndex: 0, role: 'group', 'aria-label': scrollRegionLabel },
          },
        },
      }),
    },
  });
}
```

`web/src/design/mantine.module.css` (the design's component rules; a rule Mantine also sets under its dark-scheme selector is prefixed with `[data-mantine-color-scheme]` so it wins in both schemes; never override an error state):

```css
.title[data-order='1'] { letter-spacing: -1.3px; }
.title[data-order='2'] { letter-spacing: -0.3px; }

[data-mantine-color-scheme] .panel { background: var(--alice-surface); color: var(--alice-text); }
[data-mantine-color-scheme] .panel[data-with-border] { border-color: var(--alice-border); }

.alert { padding: 12px 16px; }
.alertTitle { font-size: 12px; font-weight: 600; }
.alertMessage { font-size: 12px; color: inherit; }

.badge { border: 0; font-size: 11px; font-weight: 550; letter-spacing: 0; text-transform: none; padding-inline: 7px; }

.button { font-weight: 550; transition: background-color var(--alice-duration), border-color var(--alice-duration); }

[data-mantine-color-scheme] .code {
  background: var(--alice-surface-subtle);
  color: var(--alice-text);
  font-family: var(--mantine-font-family-monospace);
  font-size: 0.88em;
  border-radius: 4px;
  overflow-wrap: anywhere;
}

[data-mantine-color-scheme] .dialog { background: var(--alice-surface); border: 1px solid var(--alice-border); box-shadow: 0 30px 90px #00000038; }
[data-mantine-color-scheme] .dialogHeader { background: var(--alice-surface); border-bottom: 1px solid var(--alice-border); padding: 24px 24px 18px; }
.dialogTitle { font-size: 20px; font-weight: 600; letter-spacing: -0.6px; }
.dialogBody { padding: 24px; }
.dialogOverlay { background: var(--alice-overlay); }

[data-mantine-color-scheme] .table {
  --table-border-color: var(--alice-border);
  --table-striped-color: var(--alice-surface-subtle);
  --table-highlight-on-hover-color: var(--alice-surface-hover);
  font-size: 12px;
}
.table thead th {
  padding: 10px 18px;
  font-size: 10px;
  font-weight: 550;
  letter-spacing: 0.5px;
  color: var(--alice-text-muted);
  background: var(--alice-surface-subtle);
  white-space: nowrap;
}
.table tbody td { padding: 13px 18px; height: var(--alice-row-height); vertical-align: middle; }

.tabsList { gap: 24px; --tab-border-color: var(--alice-border); }
.tab { padding: 0 0 13px; font-size: 12px; font-weight: 500; color: var(--alice-text-secondary); background: transparent; }
.tab[data-active] { color: var(--alice-brand); border-color: var(--alice-brand); }

[data-mantine-color-scheme] .input:not([data-error]) { --input-bd: var(--alice-border-strong); }
[data-mantine-color-scheme] .input { background: var(--alice-surface); color: var(--alice-text); font-size: 12px; }
.inputLabel { font-size: 11px; font-weight: 550; color: var(--alice-text); }
.inputDescription { font-size: 11px; color: var(--alice-text-secondary); }
```

`web/src/design/base.css`:

```css
/* Global rules of the Clarity design (alice-design/dist/styles.css): type smoothing, selection and the focus ring. */
body { -webkit-font-smoothing: antialiased; }
::selection { background: var(--alice-brand-line); }
:focus-visible,
.mantine-focus-auto:focus-visible { outline: 3px solid var(--alice-focus); outline-offset: 3px; }
.alice-mono { font-family: var(--mantine-font-family-monospace); overflow-wrap: anywhere; }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; scroll-behavior: auto !important; }
}
```

`web/src/theme.css`: change the scroll-region rule's color only (`outline: 2px solid var(--alice-focus); outline-offset: -2px;` — the 2 px inside ring is an e2e contract, `phase5.spec.ts:1013-1025`) and keep the `Code` rule.

`web/src/preferences.ts`:

```ts
import { useCallback, useState } from 'react';

// Per-device presentation preferences (design: "Your preference stays on this device"). The color mode is stored by
// Mantine's localStorageColorSchemeManager under COLOR_SCHEME_KEY; public/theme-init.js reads both keys before the app
// runs. A blocked store only loses persistence.
export const COLOR_SCHEME_KEY = 'alice.colorScheme';
export const DENSITY_KEY = 'alice.density';

export type Density = 'comfortable' | 'compact';

export function readDensity(): Density {
  try {
    return localStorage.getItem(DENSITY_KEY) === 'compact' ? 'compact' : 'comfortable';
  } catch {
    return 'comfortable';
  }
}

export function applyDensity(d: Density): void {
  document.documentElement.dataset.density = d;
}

export function saveDensity(d: Density): void {
  applyDensity(d);
  try {
    localStorage.setItem(DENSITY_KEY, d);
  } catch {
    // A private window or a policy: the choice holds until the page is reloaded.
  }
}

export function useDensity(): [Density, (d: Density) => void] {
  const [density, setDensity] = useState<Density>(readDensity);
  const set = useCallback((d: Density) => {
    saveDensity(d);
    setDensity(d);
  }, []);
  return [density, set];
}
```

`web/public/theme-init.js`:

```js
// Runs before the app bundle (index.html; a same-origin script, so CSP script-src 'self' allows it). It applies the
// stored color mode and table density, so a dark-mode user never sees a light page first. Keys: web/src/preferences.ts.
(function () {
  var root = document.documentElement;
  try {
    var scheme = localStorage.getItem('alice.colorScheme');
    if (scheme !== 'light' && scheme !== 'dark') {
      scheme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    root.setAttribute('data-mantine-color-scheme', scheme);
    if (localStorage.getItem('alice.density') === 'compact') root.setAttribute('data-density', 'compact');
  } catch (e) {
    // Storage is blocked: the app applies its defaults when it starts.
  }
})();
```

`web/index.html`: add `<script src="/theme-init.js"></script>` right after the `csp-nonce` meta.

`web/src/ThemeProvider.tsx`: add `colorSchemeManager={schemeManager}` (module-level `const schemeManager = localStorageColorSchemeManager({ key: COLOR_SCHEME_KEY })`) and `defaultColorScheme="auto"`; keep `getStyleNonce={readCspNonce}` and the per-language theme.

`web/src/main.tsx`: imports in this order: `@mantine/core/styles.css`, `./design/tokens.css`, `./theme.css`, `./design/base.css`; then `applyDensity(readDensity())` before `startApp`.

`web/src/test/render.tsx` (C8): the `providers()` helper uses `appTheme(i18n.t('ui.scrollRegion'))`, `cssVariablesResolver`, and `forceColorScheme={opts.colorScheme}` when given; add the optional `opts` argument to `renderApp` and the `colorScheme` field to `renderRoute`'s options. `web/src/test/setup.ts`: in `beforeEach`, also `document.documentElement.removeAttribute('data-density')`.

- [ ] **Step 4: Run the tests and the whole suite**

Run: `cd web && npx vitest run src/design src/preferences.test.ts src/themeInit.test.ts src/theme.test.ts`
Expected: PASS.

Run: `make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check && make web`
Expected: all green. Existing tests that asserted `DANGER_HOVER` or black text are only in `theme.test.ts` (rewritten). If a component test fails because Mantine now renders the app theme in tests (for example a snapshot of a color), fix the test's expectation to the semantic token, never the token itself. `make web` must emit `assets/geist-*.woff` (check `ls ../internal/webui/dist/app/assets | grep woff`).

- [ ] **Step 5: Commit**

```bash
git add -- web/src/design web/src/preferences.ts web/src/preferences.test.ts web/public/theme-init.js web/src/themeInit.test.ts
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): Clarity design foundation: vendored Geist fonts and Lucide icons, light/dark semantic tokens, scheme-aware Mantine theme (system default), density preference and pre-paint script" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src/design web/src/preferences.ts web/src/preferences.test.ts \
  web/public/theme-init.js web/src/themeInit.test.ts web/src/theme.ts web/src/theme.test.ts web/src/theme.css web/src/ThemeProvider.tsx \
  web/src/main.tsx web/index.html web/src/test/render.tsx web/src/test/setup.ts
```

Gap rows for the report: tokens added beyond the design (`*-hover`, `on-strong`, `neutral*`, `auth-brand-*`); scroll-region focus ring stays 2 px inside (e2e contract) instead of the design's 3 px.

---

### Task 2: Third-party notices for the vendored fonts and icons (`tools/notices -vendored`)

**Files:**
- Create: `tools/notices/vendored.go`, `tools/notices/vendored_test.go`
- Modify: `tools/notices/main.go` (flag, `input.Vendored`, render section), `tools/notices/main_test.go` (command line), `Makefile` (`notices` target line only)

**Interfaces:**
- Consumes: `web/src/design/THIRD_PARTY.json` (Task 1; the tests use their own temporary manifest, so this task does not wait for Task 1).
- Produces: `go run ./tools/notices … -vendored web/src/design/THIRD_PARTY.json` writes a `## Web UI (vendored assets)` section after the npm section: for each entry `### <name> (<license>)`, a `Source: <source>` line, the `Files:` list, then the full text of `licenseFile`. A missing or empty license file, an empty `name`/`license`, or a listed file that does not exist fails the tool with `vendored asset <name>: …`. Without `-vendored` the output is unchanged (backwards compatible for older callers).

- [ ] **Step 1: Write the failing test** (`tools/notices/vendored_test.go`, stdlib `testing` + testify like `main_test.go`):

```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeVendored(t *testing.T, licenseText string, withFile bool) (root, manifest string) {
	t.Helper()
	root = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "web/src/design/fonts"), 0o755))
	if licenseText != "" {
		require.NoError(t, os.WriteFile(filepath.Join(root, "web/src/design/fonts/OFL.txt"), []byte(licenseText), 0o644))
	}
	if withFile {
		require.NoError(t, os.WriteFile(filepath.Join(root, "web/src/design/fonts/geist.woff"), []byte("wOFF"), 0o644))
	}
	manifest = filepath.Join(root, "web/src/design/THIRD_PARTY.json")
	require.NoError(t, os.WriteFile(manifest, []byte(`[{"name":"Geist","source":"https://github.com/vercel/geist-font","license":"OFL-1.1",
"files":["web/src/design/fonts/geist.woff"],"licenseFile":"web/src/design/fonts/OFL.txt"}]`), 0o644))
	return root, manifest
}

func TestVendoredAssetsSection(t *testing.T) {
	root, manifest := writeVendored(t, "SIL OPEN FONT LICENSE Version 1.1\n", true)
	assets, err := vendoredAssets(manifest, root)
	require.NoError(t, err)
	var b strings.Builder
	require.NoError(t, renderVendored(&b, assets))
	out := b.String()
	require.Contains(t, out, "## Web UI (vendored assets)")
	require.Contains(t, out, "### Geist (OFL-1.1)")
	require.Contains(t, out, "Source: https://github.com/vercel/geist-font")
	require.Contains(t, out, "web/src/design/fonts/geist.woff")
	require.Contains(t, out, "SIL OPEN FONT LICENSE Version 1.1")
}

func TestVendoredAssetWithoutLicenseFails(t *testing.T) {
	root, manifest := writeVendored(t, "", true)
	_, err := vendoredAssets(manifest, root)
	require.ErrorContains(t, err, "vendored asset Geist")
}

func TestVendoredAssetWithMissingFileFails(t *testing.T) {
	root, manifest := writeVendored(t, "license", false)
	_, err := vendoredAssets(manifest, root)
	require.ErrorContains(t, err, "geist.woff")
}
```

Add to `TestCommandLine` in `main_test.go` a case that `-vendored` is accepted and optional.

Run: `go test ./tools/notices/ -run 'Vendored|CommandLine' -count=1`
Expected: FAIL (`undefined: vendoredAssets`).

- [ ] **Step 2: Implement** `vendored.go`:

```go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// vendoredAsset is one entry of web/src/design/THIRD_PARTY.json: files copied into the web UI that are not npm packages
// (the Geist fonts and the Lucide icon subset of the Clarity design). Paths are relative to the repository root.
type vendoredAsset struct {
	Name        string   `json:"name"`
	Source      string   `json:"source"`
	License     string   `json:"license"`
	Files       []string `json:"files"`
	LicenseFile string   `json:"licenseFile"`
	text        string
}

// vendoredAssets reads the manifest and every license text; a missing license, name or listed file is an error, so a
// release never ships an asset without its notice.
func vendoredAssets(manifest, root string) ([]vendoredAsset, error) {
	raw, err := os.ReadFile(manifest) //nolint:gosec // G304: the manifest path is the operator's flag
	if err != nil {
		return nil, fmt.Errorf("vendored assets: %w", err)
	}
	var out []vendoredAsset
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("vendored assets: %s: %w", manifest, err)
	}
	for i := range out {
		a := &out[i]
		if a.Name == "" || a.License == "" || a.LicenseFile == "" {
			return nil, fmt.Errorf("vendored asset %q: name, license and licenseFile are required", a.Name)
		}
		for _, f := range a.Files {
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(f))); err != nil {
				return nil, fmt.Errorf("vendored asset %s: %s: %w", a.Name, f, err)
			}
		}
		text, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(a.LicenseFile))) //nolint:gosec // G304: a path from the repository's manifest
		if err != nil || strings.TrimSpace(string(text)) == "" {
			return nil, fmt.Errorf("vendored asset %s: license file %s is missing or empty", a.Name, a.LicenseFile)
		}
		a.text = string(text)
	}
	return out, nil
}

func renderVendored(w io.Writer, assets []vendoredAsset) error {
	if len(assets) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("## Web UI (vendored assets)\n\n")
	for _, a := range assets {
		fmt.Fprintf(&b, "### %s (%s)\n\n", a.Name, a.License)
		if a.Source != "" {
			fmt.Fprintf(&b, "Source: %s\n\n", a.Source)
		}
		b.WriteString("Files:\n\n")
		for _, f := range a.Files {
			fmt.Fprintf(&b, "- `%s`\n", f)
		}
		b.WriteString("\n```\n" + strings.TrimRight(a.text, "\n") + "\n```\n\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
```

In `main.go`: a `vendored := fs.String("vendored", "", "web/src/design/THIRD_PARTY.json (optional)")` flag; `generate` gets the path; when set, `in.Vendored, err = vendoredAssets(path, ".")` (the tool runs from the repository root, like the Makefile); `render` calls `renderVendored(&b, in.Vendored)` after the npm loop. Update the package comment's usage line.

`Makefile` `notices` target: append ` -vendored web/src/design/THIRD_PARTY.json` to the `go run ./tools/notices` line.

- [ ] **Step 3: Verify**

Run: `go test ./tools/notices/ -count=1 && go vet ./tools/notices/ && gofmt -l tools/notices`
Expected: `ok`, no vet output, no gofmt output. (`make notices` needs `make build`; it is run by Task 20 once Task 1's files exist.)

- [ ] **Step 4: Commit**

```bash
git add -- tools/notices/vendored.go tools/notices/vendored_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(tools): THIRD_PARTY_NOTICES lists the vendored web assets (Geist fonts, Lucide icons) from web/src/design/THIRD_PARTY.json" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- tools/notices Makefile
```

---

### Task 3: Shared UI components (PageHeader, Panel, ResourceTable, CursorFooter, StatusBadge, FactList, OperationTimeline, AttentionItem, EmptyState, Notice, MetricStrip, LinkTabs, DialogActions, AppearanceControl, ThemeToggle, LanguageToggle) and the error code in ErrorAlert

**Design source:** `ui.js` (`title`, `panel`, `panelBody`, `fact`, `empty`, `table`, `metric`, `badge`, `statusBadge`, `notice`), `pages.js` (`attentionRows`, `deploymentDetail` timeline, `pagination` footer), `admin.js` `appearance()`, `app.js` (`toggle-theme`, `toggle-language`, dialog `.dialog-actions`), `styles.css` rules of the same names, `guide.js` "05 / Components & outcome language".

**Files:**
- Create: `web/src/components/ui/{PageHeader,Panel,ResourceTable,CursorFooter,StatusBadge,FactList,OperationTimeline,AttentionItem,EmptyState,Notice,MetricStrip,LinkTabs,DialogActions,AppearanceControl,ThemeToggle,LanguageToggle}.tsx`, `web/src/components/ui/{ui.module.css,status.ts,cx.ts,index.ts}`, `web/src/components/ui/ui.test.tsx`, `web/src/components/ui/appearance.test.tsx`, `web/src/components/ui/status.test.ts`
- Modify: `web/src/components/ErrorAlert.tsx`, `web/src/components/ErrorAlert.test.tsx`, `web/src/locales/{en,tr}.json` (under the lock: `ui.table.*`, `appearance.*`)

**Interfaces:**
- Consumes: C2 (`TONE_COLOR`, `type Tone`), C3 (`useDensity`), C4 (`Icon`), `LANGUAGES`/`setLanguage`/`type Lang` from `src/i18n.ts`, `setMyLocale` from `src/api/endpoints.ts`.
- Produces: C5 exactly; `ErrorAlert` shows `jobs.errorCode` for an `ApiError` with a `code`.

- [ ] **Step 1: Add the keys (under the lock)**

| Key | EN | TR |
|---|---|---|
| `ui.table.shown_one` / `_other` | `{{count}} shown` | `{{count}} kayıt gösteriliyor` |
| `appearance.title` | A workspace that feels right | Size uygun bir çalışma alanı |
| `appearance.description` | Choose a color mode and information density. Your preference stays on this device. | Renk modunu ve bilgi yoğunluğunu seçin. Tercihiniz bu cihazda saklanır. |
| `appearance.colorMode` | Color mode | Renk modu |
| `appearance.light` / `dark` / `system` | Light / Dark / System | Açık / Koyu / Sistem |
| `appearance.compact` | Compact tables | Kompakt tablolar |
| `appearance.compactHelp` | Use 48 px rows to see more information at once. | Tek seferde daha fazla bilgi için 48 piksel satırlar kullanın. |
| `appearance.languageHelp` | Saved to your account, so it follows you to other browsers. | Hesabınıza kaydedilir; diğer tarayıcılarda da geçerli olur. |
| `appearance.toggle` | Switch color mode | Renk modunu değiştir |

- [ ] **Step 2: Write the failing tests**

`web/src/components/ui/ui.test.tsx` (use `renderApp` from `src/test/render.tsx`; wrap router-dependent components in `MemoryRouter`):

```tsx
import { readFileSync } from 'node:fs';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { Table } from '@mantine/core';
import { renderApp } from '../../test/render';
import { AttentionItem, CursorFooter, DialogActions, EmptyState, FactList, LinkTabs, MetricStrip, Notice, OperationTimeline, PageHeader, Panel, ResourceTable, StatusBadge } from '.';

const css = readFileSync('src/components/ui/ui.module.css', 'utf8');

describe('PageHeader', () => {
  it('is the page’s only level-1 heading, with eyebrow, description, actions and a back link', async () => {
    await renderApp(<MemoryRouter><PageHeader title="Certificates" eyebrow="Monday" description="Every certificate." actions={<button>Export</button>} back={{ to: '/certificates', label: 'All certificates' }} /></MemoryRouter>);
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByRole('heading', { level: 1, name: 'Certificates' })).toBeVisible();
    expect(screen.getByText('Monday')).toBeVisible();
    expect(screen.getByRole('link', { name: 'All certificates' })).toHaveAttribute('href', '/certificates');
    expect(screen.getByRole('button', { name: 'Export' })).toBeVisible();
  });
});

describe('Panel', () => {
  it('heads its content with a level-2 title and is a region only when named', async () => {
    const { rerender } = await renderApp(<Panel title="Validity">body</Panel>);
    expect(screen.getByRole('heading', { level: 2, name: 'Validity' })).toBeVisible();
    expect(screen.queryByRole('region')).not.toBeInTheDocument();
    rerender(<Panel title="Validity" aria-label="Validity" headingOrder={3}>body</Panel>);
    expect(screen.getByRole('region', { name: 'Validity' })).toBeVisible();
    expect(screen.getByRole('heading', { level: 3 })).toBeVisible();
  });
});

describe('ResourceTable', () => {
  it('keeps the table name, its test id, the focusable scroll region and the toolbar and footer slots', async () => {
    await renderApp(
      <ResourceTable label="Certificate inventory" testId="certificates-table" toolbar={<input aria-label="Search" />} footer={<span>2 shown</span>}>
        <Table.Thead><Table.Tr><Table.Th>Name</Table.Th></Table.Tr></Table.Thead>
        <Table.Tbody><Table.Tr><Table.Td>a</Table.Td></Table.Tr></Table.Tbody>
      </ResourceTable>,
    );
    const table = screen.getByRole('table', { name: 'Certificate inventory' });
    expect(table).toHaveAttribute('data-testid', 'certificates-table');
    expect(within(table).getAllByRole('row')).toHaveLength(2);
    expect(screen.getByRole('group', { name: 'Table, scrolls sideways' })).toHaveAttribute('tabindex', '0');
    expect(screen.getByRole('textbox', { name: 'Search' })).toBeVisible();
    expect(screen.getByText('2 shown')).toBeVisible();
  });
});

describe('CursorFooter', () => {
  it('states how many rows are shown, never a total, and offers Load more only while the server has more', async () => {
    const more = vi.fn();
    const { rerender } = await renderApp(<CursorFooter shown={50} hasMore loading={false} onMore={more} moreLabel="Load more" />);
    expect(screen.getByText('50 shown')).toBeVisible();
    expect(screen.queryByText(/ of /)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(more).toHaveBeenCalledOnce();
    rerender(<CursorFooter shown={51} hasMore={false} loading={false} onMore={more} moreLabel="Load more" />);
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
  });
});

describe('StatusBadge', () => {
  it('is a Mantine badge (rotation e2e reads .mantine-Badge-root) with text, tone and passed-through attributes', async () => {
    const { container } = await renderApp(<StatusBadge tone="danger" icon="Fingerprint" data-status="host_key_changed" testId="target-status">Identity changed</StatusBadge>);
    const badge = container.querySelector('.mantine-Badge-root')!;
    expect(badge).toHaveTextContent('Identity changed');
    expect(badge).toHaveAttribute('data-tone', 'danger');
    expect(badge).toHaveAttribute('data-status', 'host_key_changed');
    expect(screen.getByTestId('target-status')).toBe(badge);
  });
});

describe('FactList', () => {
  it('is a description list whose values break long tokens such as fingerprints', async () => {
    await renderApp(<FactList label="Certificate details" facts={[{ label: 'SHA-256', value: 'AB:CD', testId: 'fp' }]} />);
    expect(screen.getByRole('term')).toHaveTextContent('SHA-256');
    expect(screen.getByRole('definition')).toHaveTextContent('AB:CD');
    expect(screen.getByTestId('fp').tagName).toBe('DD');
    expect(css).toMatch(/\.factValue\s*\{[^}]*overflow-wrap:\s*anywhere/);
  });
});

describe('OperationTimeline', () => {
  it('is a named ordered list whose steps carry their state in text and the caller’s data attributes', async () => {
    await renderApp(<OperationTimeline label="Steps" steps={[
      { id: 'backup', title: 'Back up current files', state: 'done', stateLabel: 'Done', dataAttrs: { 'data-step': 'backup', 'data-status': 'ok' } },
      { id: 'reload', title: 'Reload Nginx', state: 'notRun', stateLabel: 'Not run' },
    ]} />);
    const list = screen.getByRole('list', { name: 'Steps' });
    const items = within(list).getAllByRole('listitem');
    expect(items[0]).toHaveAttribute('data-step', 'backup');
    expect(items[0].querySelector('[data-role="step-status"]')).toHaveTextContent('Done');
    expect(items[1]).toHaveTextContent('Not run');
  });
});

describe('AttentionItem', () => {
  it('links to where the condition is handled, with the name as its own text', async () => {
    await renderApp(<MemoryRouter><AttentionItem tone="danger" icon="Fingerprint" title="Server identity changed" detail={<code>seed-web-3</code>} to="/servers/1" /></MemoryRouter>);
    const link = screen.getByRole('link', { name: /Server identity changed/ });
    expect(link).toHaveAttribute('href', '/servers/1');
    expect(screen.getByText('seed-web-3', { exact: true })).toBeVisible();
  });
});

describe('EmptyState, Notice, MetricStrip, LinkTabs, DialogActions', () => {
  it('render their parts with the roles the pages rely on', async () => {
    await renderApp(
      <MemoryRouter initialEntries={['/rotations']}>
        <EmptyState title="No matching certificates" description="Clear your filters." action={<button>Clear filters</button>} />
        <Notice tone="warning" title="Renewal due">Review the locations.</Notice>
        <Notice tone="danger" title="Locked" role="alert" />
        <MetricStrip label="Summary" items={[{ label: 'Monitored certificates', value: 8, icon: 'FileKey2', to: '/certificates' }]} />
        <LinkTabs label="SSH keys sections" items={[{ to: '/ssh-keys', label: 'Inventory' }, { to: '/rotations', label: 'Key rotations', match: ['/rotation/'] }]} />
        <DialogActions note="Changes affect selected locations only."><button>Start</button></DialogActions>
      </MemoryRouter>,
    );
    expect(screen.getByText('No matching certificates')).toBeVisible();
    expect(screen.getByRole('note')).toHaveTextContent('Renewal due');
    expect(screen.getByRole('alert')).toHaveTextContent('Locked');
    expect(screen.getByRole('link', { name: /Monitored certificates/ })).toHaveAttribute('href', '/certificates');
    expect(screen.getByRole('link', { name: 'Key rotations' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('link', { name: 'Inventory' })).not.toHaveAttribute('aria-current');
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument(); // the shell's nav must stay the only one
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument();
    expect(screen.getByText('Changes affect selected locations only.')).toBeVisible();
  });
});
```

`web/src/components/ui/appearance.test.tsx`:

```tsx
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { MantineProvider } from '@mantine/core';
import { renderApp } from '../../test/render';
import { server } from '../../test/server';
import { AppearanceControl, LanguageToggle, ThemeToggle } from '.';

const root = document.documentElement;

describe('AppearanceControl', () => {
  it('offers light, dark and system as radios and remembers the choice on this device', async () => {
    await renderApp(<AppearanceControl signedIn={false} />);
    const dark = screen.getByRole('radio', { name: /Dark/ });
    await userEvent.click(dark);
    expect(dark).toBeChecked();
    expect(root).toHaveAttribute('data-mantine-color-scheme', 'dark');
    expect(localStorage.getItem('alice.colorScheme')).toBe('dark');
    await userEvent.click(screen.getByRole('radio', { name: /System/ }));
    expect(localStorage.getItem('alice.colorScheme')).toBe('auto');
  });
  it('switches compact tables and saves the language to the account only when signed in', async () => {
    const saved = vi.fn();
    server.use(http.put('/api/v1/auth/locale', () => { saved(); return new HttpResponse(null, { status: 204 }); }));
    await renderApp(<AppearanceControl signedIn />);
    await userEvent.click(screen.getByRole('switch', { name: 'Compact tables' }));
    expect(root).toHaveAttribute('data-density', 'compact');
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Language' }), 'tr');
    await waitFor(() => expect(root).toHaveAttribute('lang', 'tr'));
    expect(saved).toHaveBeenCalledOnce();
  });
});

describe('ThemeToggle and LanguageToggle', () => {
  it('flips the computed scheme', async () => {
    await renderApp(<ThemeToggle />);
    await userEvent.click(screen.getByRole('button', { name: 'Switch color mode' }));
    expect(root).toHaveAttribute('data-mantine-color-scheme', 'dark');
  });
  it('is named by the other language in its own name and switches to it (two languages)', async () => {
    await renderApp(<LanguageToggle signedIn={false} />);
    const toggle = screen.getByRole('button', { name: 'Türkçe' });
    expect(toggle).toHaveTextContent('tr');
    await userEvent.click(toggle);
    await waitFor(() => expect(root).toHaveAttribute('lang', 'tr'));
    expect(screen.getByRole('button', { name: 'English' })).toBeVisible();
  });
});
```

`web/src/components/ui/status.test.ts`: every `TargetStatus` value has a tone; `deploymentTone` for each `DeploymentStatus` and for a cancelled failure (`{ status: 'failed', error: { reason: 'deployment.cancelled' } }` → `neutral`); `expiryTone` for each `ExpiryState`.

`ErrorAlert.test.tsx`: add `it('shows the stable error code of an API error', …)`: an `ApiError(409, { code: 'ALC-ROT-0001', reason: 'rotation.policy_exists', message_key: 'errors.rotation.policy_exists', … })` renders `Error code: ALC-ROT-0001` and still the request ID.

Run: `cd web && npx vitest run src/components/ui src/components/ErrorAlert.test.tsx`
Expected: FAIL (modules missing; the error-code test fails on the current ErrorAlert).

- [ ] **Step 3: Implement**

`cx.ts`:

```ts
// cx joins class names, skipping the empty ones.
export function cx(...names: (string | false | null | undefined)[]): string {
  return names.filter(Boolean).join(' ');
}
```

`PageHeader.tsx`:

```tsx
import { Anchor, Group, Text, Title } from '@mantine/core';
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { Icon, type IconName } from '../../design/Icon';
import classes from './ui.module.css';

export interface PageHeaderProps {
  title: ReactNode;
  description?: ReactNode;
  eyebrow?: ReactNode;
  actions?: ReactNode;
  back?: { to: string; label: string };
  icon?: IconName;
  status?: ReactNode;
}

// PageHeader is the design's page head: eyebrow, the page's only <h1>, a one-line description and the page actions.
export function PageHeader({ title, description, eyebrow, actions, back, icon, status }: PageHeaderProps) {
  return (
    <>
      {back && (
        <Anchor component={Link} to={back.to} className={classes.backLink}>
          <Icon name="ArrowLeft" size={14} />
          {back.label}
        </Anchor>
      )}
      <header className={classes.pageHead}>
        <div className={classes.pageHeadText}>
          {eyebrow && <div className={classes.eyebrow}>{eyebrow}</div>}
          <Group gap="sm" wrap="wrap" align="center">
            {icon && (
              <span className={classes.detailIcon}>
                <Icon name={icon} size={23} />
              </span>
            )}
            <Title order={1}>{title}</Title>
            {status}
          </Group>
          {description && <Text className={classes.description}>{description}</Text>}
        </div>
        {actions && (
          <Group gap="xs" className={classes.actions}>
            {actions}
          </Group>
        )}
      </header>
    </>
  );
}
```

`Panel.tsx`:

```tsx
import { Text, Title } from '@mantine/core';
import type { ReactNode } from 'react';
import { cx } from './cx';
import classes from './ui.module.css';

export interface PanelProps {
  title?: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  footer?: ReactNode;
  children: ReactNode;
  padded?: boolean;
  headingOrder?: 2 | 3;
  testId?: string;
  className?: string;
  'aria-label'?: string;
}

// Panel is the design's bordered surface with a heading, an optional subtitle, a corner action and a footer bar.
// Unnamed it is no landmark; give it aria-label only where a region is wanted.
export function Panel({ title, description, action, footer, children, padded = true, headingOrder = 2, testId, className, 'aria-label': label }: PanelProps) {
  return (
    <section className={cx(classes.panel, className)} data-testid={testId} aria-label={label}>
      {(title || action) && (
        <header className={classes.panelHead}>
          <div>
            {title && (
              <Title order={headingOrder} className={classes.panelTitle}>
                {title}
              </Title>
            )}
            {description && <Text className={classes.panelDescription}>{description}</Text>}
          </div>
          {action}
        </header>
      )}
      <div className={padded ? classes.panelBody : classes.panelFlush}>{children}</div>
      {footer && <footer className={classes.panelFoot}>{footer}</footer>}
    </section>
  );
}
```

`ResourceTable.tsx`:

```tsx
import { Table } from '@mantine/core';
import type { ReactNode } from 'react';
import classes from './ui.module.css';

export interface ResourceTableProps {
  label: string;
  minWidth?: number;
  toolbar?: ReactNode;
  footer?: ReactNode;
  testId?: string;
  striped?: boolean;
  children: ReactNode;
}

// ResourceTable is the design's inventory table: a toolbar (search, native selects, saved views, export), the table in
// the theme's focusable scroll region, and a footer for "N shown" and the cursor's Load more (R13). The caller writes
// Table.Thead and Table.Tbody, so rows keep their test ids and cells.
export function ResourceTable({ label, minWidth = 640, toolbar, footer, testId, striped = false, children }: ResourceTableProps) {
  return (
    <div className={classes.tablePanel}>
      {toolbar && <div className={classes.toolbar}>{toolbar}</div>}
      <Table.ScrollContainer minWidth={minWidth}>
        <Table aria-label={label} data-testid={testId} striped={striped} highlightOnHover>
          {children}
        </Table>
      </Table.ScrollContainer>
      {footer && <div className={classes.tableBottom}>{footer}</div>}
    </div>
  );
}
```

`CursorFooter.tsx`:

```tsx
import { Button } from '@mantine/core';
import { useTranslation } from 'react-i18next';

export interface CursorFooterProps {
  shown: number;
  hasMore: boolean;
  loading: boolean;
  onMore: () => void;
  moreLabel: string;
}

// CursorFooter is a ResourceTable footer for cursor-paged lists: how many rows are on screen and Load more. It never
// states a total (the API has none) and never numbers pages.
export function CursorFooter({ shown, hasMore, loading, onMore, moreLabel }: CursorFooterProps) {
  const { t } = useTranslation();
  return (
    <>
      <span>{t('ui.table.shown', { count: shown })}</span>
      {hasMore && (
        <Button variant="default" size="xs" onClick={onMore} loading={loading}>
          {moreLabel}
        </Button>
      )}
    </>
  );
}
```

`StatusBadge.tsx`:

```tsx
import { Badge } from '@mantine/core';
import type { HTMLAttributes, ReactNode } from 'react';
import { Icon, type IconName } from '../../design/Icon';
import { TONE_COLOR, type Tone } from '../../theme';
import classes from './ui.module.css';

export type { Tone };

export interface StatusBadgeProps extends Omit<HTMLAttributes<HTMLDivElement>, 'color' | 'children'> {
  tone: Tone;
  icon?: IconName;
  children: ReactNode;
  testId?: string;
  size?: 'sm' | 'md' | 'lg';
}

// StatusBadge is the design's status pill: text plus an icon (or a dot) plus color, never color alone. It stays a Mantine
// Badge, so existing selectors (.mantine-Badge-root) and data attributes keep working.
export function StatusBadge({ tone, icon, children, testId, size = 'md', ...rest }: StatusBadgeProps) {
  return (
    <Badge
      color={TONE_COLOR[tone]}
      variant="light"
      size={size}
      data-tone={tone}
      data-testid={testId}
      leftSection={icon ? <Icon name={icon} size={13} /> : <span className={classes.dot} aria-hidden="true" />}
      {...rest}
    >
      {children}
    </Badge>
  );
}
```

`FactList.tsx`:

```tsx
import type { ReactNode } from 'react';
import classes from './ui.module.css';

export interface Fact {
  label: ReactNode;
  value: ReactNode;
  testId?: string;
  key?: string;
}

// FactList is the design's label/value list as a description list; values wrap anywhere (fingerprints, paths, URLs).
export function FactList({ facts, label }: { facts: Fact[]; label?: string }) {
  return (
    <dl className={classes.facts} aria-label={label}>
      {facts.map((f, i) => (
        <div className={classes.fact} key={f.key ?? i}>
          <dt className={classes.factLabel}>{f.label}</dt>
          <dd className={classes.factValue} data-testid={f.testId}>
            {f.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}
```

`OperationTimeline.tsx`:

```tsx
import { Loader } from '@mantine/core';
import type { ReactNode } from 'react';
import { Icon, type IconName } from '../../design/Icon';
import classes from './ui.module.css';

export type StepState = 'done' | 'failed' | 'running' | 'waiting' | 'skipped' | 'notRun' | 'unknown';

export interface TimelineStep {
  id: string;
  title: ReactNode;
  detail?: ReactNode;
  state: StepState;
  stateLabel: string;
  time?: ReactNode;
  dataAttrs?: Record<string, string>;
}

const MARKER: Record<Exclude<StepState, 'running'>, IconName> = {
  done: 'Check',
  failed: 'CircleX',
  waiting: 'Clock3',
  skipped: 'CircleOff',
  notRun: 'Circle',
  unknown: 'CircleHelp',
};

// OperationTimeline is the design's step sequence. The state is always written out (stateLabel) next to its marker;
// the marker alone never carries the meaning. A step that was not run says so — never a green tick (IMPLEMENTATION §5).
export function OperationTimeline({ steps, label }: { steps: TimelineStep[]; label: string }) {
  return (
    <ol className={classes.timeline} aria-label={label}>
      {steps.map((s) => (
        <li key={s.id} className={classes.timelineStep} {...s.dataAttrs}>
          <span className={classes.stepMarker} data-state={s.state} aria-hidden="true">
            {s.state === 'running' ? <Loader size={12} /> : <Icon name={MARKER[s.state]} size={13} />}
          </span>
          <div className={classes.stepText}>
            <div className={classes.stepTitle}>{s.title}</div>
            <div className={classes.stepStatus} data-role="step-status">
              {s.stateLabel}
            </div>
            {s.detail && <div className={classes.stepDetail}>{s.detail}</div>}
          </div>
          {s.time && <span className={classes.stepTime}>{s.time}</span>}
        </li>
      ))}
    </ol>
  );
}
```

`AttentionItem.tsx`:

```tsx
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { Icon, type IconName } from '../../design/Icon';
import classes from './ui.module.css';

export interface AttentionItemProps {
  tone: 'warning' | 'danger' | 'info';
  icon: IconName;
  title: ReactNode;
  detail?: ReactNode;
  meta?: ReactNode;
  to?: string;
  onClick?: () => void;
  testId?: string;
}

// AttentionItem is one row of "Needs attention": a tinted status box, what happened, which resource, and where to act.
export function AttentionItem({ tone, icon, title, detail, meta, to, onClick, testId }: AttentionItemProps) {
  const body = (
    <>
      <span className={classes.statusBox} data-tone={tone} aria-hidden="true">
        <Icon name={icon} size={15} />
      </span>
      <span className={classes.attentionText}>
        <span className={classes.attentionTitle}>{title}</span>
        {detail && <span className={classes.attentionDetail}>{detail}</span>}
        {meta && <span className={classes.attentionMeta}>{meta}</span>}
      </span>
      {(to || onClick) && <Icon name="ChevronRight" size={14} className={classes.chevron} />}
    </>
  );
  if (to)
    return (
      <Link to={to} className={classes.attentionRow} data-testid={testId}>
        {body}
      </Link>
    );
  if (onClick)
    return (
      <button type="button" className={classes.attentionRow} onClick={onClick} data-testid={testId}>
        {body}
      </button>
    );
  return (
    <div className={classes.attentionRow} data-testid={testId}>
      {body}
    </div>
  );
}
```

`EmptyState.tsx`:

```tsx
import type { ReactNode } from 'react';
import { Icon, type IconName } from '../../design/Icon';
import classes from './ui.module.css';

export interface EmptyStateProps {
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  icon?: IconName;
  testId?: string;
}

// EmptyState distinguishes "nothing here yet" (with the way to add it) from "no match" (with Clear filters): the
// caller chooses the copy; the design's guide requires both.
export function EmptyState({ title, description, action, icon = 'Search', testId }: EmptyStateProps) {
  return (
    <div className={classes.empty} data-testid={testId}>
      <Icon name={icon} size={32} className={classes.emptyIcon} />
      <p className={classes.emptyTitle}>{title}</p>
      {description && <p className={classes.emptyText}>{description}</p>}
      {action}
    </div>
  );
}
```

`Notice.tsx`:

```tsx
import { Alert } from '@mantine/core';
import type { ReactNode } from 'react';
import { Icon, type IconName } from '../../design/Icon';
import { TONE_COLOR, type Tone } from '../../theme';
import classes from './ui.module.css';

export interface NoticeProps {
  tone: Tone;
  title: ReactNode;
  children?: ReactNode;
  action?: ReactNode;
  role?: 'alert' | 'status' | 'note';
  testId?: string;
}

const ICON: Record<Tone, IconName> = { brand: 'ShieldCheck', success: 'ShieldCheck', info: 'CircleDot', neutral: 'CircleDot', warning: 'CircleAlert', danger: 'ShieldAlert' };

// Notice is the design's status line for page-level information. A static notice is a "note"; pass role="alert" only
// for something that just went wrong and role="status" for a result the person is waiting for.
export function Notice({ tone, title, children, action, role = 'note', testId }: NoticeProps) {
  return (
    <Alert color={TONE_COLOR[tone]} title={title} role={role} data-testid={testId} icon={<Icon name={ICON[tone]} size={17} />}>
      {children}
      {action && <div className={classes.noticeAction}>{action}</div>}
    </Alert>
  );
}
```

`MetricStrip.tsx`:

```tsx
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { Icon, type IconName } from '../../design/Icon';
import classes from './ui.module.css';

export interface Metric {
  label: ReactNode;
  value: ReactNode;
  foot?: ReactNode;
  icon: IconName;
  to?: string;
  tone?: 'warning' | 'danger';
  testId?: string;
}

// MetricStrip is the design's four-number band. A metric with "to" is a link to exactly the rows it counts.
export function MetricStrip({ items, label }: { items: Metric[]; label: string }) {
  return (
    <div className={classes.metricStrip} role="group" aria-label={label}>
      {items.map((m, i) => {
        const body = (
          <>
            <span className={classes.metricLabel}>
              {m.label}
              <Icon name={m.icon} size={16} />
            </span>
            <span className={classes.metricValue}>{m.value}</span>
            {m.foot && (
              <span className={classes.metricFoot} data-tone={m.tone}>
                {m.foot}
              </span>
            )}
          </>
        );
        return m.to ? (
          <Link key={i} to={m.to} className={classes.metric} data-testid={m.testId}>
            {body}
          </Link>
        ) : (
          <div key={i} className={classes.metric} data-testid={m.testId}>
            {body}
          </div>
        );
      })}
    </div>
  );
}
```

`LinkTabs.tsx`:

```tsx
import type { ReactNode } from 'react';
import { Link, useLocation } from 'react-router';
import classes from './ui.module.css';

export interface LinkTab {
  to: string;
  label: ReactNode;
  match?: string[];
}

// LinkTabs are the design's page tabs when each tab is its own address (SSH keys | Key rotations). They are links in
// a named group — not a tablist and not a navigation landmark (the shell's nav must stay the only one).
export function LinkTabs({ items, label }: { items: LinkTab[]; label: string }) {
  const { pathname } = useLocation();
  return (
    <div className={classes.linkTabs} role="group" aria-label={label}>
      {items.map((it) => {
        const active = pathname === it.to || pathname.startsWith(`${it.to}/`) || (it.match ?? []).some((m) => pathname.startsWith(m));
        return (
          <Link key={it.to} to={it.to} className={classes.linkTab} aria-current={active ? 'page' : undefined} data-active={active || undefined}>
            {it.label}
          </Link>
        );
      })}
    </div>
  );
}
```

`DialogActions.tsx`:

```tsx
import type { ReactNode } from 'react';
import classes from './ui.module.css';

// DialogActions is the design's dialog footer bar (subtle background, a note on the left, buttons on the right).
export function DialogActions({ children, note }: { children: ReactNode; note?: ReactNode }) {
  return (
    <div className={classes.dialogActions}>
      {note && <span className={classes.dialogNote}>{note}</span>}
      {children}
    </div>
  );
}
```

`AppearanceControl.tsx`, `ThemeToggle.tsx`, `LanguageToggle.tsx`:

```tsx
// AppearanceControl.tsx
import { NativeSelect, Switch, useMantineColorScheme, type MantineColorScheme } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { setMyLocale } from '../../api/endpoints';
import { Icon } from '../../design/Icon';
import { LANGUAGES, setLanguage, type Lang } from '../../i18n';
import { useDensity } from '../../preferences';
import classes from './ui.module.css';

const MODES: { value: MantineColorScheme; key: string }[] = [
  { value: 'light', key: 'appearance.light' },
  { value: 'dark', key: 'appearance.dark' },
  { value: 'auto', key: 'appearance.system' },
];

// AppearanceControl is the design's appearance panel: color mode (per device), compact tables (per device) and the
// language (saved to the account when signed in, like the top bar's toggle).
export function AppearanceControl({ signedIn }: { signedIn: boolean }) {
  const { t, i18n } = useTranslation();
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const [density, setDensity] = useDensity();
  const changeLanguage = async (code: Lang) => {
    try {
      await setLanguage(i18n, code);
    } catch {
      return; // the texts could not be loaded; the current language stays
    }
    if (signedIn) {
      try {
        await setMyLocale(code);
      } catch {
        // best effort, as in the top bar
      }
    }
  };
  return (
    <div>
      <fieldset className={classes.modeSet}>
        <legend className={classes.fieldLabel}>{t('appearance.colorMode')}</legend>
        <div className={classes.appearanceOptions}>
          {MODES.map((m) => {
            const active = colorScheme === m.value;
            return (
              <label key={m.value} className={classes.appearanceOption} data-active={active || undefined}>
                <input type="radio" name="alice-color-mode" value={m.value} checked={active} onChange={() => setColorScheme(m.value)} className={classes.visuallyHidden} />
                <span className={classes.miniApp} data-mode={m.value} aria-hidden="true">
                  <i />
                  <span />
                </span>
                <span className={classes.themeChoice}>
                  {t(m.key)}
                  <Icon name={active ? 'CircleCheck' : 'Circle'} size={16} />
                </span>
              </label>
            );
          })}
        </div>
      </fieldset>
      <div className={classes.switchRow}>
        <div>
          <div className={classes.rowTitle}>{t('appearance.compact')}</div>
          <p className={classes.rowHelp}>{t('appearance.compactHelp')}</p>
        </div>
        <Switch checked={density === 'compact'} onChange={(e) => setDensity(e.currentTarget.checked ? 'compact' : 'comfortable')} aria-label={t('appearance.compact')} />
      </div>
      <div className={classes.switchRow}>
        <div>
          <div className={classes.rowTitle}>{t('language.label')}</div>
          {signedIn && <p className={classes.rowHelp}>{t('appearance.languageHelp')}</p>}
        </div>
        <NativeSelect aria-label={t('language.label')} value={i18n.language} onChange={(e) => void changeLanguage(e.currentTarget.value as Lang)} data={LANGUAGES.map((l) => ({ value: l.code, label: l.name }))} />
      </div>
    </div>
  );
}
```

```tsx
// ThemeToggle.tsx
import { ActionIcon, useComputedColorScheme, useMantineColorScheme } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Icon } from '../../design/Icon';

// ThemeToggle is the top bar's light/dark switch; it stores an explicit choice (Your account offers "System" again).
export function ThemeToggle() {
  const { t } = useTranslation();
  const { setColorScheme } = useMantineColorScheme();
  const computed = useComputedColorScheme('light');
  return (
    <ActionIcon variant="subtle" color="gray" size="lg" aria-label={t('appearance.toggle')} title={t('appearance.toggle')} onClick={() => setColorScheme(computed === 'dark' ? 'light' : 'dark')}>
      <Icon name={computed === 'dark' ? 'Sun' : 'Moon'} />
    </ActionIcon>
  );
}
```

```tsx
// LanguageToggle.tsx
import { Button } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { setMyLocale } from '../../api/endpoints';
import { LANGUAGES, setLanguage } from '../../i18n';
import classes from './ui.module.css';

// LanguageToggle is the design's TR/EN button (R9): it shows the other language's code and is named by that language's
// own name, so a person who reads only that language finds it. With two languages it toggles.
export function LanguageToggle({ signedIn }: { signedIn: boolean }) {
  const { i18n } = useTranslation();
  const other = LANGUAGES.find((l) => l.code !== i18n.language) ?? LANGUAGES[0];
  const change = async () => {
    try {
      await setLanguage(i18n, other.code);
    } catch {
      return;
    }
    if (signedIn) {
      try {
        await setMyLocale(other.code);
      } catch {
        // best effort: the page is already translated
      }
    }
  };
  return (
    <Button variant="subtle" color="gray" size="xs" aria-label={other.name} lang={other.code} onClick={() => void change()}>
      <span className={classes.langCode} aria-hidden="true">
        {other.code}
      </span>
    </Button>
  );
}
```

`status.ts` per C5 (import `TargetStatus` from `../../api/types`, `Deployment` and `isCancelled` from `../../api/deployments`, `ExpiryState` from `../Expiry`).

`index.ts` re-exports every component, its props types, `cx` and the `status.ts` helpers.

`ui.module.css` (from `styles.css`, tokens only):

```css
.pageHead { display: flex; align-items: center; justify-content: space-between; gap: 18px; margin-bottom: 26px; }
.pageHeadText { min-width: 0; }
.eyebrow { font-family: var(--mantine-font-family-monospace); font-size: 10px; font-weight: 500; text-transform: uppercase; letter-spacing: 1.3px; color: var(--alice-text-muted); margin-bottom: 7px; }
.description { font-size: 12px; margin-top: 9px; color: var(--alice-text-secondary); }
.actions { flex-wrap: wrap; justify-content: flex-end; }
.backLink { display: inline-flex; align-items: center; gap: 5px; font-size: 12px; font-weight: 550; margin-bottom: 16px; color: var(--alice-brand); }
.detailIcon { width: 48px; height: 52px; border: 1px solid var(--alice-border); background: var(--alice-surface); border-radius: 6px; display: grid; place-items: center; color: var(--alice-text-secondary); flex-shrink: 0; }
.panel { background: var(--alice-surface); border: 1px solid var(--alice-border); border-radius: var(--alice-radius-md); overflow: hidden; min-width: 0; }
.panelHead { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 20px 22px 0; }
.panelTitle { font-size: 16px; }
.panelDescription { font-size: 11px; margin-top: 4px; color: var(--alice-text-secondary); }
.panelBody { padding: 22px; }
.panelFlush { padding-top: 16px; }
.panelFoot { padding: 12px 22px; border-top: 1px solid var(--alice-border); display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; font-size: 11px; color: var(--alice-text-muted); }
.tablePanel { background: var(--alice-surface); border: 1px solid var(--alice-border); border-radius: var(--alice-radius-md); overflow: hidden; min-width: 0; }
.toolbar { display: flex; align-items: flex-end; gap: 8px; padding: 16px 18px; border-bottom: 1px solid var(--alice-border); flex-wrap: wrap; }
.tableBottom { padding: 13px 18px; border-top: 1px solid var(--alice-border); display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; font-size: 11px; color: var(--alice-text-muted); }
.dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; display: inline-block; }
.facts { margin: 0; display: grid; }
.fact { padding: 12px 0; border-bottom: 1px solid var(--alice-border); display: grid; grid-template-columns: 125px minmax(0, 1fr); gap: 12px; font-size: 12px; }
.fact:first-child { padding-top: 0; }
.fact:last-child { border-bottom: 0; padding-bottom: 0; }
.factLabel { color: var(--alice-text-muted); font-size: 11px; }
.factValue { margin: 0; min-width: 0; overflow-wrap: anywhere; }
.timeline { list-style: none; margin: 0; padding: 22px; }
.timelineStep { position: relative; display: flex; gap: 14px; padding-bottom: 25px; }
.timelineStep:last-child { padding-bottom: 0; }
.timelineStep::before { content: ''; position: absolute; left: 13px; top: 28px; bottom: 0; width: 1px; background: var(--alice-border); }
.timelineStep:last-child::before { display: none; }
.stepMarker { width: 28px; height: 28px; border: 1px solid var(--alice-border); border-radius: 50%; background: var(--alice-surface-subtle); display: grid; place-items: center; flex-shrink: 0; color: var(--alice-text-muted); position: relative; z-index: 1; }
.stepMarker[data-state='done'] { background: var(--alice-success-soft); border-color: var(--alice-brand-line); color: var(--alice-success); }
.stepMarker[data-state='failed'] { background: var(--alice-danger-soft); color: var(--alice-danger); }
.stepMarker[data-state='running'], .stepMarker[data-state='waiting'] { background: var(--alice-info-soft); color: var(--alice-info); }
.stepText { flex: 1; min-width: 0; }
.stepTitle { font-size: 12px; font-weight: 600; margin-top: 4px; }
.stepStatus { font-size: 11px; color: var(--alice-text-secondary); }
.stepDetail { font-size: 11px; margin-top: 5px; color: var(--alice-text-secondary); overflow-wrap: anywhere; }
.stepTime { margin-left: auto; padding-top: 5px; font-family: var(--mantine-font-family-monospace); font-size: 10px; color: var(--alice-text-muted); white-space: nowrap; }
.attentionList { list-style: none; margin: 0; padding: 9px 0 0; }
.attentionRow { display: flex; align-items: flex-start; gap: 11px; width: 100%; padding: 16px 22px; border: 0; border-bottom: 1px solid var(--alice-border); background: none; text-align: left; font: inherit; color: var(--alice-text); text-decoration: none; }
li:last-child > .attentionRow { border-bottom: 0; }
a.attentionRow:hover, button.attentionRow:hover { background: var(--alice-surface-hover); }
.statusBox { width: 29px; height: 29px; border-radius: 7px; display: grid; place-items: center; flex-shrink: 0; background: var(--alice-warning-soft); color: var(--alice-warning); }
.statusBox[data-tone='danger'] { background: var(--alice-danger-soft); color: var(--alice-danger); }
.statusBox[data-tone='info'] { background: var(--alice-info-soft); color: var(--alice-info); }
.attentionText { display: grid; gap: 4px; min-width: 0; }
.attentionTitle { font-size: 12px; font-weight: 600; }
.attentionDetail { font-size: 11px; color: var(--alice-text-secondary); overflow-wrap: anywhere; }
.attentionMeta { font-size: 10px; color: var(--alice-text-muted); }
.chevron { margin-left: auto; align-self: center; flex-shrink: 0; color: var(--alice-text-muted); }
.empty { text-align: center; padding: 60px 24px; }
.emptyIcon { color: var(--alice-text-muted); margin-bottom: 14px; }
.emptyTitle { margin: 0; font-size: 16px; font-weight: 600; color: var(--alice-text); }
.emptyText { margin: 8px auto 18px; max-width: 330px; font-size: 12px; color: var(--alice-text-secondary); }
.noticeAction { margin-top: 10px; }
.metricStrip { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); margin-bottom: 24px; padding: 23px 0; background: var(--alice-surface); border: 1px solid var(--alice-border); border-radius: var(--alice-radius-md); }
.metric { display: block; min-width: 0; padding: 0 23px; border-right: 1px solid var(--alice-border); color: var(--alice-text); text-decoration: none; }
.metric:last-child { border-right: 0; }
a.metric:hover .metricValue { color: var(--alice-brand); }
.metricLabel { display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 11px; color: var(--alice-text-secondary); }
.metricLabel svg { color: var(--alice-text-muted); }
.metricValue { display: block; margin: 9px 0 6px; font-size: 33px; font-weight: 530; line-height: 1.1; letter-spacing: -1.3px; font-variant-numeric: tabular-nums; }
.metricFoot { display: flex; align-items: center; gap: 5px; font-size: 11px; color: var(--alice-text-secondary); }
.metricFoot[data-tone='warning'] { color: var(--alice-warning); }
.metricFoot[data-tone='danger'] { color: var(--alice-danger); }
.linkTabs { display: flex; gap: 24px; margin-bottom: 24px; border-bottom: 1px solid var(--alice-border); overflow-x: auto; }
.linkTab { display: flex; align-items: center; gap: 8px; margin-bottom: -1px; padding: 0 0 13px; border-bottom: 2px solid transparent; white-space: nowrap; font-size: 12px; font-weight: 500; color: var(--alice-text-secondary); text-decoration: none; }
.linkTab[data-active] { border-color: var(--alice-brand); color: var(--alice-brand); }
.dialogActions { display: flex; align-items: center; justify-content: flex-end; flex-wrap: wrap; gap: 9px; margin: 24px -24px -24px; padding: 16px 24px; border-top: 1px solid var(--alice-border); background: var(--alice-surface-subtle); }
.dialogNote { margin-right: auto; font-size: 11px; color: var(--alice-text-muted); }
.modeSet { border: 0; margin: 0; padding: 0; min-width: 0; }
.fieldLabel { padding: 0; font-size: 11px; font-weight: 550; color: var(--alice-text); }
.appearanceOptions { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 13px; margin-top: 12px; }
.appearanceOption { display: block; padding: 10px; border: 1px solid var(--alice-border); border-radius: 8px; font-size: 12px; cursor: pointer; }
.appearanceOption[data-active] { padding: 9px; border: 2px solid var(--alice-brand); }
.appearanceOption:has(input:focus-visible) { outline: 3px solid var(--alice-focus); outline-offset: 3px; }
/* The previews show each mode as it looks, whatever the current scheme: fixed colors on purpose (aria-hidden). */
.miniApp { display: flex; gap: 5px; height: 76px; margin-bottom: 10px; padding: 5px; border-radius: 4px; background: #f4f6f2; border: 1px solid #cfd8d0; }
.miniApp > i { width: 23%; border-radius: 2px; background: #d8e3db; }
.miniApp > span { flex: 1; border-radius: 2px; background: repeating-linear-gradient(to bottom, #ffffff 0 10px, #e4eae3 10px 13px); }
.miniApp[data-mode='dark'] { background: #142019; border-color: #314538; }
.miniApp[data-mode='dark'] > i { background: #2d4435; }
.miniApp[data-mode='dark'] > span { background: repeating-linear-gradient(to bottom, #24372b 0 10px, #354b3e 10px 13px); }
.miniApp[data-mode='auto'] { background: linear-gradient(90deg, #f4f6f2 50%, #142019 50%); }
.miniApp[data-mode='auto'] > span { background: linear-gradient(90deg, #e4eae3 50%, #354b3e 50%); }
.themeChoice { display: flex; align-items: center; justify-content: space-between; gap: 6px; }
.visuallyHidden { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
.switchRow { display: flex; align-items: center; gap: 20px; padding: 18px 0; border-bottom: 1px solid var(--alice-border); }
.switchRow > :last-child { margin-left: auto; flex-shrink: 0; }
.rowTitle { font-size: 14px; font-weight: 600; }
.rowHelp { margin: 4px 0 0; font-size: 11px; color: var(--alice-text-secondary); }
.langCode { text-transform: uppercase; letter-spacing: 0.5px; font-size: 11px; }
@media (max-width: 1199px) { .panelHead { padding: 18px 18px 0; } .panelBody { padding: 18px; } }
@media (max-width: 1019px) { .pageHead { align-items: flex-start; } .metricStrip { padding: 18px 0; } .metricValue { font-size: 28px; } }
@media (max-width: 767px) {
  .pageHead { flex-wrap: wrap; gap: 12px; margin-bottom: 22px; }
  .actions { justify-content: flex-start; }
  .toolbar, .tableBottom { padding: 12px; }
  .fact { grid-template-columns: 110px minmax(0, 1fr); }
  .metricStrip { grid-template-columns: repeat(2, minmax(0, 1fr)); padding: 0; }
  .metric { padding: 18px; border-bottom: 1px solid var(--alice-border); }
  .metric:nth-child(2n) { border-right: 0; }
  .metric:nth-last-child(-n + 2) { border-bottom: 0; }
  .metricValue { font-size: 30px; }
  .appearanceOptions { gap: 7px; }
  .switchRow { flex-wrap: wrap; }
}
@media (max-width: 389px) { .fact { grid-template-columns: minmax(0, 1fr); gap: 4px; } }
```

`ErrorAlert.tsx`: below the action and details, show `t('jobs.errorCode', { code: error.code })` (in a `Text size="xs" c="dimmed"` with the code inside `<Code translate="no">`) when `error.code` is set, then the request ID line as today with `c="dimmed"` instead of `c="gray.7"`.

- [ ] **Step 4: Run**

Run: `cd web && npx vitest run src/components/ui src/components/ErrorAlert.test.tsx && cd .. && make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check && make web-coverage`
Expected: PASS; coverage at or above the floors.

- [ ] **Step 5: Commit**

```bash
git add -- web/src/components/ui
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): the Clarity design's shared components (page header, panel, resource table, status badge, fact list, operation timeline, attention item, empty state, notice, metric strip, link tabs, dialog actions, appearance controls); error alerts show the ALC code" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src/components/ui web/src/components/ErrorAlert.tsx web/src/components/ErrorAlert.test.tsx
```

Gap rows: CursorFooter instead of numbered pagination (R13); Notice `note` role for static notices; LinkTabs as a link group; the AppearanceControl language select (design: select) saves to the account.

---

### Task 4: Application shell, navigation groups, command palette, attention bell, banners and footer; the label changes and their e2e edits

**Design source:** `app.js` (`nav()`, `renderSidebar`, `renderTopbar`, `render` license-locked banner, `openSearch`/`renderSearch`, `notifications` dialog, `pageNames()`), `pages.js` `footer()`, `styles.css` (`.sidebar` … `.mobile-menu`, `.main`, `.footer`, the 1200/1020/760 media rules), `IMPLEMENTATION.md` §2, R5–R9, R11, "Label changes" rows 1–8.

**Files:**
- Modify: `web/src/layout/AppLayout.tsx`, `web/src/layout/AppLayout.test.tsx`, `web/src/components/BackupBanner.tsx`, `web/src/components/LicenseBanners.tsx`, `web/src/components/NotificationsBanner.tsx` (and their tests where a color or structure is asserted), `web/src/pages/DashboardPage.tsx` (the heading block only), `web/src/pages/DashboardPage.test.tsx` (heading assertions only), `web/src/App.test.tsx` and `web/src/screens.i18n.test.tsx` (only what the label changes break), `web/src/locales/{en,tr}.json` (under the lock), `web/e2e/helpers.ts`, `web/e2e/phase1.spec.ts`, `web/e2e/phase3.spec.ts`, `web/e2e/phase4.spec.ts`, `web/e2e/phase6.spec.ts`, `web/e2e/phase7.spec.ts`
- Create: `web/src/layout/AppLayout.module.css`, `web/src/components/shell/CommandPalette.tsx`, `web/src/components/shell/AttentionBell.tsx`, `web/src/components/shell/shell.test.tsx`, `web/src/components/dashboard/conditions.ts`, `web/src/components/dashboard/conditions.test.ts`
- Keep: `web/src/LanguageSwitcher.tsx` (still used by `LoginPage` until Task 15; Task 17 deletes it when unused)

**Interfaces:**
- Consumes: C4, C5 (`AttentionItem`, `ThemeToggle`, `LanguageToggle`, `cx`), `ALERTS_KEY`/`getAlerts`, `getVersion`, `listAllTargets`, `formatDateTime`.
- Produces: C6 (`conditions.ts`), C7 (`NAV_ITEMS` with `icon`/`group`/`match`, `ACCOUNT_ITEMS`, `isActive(item, pathname)`), the label changes.

- [ ] **Step 1: Keys and label changes (under the lock)**

New keys:

| Key | EN | TR |
|---|---|---|
| `shell.skip` | Skip to content | İçeriğe geç |
| `shell.workspace` | Workspace | Çalışma alanı |
| `shell.details` | Details | Ayrıntılar |
| `shell.installation` | Self-hosted installation | Kurum içi kurulum |
| `shell.versionLine` | Version {{version}} | Sürüm {{version}} |
| `shell.footer` | Self-hosted · Alice {{version}} | Kendi sunucunuzda · Alice {{version}} |
| `shell.search.open` | Search pages | Sayfalarda ara |
| `shell.search.title` | Go to a page | Bir sayfaya gidin |
| `shell.search.placeholder` | Find a page… | Bir sayfa bulun… |
| `shell.search.hint` | Only pages you can open · Enter opens the first · Esc closes | Yalnızca açabileceğiniz sayfalar · Enter ilkini açar · Esc kapatır |
| `shell.search.empty` | No page matches. | Eşleşen sayfa yok. |
| `shell.attention.open` | View attention items | İlgi bekleyenleri gör |
| `shell.attention.overview` | Open the overview | Genel bakışı aç |
| `nav.groups.inventory` | Inventory | Envanter |
| `nav.groups.operations` | Operations | Operasyon |
| `nav.groups.administration` | Administration | Yönetim |
| `nav.rotations` | Key rotations | Anahtar rotasyonları |

Changed values (Label changes table): `nav.dashboard` and `dashboard.title` → Overview / Genel bakış; `nav.users` and `users.title` → People & access / Kişiler ve erişim; `nav.audit` and `audit.title` → Audit trail / Denetim kaydı (TR unchanged); `nav.account` and `account.title` → Your account / Hesabınız; `nav.deployments` and `deployments.title` → Deployments / Dağıtımlar. Then search the **values** of `web/src/locales/en.json` and `tr.json` for the old page names used as page names (`grep -n "Audit log\|My account\|Deployment history\|the Users page\|Users page\|Dashboard\|Hesabım\|Dağıtım geçmişi\|Kullanıcılar sayfa\|Pano"`) and update those references to the new names; lower-case "audit log" as the thing (not the page) stays. Remove keys that become unused (`dashboard.welcome` once DashboardPage no longer uses it, `home.title` if unused — `grep -rn` in `web/src` and `web/e2e` first). `locales/common` is not edited (R11).

- [ ] **Step 2: Write the failing tests**

`web/src/layout/AppLayout.test.tsx` — keep the three existing tests (the Settings link test now finds `Settings` under Administration) and add:

```tsx
import { within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { auditorSession } from '../test/fixtures';
import { ACCOUNT_ITEMS, NAV_ITEMS, isActive } from './AppLayout';

// The brand link ("Alice.") is in the navigation too; it is not a destination.
const linkNames = () => within(screen.getByRole('navigation', { name: 'Main navigation' })).getAllByRole('link').map((a) => a.textContent ?? '').filter((n) => !n.startsWith('Alice'));

describe('AppLayout shell', () => {
  it.each([
    [adminSession, ['Overview', 'Certificates', 'SSH keys', 'Servers', 'Key Vaults', 'Deployments', 'Audit trail', 'People & access', 'Settings', 'License', 'Your account', 'API tokens']],
    [operatorSession, ['Overview', 'Certificates', 'SSH keys', 'Servers', 'Key Vaults', 'Deployments', 'Your account', 'API tokens']],
    [auditorSession, ['Overview', 'Certificates', 'SSH keys', 'Servers', 'Key Vaults', 'Deployments', 'Audit trail', 'License', 'Your account', 'API tokens']],
  ])('renders the destinations of each role, in the design’s groups', async (session, expected) => {
    server.use(...sessionHandlers(session));
    await renderRoute('/');
    await screen.findByRole('navigation', { name: 'Main navigation' });
    expect(linkNames()).toEqual(expected);
  });

  it('has one navigation landmark, group labels that are neither headings nor links, and one h1', async () => {
    server.use(...sessionHandlers(adminSession));
    await renderRoute('/license');
    await screen.findByRole('heading', { level: 1 });
    expect(screen.getAllByRole('navigation')).toHaveLength(1);
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.queryByRole('heading', { name: /Inventory|Operations|Administration/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Inventory' })).not.toBeInTheDocument();
  });

  it('marks the current page and keeps nav names exact', async () => {
    server.use(...sessionHandlers(adminSession));
    await renderRoute('/license');
    const link = await screen.findByRole('link', { name: 'License' });
    expect(link).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('link', { name: 'Overview' })).not.toHaveAttribute('aria-current');
  });

  it('shows the signed-in name alone, a visible Sign out button, the language toggle and the footer version', async () => {
    server.use(...sessionHandlers(adminSession));
    await renderRoute('/');
    expect(await screen.findByTestId('current-user')).toHaveTextContent(new RegExp(`^${adminSession.user.display_name}$`));
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Türkçe' })).toBeVisible();
    expect(await screen.findByText(/Self-hosted · Alice/)).toBeVisible();
  });

  it('puts the skip link, the navigation, the top bar and the main area in this order (Tab budget)', async () => {
    server.use(...sessionHandlers(adminSession));
    const { container } = await renderRoute('/');
    await screen.findByRole('navigation', { name: 'Main navigation' });
    const skip = screen.getByRole('link', { name: 'Skip to content' });
    const nav = screen.getByRole('navigation', { name: 'Main navigation' });
    const search = screen.getByRole('button', { name: 'Search pages' });
    const main = screen.getByRole('main');
    expect(skip.compareDocumentPosition(nav) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(nav.compareDocumentPosition(search) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(search.compareDocumentPosition(main) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(main).toHaveAttribute('id', 'main');
    expect(container.querySelector('a[href="#main"]')).toBe(skip);
  });

  it('writes the breadcrumb as plain text', async () => {
    // The server page itself may fail here (no target 'abc'): only the shell is under test.
    server.use(...sessionHandlers(adminSession), http.get(/\/api\/v1\/targets\/.*/, () => new HttpResponse(null, { status: 404 })));
    await renderRoute('/servers/abc');
    const crumb = await screen.findByTestId('breadcrumb');
    expect(crumb).toHaveTextContent('Workspace');
    expect(crumb).toHaveTextContent('Servers');
    expect(crumb).toHaveTextContent('Details');
    expect(within(crumb).queryByRole('link')).not.toBeInTheDocument();
  });

  it('activates Key rotations for run pages through match', () => {
    expect(isActive({ to: '/rotations', labelKey: 'nav.rotations', roles: [], icon: 'RotateCw', group: 'operations', match: ['/rotation/'] }, '/rotation/runs/1')).toBe(true);
    expect(isActive(NAV_ITEMS[0], '/servers')).toBe(false);
    expect(ACCOUNT_ITEMS.map((i) => i.to)).toEqual(['/account', '/tokens']);
  });
});
```

`web/src/components/shell/shell.test.tsx`:

```tsx
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { adminSession, operatorSession, sessionHandlers } from '../../test/fixtures';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

describe('command palette', () => {
  it('opens with Ctrl+K and lists only the pages the role may open', async () => {
    server.use(...sessionHandlers(operatorSession));
    await renderRoute('/');
    await screen.findByRole('navigation', { name: 'Main navigation' });
    await userEvent.keyboard('{Control>}k{/Control}');
    const dialog = await screen.findByRole('dialog', { name: 'Go to a page' });
    await userEvent.type(screen.getByRole('textbox', { name: 'Find a page…' }), 'audit');
    expect(dialog).toHaveTextContent('No page matches.');
  });
  it('opens the first match with Enter', async () => {
    server.use(...sessionHandlers(adminSession), http.get('/api/v1/audit', () => HttpResponse.json({ items: [], next_cursor: null })));
    const { router } = await renderRoute('/');
    await userEvent.click(await screen.findByRole('button', { name: 'Search pages' }));
    await userEvent.type(screen.getByRole('textbox', { name: 'Find a page…' }), 'audit{Enter}');
    await waitFor(() => expect(router.state.location.pathname).toBe('/audit'));
    expect(screen.queryByRole('dialog', { name: 'Go to a page' })).not.toBeInTheDocument();
  });
});

describe('attention bell', () => {
  it('reads /alerts only while open and shows each condition with its place', async () => {
    let reads = 0;
    server.use(
      ...sessionHandlers(adminSession),
      http.get('/api/v1/alerts', () => {
        reads++;
        return HttpResponse.json({ items: [{ kind: 'host_key_changed', object_id: 't1', name: 'seed-web-3', since: '2026-10-12T08:00:00Z', error_code: '' }] });
      }),
    );
    await renderRoute('/license');
    await screen.findByRole('navigation', { name: 'Main navigation' });
    expect(reads).toBe(0);
    await userEvent.click(screen.getByRole('button', { name: 'View attention items' }));
    expect(await screen.findByText('seed-web-3', { exact: true })).toBeVisible();
    expect(screen.getByRole('link', { name: /Host key changed|identity/i })).toHaveAttribute('href', '/servers/t1');
    expect(reads).toBe(1);
  });
});
```

(Use the exact `enum.targetStatus.host_key_changed` English text in the last regex.)

`conditions.test.ts`: `conditionTarget` for each kind (auth_failed of a vault → `/key-vaults/<id>`, of a server → `/servers/<id>`, host_key_changed, deployment_failed, audit_broken → `/audit`, notifications_failing → `/settings?tab=mail`, unknown → `null`); `conditionLabel` of an unknown kind is `null`; `conditionTone` and `CONDITION_ICON` cover the five kinds.

Run: `cd web && npx vitest run src/layout src/components/shell src/components/dashboard/conditions.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement**

`conditions.ts`: move `target` and `label` out of `AttentionList.tsx` as `conditionTarget`/`conditionLabel` (unchanged logic), add `CONDITION_ICON`, `conditionTone`, and `useConditionItems` (C6). Change `AttentionList.tsx` to import them (no visual change yet — Task 5 restyles it).

`AppLayout.tsx` (structure; keep the SSO-refusal effect, the close-on-navigation effect and the `SetupBanner` logic exactly):

```tsx
export type NavGroup = 'none' | 'inventory' | 'operations' | 'administration';
export interface NavItem { to: string; labelKey: string; roles: Role[]; icon: IconName; group: NavGroup; match?: string[] }

const ALL: Role[] = ['admin', 'operator', 'auditor'];

// NAV_ITEMS lists the side navigation in the design's groups. Roles mirror the server permissions (docs/authz-matrix.md);
// the UI is not an authorization boundary.
export const NAV_ITEMS: NavItem[] = [
  { to: '/', labelKey: 'nav.dashboard', roles: ALL, icon: 'LayoutDashboard', group: 'none' },
  { to: '/certificates', labelKey: 'nav.certificates', roles: ALL, icon: 'FileKey2', group: 'inventory' },
  { to: '/ssh-keys', labelKey: 'nav.sshKeys', roles: ALL, icon: 'KeyRound', group: 'inventory' },
  { to: '/servers', labelKey: 'nav.servers', roles: ALL, icon: 'Server', group: 'inventory' },
  { to: '/key-vaults', labelKey: 'nav.keyVaults', roles: ALL, icon: 'Cloud', group: 'inventory' },
  { to: '/deployments', labelKey: 'nav.deployments', roles: ALL, icon: 'Rocket', group: 'operations' },
  { to: '/audit', labelKey: 'nav.audit', roles: ['admin', 'auditor'], icon: 'ScrollText', group: 'operations' },
  { to: '/users', labelKey: 'nav.users', roles: ['admin'], icon: 'Users', group: 'administration' },
  { to: '/settings', labelKey: 'nav.settings', roles: ['admin'], icon: 'Settings2', group: 'administration' },
  { to: '/license', labelKey: 'nav.license', roles: ['admin', 'auditor'], icon: 'CreditCard', group: 'administration' },
];

export const ACCOUNT_ITEMS: NavItem[] = [
  { to: '/account', labelKey: 'nav.account', roles: ALL, icon: 'UserRound', group: 'none' },
  { to: '/tokens', labelKey: 'nav.tokens', roles: ALL, icon: 'KeySquare', group: 'none' },
];

const GROUPS: NavGroup[] = ['none', 'inventory', 'operations', 'administration'];

export function isActive(item: NavItem, pathname: string): boolean {
  if (item.to === '/') return pathname === '/';
  return pathname === item.to || pathname.startsWith(`${item.to}/`) || (item.match ?? []).some((m) => pathname.startsWith(m));
}

function initials(name: string, lang: string): string {
  return name.split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0]).join('').toLocaleUpperCase(lang);
}
```

Render (inside `AppLayout`, after the effects):

```tsx
const items = NAV_ITEMS.filter((i) => i.roles.includes(session.user.role));
const account = ACCOUNT_ITEMS.filter((i) => i.roles.includes(session.user.role));
const current = [...items, ...account].find((i) => isActive(i, location.pathname));
const deeper = current && current.to !== '/' && location.pathname !== current.to;
const navLink = (i: NavItem) => {
  const active = isActive(i, location.pathname);
  return (
    <NavLink key={i.to} component={Link} to={i.to} label={t(i.labelKey)} leftSection={<Icon name={i.icon} size={16} />}
      active={active} aria-current={active ? 'page' : undefined} onClick={nav.close} classNames={{ root: classes.link, label: classes.linkLabel }} />
  );
};
return (
  <AppShell header={{ height: 65 }} navbar={{ width: { sm: 202, lg: 222 }, breakpoint: 'sm', collapsed: { mobile: !navOpened } }} padding={0}>
    <a href="#main" className={classes.skipLink}>{t('shell.skip')}</a>
    <AppShell.Navbar id="app-navbar" aria-label={t('nav.label')} className={classes.navbar}>
      <Link to="/" className={classes.brand} onClick={nav.close}>
        <img src="/favicon.svg" alt="" className={classes.brandMark} />
        <span>{t('app.name', { ns: 'common' })}<span className={classes.brandDot} aria-hidden="true">.</span></span>
      </Link>
      <div className={classes.installation}>
        <span className={classes.installationSymbol}><Icon name="Building2" size={16} /></span>
        <div>
          <div className={classes.installationName}>{t('shell.installation')}</div>
          {version.data && <div className={classes.installationMeta}>{t('shell.versionLine', { version: version.data.version })}</div>}
        </div>
      </div>
      <div className={classes.navScroll}>
        {GROUPS.map((g) => {
          const inGroup = items.filter((i) => i.group === g);
          if (inGroup.length === 0) return null;
          return (
            <div key={g}>
              {g !== 'none' && <div className={classes.group}>{t(`nav.groups.${g}`)}</div>}
              {inGroup.map(navLink)}
            </div>
          );
        })}
      </div>
      <div className={classes.bottom}>
        {account.map(navLink)}
        <div className={classes.account}>
          <span className={classes.avatar} aria-hidden="true">{initials(session.user.display_name, i18n.language)}</span>
          <div className={classes.accountText}>
            <div className={classes.accountName} data-testid="current-user">{session.user.display_name}</div>
            <div className={classes.accountRole}>{t(`enum.role.${session.user.role}`)}</div>
          </div>
        </div>
        <Button variant="default" size="xs" fullWidth leftSection={<Icon name="LogOut" size={15} />} onClick={() => void signOut()}>
          {t('nav.signOut')}
        </Button>
      </div>
    </AppShell.Navbar>
    <AppShell.Header className={classes.header}>
      <div className={classes.headerInner}>
        <Group gap="sm" wrap="nowrap" style={{ minWidth: 0 }}>
          <Burger opened={navOpened} onClick={nav.toggle} hiddenFrom="sm" size="sm"
            aria-label={navOpened ? t('nav.closeMenu') : t('nav.openMenu')} aria-expanded={navOpened} aria-controls="app-navbar" />
          <div className={classes.breadcrumb} data-testid="breadcrumb">
            <span>{t('shell.workspace')}</span>
            <Icon name="ChevronRight" size={13} />
            <strong>{current ? t(current.labelKey) : t('app.name', { ns: 'common' })}</strong>
            {deeper && (<><Icon name="ChevronRight" size={13} /><span>{t('shell.details')}</span></>)}
          </div>
        </Group>
        <div className={classes.topActions}>
          <CommandPalette items={[...items, ...account]} />
          <span className={classes.divider} aria-hidden="true" />
          <ThemeToggle />
          <LanguageToggle signedIn />
          <AttentionBell />
        </div>
      </div>
    </AppShell.Header>
    <AppShell.Main id="main" tabIndex={-1}>
      <div className={classes.content}>
        <div className={classes.banners}>
          {signOutFailed && <Alert color="red" role="alert" data-testid="signout-error">{t('nav.signOutFailed')}</Alert>}
          <LicenseBanners />
          <NotificationsBanner />
          <BackupBanner />
          <SetupBanner />
          {stateReason && <SSOErrorAlert reason={stateReason} onClose={() => navigate({ pathname: location.pathname, search: location.search, hash: location.hash }, { replace: true })} />}
        </div>
        <Outlet />
        <footer className={classes.footer}>
          <Icon name="LockKeyhole" size={14} />
          <span>{version.data ? t('shell.footer', { version: version.data.version }) : t('app.name', { ns: 'common' })}</span>
        </footer>
      </div>
    </AppShell.Main>
  </AppShell>
);
```

`version` is `useQuery({ queryKey: ['version'], queryFn: getVersion })` (the key the dashboard already uses). The breadcrumb's `style={{ minWidth: 0 }}` is a React style property (CSSOM, allowed by the CSP); prefer a class if you add more. The brand mark is the existing `public/favicon.svg`; if it is not the design's `alice.svg`, copy `alice-design/dist/assets/alice.svg` over it in this task (same-origin image; record it in the report).

`AppLayout.module.css` (from `styles.css`; AppShell.Main keeps its own padding variables, so spacing goes on `.content`):

```css
.skipLink { position: fixed; top: -80px; left: 16px; z-index: 2000; padding: 12px; border-radius: 6px; background: var(--alice-brand); color: var(--alice-on-brand); }
.skipLink:focus { top: 12px; }
.navbar { display: flex; flex-direction: column; padding: 22px 13px 12px; background: var(--alice-surface); border-right: 1px solid var(--alice-border); }
.brand { display: flex; align-items: center; gap: 9px; padding: 0 12px 20px; font-size: 26px; font-weight: 650; letter-spacing: -1.6px; color: var(--alice-text); text-decoration: none; }
.brandMark { width: 30px; height: 30px; }
.brandDot { color: var(--alice-brand); }
.installation { display: flex; align-items: center; gap: 9px; margin: 0 4px 18px; padding: 10px; border: 1px solid var(--alice-border); border-radius: 8px; }
.installationSymbol { display: grid; place-items: center; width: 30px; height: 30px; flex-shrink: 0; border-radius: 6px; background: var(--alice-surface-subtle); color: var(--alice-text-secondary); }
.installationName { font-size: 12px; font-weight: 600; }
.installationMeta { font-size: 11px; color: var(--alice-text-secondary); }
.navScroll { flex: 1; overflow-y: auto; scrollbar-width: thin; }
.group { margin: 19px 0 8px; padding: 0 10px; font-size: 10px; font-weight: 600; letter-spacing: 1.3px; text-transform: uppercase; color: var(--alice-text-muted); }
.link { position: relative; min-height: 39px; margin: 2px 0; padding: 9px 11px; border-radius: 7px; color: var(--alice-text-secondary); }
.link:hover { background: var(--alice-surface-hover); color: var(--alice-text); }
.link[data-active] { background: var(--alice-brand-soft); color: var(--alice-brand); font-weight: 600; }
.link[data-active]::before { content: ''; position: absolute; left: 0; top: calc(50% - 8px); width: 3px; height: 16px; border-radius: 3px; background: var(--alice-brand); }
.linkLabel { font-size: 13px; }
.bottom { display: grid; gap: 6px; margin-top: 14px; padding-top: 14px; border-top: 1px solid var(--alice-border); }
.account { display: flex; align-items: center; gap: 9px; padding: 6px 8px; }
.accountText { min-width: 0; }
.avatar { display: grid; place-items: center; width: 30px; height: 30px; flex-shrink: 0; border-radius: 50%; border: 1px solid var(--alice-border); background: var(--alice-brand-soft); color: var(--alice-brand); font-size: 11px; font-weight: 600; }
.accountName { font-size: 12px; font-weight: 600; overflow-wrap: anywhere; }
.accountRole { font-size: 11px; color: var(--alice-text-secondary); }
.header { background: var(--alice-canvas); border-bottom: 1px solid var(--alice-border); }
.headerInner { display: flex; align-items: center; justify-content: space-between; gap: 16px; height: 100%; padding: 0 34px; }
.breadcrumb { display: flex; align-items: center; gap: 10px; min-width: 0; font-size: 12px; color: var(--alice-text-muted); }
.breadcrumb strong { font-weight: 500; color: var(--alice-text); }
.topActions { display: flex; align-items: center; gap: 9px; }
.divider { width: 1px; height: 20px; background: var(--alice-border); }
.content { max-width: 1700px; margin: 0 auto; padding: 30px 34px 48px; }
.banners { display: grid; gap: 12px; margin-bottom: 16px; }
.banners:empty { display: none; }
.footer { display: flex; align-items: center; gap: 8px; margin-top: 26px; font-size: 11px; color: var(--alice-text-muted); }
@media (min-width: 1600px) { .content { padding: 35px 44px; } .headerInner { padding: 0 44px; } }
@media (max-width: 1199px) { .content { padding: 26px 24px; } .headerInner { padding: 0 24px; } }
@media (max-width: 767px) {
  .headerInner { padding: 0 15px; gap: 8px; }
  .breadcrumb { display: none; }
  .content { padding: 24px 16px 32px; }
  .topActions { gap: 4px; }
  .divider { display: none; }
}
```

`CommandPalette.tsx`: a `Button variant="default" size="xs"` (accessible name and visible text `shell.search.open`, the visible text and the `⌘K` `<kbd aria-hidden>` hidden below `sm` with `visibleFrom`), `useHotkeys([['mod+K', open]])`, an `AppModal` titled `shell.search.title` with a `TextInput` (`aria-label`/`placeholder` `shell.search.placeholder`, `data-autofocus`, Enter opens the first match), a `<ul>` of `Link`s (icon + `t(labelKey)`) filtered with `toLocaleLowerCase(i18n.language)` on the translated label, the empty text and the hint. Closing clears the query. It receives `items` already filtered by role from `AppLayout` and never fetches anything (R7).

`AttentionBell.tsx`: `Popover` (position `bottom-end`, width 340, `trapFocus`) whose target is an `ActionIcon variant="subtle" color="gray" size="lg"` named `shell.attention.open` with the `Bell` icon; the dropdown has the title `dashboard.needsAttention`, reads `useQuery({ queryKey: ALERTS_KEY, queryFn: getAlerts, enabled: opened })`, shows `LoadingIndicator` / `ErrorAlert` / `dashboard.noAttention` / up to 6 `AttentionItem`s from `useConditionItems` (name in `<Code translate="no">` as detail, `dashboard.since` as meta), closes on any click inside the list, and ends with a link `shell.attention.overview` to `/` (R8).

Banners: `LicenseBanners`, `NotificationsBanner`, `BackupBanner` and `SetupBanner` keep their Alerts, colors-by-severity, roles, texts and test ids; replace `c="black"` on their links with `c="inherit"` and `fw={600}` (the tinted alert's own color, which the tokens hold at 4.5:1), and give each an `icon={<Icon …/>}` (danger `ShieldAlert`, warning/caution `CircleAlert`, info `CircleDot`). `backup-alarm-banner` must still contain only the `backups.alarm` text.

`DashboardPage.tsx`: replace the `<div>` with the two titles by `<Title order={1}>{t('dashboard.title')}</Title>` (Task 5 replaces it with `PageHeader`); nothing else.

- [ ] **Step 4: Edit the e2e specs for the label changes** (blind edit; Task 18 runs them)

- `web/e2e/helpers.ts` `COPY.en`: `navUsers: 'People & access'`, `navAudit: 'Audit trail'`, `navAccount: 'Your account'`, `usersHeading: 'People & access'`; `COPY.tr`: `navUsers: 'Kişiler ve erişim'`, `navAccount: 'Hesabınız'`, `usersHeading: 'Kişiler ve erişim'` (`navAudit` TR stays `Denetim kaydı`). Remove `welcome` from both and add:

```ts
// expectSignedInAs proves who is signed in after a sign-in or the wizard: the Overview heading and the sidebar's name
// (the design has no personal "Welcome" heading; label change 2 of docs/superpowers/plans/2026-10-12-phase-9-design.md).
export async function expectSignedInAs(page: Page, name: string): Promise<void> {
  const lang = await uiLang(page);
  await expect(page.getByRole('heading', { level: 1, name: translator(lang)('dashboard.title') })).toBeVisible();
  await expect(page.getByTestId('current-user')).toHaveText(name);
}
```

  and use it at `helpers.ts:603` (`await expectSignedInAs(page, admin.fullName)`).
- `phase1.spec.ts:158,183`: `await expectSignedInAs(page, ADMIN.fullName)`.
- `phase7.spec.ts:268,471,618,645,716`: `await expectSignedInAs(page, <the same name>)` (keep line 619's `current-user` assertion or drop it as now redundant).
- `phase3.spec.ts:116`, `phase4.spec.ts:109`, `phase6.spec.ts:347`: replace `page.getByText('Türkçe', { exact: true }).click()` (or `'English'`) by `page.getByRole('button', { name: 'Türkçe', exact: true }).click()` (or `'English'`), keeping the wait for `PUT /api/v1/auth/locale`.
- `grep -n "Audit log\|My account\|'Users'\|Kullanıcılar\|Hesabım" web/e2e/*.ts` afterwards: every remaining literal must be a deliberate one (a server text such as an audit action label is not a page name).

- [ ] **Step 5: Run**

Run: `make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check && make web`
Expected: PASS (`web/tsconfig.json` includes `e2e`, so `tsc` type-checks the edited specs).

- [ ] **Step 6: Commit**

```bash
git add -- web/src/layout/AppLayout.module.css web/src/components/shell web/src/components/dashboard/conditions.ts web/src/components/dashboard/conditions.test.ts
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): the design's application shell: grouped role-filtered navigation, installation card, account block, top bar with breadcrumb, page palette, theme and language toggles, attention popover; design page names (Overview, People & access, Audit trail, Your account, Deployments) with the e2e specs updated" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src/layout web/src/components/shell web/src/components/dashboard/conditions.ts \
  web/src/components/dashboard/conditions.test.ts web/src/components/dashboard/AttentionList.tsx web/src/components/BackupBanner.tsx \
  web/src/components/LicenseBanners.tsx web/src/components/NotificationsBanner.tsx web/src/pages/DashboardPage.tsx web/src/pages/DashboardPage.test.tsx \
  web/src/App.test.tsx web/src/screens.i18n.test.tsx web/e2e
```

(Commit only the test files you actually changed; drop the others from the path list.)

Gap rows: no organization name (no tenancy model); resource search (no API, R7); bell without unread state (R8); mobile navigation full-width (Mantine AppShell; e2e contract) instead of the design's 222 px drawer; Sign out and the account links visible in the sidebar instead of the design's account dialog.

---

### Task 5: Overview (dashboard) with Operations and Assurance

**Design source:** `pages.js` `overviewPage()`, `assuranceDashboard()`, `attentionRows()`, `activityItems()`; `styles.css` `.metric-strip`, `.dashboard-grid`, `.horizon*`, `.bars`, `.bar-column`, `.attention-*`, `.health-track`, `.micro-*`, `.activity-*`, `.rotation-path`, `.large-value`; `IMPLEMENTATION.md` §3; R10, R12.

**Files:**
- Modify: `web/src/pages/DashboardPage.tsx`, `web/src/pages/DashboardPage.test.tsx`, `web/src/components/dashboard/{Widget,CertificateCounts,ExpiringList,FailedDeployments,TargetsByStatus,LicenseCard,RotationUpcoming,AuditHead,BackupCard,AttentionList,SetupChecklist}.tsx` and their tests, `web/src/test/screens.ts` (under the lock, the `/` ready text), `web/src/locales/{en,tr}.json` (under the lock), `web/e2e/phase8.spec.ts`
- Create: `web/src/pages/DashboardPage.module.css`, `web/src/components/dashboard/ExpiryHorizon.tsx`, `web/src/components/dashboard/ExpiryHorizon.test.tsx`

**Interfaces:**
- Consumes: C5 (`PageHeader`, `Panel`, `MetricStrip`, `AttentionItem`, `StatusBadge`, `FactList`, `ResourceTable`, `EmptyState`), C6 (`useConditionItems`), `DashboardSummary`, `getExpiring`, `getAlerts`, `getVersion`, `listAudit({ limit: 5 })`.
- Produces: `ExpiryHorizon({ counts })` (`counts: DashboardSummary['certificates']`) with `data-testid="dashboard-counts"`, and `exclusiveBuckets(c): { key: 'expired' | 'd7' | 'd30' | 'd60'; count: number }[]`.

- [ ] **Step 1: Keys (under the lock)** — EN / TR from the design:

| Key | EN | TR |
|---|---|---|
| `dashboard.description` | Your certificates, keys and infrastructure. In clear view. | Sertifikalarınız, anahtarlarınız ve altyapınız. Tek bakışta. |
| `dashboard.updated` | Updated {{time}} | Güncellendi: {{time}} |
| `dashboard.tabs.label` | Overview views | Genel bakış görünümleri |
| `dashboard.tabs.operations` | Operations | Operasyon |
| `dashboard.tabs.assurance` | Assurance | Güvence |
| `dashboard.metrics.label` | Summary | Özet |
| `dashboard.metrics.monitored` | Monitored certificates | İzlenen sertifikalar |
| `dashboard.metrics.within30_one` / `_other` | {{count}} expires within 30 days / {{count}} expire within 30 days | {{count}} tanesi 30 gün içinde doluyor |
| `dashboard.metrics.targets` | Managed targets | Yönetilen hedefler |
| `dashboard.metrics.review_one` / `_other` | {{count}} needs review / {{count}} need review | {{count}} hedefi inceleyin |
| `dashboard.metrics.rotations` | Key rotations | Anahtar rotasyonları |
| `dashboard.metrics.rotationsRunning_one` / `_other` | {{count}} rotation in progress / {{count}} rotations in progress | {{count}} rotasyon devam ediyor |
| `dashboard.metrics.attention` | Needs attention | İlgi bekleyen |
| `dashboard.metrics.attentionFoot` | Conditions to resolve | Çözülmesi gereken durumlar |
| `dashboard.horizon.title` | Expiration horizon | Sertifika bitiş takvimi |
| `dashboard.horizon.subtitle` | Plan the next renewal before it becomes urgent. | Acil duruma dönüşmeden sonraki yenilemeyi planlayın. |
| `dashboard.horizon.window` | Time window | Zaman aralığı |
| `dashboard.horizon.days` | {{days}}d | {{days}}g |
| `dashboard.horizon.headline` | expiring within {{days}} days, expired included | {{days}} gün içinde doluyor, süresi dolanlar dahil |
| `dashboard.horizon.d7` | 1–7 days | 1–7 gün |
| `dashboard.horizon.d30` | 8–30 days | 8–30 gün |
| `dashboard.horizon.d60` | 31–60 days | 31–60 gün |
| `dashboard.horizon.chart` | Certificates by expiry: {{expired}} expired, {{d7}} within 7 days, {{d30}} in 8 to 30 days, {{d60}} in 31 to 60 days. | Bitişe göre sertifikalar: {{expired}} süresi dolmuş, {{d7}} 7 gün içinde, {{d30}} 8–30 gün içinde, {{d60}} 31–60 gün içinde. |
| `dashboard.horizon.cumulative` | Each link opens exactly the certificates it counts; longer windows include shorter ones. | Her bağlantı yalnızca saydığı sertifikaları açar; uzun pencereler kısa olanları da içerir. |
| `dashboard.panels.attentionSub` | The right next action, in priority order. | Öncelik sırasına göre sonraki adımlar. |
| `dashboard.panels.renewals` | Upcoming renewals | Yaklaşan yenilemeler |
| `dashboard.panels.renewalsSub` | Soonest expiry first · includes expired certificates | En yakın bitiş önce · süresi dolanlar dahil |
| `dashboard.panels.renewalsShown` | The {{count}} soonest are shown. | En yakın {{count}} kayıt gösteriliyor. |
| `dashboard.panels.viewAll` | View all | Tümünü gör |
| `dashboard.panels.connectivity` | Target connectivity | Hedef bağlantıları |
| `dashboard.panels.connectivitySub` | Last observed connection state | Son gözlemlenen bağlantı durumu |
| `dashboard.panels.connectedOf` | of {{total}} connected | / {{total}} bağlı |
| `dashboard.panels.openServers` | Open servers | Sunucuları aç |
| `dashboard.panels.deployments` | Recent deployments | Son dağıtımlar |
| `dashboard.panels.deploymentsSub` | A result you can inspect, step by step. | Adım adım inceleyebileceğiniz işlem sonuçları. |
| `dashboard.panels.viewHistory` | View history | Geçmiş |
| `dashboard.panels.rotation` | Key rotation | Anahtar rotasyonu |
| `dashboard.panels.rotationSub` | Planned transitions. Controlled access. | Planlı geçişler. Kontrollü erişim. |
| `dashboard.panels.openRotations` | View rotations | Rotasyonları gör |
| `dashboard.assurance.audit` | Audit integrity | Denetim bütünlüğü |
| `dashboard.assurance.auditSub` | Evidence from the latest chain verification | Son zincir doğrulamasından elde edilen kanıt |
| `dashboard.assurance.intact` | Chain intact | Zincir sağlam |
| `dashboard.assurance.scope` | Hash-chain continuity, not independent proof against a compromised host. External forwarding adds independent evidence. | Özet zinciri devamlılığı; ele geçirilmiş bir sunucuya karşı bağımsız kanıt değildir. Harici yönlendirme bağımsız kanıt sağlar. |
| `dashboard.assurance.inspect` | Inspect audit trail | Denetim kaydını incele |
| `dashboard.assurance.recovery` | Recovery readiness | Kurtarmaya hazırlık |
| `dashboard.assurance.recoverySub` | Backup status, without an invented health score | Yedekleme durumu ve son kontrol bilgileri |
| `dashboard.assurance.restoreDrill` | Restore drill | Geri yükleme provası |
| `dashboard.assurance.restoreNote` | Not established by a backup checksum | Yedek sağlama toplamı bunu kanıtlamaz |
| `dashboard.assurance.evidence` | Evidence trail | Kanıt kaydı |
| `dashboard.assurance.evidenceSub` | A traceable result for each sensitive action. | Her hassas işlem için izlenebilir sonuç. |

- [ ] **Step 2: Write the failing tests**

`ExpiryHorizon.test.tsx`:

```tsx
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { renderApp } from '../../test/render';
import { ExpiryHorizon, exclusiveBuckets } from './ExpiryHorizon';

const counts = { monitored: 8, expired: 1, within_7: 4, within_30: 7, within_60: 8, kv_expired: 5, kv_within_30: 9 };

describe('ExpiryHorizon', () => {
  it('derives exclusive buckets from cumulative counts (IMPLEMENTATION §3)', () => {
    expect(exclusiveBuckets(counts)).toEqual([
      { key: 'expired', count: 1 },
      { key: 'd7', count: 3 },
      { key: 'd30', count: 3 },
      { key: 'd60', count: 1 },
    ]);
  });
  it('never adds Key Vault keys and secrets to the certificate buckets', () => {
    const sum = exclusiveBuckets(counts).reduce((n, b) => n + b.count, 0);
    expect(sum).toBe(counts.within_60);
  });
  it('clamps a window that the server reports smaller than the one inside it', () => {
    expect(exclusiveBuckets({ ...counts, within_30: 3 }).find((b) => b.key === 'd30')!.count).toBe(0);
  });
  it('keeps the cumulative links, each named by its label and number only, and the monitored line', async () => {
    await renderApp(<MemoryRouter><ExpiryHorizon counts={counts} /></MemoryRouter>);
    const box = screen.getByTestId('dashboard-counts');
    expect(within(box).getByRole('link', { name: /^Expired\s*1$/ })).toHaveAttribute('href', '/certificates?expiry=expired');
    expect(within(box).getByRole('link', { name: /^Within 7 days\s*4$/ })).toHaveAttribute('href', '/certificates?expiry=7');
    expect(within(box).getByRole('link', { name: /^Within 30 days\s*7$/ })).toHaveAttribute('href', '/certificates?expiry=30');
    expect(within(box).getByRole('link', { name: /^Within 60 days\s*8$/ })).toHaveAttribute('href', '/certificates?expiry=60');
    expect(within(box).getByText('Certificates in use: 8', { exact: true })).toBeVisible();
    expect(screen.getByRole('img', { name: /1 expired, 3 within 7 days, 3 in 8 to 30 days, 1 in 31 to 60 days/ })).toBeVisible();
  });
  it('states the chosen cumulative window in the headline', async () => {
    await renderApp(<MemoryRouter><ExpiryHorizon counts={counts} /></MemoryRouter>);
    await userEvent.click(screen.getByRole('radio', { name: '7d' }));
    expect(screen.getByTestId('horizon-headline')).toHaveTextContent('4');
    expect(screen.getByTestId('horizon-headline')).toHaveTextContent('expiring within 7 days, expired included');
  });
});
```

`DashboardPage.test.tsx` — add (keep the existing partial-error and role tests, adapting texts):

```tsx
it('has the design’s header: the date eyebrow, Overview as the only h1 and the description', async () => {
  server.use(...sessionHandlers(adminSession), ...dashboardHandlers());
  await renderRoute('/');
  expect(await screen.findByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  expect(screen.getByText('Your certificates, keys and infrastructure. In clear view.')).toBeVisible();
});

it('hides the Assurance tab for an Operator, whose summary has no audit and no backup', async () => {
  server.use(...sessionHandlers(operatorSession), ...dashboardHandlers({ audit: null, backup: null }));
  await renderRoute('/');
  await screen.findByTestId('dashboard-counts');
  expect(screen.queryByRole('tab', { name: 'Assurance' })).not.toBeInTheDocument();
  expect(screen.queryByTestId('backup-card')).not.toBeInTheDocument();
});

it('shows audit integrity, recovery readiness and the license on the Assurance tab, kept in the address', async () => {
  server.use(...sessionHandlers(adminSession), ...dashboardHandlers());
  const { router } = await renderRoute('/');
  await userEvent.click(await screen.findByRole('tab', { name: 'Assurance' }));
  expect(router.state.location.search).toBe('?view=assurance');
  expect(await screen.findByTestId('audit-head')).toBeVisible();
  expect(screen.getByTestId('backup-card')).toHaveTextContent('Not established by a backup checksum');
  expect(screen.getByTestId('license-card')).toBeVisible();
});

it('lists conditions as attention items with the resource name as its own text', async () => {
  server.use(...sessionHandlers(adminSession), ...dashboardHandlers(), http.get('/api/v1/alerts', () => HttpResponse.json({ items: [{ kind: 'host_key_changed', object_id: 't1', name: 'seed-web-3', since: '2026-10-12T08:00:00Z', error_code: '' }] })));
  await renderRoute('/');
  const list = await screen.findByTestId('attention-list');
  expect(within(list).getByText('seed-web-3', { exact: true })).toBeVisible();
  expect(within(list).getByRole('link')).toHaveAttribute('href', '/servers/t1');
});

it('keeps the expiring list a real table with the name in the first code of each row and no total', async () => {
  server.use(...sessionHandlers(adminSession), ...dashboardHandlers());
  await renderRoute('/');
  const list = await screen.findByTestId('expiring-list');
  const rows = list.querySelectorAll('tbody tr');
  expect(rows.length).toBeGreaterThan(0);
  expect(rows[0].querySelector('code')).not.toBeNull();
  expect(list).not.toHaveTextContent(/ of \d+/);
});
```

(`dashboardHandlers(overrides?)` is a small helper at the top of the test file over the existing fixtures: summary with `emptyDashboardSummary` merged with overrides, `/dashboard/expiring` with one item, `/alerts` empty, `/version`, `/audit?limit=5` empty.)

Run: `cd web && npx vitest run src/pages/DashboardPage.test.tsx src/components/dashboard`
Expected: FAIL.

- [ ] **Step 3: Implement**

`ExpiryHorizon.tsx`: `exclusiveBuckets(c) = [{key:'expired', count:c.expired}, {key:'d7', count:max(0, c.within_7 - c.expired)}, {key:'d30', count:max(0, c.within_30 - c.within_7)}, {key:'d60', count:max(0, c.within_60 - c.within_30)}]`. The component is a `Panel` (`testId="dashboard-counts"`, title `dashboard.horizon.title`, description `…subtitle`, action = a Mantine `SegmentedControl` labelled `dashboard.horizon.window` with `7`, `30`, `60` whose labels are `dashboard.horizon.days`) with: the headline block (`data-testid="horizon-headline"`: the big number `within_<days>` and `dashboard.horizon.headline`; a `StatusBadge tone="danger"` with `dashboard.expired` + count when `expired > 0`); the bar chart (`role="img"`, `aria-label` = `dashboard.horizon.chart`; four columns, height proportional to the largest bucket with a 3 px minimum, colors `--alice-chart-expired`, `--alice-chart-urgent`, `--alice-chart`, `--alice-chart-muted`; each column shows its count and its label `dashboard.expired` / `dashboard.horizon.d7|d30|d60` as text); then the key row with the four cumulative links of `CertificateCounts` (label text + `<b>` count; the link's accessible name must be exactly "label count"), the `dashboard.monitored` text, the `dashboard.kvExpiring` link when `kv_within_30 > 0`, and the `dashboard.horizon.cumulative` note. `CertificateCounts.tsx` is deleted (its test moves into `ExpiryHorizon.test.tsx`).

`DashboardPage.tsx`:

```tsx
const [params, setParams] = useSearchParams();
const assuranceAllowed = !!(s?.audit || s?.backup);
const view = params.get('view') === 'assurance' && assuranceAllowed ? 'assurance' : 'operations';
return (
  <>
    <PageHeader
      eyebrow={new Intl.DateTimeFormat(i18n.language, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' }).format(now)}
      title={t('dashboard.title')}
      description={t('dashboard.description')}
    />
    {/* partial errors exactly as today: dashboard.loadFailed + one ErrorAlert per failed query */}
    {s?.setup_checklist && <SetupChecklist items={s.setup_checklist} />}
    <Tabs value={view} onChange={(v) => setParams(v === 'assurance' ? { view: 'assurance' } : {}, { replace: true })} aria-label={t('dashboard.tabs.label')}>
      <Tabs.List>
        <Tabs.Tab value="operations">{t('dashboard.tabs.operations')}</Tabs.Tab>
        {assuranceAllowed && <Tabs.Tab value="assurance">{t('dashboard.tabs.assurance')}</Tabs.Tab>}
        <span className={classes.updated} data-testid="server-status" aria-live="polite">{status /* home.server* as today */}{s && ` · ${t('dashboard.updated', { time: formatDateTime(s.generated_at, i18n.language) })}`}</span>
      </Tabs.List>
    </Tabs>
    {s && <MetricStrip label={t('dashboard.metrics.label')} items={metrics(s)} />}
    {view === 'operations' ? (
      <div className={classes.grid} aria-busy={loading}>
        {s && <ExpiryHorizon counts={s.certificates} />}
        {alerts.data && <AttentionList items={alerts.data.items} />}
        {expiring.data && <ExpiringList items={expiring.data.items} />}
        {s && <TargetsByStatus targets={s.targets} />}
        {s && <FailedDeployments deployments={s.deployments} />}
        {s && <RotationUpcoming rotation={s.rotation} />}
      </div>
    ) : (
      <div className={classes.assurance}>
        {s?.audit && <AuditHead audit={s.audit} />}
        {s?.backup && <BackupCard backup={s.backup} admin={role === 'admin'} />}
        {s && <LicenseCard license={s.license} detailed={role === 'admin' || role === 'auditor'} />}
        <EvidenceTrail />
      </div>
    )}
  </>
);
```

`now` comes from the existing `useNow()` of `Expiry.tsx`. The `" · "` join in the status line is a separator between two complete translated strings, not sentence assembly. `metrics(s)` builds the four `Metric`s: monitored (`value` `s.certificates.monitored`, foot `dashboard.metrics.within30` with `within_30`, `tone: 'warning'` when > 0, `to: '/certificates?expiry=30'`), targets (`s.targets.total`, foot `dashboard.metrics.review` with the sum of `by_status` for `host_key_changed`, `auth_failed`, `unreachable`, `degraded`, `pending_host_key`, `to: '/servers'`), rotations (`s.rotation.running`, foot `dashboard.metrics.rotationsRunning`, `to: '/rotations'`), attention (`s.attention`, foot `dashboard.metrics.attentionFoot`, `tone: 'warning'` when > 0, no link). The design's operations grid (`.dashboard-grid`: `minmax(0,1.65fr) minmax(310px,1fr)`, one column below 1020 px) goes into `DashboardPage.module.css`, with `.updated` (11 px, muted, `margin-left: auto`, `align-self: center`) and `.assurance` (two columns ≥ 1020 px).

Widgets: `Widget` becomes a `Panel` with `aria-label={title}` (keeps the named region and the `testId`); each widget keeps its `testId` and its texts and adopts the design: `AttentionList` → `<ul className={ui.attentionList}>` of `AttentionItem`s from `useConditionItems` (title = label, detail = name in `<Code translate="no">`, meta = `dashboard.since`, `to`), panel action = `StatusBadge tone="warning"` with the count of shown items when > 0, `EmptyState icon="ShieldCheck"` with `dashboard.noAttention` when empty; `ExpiringList` → `ResourceTable` (label `dashboard.panels.renewals`, rows as today: name in `<Code>`, where, `Expiry`) with footer `dashboard.panels.renewalsShown` and a `dashboard.panels.viewAll` link to `/certificates?expiry=30` — no total; `TargetsByStatus` → the design's connectivity panel: big number = `by_status.ok`, `dashboard.panels.connectedOf` with `total`, a health track (one segment per status with `flex-grow` = count, colors success/warning/danger tokens, `role="img"` with the per-status `dashboard.statusCount` list as label) and the existing per-status links; `FailedDeployments` → recent deployments activity list (icon by status, certificate name, target name, `DeploymentStatusBadge`-like `StatusBadge` with `deploymentTone`, time) with `failed_7d` as panel action badge and `dashboard.panels.viewHistory`; `RotationUpcoming` → key rotation panel (upcoming list, running and needs-attention counts as `StatusBadge`s, link `dashboard.panels.openRotations` to `/rotations`); `AuditHead` → audit integrity (`StatusBadge` intact/broken, `large-value` head sequence, `FactList` of last checked / head hash in `<Code>`, `dashboard.assurance.scope`, `dashboard.assurance.inspect` link); `BackupCard` → recovery readiness (alarm/failing as `Notice`, `large-value` age, `FactList` last backup, `dashboard.assurance.restoreDrill` = `dashboard.assurance.restoreNote`, admin link) keeping `backups.lastSuccess`, `backups.alarm`, `dashboard.backup.open`; `LicenseCard` keeps its logic; `SetupChecklist` → `Panel` with the design's attention rows (one `<li>` per item with its link and a `StatusBadge` required/done), keeping `data-testid="setup-checklist"`, the heading `dashboard.checklist.title`, list items and link names. `EvidenceTrail` (inside `DashboardPage.tsx`): a `Panel` with the 5 newest audit entries (`listAudit({ limit: 5 })`, enabled only on the Assurance tab) in a `ResourceTable` (time, actor, action label, result badge) and a link `dashboard.assurance.inspect` to `/audit`; it renders nothing for a 403.

`web/src/test/screens.ts` (lock): the `/` screen's ready text becomes `Expiration horizon` / `Sertifika bitiş takvimi` if `Expiring soon` is no longer visible.

- [ ] **Step 4: Edit `web/e2e/phase8.spec.ts`** (label change 9): before each `backup-card` assertion at lines 348–352, 373, 383 and 396, open the Assurance tab with `await page.getByRole('tab', { name: t('dashboard.tabs.assurance') }).click()` (the Operator check at line 383 stays `toHaveCount(0)` — and also expects the tab itself to be absent).

- [ ] **Step 5: Run**

Run: `make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -- web/src/pages/DashboardPage.module.css web/src/components/dashboard/ExpiryHorizon.tsx web/src/components/dashboard/ExpiryHorizon.test.tsx
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): the design's Overview: metric strip, expiry horizon from exclusive buckets, attention items, renewals, connectivity, recent deployments, rotation; Assurance tab with audit integrity, recovery readiness and license" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src/pages/DashboardPage.tsx web/src/pages/DashboardPage.test.tsx \
  web/src/pages/DashboardPage.module.css web/src/components/dashboard web/e2e/phase8.spec.ts
```

Gap rows: 5-day histogram → 4 exclusive buckets (R12); "SSH keys" metric → "Key rotations" (no total for keys); evidence trail limited to the 5 newest entries; license panel moved to Assurance (Operators see license states only through the banners); setup checklist ("Finish setting up") added in the design's attention-row language.

---

### Task 6: Certificates list and detail

**Design source:** `pages.js` `certificatesPage()`, `certRows()`, `nameCell()`, `expiryCell()`, `certificateDetail(id)`; `app.js` `upload-cert`, `create-csr`, `deployDialog`, `saveViewDialog`, `exportData`; `styles.css` `.filter-chips`, `.filter-chip`, `.toolbar`, `.resource-name`, `.resource-icon`, `.expiry-track`, `.detail-grid`, `.topology*`, `.usage-node`, `.connector`, `.validity`, `.progress-track`.

**Files:**
- Modify: `web/src/pages/CertificatesPage.tsx` (+ test), `web/src/pages/CertificateDetailPage.tsx` (+ test), `web/src/components/{PendingCSRs,SavedViews,ExportButton,UploadCertificateDialog,CreateCSRDialog,CSRPem,DeployDialog,ImportHistory,ImportToKeyVaultDialog,UploadWarnings,Expiry}.tsx` (and their tests where structure changes), `web/src/locales/{en,tr}.json` (lock)
- Create: `web/src/pages/CertificatesPage.module.css`, `web/src/pages/CertificateDetailPage.module.css`, `web/src/components/certificates/UsageTopology.tsx`, `web/src/components/certificates/UsageTopology.test.tsx`

**Interfaces:**
- Consumes: C5; `useUrlFilters`, `useDebouncedParam`, the existing infinite query; `DASHBOARD_KEY`/`getDashboardSummary` (chip counts); `CertificateDetail.locations` and `locations_truncated`.
- Produces: `Expiry` renders through `StatusBadge` (`expiryTone`, `expiryIcon`), keeping `part`, `data-state` and its texts.

- [ ] **Step 1: Keys (lock)**

| Key | EN | TR |
|---|---|---|
| `certificates.page.description` | Every certificate. Every location. One inventory. | Her sertifika ve kullanıldığı her konum. Tek envanter. |
| `certificates.page.chips` | Expiry shortcuts | Bitiş kısayolları |
| `certificates.page.all` | All certificates | Tüm sertifikalar |
| `certificates.page.next7` | Next 7 days | 7 gün içinde |
| `certificates.page.next30` | Next 30 days | 30 gün içinde |
| `certificates.page.cumulative` | Expiry filters are cumulative: “Next 30 days” includes expired certificates. | Bitiş filtreleri birikimlidir: “30 gün içinde” süresi dolan sertifikaları da içerir. |
| `certificates.page.noMatchTitle` | No matching certificates | Eşleşen sertifika yok |
| `certificates.page.noMatchText` | Try a different search or clear your filters. | Farklı bir arama deneyin veya filtreleri temizleyin. |
| `certificates.page.emptyTitle` | Your inventory starts here | Envanteriniz burada başlar |
| `certificates.page.usedTitle` | Where this certificate is used | Bu sertifika nerede kullanılıyor? |
| `certificates.page.usedSub` | Follow the source to the exact server and website. | Kaynaktan sunucuya ve web sitesine kadar izleyin. |
| `certificates.page.source` | Certificate source | Sertifika kaynağı |
| `certificates.page.locations` | Deployed locations | Kullanım konumları |
| `certificates.page.topologyNote` | Connections are the locations Alice discovered or deployed to. | Bağlantılar, Alice’in keşfettiği veya dağıttığı konumlardır. |
| `certificates.page.truncated` | More locations exist than are shown here. | Burada gösterilenden daha fazla konum var. |
| `certificates.page.details` | Certificate details | Sertifika ayrıntıları |
| `certificates.page.validity` | Validity | Geçerlilik |
| `certificates.page.remaining` | Time remaining | Kalan süre |
| `certificates.page.validityNote` | Certificate validity alone does not verify the remote endpoint. | Sertifika geçerliliği tek başına uzak uç noktayı doğrulamaz. |
| `certificates.page.nextAction` | Next action | Sonraki adım |
| `certificates.page.dataHandling` | Data handling | Veri kullanımı |
| `certificates.page.keysPrivate` | Private keys stay private | Özel anahtarlar gizli kalır |
| `certificates.page.keysPrivateText` | TLS private keys are never returned to the browser. Fingerprints and public certificate details are visible here. | TLS özel anahtarları tarayıcıya gönderilmez. Burada parmak izleri ve herkese açık sertifika bilgileri görünür. |

- [ ] **Step 2: Write the failing tests**

`CertificatesPage.test.tsx` — add:

```tsx
it('shows the design header, chips with the summary’s cumulative counts and none on All', async () => {
  server.use(...sessionHandlers(adminSession), http.get('/api/v1/dashboard/summary', () => HttpResponse.json({ ...emptyDashboardSummary, certificates: { ...emptyDashboardSummary.certificates, expired: 1, within_7: 4, within_30: 7 } })));
  await renderRoute('/certificates');
  expect(await screen.findByRole('heading', { level: 1, name: 'Certificates' })).toBeVisible();
  const chips = screen.getByRole('group', { name: 'Expiry shortcuts' });
  expect(within(chips).getByRole('button', { name: 'All certificates' })).toHaveTextContent(/^All certificates$/);
  expect(within(chips).getByRole('button', { name: /Next 7 days/ })).toHaveTextContent('4');
  expect(within(chips).getByRole('button', { name: /Next 30 days/ })).toHaveTextContent('7');
});

it('sets the same URL filter as the native expiry select from a chip', async () => {
  server.use(...sessionHandlers(adminSession));
  const { router } = await renderRoute('/certificates');
  await userEvent.click(within(await screen.findByRole('group', { name: 'Expiry shortcuts' })).getByRole('button', { name: /Next 30 days/ }));
  expect(router.state.location.search).toBe('?expiry=30');
  expect(screen.getByRole('combobox', { name: 'Expiry' })).toHaveValue('30');
  expect(within(screen.getByRole('group', { name: 'Expiry shortcuts' })).getByRole('button', { name: /Next 30 days/ })).toHaveAttribute('aria-pressed', 'true');
});

it.each([
  ['/certificates', 'Your inventory starts here'],
  ['/certificates?q=nothing', 'No matching certificates'],
])('tells an empty inventory from a filter without matches (%s)', async (path, text) => {
  server.use(...sessionHandlers(adminSession), targets, noCsrs, http.get('/api/v1/certificates', () => HttpResponse.json({ items: [], next_cursor: null })));
  await renderRoute(path);
  expect(await screen.findByText(text)).toBeVisible();
  expect(screen.queryByTestId('certificates-table')).not.toBeInTheDocument();
});

it('pages with the cursor and states only how many rows are shown', async () => {
  server.use(
    ...sessionHandlers(operatorSession),
    targets,
    noCsrs,
    http.get('/api/v1/certificates', ({ request }) => {
      const cursor = new URL(request.url).searchParams.get('cursor');
      if (cursor === 'p2') return HttpResponse.json({ items: [certificateFixture({ id: 'c3', subject_cn: 'second.example.test' })], next_cursor: null });
      return HttpResponse.json({ items: [certificateFixture({ id: 'c1' })], next_cursor: 'p2' });
    }),
  );
  await renderRoute('/certificates');
  expect(await screen.findByText('1 shown')).toBeVisible();
  await userEvent.click(screen.getByRole('button', { name: 'Show more' }));
  expect(await screen.findByText('2 shown')).toBeVisible();
  expect(screen.queryByRole('button', { name: 'Show more' })).not.toBeInTheDocument();
  expect(screen.queryByText(/ of \d+/)).not.toBeInTheDocument();
});
```

(`targets`, `noCsrs`, `certificateFixture` are this file's existing fixtures; `Show more` is the current `certificates.loadMore` text.)

`CertificateDetailPage.test.tsx` — add: the header has the resource tile, the label as the only h1 and the source line; the validity panel shows the days left and `Valid from`/`Valid until`; "Where this certificate is used" lists each location's server as a link to `/servers/<target_id>` (from `locations`, never from names) and shows `certificates.page.truncated` when `locations_truncated` is true; an expired certificate shows a danger `Notice` ("This certificate has expired" — reuse the existing expired texts) and the deploy button stays disabled with its hint; `deploy-hint`, `chain-hint`, the `certificates.detail.usedWhere` table (rows = sites + 1) and `certificates.keyHeld` text are unchanged.

`UsageTopology.test.tsx`: groups locations by `target_id`; one `usage-node` link per target with the site names; the source node names a Key Vault when the certificate came from one; no link is derived from a name.

Run: `cd web && npx vitest run src/pages/CertificatesPage.test.tsx src/pages/CertificateDetailPage.test.tsx src/components/certificates`
Expected: FAIL.

- [ ] **Step 3: Implement**

List page: `PageHeader` (title `certificates.title`, description, actions = `ExportButton`, Upload (operate), Create CSR as `variant="default"`); the chips row (`role="group"` `aria-label` `certificates.page.chips`; buttons with `aria-pressed`, `variant` `light` when pressed else `default`, the count in a `<b>` from the summary for expired/7/30, none for All; clicking sets `{ expiry: value }` through `setFilters`, All clears it); `PendingCSRs` restyled as a `Panel`; `ResourceTable` (`label` = existing table label, `testId="certificates-table"`, `minWidth` 720) whose `toolbar` holds the search `TextInput` (Search icon left section), the native selects (source, server, expiry — unchanged `NativeSelect`s with their labels), `SavedViews` and Clear filters, and whose `footer` is `CursorFooter` (`moreLabel` `certificates.loadMore`); rows as the design's `certRows()` (resource tile icon by source, the name in `<Code>` as today plus `sourceName · issuer` as secondary text, expiry date + `Expiry` badge, used-on count, algorithm, private key badge `Held by Alice`/`Not collected` when the row has that field, open link). The empty state is an `EmptyState` titled `certificates.page.emptyTitle` with the existing `certificates.empty` text as description (and the Upload action for operate roles); the no-match state is titled `certificates.page.noMatchTitle` with `…noMatchText` and a Clear filters button. Both are inside the table panel (the table is not rendered when there are no rows; the header row count contract applies only when rows exist). `certificates.page.cumulative` below the panel.

Detail page: `PageHeader` with `back` (`certificates.title` → `/certificates`), `icon="FileKey2"`, title = the existing h1 content (the label in `<Code>`), description = source line, actions = copy fingerprint (`CopyButton`), Deploy (existing logic and disabled reasons). Then the state `Notice` (expired danger / ≤ 7 days warning / else `certificates.page.validityNote` brand) and the design's `detail-grid` (`CertificateDetailPage.module.css`: `minmax(0,1.8fr) minmax(290px,1fr)`, one column below 1020 px): left — `UsageTopology` panel, `certificates.page.details` `FactList` (existing facts: CN, issuer, SANs in `<Code>`, algorithm, chain `StatusBadge`, private key, SHA-256 mono, the `chain-hint` text), the existing "used where" table (`ResourceTable`), recent deployments, import history (admin) — right — validity panel (eyebrow `certificates.page.remaining`, `large-value` days colored by `expiryTone`, `Progress` with `--alice-warning` ≤ 30 days else brand, `FactList` valid from/until), next action panel (the existing `deploy-hint` content and button), data handling panel. Dialogs (`UploadCertificateDialog`, `CreateCSRDialog`, `DeployDialog`, `ImportToKeyVaultDialog`) keep their fields, names and steps; their footers adopt `DialogActions`; inline `c=`/`color=` shades in them become semantic (`c="dimmed"`, `var(--alice-danger)`), and the gray-4 border styles become `var(--alice-border)`.

`UsageTopology.tsx`: source node (`usage-node center`, icon `Cloud` for Key Vault, `Server` for discovered, `FileKey2` otherwise; label = vault name or source label) → connector → targets column (one `Link` per `target_id` to `/servers/<id>` with the target name and its site names `<site>:443` from the location's listen/port fields as present in `CertificateLocation`), `certificates.page.topologyNote` in the panel footer, `certificates.page.truncated` when `locations_truncated`. CSS from `.topology`, `.topology-flow`, `.connector`, `.usage-node` (tokens only; the dotted background uses `--alice-border`).

- [ ] **Step 4: Run** — `make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check` — PASS.

- [ ] **Step 5: Commit**

```bash
git add -- web/src/pages/CertificatesPage.module.css web/src/pages/CertificateDetailPage.module.css web/src/components/certificates
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): certificates in the design: expiry chips with summary counts, inventory table with toolbar and cursor footer, detail with source-to-location view, validity and next action" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src/pages/CertificatesPage.tsx web/src/pages/CertificatesPage.test.tsx \
  web/src/pages/CertificatesPage.module.css web/src/pages/CertificateDetailPage.tsx web/src/pages/CertificateDetailPage.test.tsx \
  web/src/pages/CertificateDetailPage.module.css web/src/components/certificates web/src/components/PendingCSRs.tsx web/src/components/SavedViews.tsx \
  web/src/components/ExportButton.tsx web/src/components/UploadCertificateDialog.tsx web/src/components/CreateCSRDialog.tsx web/src/components/CSRPem.tsx \
  web/src/components/DeployDialog.tsx web/src/components/ImportHistory.tsx web/src/components/ImportToKeyVaultDialog.tsx web/src/components/UploadWarnings.tsx \
  web/src/components/Expiry.tsx
```

(Add the test files of the components you changed; drop paths you did not change.)

Gap rows: numbered pagination → cursor footer; "All" chip has no count (no total); native expiry select kept beside the chips (7/14/30/60/90 windows); pending CSRs, Create CSR, import into Key Vault, import history, truncated locations — design has none, built from Panel/ResourceTable/Notice; the design's Overview/Locations/Deployment history tabs are not built (sections on one page).

---

### Task 7: Servers list and detail

**Design source:** `pages.js` `serversPage()`, `serverDetail(id)`; `app.js` `add-target`, `review-host`, `discover`/`test-connection`; `styles.css` `.mini-stats`, `.mini-stat`, `.detail-grid`.

**Files:**
- Modify: `web/src/pages/TargetsPage.tsx` (+ test), `web/src/pages/TargetDetailPage.tsx` (+ test), `web/src/components/{AddServerModal,HostKeyConfirm,BlockedJobsPanel,PlatformKeyPanel,WebsitesPanel,LocationSettingsDialog,LocationWarning,TargetStatusBadge,JobErrorAlert,RemoveKeyDialog,KeyFlags}.tsx` (+ tests where structure changes), locales (lock)
- Create: `web/src/pages/TargetsPage.module.css`

**Interfaces:** Consumes C5 (`TARGET_TONE`, `TARGET_ICON`). Produces: `TargetStatusBadge` and `KeyFlags` render through `StatusBadge` (same props, texts, `testId`).

- [ ] **Step 1: Keys (lock)**

| Key | EN | TR |
|---|---|---|
| `targets.page.description` | Know what is connected, what changed, and what needs a closer look. | Bağlı hedefleri, değişiklikleri ve incelenmesi gerekenleri görün. |
| `targets.page.total` | in total | toplam |
| `targets.page.connected` | connected | bağlı |
| `targets.page.identityChanged` | identity changed | kimlik değişti |
| `targets.page.unreachable` | unreachable | erişilemiyor |
| `targets.page.vaultsElsewhere` | Azure Key Vaults are listed separately. | Azure Key Vault kasaları ayrı listelenir. |
| `targets.page.verifiedTitle` | Connection verified | Bağlantı doğrulandı |
| `targets.page.verifiedText` | Observed SSH identity matches the pinned fingerprint. | Gözlemlenen SSH kimliği sabitlenen parmak iziyle eşleşiyor. |
| `targets.page.unreachableTitle` | The last connection attempt failed | Son bağlantı denemesi başarısız oldu |
| `targets.page.unreachableText` | Inventory reflects the last successful discovery. Check reachability before changing credentials. | Envanter son başarılı keşfi yansıtır. Kimlik bilgilerini değiştirmeden önce erişimi kontrol edin. |
| `targets.page.connection` | Connection details | Bağlantı ayrıntıları |
| `targets.page.operations` | Available operations | Kullanılabilir işlemler |
| `targets.page.operationsText` | Alice updates certificate and key files through its restricted helper. Nginx configuration remains under your control. | Alice, kısıtlı yardımcı aracı üzerinden sertifika ve anahtar dosyalarını günceller. Nginx yapılandırması sizin kontrolünüzdedir. |
| `targets.page.readOnly` | Read only | Salt okunur |

- [ ] **Step 2: Write the failing tests** — `TargetsPage.test.tsx`: header (h1 `Servers`, description, Add server for admins only); mini-stats computed from the **complete** list (`listAllServers`) — total, `ok`, `host_key_changed`, `unreachable` — each a number plus its state word; `targets-table` still has exactly one header row plus one row per server; status cells are `StatusBadge`s with text and icon (`data-tone`); `BlockedJobsPanel` ("Waiting for an administrator", `blocked-jobs`) and `PlatformKeyPanel` still render for admins. `TargetDetailPage.test.tsx`: header with `icon="Server"`, the server name as the only h1, `target-status` badge text exact; `host_key_changed` shows a danger `Notice` with the review button (admins) and keeps `host-key-changed`; unreachable shows `targets.page.unreachableTitle`; ok shows `targets.page.verifiedTitle`; connection details `FactList` includes the pinned fingerprint in mono; `target-keys` first cell is still the OS user; Operators see `targets.page.readOnly` instead of admin-only buttons (existing gating unchanged).

Run: `cd web && npx vitest run src/pages/TargetsPage.test.tsx src/pages/TargetDetailPage.test.tsx` — FAIL.

- [ ] **Step 3: Implement** — List: `PageHeader` (actions: Add server for admins), the design's mini-stats row (`TargetsPage.module.css` `.miniStats`/`.miniStat`: number in `<b>` 18 px, a dot in the tone color, the state word), `BlockedJobsPanel` as a `Panel` (title `jobs.blockedTitle`, its buttons and `blocked-jobs` ids unchanged) and `PlatformKeyPanel` as a `Panel` above the table, then `ResourceTable` (`testId="targets-table"`, columns Server (tile + name link + OS/type secondary), Address (`host:port` mono), Platform badge, Connection (`TargetStatusBadge`), Last checked (mono), open icon link with an `aria-label` naming the server) and footer `targets.page.vaultsElsewhere`; no extra rows (the empty state replaces the table). Detail: `PageHeader` (`back` to `/servers`, `icon="Server"`, status badge, description `host:port · platform`, actions: Test connection / Discover for operate, Delete for admins), the identity `Notice` (danger/warning/brand per status), then `detail-grid`: left — keys table (`target-keys`), `WebsitesPanel` (Nginx), host-key confirmation card as a `Panel` — right — `targets.page.connection` `FactList` (state badge, address, platform, last checked, discovery interval if present, host fingerprint mono), `targets.page.operations` panel (`operationsText` + the operate buttons or the read-only badge). Job alerts (`JobErrorAlert` with its error code line, `StillWorkingAlert`, `BlockedJobAlert`, `StoppedJobAlert`) keep texts and roles; `c="gray.7"` → `c="dimmed"`. Dialogs keep fields and names, footers adopt `DialogActions`.

- [ ] **Step 4: Run** — `make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check` — PASS.

- [ ] **Step 5: Commit**

```bash
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): servers in the design: connection mini-stats, inventory table, identity notices, connection facts and operations panel; held jobs and the platform key as panels" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src/pages/TargetsPage.tsx web/src/pages/TargetsPage.test.tsx \
  web/src/pages/TargetsPage.module.css web/src/pages/TargetDetailPage.tsx web/src/pages/TargetDetailPage.test.tsx web/src/components/AddServerModal.tsx \
  web/src/components/HostKeyConfirm.tsx web/src/components/BlockedJobsPanel.tsx web/src/components/PlatformKeyPanel.tsx web/src/components/WebsitesPanel.tsx \
  web/src/components/LocationSettingsDialog.tsx web/src/components/LocationWarning.tsx web/src/components/TargetStatusBadge.tsx \
  web/src/components/JobErrorAlert.tsx web/src/components/RemoveKeyDialog.tsx web/src/components/KeyFlags.tsx
```

(`git add --` the new `TargetsPage.module.css` first; add changed component tests.)

Gap rows: held jobs "Waiting for an administrator", the platform public key and preparation script, host-key confirmation and repin, websites with verification settings, job progress alerts, delete — built from Panel/Notice/FactList/ResourceTable; the design's "Certificates on this server" panel is covered by the websites panel (locations with certificates).

---

### Task 8: Key Vaults list, detail and Key Vault certificate

**Design source:** `pages.js` `vaultsPage()`, `vaultDetail(id)`, `vaultCertificateDetail()`; `app.js` `connect-vault`, `check-vault`; `styles.css` `.vault-card`, `.vault-counts`, `.resource-icon.azure`.

**Files:**
- Modify: `web/src/pages/KeyVaultsPage.tsx`, `KeyVaultDetailPage.tsx`, `KVCertificatePage.tsx` (+ tests), `web/src/components/{VaultInventory,VaultStatusBadge,AccessCheckPanel,AddKeyVaultDialog,ReplaceCredentialsDialog,BindingPanel,ConnectWebsitesDialog,KVDeployDialog,AutoDeploySwitch,RoleGuide,SignInFields,vaultText}.ts(x)` (+ tests where structure changes), locales (lock)
- Create: `web/src/pages/KeyVaults.module.css`

**Interfaces:** Consumes C5. Produces: `VaultStatusBadge` through `StatusBadge` (same props/texts/`testId`).

- [ ] **Step 1: Keys (lock)**

| Key | EN | TR |
|---|---|---|
| `vaults.page.description` | See certificate versions and the websites connected to them. | Sertifika sürümlerini ve bunlara bağlı web sitelerini görün. |
| `vaults.page.boundaryTitle` | A precise boundary for Azure access | Azure erişimi için net kapsam |
| `vaults.page.boundaryText` | Certificates can be monitored and deployed to Nginx. Keys are inventory-only; secrets show metadata only. | Sertifikalar izlenebilir ve Nginx’e dağıtılabilir. Anahtarlar yalnızca envanter içindir; gizli verilerin sadece üst bilgileri gösterilir. |
| `vaults.page.keysOnlyTitle` | Key inventory only | Yalnızca anahtar envanteri |
| `vaults.page.keysOnlyText` | Azure Key Vault key rotation is outside Alice v1 scope. | Azure Key Vault anahtar rotasyonu Alice v1 kapsamı dışındadır. |
| `vaults.page.metadataTitle` | Metadata only | Yalnızca üst bilgi |
| `vaults.page.metadataText` | Secret values are never shown. Certificate backing secrets are used only for authorized certificate deployment. | Gizli veri değerleri gösterilmez. Sertifika özel anahtarları sadece yetkili dağıtımlarda kullanılır. |
| `vaults.page.versions` | Version history | Sürüm geçmişi |
| `vaults.page.versionsSub` | A new version is reviewed before it reaches a website. | Yeni sürüm web sitesine ulaşmadan önce incelenir. |
| `vaults.page.policy` | Certificate policy | Sertifika ilkesi |
| `vaults.page.autoDeployTitle` | Automatic deployment is an administrator decision | Otomatik dağıtım yönetici kararıdır |
| `vaults.page.autoDeployText` | Changing this setting requires fresh identity verification. | Bu ayarı değiştirmek için yeniden kimlik doğrulaması gerekir. |

- [ ] **Step 2: Write the failing tests** — `KeyVaultsPage.test.tsx`: header (h1 `Key Vaults`, description, Add Key Vault for admins), `vaults-table` with one row per vault whose first cell has the vault tile (`Cloud`, info tone) and the name link (exact), status `StatusBadge`, last checked; the boundary `Notice` below the table; `BlockedJobsPanel` kept. `KeyVaultDetailPage.test.tsx`: header (`back`, vault name h1, URL in `<Code>`, `vault-status`), the Mantine tabs with the same names; on the Keys tab the `vaults.page.keysOnlyTitle` notice; on the Secrets tab `vaults.page.metadataTitle`; the scroll region of each tab's table is still the named group (unchanged theme); `vault-status-help`, `vault-firewall-address`, `credentials-expiry`, `vault-warning` kept. `KVCertificatePage.test.tsx`: header, `vaults.page.versions` panel with the versions table (`kv-version-row`, order and `data-held` unchanged, `held-text`), the policy `FactList`, `binding-panel`, the auto-deploy `Notice`, and the admin-only release button with step-up unchanged.

Run: `cd web && npx vitest run src/pages/KeyVaultsPage.test.tsx src/pages/KeyVaultDetailPage.test.tsx src/pages/KVCertificatePage.test.tsx` — FAIL.

- [ ] **Step 3: Implement** — List: `PageHeader`; `ResourceTable` (`testId="vaults-table"`, minWidth 720) instead of the design's cards (R13 + e2e: rows filtered by link; recorded gap), row content from the card: tile, name + host mono, auth method, status, counts columns when present in `Target.vault`, last synced; boundary `Notice` (brand). Detail: `PageHeader` with status; access check panel, role guide and polling form as `Panel`s; tabs styled by the theme; per-tab `Notice` (keys/secrets); tables through `ResourceTable` where they are standalone tables (keep `aria-label`s = tab names). KV certificate: `detail-grid` with versions + connected websites (`BindingPanel`) left, policy `FactList` + auto-deploy `Notice` right. Dialogs keep fields; footers `DialogActions`; `SignInFields` unchanged except colors.

- [ ] **Step 4: Run** — `make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check` — PASS.

- [ ] **Step 5: Commit**

```bash
git add -- web/src/pages/KeyVaults.module.css
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): Key Vaults in the design: inventory with the Azure access boundary, detail tabs with keys-only and metadata-only notices, certificate versions and connected websites" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src/pages/KeyVaultsPage.tsx web/src/pages/KeyVaultsPage.test.tsx \
  web/src/pages/KeyVaultDetailPage.tsx web/src/pages/KeyVaultDetailPage.test.tsx web/src/pages/KVCertificatePage.tsx web/src/pages/KVCertificatePage.test.tsx \
  web/src/pages/KeyVaults.module.css web/src/components/VaultInventory.tsx web/src/components/VaultStatusBadge.tsx web/src/components/AccessCheckPanel.tsx \
  web/src/components/AddKeyVaultDialog.tsx web/src/components/ReplaceCredentialsDialog.tsx web/src/components/BindingPanel.tsx \
  web/src/components/ConnectWebsitesDialog.tsx web/src/components/KVDeployDialog.tsx web/src/components/AutoDeploySwitch.tsx web/src/components/RoleGuide.tsx \
  web/src/components/SignInFields.tsx
```

Gap rows: vault cards → table (e2e and scale); access check (monitor/deploy/import), firewall/throttled states, replace credentials, polling interval, delete with bindings, release of held versions, imports — design has none, built from Panel/Notice/FactList/ResourceTable/StatusBadge.

---

### Task 9: SSH keys list and detail (with the rotation policy panel)

**Design source:** `pages.js` `sshKeysPage()`, `sshKeyDetail(id)`; `app.js` `generate-key`, `private-key`, `remove-key`, `preview-policy`, `create-policy`; R19, R20.

**Files:**
- Modify: `web/src/pages/SSHKeysPage.tsx`, `SSHKeyDetailPage.tsx` (+ tests), `web/src/components/{RotationPolicyPanel,RotationPolicyDialog,RotationPreviewDialog,GenerateKeyDialog,DeployKeyDialog,DownloadKeyDialog}.tsx` (+ tests where structure changes), locales (lock)

**Interfaces:** Consumes C5 (`LinkTabs`). Produces: the SSH keys `LinkTabs` items `[{ to: '/ssh-keys', label: t('sshKeys.page.inventory') }, { to: '/rotations', label: t('nav.rotations'), match: ['/rotation/'] }]` exported as `SSH_KEY_TABS(t)` from `SSHKeysPage.tsx` for Task 10.

- [ ] **Step 1: Keys (lock)**

| Key | EN | TR |
|---|---|---|
| `sshKeys.page.description` | Understand access. Rotate with control. | Erişimi anlayın. Kontrollü rotasyon uygulayın. |
| `sshKeys.page.sections` | SSH key sections | SSH anahtarı bölümleri |
| `sshKeys.page.inventory` | Inventory | Envanter |
| `sshKeys.page.weakTitle` | Weak keys need review | Zayıf anahtarlar incelenmeli |
| `sshKeys.page.weakText` | Review a weak key’s locations before replacing it. | Değiştirmeden önce zayıf anahtarın kullanım konumlarını inceleyin. |
| `sshKeys.page.showWeak` | Show weak keys | Zayıf anahtarları göster |
| `sshKeys.page.publicIdentity` | Public identity | Herkese açık kimlik |
| `sshKeys.page.removeNote` | Removal applies to one selected location. A shared key can still exist on other servers. | Kaldırma işlemi seçilen tek konum için geçerlidir. Paylaşılan anahtar başka sunucularda bulunmaya devam edebilir. |
| `sshKeys.page.reviewBeforeRemoving` | Review before removing | Kaldırmadan önce inceleyin |

- [ ] **Step 2: Write the failing tests** — `SSHKeysPage.test.tsx`: header (h1 `SSH keys`, description, Export, Generate key for admin/operator), `LinkTabs` group `SSH key sections` with `Inventory` current and `Key rotations` linking to `/rotations`, no `tablist`; the weak-keys `Notice` with a link `Show weak keys` to `?flag=weak` and **no count** (R20); `ssh-keys-table` unchanged (rows, links, flags), cursor footer (`sshKeys.loadMore`), saved views, export, missing-keys switch. `SSHKeyDetailPage.test.tsx`: header (`back`, `sshKeys.detailTitle` h1, type · managed/discovered description, Download private key for admins when the key exists), `managed-key` text exact, the "Where this key is used" heading and `key-locations` table unchanged (first cell user), `sshKeys.page.publicIdentity` `FactList` (fingerprint `<Code>`), `rotation-panel` unchanged in behaviour, `sshKeys.page.reviewBeforeRemoving` notice.

Run: `cd web && npx vitest run src/pages/SSHKeysPage.test.tsx src/pages/SSHKeyDetailPage.test.tsx` — FAIL.

- [ ] **Step 3: Implement** — List: `PageHeader`, `LinkTabs` (`SSH_KEY_TABS`), weak `Notice` (warning) with the filter link (shown always for operate roles? — show it always: it costs nothing and needs no count), `ResourceTable` (`testId="ssh-keys-table"`, toolbar: search, the existing native selects, the missing switch, `SavedViews`, `ExportButton`, Clear; footer `CursorFooter`), rows per design (tile `KeyRound`, label link + fingerprint prefix mono, algorithm (+ weak `StatusBadge` via `KeyFlags`), locations, managed `StatusBadge` `Alice managed`/`Discovered` using existing texts, rotation status `StatusBadge` when present). Detail: `PageHeader`; `detail-grid` left — locations table (`key-locations`), public identity `FactList` (fingerprint, algorithm, public key block with `CopyButton`), managed block — right — `RotationPolicyPanel` restyled as a `Panel` (testid `rotation-panel`, switch, buttons, dialogs unchanged; its run links point to `/rotation/runs/<id>`), the removal `Notice`. Dialogs keep fields, focus order and Tab budgets (60/80); footers `DialogActions` placed **after** the existing controls so the Tab order before the submit button does not grow.

- [ ] **Step 4: Run** — `make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check` — PASS.

- [ ] **Step 5: Commit**

```bash
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): SSH keys in the design: inventory and rotation link tabs, weak-key filter notice, inventory table with cursor footer, detail with locations, public identity and the rotation policy panel" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src/pages/SSHKeysPage.tsx web/src/pages/SSHKeysPage.test.tsx \
  web/src/pages/SSHKeyDetailPage.tsx web/src/pages/SSHKeyDetailPage.test.tsx web/src/components/RotationPolicyPanel.tsx \
  web/src/components/RotationPolicyDialog.tsx web/src/components/RotationPreviewDialog.tsx web/src/components/GenerateKeyDialog.tsx \
  web/src/components/DeployKeyDialog.tsx web/src/components/DownloadKeyDialog.tsx
```

Gap rows: weak-key count not shown (R20); deploy key to a server, private-key download with protection, last-root-key confirmation, missing keys, Alice connection key flag — built from the shared components.

---

### Task 10: Key rotations page (`/rotations`) and the rotation run page

**Design source:** `pages.js` `rotationsPage()`, `rotationDetail()`; `app.js` `finish-rotation`, `abort-rotation`; `styles.css` `.rotation-path`, `.rotation-phase`; `IMPLEMENTATION.md` §5; R19.

**Files:**
- Create: `web/src/pages/RotationsPage.tsx`, `web/src/pages/RotationsPage.test.tsx`, `web/src/pages/Rotations.module.css`, `web/src/components/rotation/RotationPath.tsx`, `web/src/components/rotation/RotationPath.test.tsx`
- Modify: `web/src/api/rotation.ts` (`listPolicies`), `web/src/router.tsx` (`{ path: 'rotations', element: <RotationsPage /> }`), `web/src/layout/AppLayout.tsx` (the `NAV_ITEMS` entry only), `web/src/layout/AppLayout.test.tsx` (role lists gain `Key rotations` after `Deployments`), `web/src/pages/RotationRunPage.tsx` (+ test), `web/src/components/rotationText.tsx`, `web/src/test/screens.ts` (lock: `/rotations` for admin, operator and auditor), `web/src/test/server.ts` (default handler for `GET /api/v1/rotation/policies` returning `{ items: [] }` if a default handler set exists there), locales (lock)

**Interfaces:**
- Consumes: `listRuns`, `TERMINAL_RUN`, `Policy`, `RunSummary`, `Run`, `ROTATION_POLICIES_KEY`, `ROTATION_RUNS_KEY`, `SSH_KEY_TABS` (Task 9), C5.
- Produces: `export const listPolicies = () => apiFetch<{ items: Policy[] }>(\`${v1}/policies\`);` (`GET /api/v1/rotation/policies`, permission `read`, every live policy, no cursor — openapi `listRotationPolicies`); `NAV_ITEMS` entry `{ to: '/rotations', labelKey: 'nav.rotations', roles: ALL, icon: 'RotateCw', group: 'operations', match: ['/rotation/'] }` between Deployments and Audit trail; `RotationPath({ status }: { status: string })`.

- [ ] **Step 1: Keys (lock)**

| Key | EN | TR |
|---|---|---|
| `rotation.page.description` | Move from one key to the next without losing the transition. | Anahtar değişimini kontrollü bir geçişle yönetin. |
| `rotation.page.active` | Active rotations | Aktif rotasyonlar |
| `rotation.page.noActive` | No rotation is running. | Çalışan rotasyon yok. |
| `rotation.page.policies` | Rotation policies | Rotasyon ilkeleri |
| `rotation.page.noPolicies` | No rotation policy yet. Create one on the page of a key Alice generated. | Henüz rotasyon ilkesi yok. Alice’in oluşturduğu bir anahtarın sayfasında ilke oluşturun. |
| `rotation.page.policyKey` | Policy / key | İlke / anahtar |
| `rotation.page.interval` | Interval | Aralık |
| `rotation.page.nextRun` | Next run | Sonraki işlem |
| `rotation.page.state` | Status | Durum |
| `rotation.page.openKey` | Open key | Anahtarı aç |
| `rotation.page.inspectRun` | Inspect run and locations | İşlemi ve konumları incele |
| `rotation.page.path` | Rotation progress | Rotasyon ilerlemesi |
| `rotation.page.phase.generate` | Generate new key | Yeni anahtar oluştur |
| `rotation.page.phase.deploy` | Deploy & verify | Dağıt ve doğrula |
| `rotation.page.phase.overlap` | Overlap period | Geçiş süresi |
| `rotation.page.phase.retire` | Retire old key | Eski anahtarı kaldır |
| `rotation.page.phaseDone` | Complete | Tamamlandı |
| `rotation.page.phaseCurrent` | In progress | Devam ediyor |
| `rotation.page.phaseNext` | Not started | Başlamadı |
| `rotation.page.decisions` | Available decisions | Kullanılabilir kararlar |
| `rotation.page.decisionsHelp` | Review the affected locations before confirming. Each decision asks for a fresh verification code. | Onaylamadan önce etkilenen konumları inceleyin. Her karar yeni bir doğrulama kodu ister. |
| `rotation.page.transition` | Key transition | Anahtar değişimi |
| `rotation.page.results` | Location results | Konum sonuçları |
| `rotation.page.resultsSub` | Old keys are not removed from unverified locations. | Doğrulanmamış konumlardan eski anahtarlar kaldırılmaz. |

- [ ] **Step 2: Write the failing tests**

`RotationPath.test.tsx`: `dry_run_notified` → phase 1 current, others not started; `adding_new` and `verifying_new` → phase 1 done, phase 2 current; `overlap` → 1–2 done, 3 current; `removing_old` → 1–3 done, 4 current; `completed` → all done; `rolling_back`, `aborted`, `needs_attention`, `cancelled`, `unknown` → **no path rendered** (the component returns `null`; the page shows the status badge and the reason instead — a stopped run is never drawn as progress). Each phase states its state in text (`Complete` / `In progress` / `Not started`), not only by color.

`RotationsPage.test.tsx`:

```tsx
it('lists every live policy and the runs that are not final, for every role', async () => {
  server.use(
    ...sessionHandlers(auditorSession),
    http.get('/api/v1/rotation/policies', () => HttpResponse.json({ items: [policyFixture({ id: POLICY_ID, name: 'deploy-production', enabled: true, open_rotation_id: 'r1' })] })),
    http.get('/api/v1/rotation/runs', () => HttpResponse.json({ items: [runFixture({ id: 'r1', status: 'overlap' }), runFixture({ id: 'r0', status: 'completed' })], next_cursor: null })),
  );
  await renderRoute('/rotations');
  expect(await screen.findByRole('heading', { level: 1, name: 'Key rotations' })).toBeVisible();
  expect(screen.getByRole('link', { name: 'Key rotations' })).toHaveAttribute('aria-current', 'page');
  const active = screen.getByRole('region', { name: 'Active rotations' });
  expect(within(active).getAllByRole('link', { name: 'Inspect run and locations' })).toHaveLength(1);
  expect(within(active).getByRole('link', { name: 'Inspect run and locations' })).toHaveAttribute('href', '/rotation/runs/r1');
  expect(screen.getByRole('table', { name: 'Rotation policies' })).toHaveTextContent('deploy-production');
  expect(screen.queryByRole('button', { name: /Create|Run now|Finish|Stop/ })).not.toBeInTheDocument();
});

it('says so when there is no policy and no running rotation', async () => {
  server.use(...sessionHandlers(operatorSession), http.get('/api/v1/rotation/policies', () => HttpResponse.json({ items: [] })), http.get('/api/v1/rotation/runs', () => HttpResponse.json({ items: [], next_cursor: null })));
  await renderRoute('/rotations');
  expect(await screen.findByText('No rotation is running.')).toBeVisible();
  expect(screen.getByText(/No rotation policy yet/)).toBeVisible();
});
```

`RotationRunPage.test.tsx` — keep every existing test (decisions from `actions_allowed` for admins only, step-up, polling, `run-location`, `run-counts`, status badge in `role=status aria-live=polite` with `.mantine-Badge-root`) and add: the header shows `rotation.runTitle` as the only h1 with the status badge; `RotationPath` is shown for `overlap` and absent for `aborted`; the key transition panel shows old and new fingerprints in `<Code>`; the decisions panel exists only for admins with a non-empty `actions_allowed`.

Run: `cd web && npx vitest run src/pages/RotationsPage.test.tsx src/pages/RotationRunPage.test.tsx src/components/rotation src/layout/AppLayout.test.tsx` — FAIL.

- [ ] **Step 3: Implement**

`RotationPath.tsx`: `const PHASE_OF: Record<string, number> = { dry_run_notified: 0, adding_new: 1, verifying_new: 1, overlap: 2, removing_old: 3, completed: 4 };` — `null` for any other status. Four columns (`Rotations.module.css` from `.rotation-path`/`.rotation-phase`: top border 3 px, `--alice-brand` done, `--alice-warning` current, `--alice-border` next) each with its number, name (`rotation.page.phase.*`) and state text; wrapped in `<ol aria-label={t('rotation.page.path')}>`.

`RotationsPage.tsx`: `PageHeader` (title `nav.rotations`, description); `LinkTabs` (`SSH_KEY_TABS(t)`, label `sshKeys.page.sections`); `Panel` `aria-label` + title `rotation.page.active`: the runs of the first `listRuns()` page (`useInfiniteQuery` with `next_cursor`, `CursorFooter` with the existing "show more" text) whose status is not in `TERMINAL_RUN`, each with the key label (from the policy list by `policy_id`), `StatusBadge` (tone: overlap/verifying_new warning, adding_new/removing_old/dry_run_notified info, rolling_back warning), the `overlap_until`/`planned_for` time, `RotationPath`, and the `rotation.page.inspectRun` link; `rotation.page.noActive` as `EmptyState` when none. Then `ResourceTable` (label `rotation.page.policies`): policy name + key link (`/ssh-keys/<ssh_key_id>`, `rotation.page.openKey`), interval (`rotation.every`), overlap (`rotation.overlap` value), next run (`formatDateTime`), state (`StatusBadge` enabled/disabled with `rotation.on`/`rotation.off`; last run result from `last_run_status`), and links `rotation.openRun` (`open_rotation_id`) / `rotation.openLastRun` (`last_run_id`). `EmptyState` `rotation.page.noPolicies` when the list is empty. No mutation on this page (R19).

`RotationRunPage.tsx`: `PageHeader` (`back` = `rotation.backToKey` link as today, title `rotation.runTitle`, the status badge kept inside its existing `role="status" aria-live="polite"` wrapper, description = key label · type · location count); the license-paused `Notice` (danger, role alert, existing text and test semantics), the `ReasonAlert` as today; `detail-grid`: left — `RotationPath` panel, location results `ResourceTable` (`run-locations`, rows `run-location`, first cell user), steps list (existing `run-steps`) — right — key transition panel (old/new fingerprint `<Code>`, `FactList` policy, interval, notice delivered, decision due, overlap until, kept count), decisions panel for admins (`actions_allowed` buttons exactly as today, each through `withStepUp`, help text `rotation.page.decisionsHelp`). `rotationText.tsx` colors become semantic.

- [ ] **Step 4: Run** — `make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check` — PASS.

- [ ] **Step 5: Commit**

```bash
git add -- web/src/pages/RotationsPage.tsx web/src/pages/RotationsPage.test.tsx web/src/pages/Rotations.module.css web/src/components/rotation
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): Key rotations page (active runs and every policy, read-only) and the run page in the design with its progress path; navigation entry under Operations" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src/pages/RotationsPage.tsx web/src/pages/RotationsPage.test.tsx \
  web/src/pages/Rotations.module.css web/src/components/rotation web/src/api/rotation.ts web/src/router.tsx web/src/layout/AppLayout.tsx \
  web/src/layout/AppLayout.test.tsx web/src/pages/RotationRunPage.tsx web/src/pages/RotationRunPage.test.tsx web/src/components/rotationText.tsx \
  web/src/test/server.ts
```

Gap rows: no "Create policy" on `/rotations` (needs a key, step-up and a preview); license-paused runs, decision deadline, notice pending/failed, kept locations, skipped locations, undo — built from Notice/FactList/ResourceTable; the path is hidden for stopped or failed runs.

---

### Task 11: Deployments list and detail (outcomes and the operation timeline)

**Design source:** `pages.js` `deploymentsPage()`, `deploymentDetail(id)`; `guide.js` "05 / Components & outcome language" state table; `IMPLEMENTATION.md` §5; R20.

**Files:**
- Modify: `web/src/pages/DeploymentsPage.tsx`, `DeploymentDetailPage.tsx` (+ tests), `web/src/components/{DeploymentView,DeploymentSteps,LabelledCode,CodeText}.tsx` (+ tests), locales (lock)

**Interfaces:** Consumes C5 (`OperationTimeline`, `deploymentTone`). Produces: `DeploymentSteps` (same props) renders an `OperationTimeline` labelled `deployments.stepsTitle` whose items keep `data-step`, `data-status` and the `[data-role="step-status"]` text; `DeploymentStatusBadge` renders through `StatusBadge` (same `data-status`/`data-cancelled`).

- [ ] **Step 1: Keys (lock)**

| Key | EN | TR |
|---|---|---|
| `deployments.page.description` | Every change has a sequence. Every outcome has evidence. | Her değişikliğin adımları, her sonucun kanıtı var. |
| `deployments.page.sequence` | Deployment sequence | Dağıtım adımları |
| `deployments.page.sequenceSub` | Changes are verified before an operation is marked complete. | İşlem tamamlandı olarak işaretlenmeden önce değişiklikler doğrulanır. |
| `deployments.page.details` | Operation details | İşlem ayrıntıları |
| `deployments.page.evidence` | Evidence | Kanıt |

- [ ] **Step 2: Write the failing tests** — `DeploymentSteps.test.tsx`: the step list is an `ol` named `deployments.stepsTitle`; each `li` keeps `data-step`/`data-status`; the state text is in `[data-role="step-status"]` for ok (`Done`), failed, started (`Running`, with a loader), skipped, waiting, notRun (`Not run`, never a check mark), unknown; the marker's `data-state` maps ok→done, started→running, notRun→notRun. `DeploymentView.test.tsx`: every outcome keeps its headline key and color class (succeeded verified / unverified / local / skipped verification, unchanged, failed nothing changed, cancelled before sending (neutral), rolled back and pending change restored, rollback failed (restored and not), held, recovering with next step, finishing, stopped, unknown) and now has an icon; `DeploymentStatusBadge` keeps `data-status` and `data-cancelled`. `DeploymentsPage.test.tsx`: header (h1 `Deployments`, description), the table `deployments.tableLabel` with `deployment-row`s and `deployment-source`, cursor footer, and `it('shows no outcome totals', …)` — no text like `\d+ verified`/`rolled back` counts above the table (R20). `DeploymentDetailPage.test.tsx`: header (`back` to `/deployments`, `deployments.detailTitle` h1, status badge `deployment-status`), `deployment-headline`, `deployment-state`, `recovery` card, the details `FactList` (certificate and target links by id, initiated by, source, started, verification), the evidence panel with requested/served fingerprints (`LabelledCode`), polling unchanged.

Run: `cd web && npx vitest run src/pages/DeploymentsPage.test.tsx src/pages/DeploymentDetailPage.test.tsx src/components/DeploymentSteps.test.tsx src/components/DeploymentView.test.tsx` — FAIL (create `DeploymentView.test.tsx` if it does not exist).

- [ ] **Step 3: Implement** — `DeploymentSteps`: map `ok→done`, `failed→failed`, `started→running`, `waiting→waiting`, `skipped→skipped`, `notRun→notRun`, `unknown→unknown`; `title` = the existing step name text; `stateLabel` = `deployments.stepStatus.*`; `detail` = the existing step message/time detail; `dataAttrs` = `{ 'data-step': name, 'data-status': status }`. `DeploymentOutcome` keeps its Alert colors and texts and gets icons (success `ShieldCheck`, warning `CircleAlert`, danger `ShieldAlert`, neutral/info `CircleDot`); `c="gray.7"` → `c="dimmed"`. List: `PageHeader`, `ResourceTable` (label `deployments.tableLabel`, minWidth 820; rows per design: tile `Rocket`, certificate name link + id mono, target link, triggered by + source (`deployment-source`), `DeploymentStatusBadge`, started time mono, open icon link named `deployments.openNamed`), `CursorFooter` (`deployments.loadMore`). Detail: `PageHeader` with `back`, status; the outcome `Notice`; `detail-grid` — left: `Panel` `deployments.page.sequence` (subtitle `…sequenceSub`, padded false) with `DeploymentSteps detailed`, the recovery card — right: `deployments.page.details` `FactList`, `deployments.page.evidence` panel (`LabelledCode` requested/served fingerprints; verification kind remote/local/skipped as text), technical details.

- [ ] **Step 4: Run** — `make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check` — PASS.

- [ ] **Step 5: Commit**

```bash
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): deployments in the design: history table with cursor footer, outcome notices with icons, the operation timeline, operation details and evidence" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src/pages/DeploymentsPage.tsx web/src/pages/DeploymentsPage.test.tsx \
  web/src/pages/DeploymentDetailPage.tsx web/src/pages/DeploymentDetailPage.test.tsx web/src/components/DeploymentView.tsx \
  web/src/components/DeploymentView.test.tsx web/src/components/DeploymentSteps.tsx web/src/components/DeploymentSteps.test.tsx \
  web/src/components/LabelledCode.tsx web/src/components/CodeText.tsx
```

(`git add --` `DeploymentView.test.tsx` first if it is new.)

Gap rows: no outcome totals (R20); no search/status filter on deployments (the API has none in the UI today); the design's "Operation log" panel is not built (no raw log in the API; the steps carry the evidence); held, finishing, stopped, unknown, cancelled-before-sending, pending-change-restored, recovery card — design has none, built from Notice/OperationTimeline.

---

### Task 12: Audit trail and License

**Design source:** `pages.js` `auditPage()`, `auditTable()`; `admin.js` `licensePage()`; `app.js` `verify-audit`, `audit-detail`, `export-audit`, `upload-license`; `styles.css` `.license-card`, `.license-usage`, `.rule-list`, `.rule-item`.

**Files:**
- Modify: `web/src/pages/AuditPage.tsx` (+ test), `web/src/pages/LicensePage.tsx` (+ test), `web/src/components/LicenseUpload.tsx` only if Task 16 has not already restyled it (it is Task 16's file; touch only colors here if needed and say so), locales (lock)
- Create: `web/src/pages/LicensePage.module.css`

**Interfaces:** Consumes C5.

- [ ] **Step 1: Keys (lock)**

| Key | EN | TR |
|---|---|---|
| `audit.page.description` | Who did what, where, and with which result. | Kim, nerede, ne yaptı ve sonucu ne oldu? |
| `audit.page.newestFirst` | Newest first | En yeni önce |
| `license.page.description` | A predictable annual license. Your data stays yours. | Öngörülebilir yıllık lisans. Verileriniz size ait. |
| `license.page.eyebrow` | Alice license | Alice lisansı |
| `license.page.usage` | Managed targets | Yönetilen hedefler |
| `license.page.usageHelp` | Certificates and keys are not counted. | Sertifika ve anahtarlar sayılmaz. |
| `license.page.renewal` | What happens at renewal? | Yenileme sırasında ne olur? |
| `license.page.rule1Title` | Upload the signed file | İmzalı dosyayı yükleyin |
| `license.page.rule1` | Review the customer, validity period and target limit before activation. | Etkinleştirmeden önce kurum adını, süreyi ve hedef sınırını inceleyin. |
| `license.page.rule2Title` | Seven-day grace period | Yedi günlük ek süre |
| `license.page.rule2` | Annual licenses keep full operation during the grace period. Evaluation licenses have no grace period. | Yıllık lisanslar ek sürede tam çalışır. Deneme lisansında ek süre yoktur. |
| `license.page.rule3Title` | Your inventory remains accessible | Envanteriniz erişilebilir kalır |
| `license.page.rule3` | Lock mode does not delete keys or revoke certificates. In-flight changes finish or roll back safely. | Kilit modu anahtarları silmez veya sertifikaları iptal etmez. Devam eden işlemler tamamlanır ya da güvenle geri alınır. |

- [ ] **Step 2: Write the failing tests** — `AuditPage.test.tsx`: header (h1 `Audit trail`, description, actions Export CSV, Export JSON, Verify integrity — names unchanged); the verify result becomes a `Notice` (brand "intact" / danger "broken", existing texts); the filter form in the `ResourceTable` toolbar (fields `audit.filters.*` with their exact labels, Apply button); rows keep the actor, action label, object, result badge (`StatusBadge` success/danger/warning by result) and the details toggle `button[aria-expanded]` inside the row with the details group `audit.columns.details`; cursor footer. `LicensePage.test.tsx`: header (h1 `License`, Upload only for admins); the license card (brand-soft panel) with `license-phase` (`StatusBadge`), `license-summary` text unchanged (`Valid until …, N targets`), `installation-id`, the usage progress when the target count is known; the renewal rules panel (three numbered rules); history table; `license-installed` and the upload preview dialog unchanged; the locked phase shows the danger `Notice` with the existing locked texts.

Run: `cd web && npx vitest run src/pages/AuditPage.test.tsx src/pages/LicensePage.test.tsx` — FAIL.

- [ ] **Step 3: Implement** — Audit: `PageHeader` (actions: the export buttons and Verify, primary), integrity `Notice`, `ResourceTable` (`label` = existing table label, minWidth 900, toolbar = the filter form, footer = `CursorFooter` + `audit.page.newestFirst`); rows per `auditTable()` (time + `#seq` mono, avatar initials + actor, action label, object, result `StatusBadge`, details toggle); `c="gray.7"` → `c="dimmed"`; `RESULT_COLORS` replaced by tones. License: `PageHeader`; the locked/grace/evaluation `Notice` from the phase; grid (`LicensePage.module.css` `.grid` two columns ≥ 1020 px): left the license card (`.licenseCard` = `--alice-brand-soft` background, `--alice-brand-line` border; eyebrow `license.page.eyebrow` + phase badge; customer as h2; license id mono; usage box on `--alice-surface` with `Progress`; `FactList` end, `installation-id`, activation), right the renewal rules (`.ruleList` numbered `01–03` mono tiles) and history `ResourceTable`; the admin upload section (`LicenseUpload`) as a `Panel`.

- [ ] **Step 4: Run** — `make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check` — PASS.

- [ ] **Step 5: Commit**

```bash
git add -- web/src/pages/LicensePage.module.css
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): audit trail and license in the design: integrity notice, audit table with filters and details, license card with usage, renewal rules and history" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src/pages/AuditPage.tsx web/src/pages/AuditPage.test.tsx \
  web/src/pages/LicensePage.tsx web/src/pages/LicensePage.test.tsx web/src/pages/LicensePage.module.css
```

Gap rows: export JSON beside CSV, verify broken state, phases evaluation/grace/locked/expired, tampered/clock banners, pending/duplicate/correction states of an upload — built from Notice/StatusBadge/FactList.

---

### Task 13: People & access, API tokens, Your account (Appearance)

**Design source:** `admin.js` `usersPage()`, `tokensPage()`, `accountPage()`, `appearance()`; `app.js` `add-user`, `manage-user`, `create-token`, `revoke-token`, `recovery-codes`, `change-password`; R11 (token term), R16 (Appearance on Your account).

**Files:**
- Modify: `web/src/pages/UsersPage.tsx`, `TokensPage.tsx`, `AccountPage.tsx` (+ tests), locales (lock)
- Create: `web/src/pages/People.module.css`

**Interfaces:** Consumes C5 (`AppearanceControl`).

- [ ] **Step 1: Keys (lock)**

| Key | EN | TR |
|---|---|---|
| `users.page.description` | Clear responsibilities. Deliberate permissions. | Net sorumluluklar. Bilinçli yetkilendirme. |
| `users.page.roles` | Roles | Roller |
| `users.page.admin` | Manage the installation, identities and policies. | Kurulumu, kimlikleri ve ilkeleri yönetir. |
| `users.page.operator` | Discover inventory and operate certificates and SSH keys. | Envanteri keşfeder, sertifika ve SSH anahtarlarını işletir. |
| `users.page.auditor` | Read inventory, inspect evidence and export records. | Envanteri okur, kanıtları inceler ve kayıtları dışa aktarır. |
| `tokens.page.description` | Personal access for automation, bounded by your role. | Rolünüzle sınırlı, otomasyon için kişisel erişim. |
| `tokens.page.boundTitle` | A token never has more access than its owner | Bir API anahtarı, sahibinin yetkilerini aşamaz |
| `tokens.page.boundText` | An auditor can create read-only tokens. Sensitive actions that need the browser, such as downloading a private key, are not possible with a token. | Denetçi yalnızca okuma yetkili API anahtarı oluşturabilir. Özel anahtar indirme gibi tarayıcı gerektiren hassas işlemler API anahtarıyla yapılamaz. |
| `account.page.description` | Personal security, language and workspace preferences. | Kişisel güvenlik, dil ve çalışma alanı tercihleri. |
| `account.page.security` | Sign-in and recovery | Oturum açma ve kurtarma |

- [ ] **Step 2: Write the failing tests** — `UsersPage.test.tsx`: header (h1 `People & access`, description, Add user); a `group` named `Roles` with three role cards (role name + description); the people table in a `ResourceTable` (person: avatar initials + name + username/email, role badge, sign-in method badge (local + TOTP / SSO provider), status badge, last sign-in, `Manage <username>` button — names unchanged); dialogs unchanged (native Role select, step-up). `TokensPage.test.tsx`: header (h1 `API tokens`), the bound `Notice`, the SSO users note (`tokens-sso-note`), the new token reveal (`new-token`, shown once) and the table with `Revoke token <name>` buttons unchanged. `AccountPage.test.tsx`: header (h1 `Your account`); the profile panel (avatar, name, role · e-mail, `account-summary`, MFA `StatusBadge`), `Create new recovery codes` and the password form unchanged; the Appearance panel (title `appearance.title`, `AppearanceControl signedIn`) with radios Light/Dark/System, the Compact tables switch and the Language select; SSO accounts see no password form (as today).

Run: `cd web && npx vitest run src/pages/UsersPage.test.tsx src/pages/TokensPage.test.tsx src/pages/AccountPage.test.tsx` — FAIL.

- [ ] **Step 3: Implement** — Users: `PageHeader`; role cards (`People.module.css` `.roleCards` three columns ≥ 1020 px, `.roleCard` = `micro-card`: role name `enum.role.*` + icon `ShieldCheck`/`Settings2`/`Eye` + description); `ResourceTable` (the table gains the scroll container it lacked — the e2e notes it overflowed at 375 px; `minWidth` 760). Tokens: `PageHeader`; bound `Notice`; existing alerts/notes; `ResourceTable`. Account: `PageHeader`; grid (two columns ≥ 1020 px): profile `Panel` (account summary, `FactList`, recovery codes action and the existing change-password form inside, `account.page.security` as title) and Appearance `Panel` (title `appearance.title`, description `appearance.description`, `AppearanceControl signedIn`). Remove the account page's old `Paper` sections and `Title order={2}` without size.

- [ ] **Step 4: Run** — `make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check` — PASS.

- [ ] **Step 5: Commit**

```bash
git add -- web/src/pages/People.module.css
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): People & access, API tokens and Your account in the design: role cards, people and token tables, the token boundary notice, the appearance panel (color mode, compact tables, language)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src/pages/UsersPage.tsx web/src/pages/UsersPage.test.tsx \
  web/src/pages/TokensPage.tsx web/src/pages/TokensPage.test.tsx web/src/pages/AccountPage.tsx web/src/pages/AccountPage.test.tsx \
  web/src/pages/People.module.css
```

Gap rows: TR "API anahtarları" kept (R11); manage dialog actions (edit, set password, revoke sessions, reset MFA), SSO users and the last-admin protection error, new token shown once — built from the shared components; Appearance on Your account instead of Settings (R16).

---

### Task 14: Settings (eight tabs, vertical navigation) and SSO settings

**Design source:** `admin.js` `settingsPage(tab)` (mail, alerts, sso, backups, https, forwarding bodies), `styles.css` `.settings-layout`, `.settings-nav`, `.form-section`, `.form-actions`, `.switch-row`, `.micro-card`; R16.

**Files:**
- Modify: `web/src/pages/SettingsPage.tsx` (+ test), `web/src/components/settings/{AlertSettings,GeneralSettings,RecipientsSettings,MailSettings,BackupsTab,HttpsTab,ForwardingTab,SavedNote,TrustCertificateDialog}.tsx`, `web/src/components/sso/{SSOSettings,MappingsTable,ProviderDialog}.tsx` (+ tests where structure changes), locales (lock)
- Create: `web/src/pages/SettingsPage.module.css`

**Interfaces:** Consumes C5. Keeps `useUrlFilters(['tab'])`, the tab values and order, `keepMounted={false}`, step-up on read (`useSetting`).

- [ ] **Step 1: Keys (lock)**

| Key | EN | TR |
|---|---|---|
| `settings.page.description` | Make Alice work the way your team does. | Alice’i ekibinizin çalışma biçimine uyarlayın. |
| `settings.page.sections` | Settings sections | Ayar bölümleri |
| `settings.page.mail` | The mail server Alice uses to send alerts. | Alice’in uyarıları göndermek için kullandığı e-posta sunucusu. |
| `settings.page.recipients` | The people who receive operational alerts. | Operasyon uyarılarını alan kişiler. |
| `settings.page.alerts` | Warn early enough to act. Keep urgent signals distinct. | Harekete geçmek için yeterince erken uyarın. Acil sinyalleri ayırt edin. |
| `settings.page.general` | Defaults for this Alice installation. | Bu Alice kurulumu için varsayılanlar. |
| `settings.page.backups` | Encrypted backups protect recovery data. Test your restore procedure separately. | Şifreli yedekler kurtarma verisini korur. Geri yükleme sürecinizi ayrıca test edin. |
| `settings.page.https` | The certificate presented by this Alice installation. | Bu Alice kurulumunun sunduğu sertifika. |
| `settings.page.forwarding` | Send audit events to an independent syslog or SIEM destination. | Denetim olaylarını bağımsız bir syslog veya SIEM hedefine yönlendirin. |
| `settings.page.sso` | Connect an OpenID Connect provider and map groups to Alice roles. | Bir OpenID Connect sağlayıcısı bağlayın ve grupları Alice rolleriyle eşleştirin. |
| `settings.page.breakGlassTitle` | Keep a local recovery administrator | Yerel kurtarma yöneticisi bulundurun |
| `settings.page.breakGlassText` | A local account provides access if the identity provider is unavailable. | Kimlik sağlayıcısına ulaşılamadığında yerel hesap erişim sağlar. |

- [ ] **Step 2: Write the failing tests** — `SettingsPage.test.tsx`: header (h1 `Settings`, description); the tablist named `Settings sections` lists exactly `[mail, recipients, alerts, general, backups, https, forwarding, sso]` tab texts in that order (`toHaveTextContent` per tab equals `t('settings.tabs.<x>')`), each tab with an icon; `/settings?tab=backups` selects Backups; Home/End move focus within the vertical list and Enter selects; the selected tab's panel shows the tab label as its `h2` and `settings.page.<x>` as description; the SSO tab shows the break-glass `Notice`; the form actions row (`.formActions`) holds each form's save button; every test id of the tabs (`backup-now`, `backups-table`, `backup-download-<name>`, `https-temporary`, `https-upload-form`, `forwarding-form`, `forwarding-ca-set`) is unchanged; reading a tab still asks for step-up (existing tests).

Run: `cd web && npx vitest run src/pages/SettingsPage.test.tsx src/components/settings src/components/sso` — FAIL.

- [ ] **Step 3: Implement** — `PageHeader`; `SettingsPage.module.css` `.layout` (grid `175px minmax(0,1fr)`, gap 28 px ≥ 1020 px; `150px` 768–1019 px; one column below 768 px); `Tabs orientation={wide ? 'vertical' : 'horizontal'}` (`const wide = useMediaQuery('(min-width: 48em)')`), `Tabs.List aria-label={t('settings.page.sections')}` with the design's settings-nav styling (`.navList`, `.navTab`: 11–12 px, 6 px radius, `--alice-brand-soft` active, no underline in vertical mode; horizontal scroll with underline below 768 px), each `Tabs.Tab` with `leftSection={<Icon …/>}` (mail `Mail`, recipients `Users`, alerts `Bell`, general `Settings2`, backups `DatabaseBackup`, https `LockKeyhole`, forwarding `Network`, sso `ShieldCheck`); each `Tabs.Panel` = `Panel` (padded, `.formSection` max-width 770 px) with `Title order={2}` = tab label, `settings.page.<x>`, then the existing tab component. Tab components: `SavedNote` uses `c="var(--alice-success)"` instead of `teal.9`; `c="red.9"` → `c="var(--alice-danger)"`; save buttons sit in a `.formActions` row (border-top, right aligned); BackupsTab schedule and state as the design's `micro-card`s + `ResourceTable` (cells order unchanged: name, kind, size, time, check, actions); HttpsTab current certificate as `FactList`; ForwardingTab state as `FactList`; SSO providers as `Panel`s (`usage-node` head: provider name, issuer mono, enabled `StatusBadge`) with `MappingsTable` in a `ResourceTable`; break-glass `Notice` on the SSO tab.

- [ ] **Step 4: Run** — `make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check` — PASS.

- [ ] **Step 5: Commit**

```bash
git add -- web/src/pages/SettingsPage.module.css
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): settings in the design: vertical section navigation with the product's eight tabs, a described panel per tab, form actions rows, SSO providers and the break-glass notice" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src/pages/SettingsPage.tsx web/src/pages/SettingsPage.test.tsx \
  web/src/pages/SettingsPage.module.css web/src/components/settings web/src/components/sso
```

Gap rows: separate Recipients tab, SMTP untrusted-certificate trust dialog, test e-mail, alert threshold rows, public URL, backup download/schedule/free space, HTTPS PEM/PFX upload with warnings, forwarding CA write-only and backlog, SSO allow-admin and mappings — built from Panel/FactList/ResourceTable/Notice; design's Appearance tab, organization name and display time zone not built (R16).

---

### Task 15: Sign-in, MFA, first-sign-in enrollment, step-up dialog, not-found and error pages

**Design source:** `admin.js` `loginPage()`; `app.js` `stepUp()`, `openModal()`, `demo-sso`; `pages.js` `notFound()`, `deniedPage()`; `styles.css` `.auth-*`, `dialog`, `.dialog-head`, `.dialog-actions`; R17.

**Files:**
- Modify: `web/src/pages/LoginPage.tsx` (+ test), `web/src/components/StepUpProvider.tsx` (+ test), `web/src/components/AppModal.tsx` (+ test), `web/src/components/TotpEnrollment.tsx`, `web/src/components/RecoveryCodes.tsx` (+ test), `web/src/components/SSOErrorAlert.tsx`, `web/src/pages/NotFoundPage.tsx`, `web/src/pages/RouteErrorPage.tsx`, `web/src/auth/guards.tsx` (the no-access view and `PageLoader` only), locales (lock)
- Create: `web/src/components/auth/AuthLayout.tsx`, `web/src/components/auth/AuthLayout.test.tsx`, `web/src/components/auth/auth.module.css`

**Interfaces:**
- Consumes: C5 (`ThemeToggle`, `LanguageToggle`, `EmptyState`, `DialogActions`), C4.
- Produces: `AuthLayout({ children }: { children: ReactNode })` — the split layout with the brand side and the form side (toggles top right); used by `LoginPage` and by `NotFoundPage`/`RouteErrorPage` (form side only, `brand={false}`). `TotpEnrollment` and `RecoveryCodes` keep their props, texts and test ids (used by Task 16 unchanged).

- [ ] **Step 1: Keys (lock)**

| Key | EN | TR |
|---|---|---|
| `login.subtitle` | Sign in with your Alice account. | Alice hesabınızla giriş yapın. |
| `login.mfaNote` | Protected with multi-factor authentication | Çok faktörlü doğrulama ile korunur |
| `login.brand.eyebrow` | Certificates. Keys. Clarity. | Sertifikalar. Anahtarlar. Netlik. |
| `login.brand.tagline` | A little less uncertainty. A lot more control. | Daha az belirsizlik. Daha fazla kontrol. |
| `login.brand.text` | One considered workspace for the certificates and keys your infrastructure depends on. | Altyapınızın dayandığı sertifikalar ve anahtarlar için özenle tasarlanmış tek çalışma alanı. |
| `login.brand.selfHosted` | Self-hosted | Kendi sunucunuzda |
| `login.brand.offline` | Offline-ready | Çevrimdışı çalışır |
| `login.brand.control` | Built for control | Kontrol için tasarlandı |
| `ui.stepUp.subtitle` | Fresh identity verification is required for this operation. | Bu işlem için yeniden kimlik doğrulaması gerekir. |

- [ ] **Step 2: Write the failing tests** — `AuthLayout.test.tsx`: the brand side is an `aside` (complementary) with the tagline as a paragraph (no heading), the eyebrow and the footer items; the form side holds the children, the theme toggle (`Switch color mode`) and the language toggle (`Türkçe`); with `brand={false}` there is no aside. `LoginPage.test.tsx` — keep every existing test (phases, redirects, SSO buttons and `sso-error`, `?ended=1`, recovery-code toggle, enrollment) and add: exactly one h1 `Sign in to Alice` in the form side; `login.subtitle`; the `Sign in` button is the only button with that exact name (SSO buttons say `Sign in with <name>`); the MFA note under the form; the language toggle switches the page to Turkish (`Alice'e giriş yapın`) without a session (`signedIn={false}`: no `PUT /auth/locale`). `StepUpProvider.test.tsx` — keep all; add: the dialog named `Confirm it's you` shows `ui.stepUp.subtitle`, the code field `6-digit code` is focused, the footer (`DialogActions`) has Cancel and `Confirm` (primary with an icon), Enter submits; the SSO variant keeps its focused continue button and has no textbox. `RecoveryCodes.test.tsx`: codes in a mono grid, `recovery-codes` still contains the 10 codes, Continue disabled until the checkbox. `TotpEnrollment`: the QR image sits on a light tile in both schemes (class present; render with `colorScheme: 'dark'`), `totp-secret` unchanged. Not found / route error / no access: one h1 each (`ui.notFoundTitle`, `routeError.title`, `ui.noAccess`), the existing links/buttons.

Run: `cd web && npx vitest run src/pages/LoginPage.test.tsx src/components/StepUpProvider.test.tsx src/components/RecoveryCodes.test.tsx src/components/auth src/pages/NotFoundPage.test.tsx src/pages/RouteErrorPage.test.tsx` — FAIL (create the page tests that do not exist).

- [ ] **Step 3: Implement**

`AuthLayout.tsx`:

```tsx
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { LanguageToggle, ThemeToggle } from '../ui';
import classes from './auth.module.css';

// AuthLayout is the design's sign-in layout (loginPage): a brand side with the product's promise and a form side.
// The brand side is decorative context (an aside, no heading): the form side carries the page's only <h1>.
export function AuthLayout({ children, brand = true }: { children: ReactNode; brand?: boolean }) {
  const { t } = useTranslation();
  return (
    <div className={brand ? classes.layout : classes.single}>
      {brand && (
        <aside className={classes.brandSide} aria-label={t('app.name', { ns: 'common' })}>
          <div className={classes.brand}>
            <img src="/favicon.svg" alt="" className={classes.brandMark} />
            <span>{t('app.name', { ns: 'common' })}<span className={classes.brandDot} aria-hidden="true">.</span></span>
          </div>
          <div className={classes.copy}>
            <p className={classes.eyebrow}>{t('login.brand.eyebrow')}</p>
            <p className={classes.tagline}>{t('login.brand.tagline')}</p>
            <p className={classes.text}>{t('login.brand.text')}</p>
          </div>
          <div className={classes.orbit} aria-hidden="true" />
          <ul className={classes.brandFooter}>
            <li>{t('login.brand.selfHosted')}</li>
            <li>{t('login.brand.offline')}</li>
            <li>{t('login.brand.control')}</li>
          </ul>
        </aside>
      )}
      <main className={classes.formSide}>
        <div className={classes.top}>
          <ThemeToggle />
          <LanguageToggle signedIn={false} />
        </div>
        <div className={classes.form}>{children}</div>
      </main>
    </div>
  );
}
```

`auth.module.css` from `styles.css` `.auth-*` (brand side background `--alice-auth-brand-bg`, text `--alice-auth-brand-text`, muted `--alice-auth-brand-muted`, orbit rings `--alice-auth-brand-line`; the brand side keeps these fixed colors in both schemes, as the design does; grid `1.05fr 1fr`, brand side hidden below 768 px; form max-width 350 px (420 px for the enrollment and codes phases via a `data-wide` attribute); tagline 52 px / 43 px ≤ 1199 px; `.single` centers the form side alone). Footer list items separated with `·` via CSS `li + li::before { content: '·'; margin-inline-end: 18px; }` (decorative).

`LoginPage.tsx`: wrap in `AuthLayout`; the form side: the shield tile (`Icon name="Fingerprint"` in a `resource-icon` tile), `<Title order={1}>{t('login.title')}</Title>` (and the MFA/enroll titles as today, which replace the h1 text per phase — keep one h1 per phase), `login.subtitle` in the password phase, the existing alerts, fields and full-width `Sign in` button, the `login.or` divider (`.divider` with lines), SSO buttons (`variant="default"`, full width, `Building2` icon), and `login.mfaNote` with `LockKeyhole`. Remove the old `LanguageSwitcher` use (the toggle is in `AuthLayout`). Keep the `<main>` count at one: `AuthLayout` provides it, so the page must not render another `<main>`.

`StepUpProvider.tsx`: the `AppModal` keeps `title={t('ui.stepUp.title')}` (dialog name), adds `ui.stepUp.subtitle` as the first paragraph, the existing code field, and `DialogActions` with Cancel (`variant="default"`) and Confirm (`leftSection={<Icon name="ShieldCheck" size={15} />}`); the SSO variant likewise with its continue button. `AppModal.tsx`: unchanged API; the theme styles it.

`TotpEnrollment.tsx`: QR inside a `.qrTile` defined in `components/auth/auth.module.css` (background `#ffffff`, 12 px padding, 10 px radius — fixed white on purpose: authenticator apps scan dark-on-light), manual key in mono `Code block`; `RecoveryCodes.tsx`: codes in a two-column mono grid on `--alice-surface-subtle`, Copy/Download as `variant="default"` buttons with icons.

`NotFoundPage`/`RouteErrorPage`: `AuthLayout brand={false}` with an `EmptyState`-like block: `Icon name="Search"` / `CircleAlert`, `<Title order={1}>`, the text, the existing link/button (primary). `guards.tsx`: the no-access view = `<Title order={1}>{t('ui.noAccess')}</Title>` inside an `EmptyState` with `icon="ShieldAlert"` and a link `ui.backHome` to `/`; `PageLoader` unchanged except `c` colors.

- [ ] **Step 4: Run** — `make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check` — PASS.

- [ ] **Step 5: Commit**

```bash
git add -- web/src/components/auth
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): sign-in in the design's split layout with theme and language toggles; step-up, enrollment, recovery codes, not-found, error and no-access screens in the design" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src/components/auth web/src/pages/LoginPage.tsx web/src/pages/LoginPage.test.tsx \
  web/src/components/StepUpProvider.tsx web/src/components/StepUpProvider.test.tsx web/src/components/AppModal.tsx web/src/components/TotpEnrollment.tsx \
  web/src/components/RecoveryCodes.tsx web/src/components/RecoveryCodes.test.tsx web/src/components/SSOErrorAlert.tsx web/src/pages/NotFoundPage.tsx \
  web/src/pages/RouteErrorPage.tsx web/src/auth/guards.tsx
```

(Add the new page tests with `git add --` first.)

Gap rows: product heading "Sign in to Alice" instead of "Welcome to Alice / Atlas workspace" (R17); MFA code, recovery-code sign-in, first-sign-in enrollment, session-ended notice, SSO refusals, rate limiting — design has only a demo; QR tile fixed white; SSO step-up variant; route error page.

---

### Task 16: First-run wizard in the design's setup shell

**Design source:** `admin.js` `setupPage()`; `styles.css` `.setup-layout`, `.setup-shell`, `.setup-steps`, `.setup-step`, `.setup-step-number`, `.setup-content`, `.form-actions`, `.check-option`; `IMPLEMENTATION.md` §7 last paragraph; R18; `docs/first-run.md` (the real steps).

**Files:**
- Create: `web/src/pages/setup/SetupShell.tsx`, `web/src/pages/setup/SetupRail.tsx`, `web/src/pages/setup/setup.module.css`, `web/src/pages/setup/SetupRail.test.tsx`
- Modify: `web/src/pages/SetupPage.tsx`, `web/src/pages/SetupPage.test.tsx`, `web/src/pages/setup/{CodeStep,LanguageStep,AdminStep,PassphraseStep,HttpsStep,MailStep,LicenseStep,PlatformStep,DoneStep}.tsx` (+ tests where structure changes), `web/src/components/LicenseUpload.tsx`, locales (lock)

**Interfaces:**
- Consumes: `startOf`, `BACK`, `WizardStep` (unchanged), `TotpEnrollment`/`RecoveryCodes` (Task 15, unchanged props), C5.
- Produces: `railIndex(step: WizardStep): number` (code, language → 0; admin, totp, codes → 1; passphrase → 2; https → 3; mail → 4; license → 5; platform → 6; done → 7), `SetupRail({ current }: { current: WizardStep })`, `SetupShell({ current, children }: { current: WizardStep; children: ReactNode })`; the steps `HttpsStep`, `MailStep`, `LicenseStep`, `PlatformStep`, `DoneStep` gain an optional `back?: ReactNode` rendered first in their actions row.

- [ ] **Step 1: Keys (lock)**

| Key | EN | TR |
|---|---|---|
| `setup.rail.label` | Setup progress | Kurulum adımları |
| `setup.rail.title` | Your private workspace | Size ait çalışma alanı |
| `setup.rail.code` | Setup code & language | Kurulum kodu ve dil |
| `setup.rail.admin` | Administrator & MFA | Yönetici ve MFA |
| `setup.rail.passphrase` | Recovery passphrase | Kurtarma parolası |
| `setup.rail.https` | HTTPS certificate | HTTPS sertifikası |
| `setup.rail.mail` | Mail server | E-posta sunucusu |
| `setup.rail.license` | License | Lisans |
| `setup.rail.platform` | First server | İlk sunucu |
| `setup.rail.done` | Done | Tamamlandı |
| `setup.rail.current` | Current step | Geçerli adım |
| `setup.rail.next` | Not started | Başlamadı |
| `setup.rail.counter` | Step {{n}} of {{total}} | Adım {{n}} / {{total}} |
| `setup.shell.badge` | Setup | Kurulum |

- [ ] **Step 2: Write the failing tests**

`SetupRail.test.tsx`:

```tsx
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderApp } from '../../test/render';
import { SetupRail, railIndex } from './SetupRail';

describe('SetupRail', () => {
  it('maps every wizard step to its rail item', () => {
    expect(['code', 'language', 'admin', 'totp', 'codes', 'passphrase', 'https', 'mail', 'license', 'platform', 'done'].map((s) => railIndex(s as never))).toEqual([0, 0, 1, 1, 1, 2, 3, 4, 5, 6, 7]);
  });
  it('is not interactive: no links, no buttons, nothing focusable', async () => {
    const { container } = await renderApp(<SetupRail current="mail" />);
    const rail = screen.getByRole('list', { name: 'Setup progress' });
    expect(within(rail).queryAllByRole('link')).toHaveLength(0);
    expect(within(rail).queryAllByRole('button')).toHaveLength(0);
    expect(container.querySelectorAll('[tabindex]')).toHaveLength(0);
    await userEvent.click(within(rail).getByText('HTTPS certificate'));
    expect(within(rail).getByText('Mail server').closest('li')).toHaveAttribute('aria-current', 'step');
  });
  it('marks earlier items done and later items not started, in text', async () => {
    await renderApp(<SetupRail current="mail" />);
    const items = within(screen.getByRole('list', { name: 'Setup progress' })).getAllByRole('listitem');
    expect(items).toHaveLength(7);
    expect(items[3]).toHaveTextContent('Done');
    expect(items[4]).toHaveAttribute('aria-current', 'step');
    expect(items[5]).toHaveTextContent('Not started');
  });
  it('shows every item done on the last screen', async () => {
    await renderApp(<SetupRail current="done" />);
    for (const li of within(screen.getByRole('list', { name: 'Setup progress' })).getAllByRole('listitem')) expect(li).toHaveTextContent('Done');
  });
});
```

`SetupPage.test.tsx` — keep **every** existing test (step order for a fresh status, resume at `next_step`, Back targets, no Back before the HTTPS step, passphrase strength gating, `gone()` on 404, `setup-back`, `setup-skip`, `https-keep-temporary`, `https-done`, `installation-id`, `platform-public-key`, both languages without raw keys) and add:

```tsx
it('keeps "Set up Alice" as the only h1 and each step title as an h2 inside the setup shell', async () => {
  server.use(...freshSetupHandlers()); // the file's existing fresh-install handlers
  await renderRoute('/setup');
  expect(await screen.findByRole('heading', { level: 1, name: 'Set up Alice' })).toBeVisible();
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  expect(screen.getByRole('heading', { level: 2, name: 'Enter the setup code' })).toBeVisible();
  expect(screen.getByRole('list', { name: 'Setup progress' })).toBeVisible();
});

it('rail marks the step resumed from next_step and Back sits in the step’s actions row', async () => {
  server.use(...adminSetupHandlers({ next_step: 'mail' })); // the file's existing resume handlers
  await renderRoute('/setup');
  await screen.findByRole('heading', { level: 2, name: 'Mail server (optional)' });
  expect(within(screen.getByRole('list', { name: 'Setup progress' })).getByText('Mail server').closest('li')).toHaveAttribute('aria-current', 'step');
  const back = screen.getByTestId('setup-back');
  const skip = screen.getByTestId('setup-skip');
  expect(back.compareDocumentPosition(skip) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
});
```

(Use the existing helper names of `SetupPage.test.tsx` for the handlers; if they are inline, extract them into two local functions first, in the same commit.)

Run: `cd web && npx vitest run src/pages/SetupPage.test.tsx src/pages/setup` — FAIL.

- [ ] **Step 3: Implement**

`SetupRail.tsx`:

```tsx
import { useTranslation } from 'react-i18next';
import { Icon } from '../../design/Icon';
import type { WizardStep } from '../SetupPage';
import classes from './setup.module.css';

const ITEMS = ['code', 'admin', 'passphrase', 'https', 'mail', 'license', 'platform'] as const;
const INDEX: Record<WizardStep, number> = { code: 0, language: 0, admin: 1, totp: 1, codes: 1, passphrase: 2, https: 3, mail: 4, license: 5, platform: 6, done: 7 };

export function railIndex(step: WizardStep): number {
  return INDEX[step];
}

// SetupRail shows where the person is in the real installer. It never navigates: the wizard's own buttons (and Back
// where BACK allows it) are the only way between steps, so no check can be skipped (IMPLEMENTATION §7, R18).
export function SetupRail({ current }: { current: WizardStep }) {
  const { t } = useTranslation();
  const at = railIndex(current);
  return (
    <div className={classes.rail}>
      <p className={classes.railTitle}>{t('setup.rail.title')}</p>
      <p className={classes.counter}>{t('setup.rail.counter', { n: Math.min(at + 1, ITEMS.length), total: ITEMS.length })}</p>
      <ol className={classes.railList} aria-label={t('setup.rail.label')}>
        {ITEMS.map((item, i) => {
          const state = i < at ? 'done' : i === at ? 'current' : 'next';
          return (
            <li key={item} className={classes.railItem} data-state={state} aria-current={state === 'current' ? 'step' : undefined}>
              <span className={classes.railNumber} aria-hidden="true">
                {state === 'done' ? <Icon name="Check" size={13} /> : i + 1}
              </span>
              <span className={classes.railText}>
                <span>{t(`setup.rail.${item}`)}</span>
                <span className={classes.railState}>{t(state === 'done' ? 'setup.rail.done' : state === 'current' ? 'setup.rail.current' : 'setup.rail.next')}</span>
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
```

(The `railState` text is visually hidden for `current`/`next` on wide screens through CSS `.railItem[data-state='next'] .railState { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }` — it stays in the accessibility tree; `done` shows a check icon plus the hidden word.)

`SetupShell.tsx`: the design's `setup-layout` (max-width 1040 px, centered): top row with the brand mark + `<Title order={1}>{t('setup.title')}</Title>` (styled 20 px), a `StatusBadge tone="neutral"` `setup.shell.badge`, and on the right `ThemeToggle` + `LanguageToggle signedIn={false}` **only on the `code` step** (the language step owns the choice afterwards; after the administrator exists the account locale applies); below, the `setup-shell` grid (`245px 1fr`, one column below 768 px) with `SetupRail` and the content `<section>` (padding 40 px / 25 px) that renders `children`; the whole in a `<main>`.

`SetupPage.tsx`: render `SetupShell current={current}` instead of the `Container`/`Stack`/`Title`; pass `back={back && <Button variant="default" data-testid="setup-back" leftSection={<Icon name="ArrowLeft" size={15} />} onClick={() => setStep(back)}>{t('setup.back')}</Button>}` into the step that has one (https, mail, license, platform, done); everything else (state, `startOf`, `verifyAdmin`, `gone`, drafts) is unchanged.

Steps: each step's title becomes `<Title order={2} className={classes.stepTitle}>` (27 px, as the design's step h1); its help text the design's intro paragraph style; its final buttons row becomes `<div className={classes.formActions}>{back}<span className={classes.spacer} />{…existing buttons}</div>` (border-top, `justify-content: flex-end`, the Back button first). Radio choices (language, HTTPS format, license choice) use the design's `.check-option` look (bordered rows) through a CSS class on the Mantine `Radio`/`Checkbox` root — labels and names unchanged. `PassphraseStep` keeps the strength meter (`passphrase-strength`), `tooWeak`, the stored checkbox and the disabled Save until good/strong. `LicenseUpload` keeps its size cap and preview dialog; its colors become semantic.

`setup.module.css` (from `styles.css`):

```css
.layout { max-width: 1040px; margin: 0 auto; padding: 35px 25px; }
.top { display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
.brand { display: flex; align-items: center; gap: 10px; }
.brandMark { width: 30px; height: 30px; }
.title { font-size: 20px; letter-spacing: -0.6px; }
.shell { display: grid; grid-template-columns: 245px minmax(0, 1fr); min-height: 610px; margin-top: 40px; overflow: hidden; background: var(--alice-surface); border: 1px solid var(--alice-border); border-radius: var(--alice-radius-lg); }
.rail { padding: 30px; background: var(--alice-surface-subtle); border-right: 1px solid var(--alice-border); }
.railTitle { margin: 0; font-size: 14px; font-weight: 600; color: var(--alice-text); }
.counter { display: none; margin: 0; font-size: 11px; color: var(--alice-text-muted); }
.railList { list-style: none; margin: 0; padding: 0; }
.railItem { display: flex; align-items: center; gap: 12px; margin: 25px 0; font-size: 12px; color: var(--alice-text-muted); }
.railItem[data-state='current'] { color: var(--alice-brand); font-weight: 600; }
.railItem[data-state='done'] { color: var(--alice-text-secondary); }
.railNumber { display: grid; place-items: center; width: 23px; height: 23px; flex-shrink: 0; border: 1px solid var(--alice-border-strong); border-radius: 50%; font: 10px var(--mantine-font-family-monospace); }
.railItem[data-state='current'] .railNumber { background: var(--alice-brand); border-color: var(--alice-brand); color: var(--alice-on-brand); }
.railItem[data-state='done'] .railNumber { background: var(--alice-success-soft); border-color: var(--alice-brand-line); color: var(--alice-success); }
.railText { display: grid; }
.railState { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
.content { padding: 40px; min-width: 0; }
.stepTitle { font-size: 27px; font-weight: 590; letter-spacing: -1px; line-height: 1.2; }
.intro { margin: 12px 0 30px; font-size: 12px; color: var(--alice-text-secondary); }
.formActions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 24px; padding-top: 20px; border-top: 1px solid var(--alice-border); }
.spacer { flex: 1; }
.checkOption { padding: 14px; border: 1px solid var(--alice-border); border-radius: 7px; }
@media (max-width: 767px) {
  .layout { padding: 25px 16px; }
  .shell { grid-template-columns: minmax(0, 1fr); margin-top: 25px; }
  .rail { padding: 18px; border-right: 0; border-bottom: 1px solid var(--alice-border); }
  .railTitle { display: none; }
  .counter { display: block; }
  .railItem { display: none; }
  .railItem[data-state='current'] { display: flex; margin: 8px 0 0; }
  .content { padding: 25px; }
}
```

- [ ] **Step 4: Run** — `make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check && make web` — PASS.

- [ ] **Step 5: Commit**

```bash
git add -- web/src/pages/setup/SetupShell.tsx web/src/pages/setup/SetupRail.tsx web/src/pages/setup/setup.module.css web/src/pages/setup/SetupRail.test.tsx
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): the first-run wizard in the design's setup shell: a non-interactive progress rail over the real steps, step titles and action rows, Back beside the step's own actions; every setup check unchanged" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src/pages/SetupPage.tsx web/src/pages/SetupPage.test.tsx web/src/pages/setup \
  web/src/components/LicenseUpload.tsx
```

Gap rows: the language step stays separate (design: a select on step 1); TOTP QR and manual key, one-time recovery codes, passphrase strength meter and server-side refusal (`ALC-SET-0010`), HTTPS PEM/PFX upload or keep temporary, mail save/test/skip, license upload preview or evaluation with Installation ID, platform key with optional add server, completion with step-up, Back and resume, 404 "gone" — design shows a visual walkthrough only; the "Visual walkthrough only" note is dropped (this is the real installer).

---

### Task 17: Dark-mode sweep and the color-rule guard

**Design source:** `IMPLEMENTATION.md` §1 ("Replace direct `c="gray.7"` and `c="black"` uses throughout the components before declaring dark mode complete"); `guide.js` "Theme layer first".

**Files:**
- Create: `web/src/design/colorRules.test.ts`
- Modify: `web/eslint.config.js`; every non-test file under `web/src` that still has a hard-coded color after Tasks 4–16 (find them with the commands below); `web/src/LanguageSwitcher.tsx` (+ its test) — delete if nothing imports it; `web/src/theme.ts` only if a Mantine component still draws a palette shade in the dark scheme

**Interfaces:** none new.

- [ ] **Step 1: Write the failing guard**

`web/src/design/colorRules.test.ts`:

```ts
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : [path];
  });
}

const SOURCES = files('src').filter((f) => /\.(tsx?|css)$/.test(f) && !/\.test\.tsx?$/.test(f) && !f.startsWith(join('src', 'test')));

// Files that may hold literal colors: the tokens themselves, the Mantine palette in theme.ts, the dialog shadow, the
// generated icon data, the appearance previews (each mode drawn as it looks) and the sign-in brand side and QR tile
// (fixed in both schemes).
const HEX_ALLOWED = new Set(
  ['src/design/tokens.css', 'src/design/mantine.module.css', 'src/theme.ts', 'src/design/icons.ts', 'src/components/ui/ui.module.css', 'src/components/auth/auth.module.css'].map((p) => join(...p.split('/'))),
);

const RULES: [string, RegExp, boolean][] = [
  ['c="black" or c="white"', /\bc=["'](black|white)["']/, false],
  ['a palette shade as a text color (c="gray.7")', /\bc=["'][a-z]+\.\d["']/, false],
  ['a palette shade variable', /var\(--mantine-color-[a-z]+-\d\)/, false],
  ['a literal hex color', /(?<![\w&-])#[0-9a-fA-F]{6}(?:[0-9a-fA-F]{2})?\b|(?<![\w&-])#[0-9a-fA-F]{3}\b(?![\w-])/, true],
];

describe('no hard-coded colors (both schemes draw from the tokens)', () => {
  it.each(RULES)('has no %s', (_name, re, hexRule) => {
    const bad = SOURCES.filter((f) => !(hexRule && HEX_ALLOWED.has(f)))
      .flatMap((f) => readFileSync(f, 'utf8').split('\n').map((line, i) => ({ f, n: i + 1, line })))
      .filter(({ line }) => re.test(line) && !/^\s*(\/\/|\*|\/\*)/.test(line))
      .map(({ f, n, line }) => `${f}:${n}: ${line.trim()}`);
    expect(bad).toEqual([]);
  });
});
```

Run: `cd web && npx vitest run src/design/colorRules.test.ts`
Expected: FAIL, listing what Tasks 4–16 did not touch (for example `SavedNote`, `RoleGuide`, `rotationText`, `KVDeployDialog` borders).

Also run: `grep -rnE 'c="(black|white|[a-z]+\.[0-9])"|--mantine-color-[a-z]+-[0-9]|style=\{\{[^}]*color' web/src --include=*.tsx | grep -v test` and keep the list for the report.

- [ ] **Step 2: Fix every hit with this mapping (never a new color)**

| Found | Replace with |
|---|---|
| `c="gray.7"`, `c="gray.8"` | `c="dimmed"` (= `--alice-text-secondary`) |
| `c="red.8"`, `c="red.9"` | `c="var(--alice-danger)"` |
| `c="teal.9"`, `c="green.9"` | `c="var(--alice-success)"` |
| `c="black"` (links on tinted alerts) | `c="inherit"` with `fw={600}` |
| `var(--mantine-color-gray-4)` borders | `var(--alice-border)` |
| `var(--mantine-color-red-9)` borders | `var(--alice-danger)` |
| `var(--mantine-color-gray-7)` text | `var(--alice-text-secondary)` |
| a hex color in a component | the matching `--alice-*` token |

Then add the ESLint rule to `web/eslint.config.js` (inside the existing `no-restricted-syntax` list):

```js
{ selector: "JSXAttribute[name.name='c'][value.value=/^(black|white|[a-z]+\\.[0-9])$/]", message: 'Use a semantic color (c="dimmed", c="var(--alice-…)"): a palette shade fails in the dark scheme (Phase 9).' },
```

Delete `web/src/LanguageSwitcher.tsx` (and its test, if any) when `grep -rn "LanguageSwitcher" web/src` finds no import.

- [ ] **Step 3: Render every screen in the dark scheme**

Extend `web/src/screens.i18n.test.tsx` with a `describe('dark scheme', …)` that renders each `SCREENS` entry with `renderRoute(path, { languages, colorScheme: 'dark' })` in English and Turkish and asserts that `document.documentElement` has `data-mantine-color-scheme="dark"`, that the screen's ready text is visible and `expectNoRawKeys()` passes (jsdom cannot measure contrast; Task 18 does it in browsers).

Run: `cd web && npx vitest run src/design/colorRules.test.ts src/screens.i18n.test.tsx && cd .. && make web-test && make web-lint && cd web && npx tsc --noEmit && cd .. && make i18n-check && make web-coverage`
Expected: PASS; coverage at or above the floors.

- [ ] **Step 4: Commit**

```bash
git add -- web/src/design/colorRules.test.ts
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "fix(web): no hard-coded colors left (dark mode complete); a test and an ESLint rule keep palette shades and black text out; every screen renders in the dark scheme" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src web/eslint.config.js
```

(`web/src` here means only the files you changed: list them explicitly in the command.)

---

### Task 18: Responsive and accessibility sweep with Playwright, full Chromium suite (**Docker alone**)

**Design source:** `IMPLEMENTATION.md` "Acceptance checks" 1–3, 7; `guide.js` "04 / Behavior & accessibility"; Review Focus 1, 2 and 5.

**Files:**
- Create: `web/e2e/phase9.spec.ts`
- Modify: any web file needed to fix what the scans find (CSS modules first; components only when the markup is wrong); `web/e2e/*.spec.ts`/`helpers.ts` only where a label change of Task 4/5 was edited wrongly

**Interfaces:** Consumes `runWizard`, `resetInstall`, `seedDashboard`, `signIn`, `signOut`, `apiAs`, `expectAccessibleAt`, `translator`, `ADMIN`, `type Lang` from `helpers.ts`.

- [ ] **Step 1: Write the spec**

`web/e2e/phase9.spec.ts`:

```ts
import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { ADMIN, apiAs, expectAccessibleAt, resetInstall, runWizard, seedDashboard, signIn, signOut, translator, type Lang } from './helpers';

// Phase 9 (the Clarity design): every primary route at the design's four widths, in both color schemes and both
// languages (IMPLEMENTATION.md acceptance check 1). Soft assertions list every finding of a run.
const WIDTHS = [390, 768, 1024, 1440] as const;
const ROUTES = [
  '/', '/?view=assurance', '/certificates', '/ssh-keys', '/servers', '/key-vaults', '/deployments', '/rotations',
  '/audit', '/users', '/license', '/account', '/tokens',
] as const;
const SETTINGS = ['mail', 'recipients', 'alerts', 'general', 'backups', 'https', 'forwarding', 'sso'] as const;

async function useScheme(page: Page, scheme: 'light' | 'dark'): Promise<void> {
  await page.emulateMedia({ colorScheme: scheme });
  await page.evaluate((s) => localStorage.setItem('alice.colorScheme', s), scheme);
}

async function useLanguage(page: Page, lang: Lang): Promise<void> {
  const api = await apiAs(page);
  const res = await api.put('/api/v1/auth/locale', { locale: lang });
  expect(res.ok(), await res.text()).toBe(true);
}

async function firstDetail(page: Page, list: string, prefix: string): Promise<string | null> {
  await page.goto(list);
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  const link = page.getByRole('main').locator(`a[href^="${prefix}"]`).first();
  return (await link.count()) > 0 ? link.getAttribute('href') : null;
}

async function scanRoute(page: Page, path: string, label: string): Promise<void> {
  await page.goto(path);
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('data-mantine-color-scheme', /light|dark/);
  await expectAccessibleAt(page, label, WIDTHS, { soft: true });
}

async function install(page: Page, request: APIRequestContext, lang: Lang): Promise<string> {
  await resetInstall(request);
  const { totpSecret } = await runWizard(page, request, lang);
  await seedDashboard(request);
  return totpSecret;
}

for (const lang of ['en', 'tr'] as Lang[]) {
  test.describe(`Phase 9 design (${lang})`, () => {
    test(`every route in light and dark at 390/768/1024/1440 px (${lang})`, async ({ page, request }) => {
      test.setTimeout(30 * 60_000);
      const totpSecret = await install(page, request, lang);
      await useLanguage(page, lang);
      const details = [
        await firstDetail(page, '/certificates', '/certificates/'),
        await firstDetail(page, '/servers', '/servers/'),
        await firstDetail(page, '/deployments', '/deployments/'),
      ].filter((p): p is string => p !== null);
      for (const scheme of ['light', 'dark'] as const) {
        await useScheme(page, scheme);
        for (const path of [...ROUTES, ...details]) await scanRoute(page, path, `${path} ${scheme} ${lang}`);
        // Settings reads need a fresh step-up (5 minutes): renew it right before the tabs.
        await (await apiAs(page)).stepUp(totpSecret);
        for (const tab of SETTINGS) await scanRoute(page, `/settings?tab=${tab}`, `settings ${tab} ${scheme} ${lang}`);
      }
    });

    test(`sign-in and the wizard in the dark scheme (${lang})`, async ({ page, request }) => {
      test.setTimeout(15 * 60_000);
      await page.addInitScript(() => localStorage.setItem('alice.colorScheme', 'dark'));
      await page.emulateMedia({ colorScheme: 'dark' });
      await resetInstall(request);
      const { totpSecret } = await runWizard(page, request, lang, ADMIN, { a11y: true });
      await signOut(page);
      await expect(page.getByRole('heading', { level: 1, name: translator(lang)('login.title') })).toBeVisible();
      await expectAccessibleAt(page, `login dark ${lang}`, WIDTHS, { soft: true });
      await signIn(page, request, ADMIN, totpSecret);
    });
  });
}
```

- [ ] **Step 2: Run it (Docker alone — no other agent uses Docker; no `make lint`)**

Run: `make e2e-up && cd web && ALICE_E2E_PROJECT=alice-e2e npx playwright test e2e/phase9.spec.ts --project=chromium; cd ..`
Expected first run: findings (contrast, overflow at 390 px, focus). Fix each in the owning CSS module or component with tokens only, re-run until green. Typical fixes: `min-width: 0` on grid children, `overflow-wrap: anywhere` on fingerprints and URLs, wrapping action groups, the header actions at 390 px, Turkish labels in tabs and the settings navigation, focus outlines clipped by `overflow: hidden` panels (use `outline-offset: -3px` inside such panels).

- [ ] **Step 3: Run the whole Chromium suite**

Run: `make e2e; make e2e-down`
Expected: every test passes (122 runs of the existing specs + the 4 of `phase9.spec.ts`). A failure caused by a label change gets its spec fixed per the "Label changes" table; any other failure is a regression of the restyle and is fixed in the component (never by loosening a test). Record pass counts and the fixes in the report.

- [ ] **Step 4: Commit**

```bash
git add -- web/e2e/phase9.spec.ts
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "test(e2e): Phase 9 axe and overflow scans of every route in light and dark, EN and TR, at 390/768/1024/1440 px; responsive and accessibility fixes they found" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/e2e/phase9.spec.ts web/src
```

(Replace `web/src` by the exact list of files the scans made you change.)

---

### Task 19: Three-browser suite and the visual evidence (**Docker alone**)

**Files:**
- Create: `web/e2e/design-evidence.spec.ts`
- Modify: `web/e2e/helpers.ts` (`runWizard` and `enrollTotp` accept an optional `onScreen` callback), `Makefile` (target `e2e-design-evidence`)

**Interfaces:** `runWizard(page, request, lang, admin?, opts?: { a11y?: boolean; license?: …; onScreen?: (name: string) => Promise<void> })` and `enrollTotp(page, request, c, a11y = false, onScreen?: (name: string) => Promise<void>)`: wherever they call `expectAccessible(page, name)` under `a11y`, they also `await onScreen?.(name)`; default behaviour unchanged.

- [ ] **Step 1: Add the hook to `helpers.ts`** — inside `runWizard`, replace each `if (opts.a11y) await expectAccessible(page, '<name>');` by `await screen('<name>');` with

```ts
const screen = async (name: string) => {
  if (opts.a11y) await expectAccessible(page, name);
  if (opts.onScreen) await opts.onScreen(name);
};
```

  pass `opts.onScreen` on to `enrollTotp`, `keepTemporaryCertificateStep` and `skipMailStep` (add the same optional parameter to the two step helpers), and call `screen('wizard setup code')` once the setup-code heading is visible and `screen('wizard done')` as today.

- [ ] **Step 2: Write `web/e2e/design-evidence.spec.ts`**

```ts
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { expect, test, type Page } from '@playwright/test';
import { ADMIN, apiAs, resetInstall, runWizard, seedDashboard, signOut, type Lang } from './helpers';

// Visual evidence for the owner's review of the Clarity design (Phase 9, Task 19): screenshots of every primary route
// and every wizard screen in light and dark, English and Turkish, at 1440/1024/768/390 px, written to
// bin/design-evidence (git-ignored, never committed) with an index.html contact sheet. Opt-in: make e2e-design-evidence.
test.skip(!process.env.ALICE_DESIGN_EVIDENCE, 'set ALICE_DESIGN_EVIDENCE=1 (make e2e-design-evidence)');

const OUT = resolve(__dirname, '../../bin/design-evidence');
const WIDTHS = [1440, 1024, 768, 390] as const;
const ROUTES: [string, string][] = [
  ['overview', '/'], ['assurance', '/?view=assurance'], ['certificates', '/certificates'], ['ssh-keys', '/ssh-keys'],
  ['servers', '/servers'], ['key-vaults', '/key-vaults'], ['deployments', '/deployments'], ['rotations', '/rotations'],
  ['audit', '/audit'], ['people', '/users'], ['license', '/license'], ['account', '/account'], ['tokens', '/tokens'],
  ...(['mail', 'recipients', 'alerts', 'general', 'backups', 'https', 'forwarding', 'sso'] as const).map((tab): [string, string] => [`settings-${tab}`, `/settings?tab=${tab}`]),
];
const shots: string[] = [];

async function shoot(page: Page, dir: string, name: string): Promise<void> {
  const original = page.viewportSize();
  for (const width of WIDTHS) {
    await page.setViewportSize({ width, height: 900 });
    await page.evaluate(() => document.fonts.ready);
    const file = join(OUT, dir, String(width), `${name}.png`);
    mkdirSync(dirname(file), { recursive: true });
    await page.screenshot({ path: file, fullPage: true, animations: 'disabled' });
    shots.push(relative(OUT, file));
  }
  if (original) await page.setViewportSize(original);
}

async function scheme(page: Page, s: 'light' | 'dark'): Promise<void> {
  await page.emulateMedia({ colorScheme: s });
  await page.addInitScript((v) => localStorage.setItem('alice.colorScheme', v), s);
}

test.afterAll(() => {
  const rows = shots.map((s) => `<figure><img loading="lazy" src="${s}" alt=""><figcaption>${s}</figcaption></figure>`).join('\n');
  writeFileSync(join(OUT, 'index.html'), `<!doctype html><meta charset="utf-8"><title>Alice design evidence</title><style>body{font:13px system-ui;margin:24px}figure{display:inline-block;margin:8px;width:360px;vertical-align:top}img{width:100%;border:1px solid #ccc}</style>\n${rows}\n`);
});

for (const lang of ['en', 'tr'] as Lang[]) {
  for (const s of ['light', 'dark'] as const) {
    test(`evidence ${lang} ${s}`, async ({ page, request }) => {
      test.setTimeout(45 * 60_000);
      const dir = `${lang}-${s}`;
      await scheme(page, s);
      await resetInstall(request);
      const { totpSecret } = await runWizard(page, request, lang, ADMIN, { onScreen: (name) => shoot(page, dir, name.replace(/\s+/g, '-')) });
      await seedDashboard(request);
      await (await apiAs(page)).stepUp(totpSecret);
      for (const [name, path] of ROUTES) {
        await page.goto(path);
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
        await shoot(page, dir, name);
      }
      for (const [list, prefix, name] of [['/certificates', '/certificates/', 'certificate-detail'], ['/servers', '/servers/', 'server-detail'], ['/deployments', '/deployments/', 'deployment-detail']] as const) {
        await page.goto(list);
        const link = page.getByRole('main').locator(`a[href^="${prefix}"]`).first();
        if ((await link.count()) === 0) continue;
        await page.goto((await link.getAttribute('href'))!);
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
        await shoot(page, dir, name);
      }
      await signOut(page);
      await shoot(page, dir, 'sign-in');
    });
  }
}
```

`Makefile` (after `e2e-browsers`):

```make
.PHONY: e2e-design-evidence
e2e-design-evidence: ## Screenshots of every primary route and wizard screen (light/dark, EN/TR, 1440/1024/768/390 px) into bin/design-evidence for review; never committed (make e2e-up first)
	cd web && npx playwright install chromium && port="$${ALICE_E2E_PORT:-}" && set -a && { [ ! -f ../deploy/.env ] || . ../deploy/.env; } && set +a && { [ -z "$$port" ] || ALICE_E2E_PORT="$$port"; } && export ALICE_E2E_PORT && ALICE_DESIGN_EVIDENCE=1 ALICE_E2E_PROJECT=$(E2E_PROJECT) npx playwright test e2e/design-evidence.spec.ts --project=chromium
```

- [ ] **Step 3: Run (Docker alone)**

Run: `make e2e-up && make e2e-browsers && make e2e-design-evidence; make e2e-down`
Expected: every spec passes on Chromium, Firefox and WebKit (the existing 122 runs × 3 plus `phase9.spec.ts`; `design-evidence.spec.ts` is skipped there), then `bin/design-evidence/index.html` exists with 4 (lang × scheme) × 4 widths × (21 routes + 3 details + the wizard screens + sign-in) PNGs. Check `git status --short bin` prints nothing (git-ignored). Do not commit any PNG. WebKit needs its system libraries (`npx playwright install --with-deps webkit` — the owner's machine may need sudo; if it cannot run, record `NOT RUN (owner)` with the command and run Chromium and Firefox).

- [ ] **Step 4: Commit**

```bash
git add -- web/e2e/design-evidence.spec.ts
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "test(e2e): opt-in visual evidence of the Clarity design (every route and wizard screen, light/dark, EN/TR, four widths) into bin/design-evidence; wizard helpers take an onScreen hook" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/e2e/design-evidence.spec.ts web/e2e/helpers.ts Makefile
```

Report: the three-browser pass counts, the path of `bin/design-evidence/index.html` for the owner, and any route that could not be captured.

---

### Task 20: Documentation, design gaps, CHANGELOG; final coverage and build

**Files:**
- Create: `docs/design-gaps.md`
- Modify: `docs/first-run.md`, `docs/admin-guide.md`, `docs/operator-guide.md`, `docs/troubleshooting.md`, `docs/security-overview.md`, `docs/backup-restore.md`, `docs/nginx-host-preparation.md`, `docs/api.md` (only UI-label references), `CHANGELOG.md`, `tools/docscheck/required.txt` (only if a required sentence names a renamed label)

**Interfaces:** Consumes every task report (`.superpowers/sdd/2026-10-12-phase-9-design/task-*-report.md`) for the gap rows.

- [ ] **Step 1: `docs/design-gaps.md`** with these sections (English, no screenshots):
  1. *Source* — the design (`alice-design/`, reviewed at `erenmeren/alice@44521f5`, committed 2026-10-12) is the reference; this file records where the product differs and why.
  2. *Rulings* — R1–R22 of the plan, one line each.
  3. *Gaps filled in the design's language* — one table `| Screen | What the design lacks | How it was filled (components / tokens) | Task |` with every gap row of the task reports (at least the rows named in the plan's tasks).
  4. *Design elements not built, and why* — numbered pagination, the 5-day histogram, "SSH keys" total, deployment and weak-key counts, resource search, organization name, display time zone, Appearance in Settings, vault cards, the Operation log, the design-system and product-review pages, the "Atlas workspace" sign-in copy.
  5. *Tokens and components added beyond the design* — `*-hover`, `on-strong`, `neutral*`, `auth-brand-*`; `CursorFooter`, `Notice`, `LinkTabs`, `DialogActions`, `ThemeToggle`, `LanguageToggle`, `UsageTopology`, `RotationPath`, `SetupRail`, `AuthLayout`.
  6. *Follow-ups (not in Phase 9)* — a bounded, RBAC-scoped search endpoint; a server-side expiry histogram aggregate; total counts for paged lists if wanted; `locales/common` texts that still say "Dashboard"/"Audit log"; the TR term for API tokens; mobile navigation width.
- [ ] **Step 2: UI labels in the guides** — `grep -rn --exclude-dir=superpowers --exclude-dir=security -E "\*\*(Dashboard|Audit log|My account|Users|Deployment history)\*\*|Welcome, <" docs` and replace each UI reference with the new names (**Overview**, **Audit trail**, **Your account**, **People & access**, **Deployments**); `docs/first-run.md` step 12: "Expected: the **Overview**, with your name in the sidebar, …"; mention the progress rail once ("The left column shows where you are; it is not a menu: each step's own buttons move on."). Add to `docs/admin-guide.md` a section `## Appearance` after "Staying signed in": light, dark or system color mode and compact tables are chosen on **Your account → Appearance** (or the moon/sun button in the top bar) and stay on that computer; the language follows the account.
- [ ] **Step 3: `CHANGELOG.md`** — a new top section:

```markdown
## Unreleased — Phase 9: the Clarity design

**Changed**
- The web interface follows the Clarity product design (`alice-design/`): warm neutral surfaces, a forest accent,
  the bundled Geist fonts and Lucide icons, grouped navigation (Inventory, Operations, Administration), page headers,
  resource tables, status badges, fact lists, operation timelines and attention items.
- Light, dark and system color modes and a compact table density (per computer); the language stays per account.
- Page names: Dashboard → **Overview**, Users → **People & access**, Audit log → **Audit trail**, My account →
  **Your account**, Deployment history → **Deployments**. The Overview has Operations and Assurance tabs.
- Sign-in uses the design's split layout; the first-run wizard shows a progress rail. Every setup check is unchanged.
- New page **Key rotations** (`/rotations`): running rotations and every policy (read-only).
- Error messages show their `ALC-*` code.

**Upgrade notes**
- No API, permission or data change. Bookmarks keep working (`/rotation/runs/<id>` is unchanged).
- The browser stores `alice.colorScheme` and `alice.density` in local storage.
- `THIRD_PARTY_NOTICES.md` lists the bundled fonts (SIL OFL 1.1) and icons (ISC).
```

- [ ] **Step 4: Final checks (no Docker; do not run `make lint` while Task 19 runs Playwright)**

Run: `make docs-check && make i18n-check && make web-lint && make web-coverage && make web && make build && make notices && grep -c "Geist" bin/THIRD_PARTY_NOTICES.md`
Expected: all green; coverage at or above statements 93 / branches 90 / functions 93 / lines 95; `grep -c` ≥ 1. If `make build` cannot run here (helper build), record it and run `go test ./tools/notices/` instead.

- [ ] **Step 5: Commit**

```bash
git add -- docs/design-gaps.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "docs: the Clarity design's gaps and how the product filled them, new page names in the guides, appearance, and the Phase 9 changelog" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- docs/design-gaps.md docs/first-run.md docs/admin-guide.md docs/operator-guide.md \
  docs/troubleshooting.md docs/security-overview.md docs/backup-restore.md docs/nginx-host-preparation.md docs/api.md CHANGELOG.md
```

(Commit only the docs you changed; add `tools/docscheck/required.txt` if you changed it.)

---

## Self-review (done while writing this plan)

1. **Spec coverage.** README deliverables → tasks: operations and assurance dashboards (5); certificate inventory, filtering, saved views, CSV export, details (6); servers and identity review (7); Key Vault inventory, versions, metadata, bindings (8); SSH keys, detail, rotation policies and progress (9, 10); deployment history and outcomes (11); audit, people and access, licensing, API tokens, account (12, 13); appearance, SMTP/recipients, thresholds, SSO, backups, HTTPS, forwarding (13 appearance, 14); login/MFA and first run (15, 16); light/dark/system, EN/TR, responsive, compact density (1, 3, 17, 18); the design-system page (R22, 20). IMPLEMENTATION.md: §1 theme (1, 17), §2 shell and components (3, 4), §3 dashboard with cumulative windows and no truncated aggregates (5, R12), §4 inventories with `useUrlFilters`, cursor pagination, exports, locations and bindings (6–9), §5 deployments and rotation with `deploymentView`/`actions_allowed` (10, 11), §6 roles and license gates (4, 5, 12, R5), §7 search, preferences, wizard checks (R4, R7, 16); acceptance checks 1–3 and 7 (18, 19); 4–6 are covered by the existing role, license and deployment specs that Task 18/19 run unchanged. The owner's request: faithful design (every task names its design functions), wizard and sign-in rearranged (15, 16), gaps filled in the same language (gap rows in every task, 20), e2e green (4, 5, 18, 19), visual evidence not committed (19), docs (20).
2. **Placeholder scan.** Every code step has code or an exact mapping; page tasks whose full JSX would repeat existing logic give the composition, the props, the kept test ids and the tests instead. No "TBD"/"similar to Task N".
3. **Type consistency.** `Tone`, `TONE_COLOR`, `toneOf` (Task 1) are used by `StatusBadge`/`Notice` (3); `NAV_ITEMS`/`isActive`/`match` (4) by Task 10; `useConditionItems` (4) by Task 5 and the bell; `SSH_KEY_TABS` (9) by Task 10; `listPolicies` (10) only in Task 10; `railIndex`/`SetupRail` (16); `AuthLayout` (15); `onScreen` (19) in `runWizard`, `enrollTotp`, `keepTemporaryCertificateStep`, `skipMailStep`.
4. **Review Focus.** Dark mode (tokens.test, colorRules.test, phase9 dark scans), role gates (AppLayout role lists, palette, Assurance tab), wizard rail (SetupRail not interactive, resume test), honest numbers (exclusive buckets, chips without "All" count, no deployment totals), long labels and narrow screens (FactList wrap, phase9 at 390 px in TR). Each has a named test in its owning task.
