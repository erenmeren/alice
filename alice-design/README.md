# Alice — Clarity product design

Interactive product-design prototype based on `erenmeren/alice`, reviewed at commit `44521f52ce02fc92e02a89c9d5a2011f3b95c4a9` on 12 October 2026.

## Deliverable

- Operations and assurance dashboards.
- Certificate inventory, filtering, saved views, CSV export and resource details.
- Server inventory and identity-review states.
- Azure Key Vault inventory, certificate versions, metadata and website bindings.
- SSH key inventory, detail, rotation policies and rotation progress.
- Deployment history and success, rollback, unchanged and uncertain/recovering outcomes.
- Audit trail, people and access, licensing, API tokens and account settings.
- Appearance, SMTP/recipients, thresholds, SSO, backups, HTTPS and forwarding settings.
- Login/MFA presentation and a first-run visual walkthrough.
- An interactive design system and source-linked product review.
- Light, dark and system themes; English and Turkish; responsive layout and compact table density.

## Boundaries

This is a static design prototype using synthetic data, **not** the Alice production application. It does not access a backend, authenticate users, contact servers, send mail or generate cryptographic keys. Role restrictions are demonstrations, not a security boundary. Only theme, language, density and saved filter preferences are saved in local storage. Forms that resemble sensitive operations demonstrate review and verification; they do not collect or persist real secrets.

The original GitHub repository has not been modified. No existing security, license or state-machine code has been replaced.

## Files

- `dist/index.html` — application entry.
- `dist/tokens.css` — semantic theme tokens and bundled fonts.
- `dist/styles.css` — layouts and components.
- `dist/data.js` — synthetic sample inventory.
- `dist/ui.js` — shared rendering helpers and presentation state.
- `dist/pages.js` — operational screens.
- `dist/admin.js` — administrative and onboarding screens.
- `dist/guide.js` — design system, token export and source review.
- `dist/app.js` — routing, local interactions, simulated operations.
- `dist/assets/` — locally bundled Geist/Geist Mono fonts and selected Lucide icons with licenses.
- `validation-report.json` — automated check results and verification limits.
- `IMPLEMENTATION.md` — suggested mapping into the existing React/Mantine product.

The site is buildless. Serve `dist/` from any static HTTP server. Hash routes work without rewrite rules. No runtime packages, external fonts or CDN calls are needed.

Run `npm run check` for JavaScript syntax checks. The development validation used Happy DOM to check routes and interactions, plus arithmetic contrast checks; this is **not** a browser visual, screen-reader or real-backend test.

## Design direction

Quiet confidence, visible control. Warm neutral surfaces and a restrained forest accent provide an identity without making risk indicators compete with decoration. Use Geist for interface text, Geist Mono for fingerprints, paths and technical identifiers. The design system defines color, typography, spacing, radius, density, motion, accessibility targets and state language.

Production implementation should retain the existing React/Mantine, CSP nonce, i18n catalogs, query semantics, RBAC, step-up verification and server-derived action eligibility. The prototype's numbered pagination is illustrative; keep the API's cursor-based pagination in production.

## Verification limits

The original application was inspected in source, not run in a browser. Browser control was unavailable in this environment, so responsive visual inspection and interactive browser accessibility checks remain pending. Numeric color contrast checks do not certify the complete interface as WCAG conformant.
