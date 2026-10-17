# Rulings: web server standard (Phase A)

Spec `docs/superpowers/specs/2026-10-17-web-server-providers-design.md`, plan
`docs/superpowers/plans/2026-10-17-web-server-standard.md` (its Rulings 1–12 stand as written). Merged 2026-10-17.

## Rulings made during execution

1. Task 7 introduced `useWebServers`/`WEB_SERVERS_KEY` (planned for Task 8) because the source guard flagged the
   `'nginx'` literal in `acme/issued.tsx`; Task 8 reused it. It fetches all pages and filters on the client.
2. `softwareName` returns `''` for a type that is not a web server, without an i18n lookup.
3. Task 8 themed Mantine `Tooltip` from the design tokens (light and dark) and removed it from the
   `theme.test.ts` forbidden list; nothing pins the theme class yet.
4. The fake provider fills an empty `WebServer.Software` with its kind.

## Must be settled at the start of Phase B (final review, Important)

1. **Capabilities: snapshot vs registry.** The UI's `can()` reads `targets.capabilities` (written when the
   target was added), the server reads the provider registry. Every capability added later needs a data migration
   (00016 did for `http01_challenge`). Decide: serve server-type capabilities from the registry in the DTO, or
   refresh `targets.capabilities` on connection test / reconcile.
2. **`webserver.Spec` is Nginx-shaped.** `Test` is mandatory and decodes `NginxTestResponse`; `SharedReason`
   and `TestConnection` hard-code `helperproto.CodeNginxNotFound`. Spec §4 says the Apache/HAProxy dumps report
   version and validity themselves. Make `Test` optional (test from the dump), give the not-found code per spec or
   a shared one (not `CodeNotFound`, which means a missing file), add `MinProtocol` and `<kind>.helper_too_old`.
3. **Keyboard users cannot see the "not available" note** (`DisabledFeature`: disabled button out of the tab
   order). No Phase A user reaches the state; it must be fixed before Phase B merges.
4. **Deploy wording in shared texts.** `warnings.web_server_config_invalid`, `locations.configInvalid` and the
   operations text promise or refuse deployment; choose by `can(target, 'deploy_certificate')` and add a
   discovery-only operations text.

## Carried to Phase B (minor)

- TS source guard only knows `'nginx'`: build it from `WEB_SERVER_TYPES`.
- `migrations/web_server_integration_test.go` asserts version 16 after `Up` (use `UpTo(16)`); use non-empty
  `Params` in the next migration test.
- `maxChainCerts` exists in `nginx/verify.go` and `webserver/convert.go`: one constant or an equality test.
- Stale Nginx wording in `webserver` comments and the `ServerDumpResponse` doc comment.
- `KindForTargetType` must gain every new web-server type (the scan fallback relies on it).
- No test pins the Tooltip theme class.

## Dropped (with reason)

- `openPublisher` checks the capability before status: same precedence for any registry with the shipped nginx.
- Dense `vaultTypes` append, `ErrorIs`-only refusal test, `typeValues` reading the list directly, target B not
  asserted after Down, `kind, _` in targetjobs (guarded by `IsWebServer`), unit-only targetjobs coverage (floor is
  measured with integration), client-side `useWebServers` filter (fine at expected scale).
