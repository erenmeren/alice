import type { APIRequestContext, Locator, Page } from '@playwright/test';
import {
  ADMIN,
  FLEET,
  advanceClock,
  answerStepUp,
  apiAs,
  browserLocale,
  discoveredCertificates,
  discoveredEndpoints,
  discoveryScan,
  discoveryScope,
  discoverySettings,
  discoveryStart,
  discoverySummary,
  discoveryWait,
  drainJobs,
  expect,
  expectAccessible,
  field,
  fleetCounters,
  fleetHost,
  fleetLog,
  fleetReset,
  fleetScope,
  fleetValidPair,
  readDownload,
  resetInstall,
  runScheduled,
  runWizard,
  settle,
  signIn,
  smtpCtl,
  smtpMessages,
  test,
  translator,
  type Account,
  type Api,
  type FleetKind,
  type Lang,
} from './helpers';

// Phase 11 (network discovery) on the e2e stack: the fake TLS fleet (compose service fakefleet, one server per kind on
// 10.89.0.10, reached over the internal network "fleet" that Alice shares with it). The journeys allow exactly
// FLEET.network in the discovery settings. Scans never run by themselves in the e2e build: a test starts one and drains
// the job queue (the scan runs inside the drain). Every visible text is read from the locale files at run time.

const ADA: Account & { email: string } = { ...ADMIN, email: 'ada@example.test' };
const DAY_SECONDS = 24 * 3600;
const JOURNEY_TIMEOUT = 8 * 60_000;
const SCOPE = 'Fleet scope';

// The kinds the main journey scans: a valid certificate (stored in the inventory, so Known), an expired one, a
// self-signed one and a server that speaks plain text (no TLS handshake).
const MAIN_KINDS: FleetKind[] = ['valid', 'expired', 'self-signed', 'plaintext'];

interface Install {
  totpSecret: string;
  api: Api;
}

// install resets Alice and the fleet's log and installs Alice in lang with the Administrator ADA (who has an address).
async function install(page: Page, request: APIRequestContext, lang: Lang): Promise<Install> {
  await resetInstall(request);
  fleetReset();
  const { totpSecret } = await runWizard(page, request, lang, ADA);
  return { totpSecret, api: await apiAs(page) };
}

// seedScope allows the fleet's network and creates a scope of kinds through the API (fresh step-up), then reloads the
// page, whose CSRF token the step-up rotated.
async function seedScope(page: Page, s: Install, kinds: FleetKind[], extra = {}): Promise<string> {
  await s.api.stepUp(s.totpSecret);
  await discoverySettings(s.api);
  const id = await discoveryScope(s.api, fleetScope(SCOPE, kinds, extra));
  await page.reload();
  return id;
}

// storeValidCertificate puts the certificate the fleet's valid server presents into Alice's inventory.
async function storeValidCertificate(api: Api): Promise<void> {
  const pair = fleetValidPair();
  const res = await api.post('/api/v1/certificates/upload', { label: 'fleet valid', certificate_pem: pair.certificate_pem, private_key_pem: pair.private_key_pem });
  expect(res.status(), await res.text()).toBe(201);
}

function resultRow(page: Page, name: string): Locator {
  return page.getByTestId('discovery-result-row').filter({ hasText: name });
}

// openResults opens the Results tab (with the query string given) and waits for the table.
async function openResults(page: Page, query = ''): Promise<void> {
  await page.goto(`/discovery${query}`);
  await expect(page.getByTestId('discovery-results-table')).toBeVisible();
}

function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else cell += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') {
      row.push(cell);
      cell = '';
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
    } else cell += ch;
  }
  if (cell !== '' || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const t = translator(lang);

  test.describe(`Phase 11 network discovery (${lang})`, () => {
    test.use({ locale: browserLocale(lang), actionTimeout: 30_000 });

    test('settings, scope with live size, scan, results, drawer, Still found, adopt as server, export, axe', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const s = await install(page, request, lang);
      await s.api.stepUp(s.totpSecret);
      await storeValidCertificate(s.api);
      await page.goto('/discovery?tab=scopes');

      // Nothing is scanned until networks are allowed: the calm notice, then the settings dialog.
      await expect(page.getByText(t('discovery.settings.emptyTitle'), { exact: true }).first()).toBeVisible();
      await expectAccessible(page, 'discovery scopes, nothing allowed', { soft: true });
      await page.getByRole('button', { name: t('discovery.settings.emptyAdminAction'), exact: true }).click();
      const settings = page.getByRole('dialog', { name: t('discovery.settings.dialogTitle') });
      await field(settings, t('discovery.settings.allowed')).fill(FLEET.network);
      await settings.getByRole('button', { name: t('discovery.settings.save'), exact: true }).click();
      await answerStepUp(page, request, lang, s.totpSecret, page.locator('code', { hasText: FLEET.network }).first());
      await expect(settings).toHaveCount(0);

      // The scope: the live size says what one scan covers before it is saved.
      await page.getByRole('button', { name: t('discovery.scopes.add'), exact: true }).first().click();
      const dialog = page.getByRole('dialog', { name: t('discovery.scope.addTitle') });
      await field(dialog, t('discovery.scope.name')).fill(SCOPE);
      await field(dialog, t('discovery.scope.entries')).fill(FLEET.address);
      await field(dialog, t('discovery.scope.ports')).fill(MAIN_KINDS.map((k) => FLEET.ports[k]).join(', '));
      const covers = t('discovery.scope.preview.covers', {
        addresses: t('discovery.scope.preview.addresses', { count: 1, n: '1' }),
        ports: t('discovery.scope.preview.ports', { count: MAIN_KINDS.length, n: String(MAIN_KINDS.length) }),
      });
      await expect(dialog.getByTestId('scope-preview-live')).toHaveText(covers);
      await expectAccessible(page, 'discovery scope dialog', { soft: true, dialog });
      await dialog.getByRole('button', { name: t('discovery.scope.save'), exact: true }).click();
      await expect(dialog).toHaveCount(0);
      const scopeRow = page.getByTestId('discovery-scope-row').filter({ hasText: SCOPE });
      await expect(scopeRow).toBeVisible();
      // The switch is named by its scope.
      await expect(page.getByRole('switch', { name: SCOPE, exact: true })).toBeChecked();
      await expectAccessible(page, 'discovery scopes', { soft: true });

      // Scan now: the scan is queued, the drain runs it, the Scans tab shows the end.
      await scopeRow.getByRole('button', { name: t('discovery.scopes.scanLabel', { name: SCOPE }), exact: true }).click();
      await page.getByRole('tab', { name: t('discovery.tabs.scans') }).click();
      const done = page.locator('[data-testid="discovery-scan-row"][data-state="done"]');
      await settle(request, done.first());
      await expect(done).toHaveCount(1);
      await expect(done.first()).toContainText(SCOPE);
      await expect(done.first()).toContainText(t('discovery.scans.counts', { answered: 3, failed: 1, total: MAIN_KINDS.length }));
      await expectAccessible(page, 'discovery scans', { soft: true });

      // The fleet saw one handshake per TLS kind and no application byte at all.
      const log = fleetLog();
      expect(new Set(log.map((a) => a.kind))).toEqual(new Set(MAIN_KINDS));
      expect(fleetCounters().app_bytes_after_handshake, 'a probe never sends an application byte').toBe(0);

      // Results: the three certificates, soonest expiry first by the API; the default filter is "Still found".
      await page.getByRole('tab', { name: t('discovery.tabs.results') }).click();
      const table = page.getByTestId('discovery-results-table');
      await expect(table).toBeVisible();
      await expect(field(page, t('discovery.results.found'))).toHaveValue('');
      const expired = resultRow(page, fleetHost('expired'));
      const selfSigned = resultRow(page, fleetHost('self-signed'));
      const known = resultRow(page, fleetHost('valid'));
      await expect(page.getByTestId('discovery-result-row')).toHaveCount(3);
      // Status cell: the status and, for the self-signed one, its chip. The Expired text of the Expires column (the
      // inventory's badge) is not repeated as a chip in the row.
      await expect(expired.getByRole('cell').nth(4)).toContainText(t('discovery.enum.status.unmanaged'));
      await expect(expired.getByRole('cell').nth(4)).not.toContainText(t('discovery.chips.expired'));
      await expect(selfSigned.getByRole('cell').nth(4)).toContainText(t('discovery.chips.selfSigned'));
      await expect(known.getByRole('cell').nth(4)).toContainText(t('discovery.enum.status.known'));
      await expectAccessible(page, 'discovery results', { soft: true });

      // The side drawer is titled with the certificate and shows where it was found.
      await expired.getByRole('button').first().click();
      const drawer = page.getByRole('dialog', { name: t('discovery.drawer.titleNamed', { name: fleetHost('expired') }) });
      await expect(drawer).toBeVisible();
      await expect(drawer.getByText(t('discovery.chips.expired'), { exact: true }).first()).toBeVisible();
      const endpoint = drawer.getByTestId('discovery-endpoint');
      await expect(endpoint).toHaveCount(1);
      await expect(endpoint).toContainText(`${FLEET.address}:${FLEET.ports.expired}`);
      await expectAccessible(page, 'discovery drawer', { soft: true, dialog: drawer });
      await page.keyboard.press('Escape');
      await expect(drawer).toHaveCount(0);
      await expect(expired.getByRole('button').first()).toBeFocused();

      // Export: the file holds the rows the list shows.
      const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: t('filters.export'), exact: true }).click()]);
      try {
        const csv = parseCsv((await readDownload(download)).replace(/^\uFEFF/, ''));
        expect(download.suggestedFilename()).toMatch(/^alice-discovered-certificates-\d{4}-\d{2}-\d{2}\.csv$/);
        const text = csv.map((r) => r.join(',')).join('\n');
        for (const kind of ['valid', 'expired', 'self-signed'] as const) expect(text, `export has ${kind}`).toContain(fleetHost(kind));
        expect(csv.length - 1).toBe(3);
      } finally {
        await download.delete();
      }

      // Adopt: Add as server opens the existing dialog with the address, keeps SSH port 22 and counts the license.
      await selfSigned.getByRole('button').first().click();
      const drawer2 = page.getByRole('dialog', { name: t('discovery.drawer.titleNamed', { name: fleetHost('self-signed') }) });
      await drawer2.getByRole('button', { name: t('discovery.drawer.addServerLabel', { address: `${FLEET.address}:${FLEET.ports['self-signed']}` }) }).click();
      const add = page.getByRole('dialog', { name: t('targets.add') });
      await expect(field(add, t('targets.form.host'))).toHaveValue(FLEET.address);
      await expect(field(add, t('targets.form.port'))).toHaveValue('22');
      await add.getByRole('button', { name: t('targets.form.submit'), exact: true }).click();
      await settle(request, add.getByText(t('targets.failedHelp'), { exact: true })); // no SSH server there: the first check fails
      await add.getByRole('button', { name: t('ui.close'), exact: true }).last().click(); // the footer's, not the title bar's
      const api = await apiAs(page);
      const targets = (await (await api.get('/api/v1/targets')).json()) as { items: { host: string; port: number }[] };
      expect(targets.items.map((x) => `${x.host}:${x.port}`)).toContain(`${FLEET.address}:22`);

      // Still found: removing a port from the scope marks its endpoint gone; the default list drops the certificate and
      // "Include no longer found" brings it back with its chip.
      await page.goto('/discovery?tab=scopes');
      await page.getByRole('button', { name: t('discovery.scopes.editLabel', { name: SCOPE }), exact: true }).click();
      const edit = page.getByRole('dialog', { name: t('discovery.scope.editTitle', { name: SCOPE }) });
      await field(edit, t('discovery.scope.ports')).fill([443, FLEET.ports.expired, FLEET.ports.plaintext].join(', '));
      await edit.getByRole('button', { name: t('discovery.scope.save'), exact: true }).click();
      await answerStepUp(page, request, lang, s.totpSecret, page.getByRole('dialog', { name: t('discovery.scope.editTitle', { name: SCOPE }) }).or(page.getByTestId('discovery-scope-row')).first());
      await expect(edit).toHaveCount(0);
      await openResults(page);
      await expect(resultRow(page, fleetHost('self-signed'))).toHaveCount(0);
      await field(page, t('discovery.results.found')).selectOption('all');
      const gone = resultRow(page, fleetHost('self-signed'));
      await expect(gone).toBeVisible();
      await expect(gone.getByRole('cell').nth(4)).toContainText(t('discovery.chips.gone'));
    });

    test('Overview line and its link, the licence lock, the e-mail and the link in it', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const s = await install(page, request, lang);
      // The mail server (trusted by its fingerprint) and Alice's address, so that the e-mail has a link.
      await s.api.stepUp(s.totpSecret);
      smtpCtl('up');
      smtpCtl('reject', '');
      smtpCtl('clear');
      const origin = new URL(page.url()).origin;
      const general = await s.api.put('/api/v1/settings/general', { public_url: origin, retired_key_retention_days: 30 }, { 'If-Match': '"0"' });
      expect(general.ok(), await general.text()).toBe(true);
      const creds = smtpCtl<{ username: string; password: string }>('credentials');
      const smtp = await s.api.put(
        '/api/v1/settings/smtp',
        { host: 'fakesmtp', port: 2525, tls_mode: 'starttls', from: 'alice@example.test', username: creds.username, password: creds.password, ca_pem: '' },
        { 'If-Match': '"0"' },
      );
      expect(smtp.ok(), await smtp.text()).toBe(true);
      const refused = await s.api.post('/api/v1/settings/smtp/actions/test', { to: ADA.email });
      expect(refused.status(), 'the mail server certificate is not trusted yet').toBe(502);
      const etag = (await s.api.get('/api/v1/settings/smtp')).headers()['etag'];
      const trust = await s.api.post('/api/v1/settings/smtp/actions/trust', { fingerprint: smtpCtl<{ fingerprint: string }>('fingerprint').fingerprint }, { 'If-Match': etag });
      expect(trust.ok(), await trust.text()).toBe(true);
      smtpCtl('clear');

      const id = await seedScope(page, s, ['valid', 'expired', 'self-signed'], { alert_on_expiry: true });
      const scan = await discoveryStart(s.api, id);
      expect((await discoveryWait(s.api, request, scan.id)).state).toBe('done');

      // The expiry e-mail of the certificate that expired names it and links the unmanaged list at Alice's address.
      await runScheduled(request, 'alerts.scan');
      await runScheduled(request, 'notify.send');
      const mails = smtpMessages().filter((m) => m.Content.Headers.Subject[0].includes(fleetHost('expired')));
      expect(mails, `the expired certificate, among: ${smtpMessages().map((m) => m.Content.Headers.Subject[0]).join(' | ')}`).toHaveLength(1);
      expect(mails[0].Raw.To).toEqual([ADA.email]);
      expect(mails[0].Content.Headers.Subject[0]).toBe(t('email.alert.discovered_certificate_expired.subject', { name: fleetHost('expired') }));
      const link = mails[0].Content.Body.match(/https?:\/\/\S+\/discovery\S*/)?.[0];
      expect(link, `the discovery link in: ${mails[0].Content.Body}`).toBe(`${origin}/discovery?view=unmanaged`);
      await page.goto(link!);
      await expect(page.getByTestId('discovery-results-table')).toBeVisible();
      await expect(field(page, t('discovery.results.status'))).toHaveValue('unmanaged');
      await expect(resultRow(page, fleetHost('expired'))).toBeVisible();

      // The licence ends and the certificates come within 30 days of their end: the Overview counts them, and the line
      // links the list with the same meaning.
      await advanceClock(request, 61 * DAY_SECONDS);
      await signIn(page, request, ADA, s.totpSecret);
      const api = await apiAs(page);
      const summary = await discoverySummary(api);
      expect(summary.unmanaged_expiring_30d).toBeGreaterThan(0);
      await page.goto('/');
      const line = page.getByTestId('discovery-unmanaged');
      await expect(line).toContainText(t('dashboard.unmanagedExpiring', { count: summary.unmanaged_expiring_30d }));
      const anchor = line.getByRole('link');
      await expect(anchor).toHaveAttribute('href', '/discovery?view=unmanaged&expiry=30');
      await anchor.click();
      await expect(page).toHaveURL(/\/discovery\?view=unmanaged&expiry=30$/);
      await expect(page.getByTestId('discovery-result-row')).toHaveCount(summary.unmanaged_expiring_30d);

      // Lock: a manual start is refused with the licence text, reads and the scopes tab still work.
      const start = await api.post(`/api/v1/discovery/scopes/${id}/scans`);
      expect(start.status()).toBe(403);
      const body = (await start.json()) as { error: { code: string; reason: string; message: string } };
      expect(body.error.reason).toBe('license.locked');
      expect(body.error.code).toBe('ALC-LIC-0001');
      // The API answers in English: a request without Accept-Language, whatever the account's language.
      expect(body.error.message).toContain(translator('en')('errors.license.locked.title'));
      fleetReset();
      await drainJobs(request);
      expect(fleetLog(), 'nothing was dialled in lock').toEqual([]);
      await page.goto('/discovery?tab=scopes');
      await expect(page.getByText(t('discovery.lockedTitle'), { exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: t('discovery.scopes.scanLabel', { name: SCOPE }), exact: true })).toBeDisabled();
      await expect(page.getByText(t('discovery.block.locked'), { exact: true }).first()).toBeVisible();
      expect((await discoveredCertificates(api)).length).toBeGreaterThan(0);
      await expectAccessible(page, 'discovery scopes in lock', { soft: true });
    });

    test('a running scan is cancelled; excluded addresses are refused and never dialled', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const s = await install(page, request, lang);

      // Exclusions: a global exclusion and the built-in ones. A scope that lists an excluded address is refused with its
      // line; a range that contains Alice's own address scans the rest and records that address as not scanned.
      await s.api.stepUp(s.totpSecret);
      await discoverySettings(s.api, [FLEET.network, '127.0.0.0/8'], ['10.89.0.50']);
      const refusal = await s.api.post('/api/v1/discovery/scopes', fleetScope('Loopback', ['valid'], { entries: ['127.0.0.1'] }));
      expect(refusal.status(), await refusal.text()).toBe(422);
      expect(((await refusal.json()) as { error: { code: string } }).error.code).toMatch(/^ALC-DSC-/);
      const range = await discoveryScope(s.api, { name: 'Range', entries: ['10.89.0.0/28'], ports: [FLEET.ports.expired] });
      const ranged = await discoveryWait(s.api, request, (await discoveryStart(s.api, range)).id);
      expect(ranged.state).toBe('done');
      expect(ranged.endpoints_excluded, 'Alice itself is not dialled').toBeGreaterThan(0);
      expect(ranged.endpoints_answered).toBe(1);
      const excluded = (await discoveredEndpoints(s.api, range)).filter((e) => e.state === 'excluded');
      expect(excluded.map((e) => e.address)).toContain(FLEET.alice);

      // The same refusal on screen: the line is named, nothing is stored.
      await page.reload();
      await page.goto('/discovery?tab=scopes');
      await page.getByRole('button', { name: t('discovery.scopes.add'), exact: true }).first().click();
      const dialog = page.getByRole('dialog', { name: t('discovery.scope.addTitle') });
      await field(dialog, t('discovery.scope.name')).fill('Loopback');
      await field(dialog, t('discovery.scope.entries')).fill(`${FLEET.address}\n169.254.169.254`);
      await field(dialog, t('discovery.scope.ports')).fill('443');
      await dialog.getByRole('button', { name: t('discovery.scope.save'), exact: true }).click();
      await answerStepUp(page, request, lang, s.totpSecret, dialog.getByText(/2/).first());
      await expect(dialog.getByText(t('discovery.scope.line', { line: 2, problem: '' }).replace(/\s*$/, ''), { exact: false }).first()).toBeVisible();
      await expect(dialog).toBeVisible();
      await dialog.getByRole('button', { name: t('ui.cancel'), exact: true }).click();
      await expect(page.getByTestId('discovery-scope-row').filter({ hasText: 'Loopback' })).toHaveCount(0);

      // Cancel: the slow-loris server holds the handshake open; the scan is running while the drain runs it.
      // 15 addresses at one new connection a second keep the scan running long enough to be stopped.
      await discoveryScope(s.api, { name: 'Slow', entries: ['10.89.0.0/28'], ports: [FLEET.ports['slow-loris']], rate_per_sec: 1 });
      fleetReset();
      await page.goto('/discovery?tab=scopes');
      await page.getByRole('button', { name: t('discovery.scopes.scanLabel', { name: 'Slow' }), exact: true }).click();
      await page.getByRole('tab', { name: t('discovery.tabs.scans') }).click();
      const draining = drainJobs(request, { allowCutOff: true });
      await expect(page.locator('[data-testid="discovery-scan-row"][data-state="running"]')).toHaveCount(1, { timeout: 30_000 });
      await page.getByRole('button', { name: t('discovery.scans.cancelLabel', { name: 'Slow' }), exact: true }).click();
      await draining;
      const scans = (await (await s.api.get('/api/v1/discovery/scans?limit=1')).json()) as { items: { id: string }[] };
      await expect.poll(async () => (await discoveryScan(s.api, scans.items[0].id)).state).toBe('cancelled');
      await expect(page.locator('[data-testid="discovery-scan-row"][data-state="cancelled"]').filter({ hasText: 'Slow' })).toBeVisible();
    });
  });
}
