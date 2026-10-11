import type { APIRequestContext, BrowserContext, Locator, Page } from '@playwright/test';
import {
  ADMIN,
  COPY,
  PHONE_WIDTH,
  advanceClock,
  answerStepUp,
  apiAs,
  browserLocale,
  expect,
  expectAccessibleAt,
  field,
  idpCA,
  idpCtl,
  newCert,
  readDownload,
  resetInstall,
  runScheduled,
  runWizard,
  seedDashboard,
  selectByKeyboard,
  serverNow,
  signIn,
  signOut,
  smtpCtl,
  smtpMessages,
  tabTo,
  test,
  translator,
  type Account,
  type Lang,
  type SeedAnswer,
  type Translate,
} from './helpers';

// Phase 7 owner journeys on the e2e stack (§26.9): the seeded dashboard and its counts, a filter that narrows the
// certificate list, the export that equals the rows shown, a saved view, the mail settings with the untrusted mail
// server certificate and the test e-mail, the expiry e-mail received by the fake SMTP server exactly once, the "E-mails
// could not be sent" banner, single sign-on with the fake identity provider (refused, then an Operator) and the local
// Administrator's sign-in while the identity provider is down (X-05). Every step is asserted on the screen and on what
// it causes elsewhere: the messages the fake SMTP server accepted, the audit log (read on its page), the sign-in state.
//
// Clock: the fake identity provider stamps its tokens with the real time (exp 5 minutes, Alice's leeway 60 s), while
// the journeys move Alice's e2e clock. So the SSO journey is a test of its own that starts on a reset clock (resetInstall)
// and moves it only by the few 31 s steps of the step-up codes; the e-mail journey moves it by days.
//
// No secret in artefacts: the SMTP password and the client secret are typed, an export is downloaded. Tracing, video
// and screenshots are off for this file, Playwright's error context (field values) is off while it runs, and the
// downloaded export is read into memory and deleted in a finally block.

const DAY_SECONDS = 24 * 3600;
const JOURNEY_TIMEOUT = 12 * 60_000;
// The widths every Phase 7 screen is checked at: a phone, a tablet, the desktop widths of §26.1 item 9.
const WIDTHS = [PHONE_WIDTH, 640, 1280, 1920] as const;
// Dialogs and open menus: a phone and a desktop.
const DIALOG_WIDTHS = [PHONE_WIDTH, 1280] as const;
// The e2e convention for the Administrator's address (B11); alert e-mails go to Administrators with an address.
const ADA: Account & { email: string } = { ...ADMIN, email: 'ada@example.test' };
const IDP_NAME = 'Test IdP';
const OMER = { sub: 'e2e-omer', username: 'omer', name: 'Ömer Çelik', email: 'omer@example.test' };
const SESSION_COOKIE = '__Host-alice_session';
const ZEYNEP = { sub: 'e2e-zeynep', username: 'zeynep', name: 'Zeynep Şahin', email: 'zeynep@example.test' };
// auth.StepUpWindow: a sign-in or step-up confirms the session for this long.
const STEP_UP_SECONDS = 5 * 60;

test.use({
  trace: 'off',
  video: 'off',
  screenshot: 'off',
  ignoreHTTPSErrors: true,
});
// The fake identity provider is https://idp.alice-e2e.test:9444 for Alice (a network alias) and for the browser, where
// nothing resolves the name (never /etc/hosts). Chromium maps it to the loopback port compose publishes
// (--host-resolver-rules, set on the chromium project in playwright.config.ts). Firefox and WebKit have no such switch:
// their requests to that address are sent by Playwright to the same loopback port and answered with the provider's own
// response (redirects not followed, so the browser follows them as from the provider); a provider that is down is a
// refused connection, as in Chromium. WebKit cannot be handed a redirect (route.fulfill refuses a 3xx there): it gets a
// page that goes to the same address at once (a meta refresh, a top-level navigation from the provider's origin).
const IDP_ORIGIN = 'https://idp.alice-e2e.test:9444';
function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
async function routeIdp(context: BrowserContext, redirectByPage: boolean): Promise<void> {
  await context.route((url) => url.origin === IDP_ORIGIN, async (route) => {
    const url = IDP_ORIGIN.replace('idp.alice-e2e.test', '127.0.0.1') + route.request().url().slice(IDP_ORIGIN.length);
    let response;
    try {
      response = await route.fetch({ url, maxRedirects: 0 });
    } catch {
      await route.abort('connectionrefused');
      return;
    }
    const location = response.headers()['location'];
    if (redirectByPage && response.status() >= 300 && response.status() < 400 && location) {
      const target = escapeHtml(new URL(location, route.request().url()).toString());
      await route.fulfill({ status: 200, contentType: 'text/html', body: `<!doctype html><meta http-equiv="refresh" content="0;url=${target}"><title>redirect</title>` });
      return;
    }
    await route.fulfill({ response });
  });
}

let copyPrompt: string | undefined;
test.beforeAll(() => {
  copyPrompt = process.env.PLAYWRIGHT_NO_COPY_PROMPT;
  process.env.PLAYWRIGHT_NO_COPY_PROMPT = '1';
});
test.afterAll(() => {
  if (copyPrompt === undefined) delete process.env.PLAYWRIGHT_NO_COPY_PROMPT;
  else process.env.PLAYWRIGHT_NO_COPY_PROMPT = copyPrompt;
});

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// screen checks a whole screen at every Phase 7 width, softly (a finding fails the test at its end; the journey goes on).
async function screen(page: Page, name: string): Promise<void> {
  await expectAccessibleAt(page, name, WIDTHS, { soft: true });
}

// dialogCheck checks an open dialog or menu at a phone's and a desktop's width.
async function dialogCheck(page: Page, name: string, dialog: Locator): Promise<void> {
  await expectAccessibleAt(page, name, DIALOG_WIDTHS, { soft: true, dialog });
}

// tableNames are the names in the first column of a table's rows (each is a <code>), in order.
async function tableNames(page: Page, testId: string): Promise<string[]> {
  return page
    .getByTestId(testId)
    .locator('tbody tr')
    .evaluateAll((trs) => trs.map((tr) => (tr.querySelector('code')?.textContent ?? '').trim()));
}

// parseCsv reads RFC 4180 CSV (quoted fields, doubled quotes, CRLF or LF) into rows of cells.
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

// exportCsv clicks Export on the open list and returns the file's rows; the file is deleted whatever happens.
async function exportCsv(page: Page, t: Translate): Promise<{ bom: boolean; rows: string[][]; name: string }> {
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: t('filters.export'), exact: true }).click()]);
  try {
    const text = await readDownload(download);
    return { bom: text.startsWith('\uFEFF'), rows: parseCsv(text.replace(/^\uFEFF/, '')), name: download.suggestedFilename() };
  } finally {
    await download.delete();
  }
}

// mailDate is how e-mails render a time (R42 row 10).
function mailDate(at: number): string {
  return new Date(at).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
}

function subjects(): string[] {
  return smtpMessages().map((m) => m.Content.Headers.Subject[0]);
}

// auditShows opens the audit log filtered by an action prefix and expects a row for each action's label.
async function auditShows(page: Page, lang: Lang, t: Translate, prefix: string, actions: string[]): Promise<void> {
  await page.getByRole('link', { name: COPY[lang].navAudit, exact: true }).click();
  await expect(page.getByRole('heading', { name: COPY[lang].auditHeading })).toBeVisible();
  await field(page, t('audit.filters.action')).fill(prefix);
  await page.getByRole('button', { name: t('audit.filters.apply'), exact: true }).click();
  for (const action of actions) {
    await expect(page.getByRole('row').filter({ hasText: t(`audit.actions.${action}`) }).first(), `audit: ${action}`).toBeVisible();
  }
}

// openSettings opens a Settings tab by its address and answers the step-up prompt the first read may raise.
async function openSettings(page: Page, request: APIRequestContext, lang: Lang, secret: string, tab: string, done: Locator): Promise<void> {
  await page.goto(`/settings?tab=${tab}`);
  await answerStepUp(page, request, lang, secret, done);
}

function countLink(counts: Locator, t: Translate, key: string, n: number): Locator {
  return counts.getByRole('link', { name: new RegExp(`^${escapeRegExp(t(key))}\\s*${n}$`) });
}

// addTestProvider sets up through the screens: Alice's address saved, then the fake identity provider added and
// switched on; returns the provider's region on the Single sign-on tab. Used by the journey that is not about the form.
async function addTestProvider(page: Page, request: APIRequestContext, lang: Lang, t: Translate, secret: string): Promise<Locator> {
  await openSettings(page, request, lang, secret, 'general', field(page, t('settings.general.publicUrl')));
  await page.getByRole('button', { name: t('settings.general.save'), exact: true }).click();
  await expect(page.getByText(t('settings.saved'), { exact: true })).toBeVisible();
  const addProvider = page.getByRole('button', { name: t('sso.addProvider'), exact: true });
  await openSettings(page, request, lang, secret, 'sso', addProvider);
  const idp = idpCtl<{ issuer: string; client_id: string; client_secret: string }>('credentials');
  await addProvider.click();
  const dlg = page.getByRole('dialog', { name: t('sso.addProvider') });
  await field(dlg, t('sso.name')).fill(IDP_NAME);
  await field(dlg, t('sso.issuer')).fill(idp.issuer);
  await field(dlg, t('sso.clientId')).fill(idp.client_id);
  await field(dlg, t('sso.clientSecret')).fill(idp.client_secret);
  await field(dlg, t('sso.caPem')).fill(idpCA());
  await dlg.getByRole('switch', { name: t('sso.enabled') }).click();
  await dlg.getByRole('button', { name: t('sso.save'), exact: true }).click();
  await dlg.getByRole('button', { name: t('ui.continue'), exact: true }).click();
  await expect(dlg).toHaveCount(0);
  return page.getByRole('region', { name: IDP_NAME });
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const t = translator(lang);
  const c = COPY[lang];

  test.describe(`Phase 7 alerts, dashboard and SSO (${lang})`, () => {
    test.use({ locale: browserLocale(lang), actionTimeout: 30_000 });
    test.beforeEach(async ({ request, context, browserName }) => {
      if (browserName !== 'chromium') await routeIdp(context, browserName === 'webkit');
      await resetInstall(request);
      smtpCtl('up');
      smtpCtl('reject', '');
      smtpCtl('clear');
      idpCtl('up');
    });
    test.afterEach(() => {
      smtpCtl('up');
      idpCtl('up');
    });

    test('§26.9 owner steps 1-4: seeded dashboard, filter, export = rows, saved view, test mail and trust, the expiry e-mail once, the failing banner', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      // The contract's pinned texts are what the app shows (a locale drift fails here).
      expect(t('notifications.failingTitle')).toBe(lang === 'en' ? 'E-mails could not be sent' : 'E-postalar gönderilemedi');
      expect(t('settings.mail.sendTest')).toBe(lang === 'en' ? 'Send test e-mail' : 'Test e-postası gönder');
      expect(t('settings.mail.trust')).toBe(lang === 'en' ? 'Trust this certificate' : 'Bu sertifikaya güven');
      expect(t('dashboard.expiringSoon')).toBe(lang === 'en' ? 'Expiring soon' : 'Süresi yakında dolacaklar');
      expect(t('filters.export')).toBe(lang === 'en' ? 'Export' : 'Dışa aktar');

      const { totpSecret } = await runWizard(page, request, lang, ADA);
      const before = await serverNow(request);
      const seeded: SeedAnswer = await seedDashboard(request);
      const after = await serverNow(request);

      // Owner step 2 (§26.9 "a seeded environment shows the expected counts"): every count is a link whose list has
      // exactly that many rows; the expiring list starts with the expired certificate.
      await page.goto('/');
      await expect(page.getByRole('heading', { level: 1, name: t('dashboard.welcome', { name: ADA.fullName }) })).toBeVisible();
      const counts = page.getByTestId('dashboard-counts');
      const lines: [string, number, string][] = [
        ['dashboard.expired', seeded.certificates.expired, 'expired'],
        ['dashboard.within7', seeded.certificates.within_7, '7'],
        ['dashboard.within30', seeded.certificates.within_30, '30'],
        ['dashboard.within60', seeded.certificates.within_60, '60'],
      ];
      for (const [key, n] of lines) await expect(countLink(counts, t, key, n), key).toBeVisible();
      await expect(counts.getByText(t('dashboard.monitored', { count: seeded.certificates.monitored }), { exact: true })).toBeVisible();
      const expiring = page.getByTestId('expiring-list');
      await expect.poll(() => tableNames(page, 'expiring-list')).toEqual(seeded.expiring_30);
      await expect(expiring.locator('tbody tr').first().getByText(t('certificates.expired'), { exact: true })).toBeVisible();
      await expect(expiring.getByRole('row').filter({ has: page.getByText('www.seed.test', { exact: true }) })).toHaveCount(1);
      // The seeded server with a changed host key needs attention.
      await expect(page.getByTestId('attention-list').getByText('seed-web-3', { exact: true })).toBeVisible();
      await screen(page, 'dashboard');
      for (const [key, n, expiry] of lines) {
        await page.goto('/');
        await countLink(counts, t, key, n).click();
        await expect(page).toHaveURL(new RegExp(`/certificates\\?expiry=${expiry}$`));
        await expect.poll(() => tableNames(page, 'certificates-table'), key).toHaveLength(n);
      }

      // Owner step 3: a filter narrows the list (chosen with the keyboard), then one server; the address holds both.
      await page.goto('/');
      await page.getByRole('link', { name: t('nav.certificates'), exact: true }).click();
      await expect(page.getByRole('heading', { level: 1, name: t('certificates.title') })).toBeVisible();
      await expect.poll(() => tableNames(page, 'certificates-table')).toHaveLength(9);
      const expirySelect = field(page, t('certificates.expiry'));
      await expirySelect.focus();
      await selectByKeyboard(page, expirySelect, '30');
      await expect
        .poll(() => tableNames(page, 'certificates-table'))
        .toEqual(['old.seed.test', 'spare.seed.test', 'api.seed.test', 'www.seed.test', 'shop.seed.test', 'mail.seed.test', 'intra.seed.test']);
      await field(page, t('certificates.server')).selectOption({ label: seeded.server_filter.target });
      await expect.poll(() => tableNames(page, 'certificates-table')).toEqual(seeded.server_filter.expiry_30);
      await expect(page).toHaveURL(/[?&]expiry=30(&|$)/);
      await expect(page).toHaveURL(/[?&]target_id=[0-9a-f-]{36}(&|$)/);
      await screen(page, 'certificates, filtered');

      // The export holds exactly the rows the table shows, in order, with a byte order mark and the header row.
      const shown = await tableNames(page, 'certificates-table');
      const csv = await exportCsv(page, t);
      expect(csv.name).toMatch(/^alice-certificates-\d{4}-\d{2}-\d{2}\.csv$/);
      expect(csv.bom, 'UTF-8 byte order mark').toBe(true);
      expect(csv.rows[0].slice(0, 3)).toEqual(['id', 'subject_cn', 'label']);
      expect(csv.rows.slice(1).map((r) => r[1])).toEqual(shown);

      // A saved view, with the keyboard: the dialog opens with the name field focused and Enter saves it; the menu opens
      // with Enter and its item is chosen with the arrow keys.
      const saveView = page.getByRole('button', { name: t('filters.saveView'), exact: true });
      await saveView.focus();
      await page.keyboard.press('Enter');
      const saveDialog = page.getByRole('dialog', { name: t('filters.saveView') });
      await expect(field(saveDialog, t('filters.viewName'))).toBeFocused();
      await dialogCheck(page, 'Save view', saveDialog);
      await page.keyboard.type('Web 1 soon');
      await page.keyboard.press('Enter');
      await expect(saveDialog).toHaveCount(0);
      await page.getByRole('button', { name: t('filters.clear'), exact: true }).click();
      await expect.poll(() => tableNames(page, 'certificates-table')).toHaveLength(9);
      await expect(page).not.toHaveURL(/expiry=/);
      const views = page.getByRole('button', { name: t('filters.views'), exact: true });
      const menu = page.getByRole('menu');
      await views.click();
      await dialogCheck(page, 'Saved views menu', menu);
      await page.keyboard.press('Escape');
      await expect(menu).toHaveCount(0);
      await views.focus();
      await page.keyboard.press('Enter');
      await expect(menu).toBeVisible();
      // The menu takes the focus once it has opened (a person's next key comes later than its 150 ms transition).
      await expect.poll(() => menu.evaluate((el) => el.contains(document.activeElement)), 'the open menu has the focus').toBe(true);
      const item = menu.getByRole('menuitem', { name: 'Web 1 soon', exact: true });
      // The first item may already have the focus; otherwise the arrow key moves it there.
      if (!(await item.evaluate((el) => el === document.activeElement))) await page.keyboard.press('ArrowDown');
      await expect(item).toBeFocused();
      await page.keyboard.press('Enter');
      await expect(menu).toHaveCount(0);
      await expect.poll(() => tableNames(page, 'certificates-table')).toEqual(seeded.server_filter.expiry_30);
      await expect(page).toHaveURL(/[?&]expiry=30(&|$)/);

      // A formula-like label is exported as text (csvx): the cell starts with an apostrophe.
      const api = await apiAs(page);
      const pair = newCert('formula.example.test');
      const uploaded = await api.post('/api/v1/certificates/upload', { label: '=cmd|calc', certificate_pem: pair.cert, private_key_pem: pair.key });
      expect(uploaded.status(), await uploaded.text()).toBe(201);
      await page.goto('/certificates?q=formula.example.test');
      await expect.poll(() => tableNames(page, 'certificates-table')).toEqual(['=cmd|calc']);
      const formula = await exportCsv(page, t);
      expect(formula.rows.slice(1).map((r) => [r[1], r[2]])).toEqual([['formula.example.test', "'=cmd|calc"]]);

      // Ten exports a minute per user: the next one is refused with an error on the page, never a saved file.
      const refused = page.getByRole('alert').filter({ hasText: t('errors.rate.limited.title') });
      const exportButton = page.getByRole('button', { name: t('filters.export'), exact: true });
      let saved = 0;
      for (let i = 0; i < 11 && !(await refused.isVisible()); i++) {
        const outcome = await Promise.race([
          page.waitForEvent('download').then(async (d) => {
            await d.delete();
            return 'saved';
          }),
          refused.waitFor().then(() => 'refused'),
          exportButton.click().then(() => new Promise<never>(() => undefined)),
        ]);
        if (outcome === 'saved') saved++;
      }
      await expect(refused).toBeVisible();
      expect(saved, 'exports saved before the limit').toBeLessThanOrEqual(8);

      // Owner step 1 (F-62): the mail settings, the untrusted certificate, trust, the test e-mail.
      await page.goto('/');
      await page.getByRole('link', { name: t('nav.settings'), exact: true }).click();
      await answerStepUp(page, request, lang, totpSecret, field(page, t('settings.mail.host')));
      await expect(page.getByRole('tab', { name: t('settings.tabs.mail'), selected: true })).toBeVisible();
      const creds = smtpCtl<{ username: string; password: string }>('credentials');
      await field(page, t('settings.mail.host')).fill('fakesmtp');
      await field(page, t('settings.mail.port')).fill('2525');
      await expect(field(page, t('settings.mail.tlsMode'))).toHaveValue('starttls');
      await field(page, t('settings.mail.from')).fill('alice@example.test');
      await field(page, t('settings.mail.username')).fill(creds.username);
      // A user name without a password is refused on the password field.
      await page.getByRole('button', { name: t('settings.mail.save'), exact: true }).click();
      // (Mantine's PasswordInput marks the error with data-invalid and the described-by text, not aria-invalid.)
      await expect(field(page, t('settings.mail.password'))).toHaveAttribute('data-invalid', 'true');
      await expect(field(page, t('settings.mail.password'))).toHaveAccessibleDescription(/\S/);
      await expect(page.getByText(t('settings.saved'), { exact: true })).toHaveCount(0);
      await field(page, t('settings.mail.password')).fill(creds.password);
      await page.getByRole('button', { name: t('settings.mail.save'), exact: true }).click();
      await expect(page.getByText(t('settings.saved'), { exact: true })).toBeVisible();
      await expect(field(page, t('settings.mail.password'))).toHaveValue('');
      await expect(page.getByText(t('settings.mail.passwordKept'), { exact: true })).toBeVisible();
      await expect(field(page, t('settings.mail.testTo'))).toHaveValue(ADA.email);
      await page.getByRole('button', { name: t('settings.mail.sendTest'), exact: true }).click();
      const trust = page.getByRole('dialog', { name: t('settings.mail.untrustedTitle') });
      const fingerprint = smtpCtl<{ fingerprint: string }>('fingerprint').fingerprint;
      expect(fingerprint).toMatch(/^[0-9a-f]{64}$/);
      await expect(trust.locator('code').filter({ hasText: fingerprint })).toHaveText(fingerprint);
      await dialogCheck(page, 'Untrusted mail server certificate', trust);
      expect(subjects(), 'nothing is sent before the certificate is trusted').toEqual([]);
      // The trust button has the focus: Enter trusts exactly the fingerprint shown.
      await expect(trust.getByRole('button', { name: t('settings.mail.trust'), exact: true })).toBeFocused();
      await page.keyboard.press('Enter');
      await expect(trust).toHaveCount(0);
      await expect(page.getByText(t('settings.mail.trusted', { fingerprint }), { exact: true })).toBeVisible();
      await page.getByRole('button', { name: t('settings.mail.sendTest'), exact: true }).click();
      await expect(page.getByText(t('settings.mail.testSent', { to: ADA.email }), { exact: true })).toBeVisible();
      const testMails = smtpMessages();
      expect(testMails.map((m) => m.Content.Headers.Subject[0])).toEqual([t('email.notify.test.subject')]);
      expect(testMails[0].Raw.To).toEqual([ADA.email]);
      await screen(page, 'settings, mail');

      // Owner step 2 (e-mail, §26.9): the certificate that expires in 7 days is e-mailed once, with its website and the
      // expiry time in UTC.
      await runScheduled(request, 'alerts.scan');
      await runScheduled(request, 'notify.send');
      const sevenDays = t('email.alert.certificate_expiring.subject', { name: 'www.seed.test', days: 7 });
      const wwwMail = () => smtpMessages().filter((m) => m.Content.Headers.Subject[0] === sevenDays);
      expect(wwwMail(), `www.seed.test, 7 days, among: ${subjects().join(' | ')}`).toHaveLength(1);
      const body = wwwMail()[0].Content.Body;
      expect(body).toContain('www.seed.test');
      expect(body).toContain(seeded.server_filter.target);
      expect(
        [before, after].map((at) => mailDate(at + 7 * DAY_SECONDS * 1000 - 3600 * 1000)).some((d) => body.includes(d)),
        `the expiry time in UTC in: ${body}`,
      ).toBe(true);
      expect(wwwMail()[0].Raw.To).toEqual([ADA.email]);
      const afterFirstScan = smtpMessages().length;
      await runScheduled(request, 'alerts.scan');
      await runScheduled(request, 'notify.send');
      expect(wwwMail(), 'exactly once').toHaveLength(1);
      expect(smtpMessages(), 'a second scan sends nothing new').toHaveLength(afterFirstScan);

      // Owner step 4 (F-60): the mail server is down when www.seed.test reaches the 1-day threshold; after three failed
      // attempts Administrators see the banner and the dashboard lists it; once the server is back the e-mail arrives once.
      smtpCtl('down');
      await advanceClock(request, 6 * DAY_SECONDS);
      await runScheduled(request, 'alerts.scan');
      for (let i = 0; i < 3; i++) {
        await advanceClock(request, 3600);
        await runScheduled(request, 'notify.send');
      }
      await signIn(page, request, ADA, totpSecret); // the clock moved: the session ended
      const banner = page.getByTestId('notifications-banner');
      await expect(banner).toContainText(t('notifications.failingTitle'));
      await expect(banner.locator('code')).toHaveText(/^smtp\.[a-z_]+$/);
      await expect(page.getByTestId('attention-list').getByRole('link', { name: t('notifications.failingTitle') })).toBeVisible();
      await screen(page, 'dashboard, e-mails failing');
      await banner.getByRole('link', { name: t('notifications.openSettings') }).click();
      await expect(page).toHaveURL(/\/settings\?tab=mail$/);
      await answerStepUp(page, request, lang, totpSecret, field(page, t('settings.mail.host')));
      await expect(field(page, t('settings.mail.host'))).toHaveValue('fakesmtp');
      const oneDay = t('email.alert.certificate_expiring.subject', { name: 'www.seed.test', days: 1 });
      expect(subjects().filter((s) => s === oneDay)).toHaveLength(0);
      smtpCtl('up');
      await advanceClock(request, 3600);
      await runScheduled(request, 'notify.send');
      expect(subjects().filter((s) => s === oneDay), `www.seed.test, 1 day, among: ${subjects().join(' | ')}`).toHaveLength(1);
      await advanceClock(request, 3600);
      await runScheduled(request, 'notify.send');
      expect(subjects().filter((s) => s === oneDay), 'exactly once').toHaveLength(1);
      await signIn(page, request, ADA, totpSecret);
      await expect(page.getByRole('heading', { level: 1, name: t('dashboard.welcome', { name: ADA.fullName }) })).toBeVisible();
      await expect(page.getByTestId('attention-list')).toBeVisible();
      await expect(page.getByTestId('notifications-banner')).toHaveCount(0);

      // The audit log tells the story.
      await auditShows(page, lang, t, 'settings.smtp', ['settings_smtp_changed', 'settings_smtp_trusted', 'settings_smtp_tested']);
      await auditShows(page, lang, t, 'inventory.', ['inventory_exported']);
      await auditShows(page, lang, t, 'alert.', ['alert_sent']);
    });

    test('§26.9 owner step 5: an identity provider with the Admin mapping refused, SSO refused then signed in as Operator, break-glass while it is down (X-05)', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      expect(t('sso.allowAdmin')).toBe(lang === 'en' ? 'SSO users may be Admin' : 'SSO kullanıcıları Yönetici olabilir');
      expect(t('errors.sso.admin_mapping_disabled.title')).toBe(lang === 'en' ? 'A group cannot be mapped to Administrator.' : 'Bir grup Yönetici rolüne eşlenemez.');

      const { totpSecret } = await runWizard(page, request, lang, ADA);

      // Alice's address is prefilled with the address the page was opened at.
      const publicUrl = field(page, t('settings.general.publicUrl'));
      await openSettings(page, request, lang, totpSecret, 'general', publicUrl);
      const origin = new URL(page.url()).origin;
      await expect(publicUrl).toHaveValue(origin);
      await page.getByRole('button', { name: t('settings.general.save'), exact: true }).click();
      await expect(page.getByText(t('settings.saved'), { exact: true })).toBeVisible();

      // The tabs work with the keyboard. Phase 8 put Backups, HTTPS certificate and Audit forwarding between General and
      // Single sign-on, the last tab: from General, End moves the focus to it and Enter opens it (the arrow keys open
      // each tab on the way, and each Phase 8 tab reads its own setting, which may ask for a step-up meanwhile).
      await expect(page.getByRole('tablist').getByRole('tab')).toHaveText(
        ['mail', 'recipients', 'alerts', 'general', 'backups', 'https', 'forwarding', 'sso'].map((x) => t(`settings.tabs.${x}`)),
      );
      await page.getByRole('tab', { name: t('settings.tabs.general'), selected: true }).focus();
      await page.keyboard.press('End');
      await expect(page.getByRole('tab', { name: t('settings.tabs.sso') })).toBeFocused();
      await page.keyboard.press('Enter');
      await expect(page.getByRole('tab', { name: t('settings.tabs.sso'), selected: true })).toBeVisible();
      await expect(page).toHaveURL(/\/settings\?tab=sso$/);
      const addProvider = page.getByRole('button', { name: t('sso.addProvider'), exact: true });
      await answerStepUp(page, request, lang, totpSecret, addProvider);
      await expect(page.getByText(t('sso.noProviders'), { exact: true })).toBeVisible();
      const allowAdmin = page.getByRole('switch', { name: t('sso.allowAdmin') });
      await expect(allowAdmin).not.toBeChecked();

      // Add the provider (new providers start switched off; the switch is turned on with the keyboard).
      const idp = idpCtl<{ issuer: string; client_id: string; client_secret: string }>('credentials');
      await addProvider.click();
      const dlg = page.getByRole('dialog', { name: t('sso.addProvider') });
      await expect(field(dlg, t('sso.name'))).toBeFocused();
      await dialogCheck(page, 'Add identity provider', dlg);
      await page.keyboard.type(IDP_NAME);
      await field(dlg, t('sso.issuer')).fill(idp.issuer);
      await field(dlg, t('sso.clientId')).fill(idp.client_id);
      await field(dlg, t('sso.clientSecret')).fill(idp.client_secret);
      await expect(field(dlg, t('sso.groupsClaim'))).toHaveValue('groups');
      await field(dlg, t('sso.caPem')).fill(idpCA());
      const enabled = dlg.getByRole('switch', { name: t('sso.enabled') });
      await expect(enabled).not.toBeChecked();
      await enabled.focus();
      await page.keyboard.press('Space');
      await expect(enabled).toBeChecked();
      const save = dlg.getByRole('button', { name: t('sso.save'), exact: true });
      await tabTo(page, save, 6);
      await page.keyboard.press('Enter');
      // Saved: the dialog shows the redirect address to register at the provider, with a copy button.
      await expect(dlg.getByRole('status')).toHaveText(t('settings.saved'));
      await expect(dlg.locator('code')).toHaveText(new RegExp(`^${escapeRegExp(origin)}/api/v1/auth/oidc/[0-9a-f-]{36}/callback$`));
      await expect(dlg.getByRole('button', { name: t('sso.copy'), exact: true })).toBeVisible();
      await dialogCheck(page, 'Identity provider saved', dlg);
      // Known defect (reported to Task 19): the saved state is drawn in the same open modal, so the Continue button's
      // data-autofocus does not apply and the focus is left on the page body; Tab brings it back into the dialog.
      await tabTo(page, dlg.getByRole('button', { name: t('ui.continue'), exact: true }), 4);
      await page.keyboard.press('Enter');
      await expect(dlg).toHaveCount(0);
      const provider = page.getByRole('region', { name: IDP_NAME });
      await expect(provider.getByText(t('sso.status.enabled'), { exact: true })).toBeVisible();
      await expect(provider.getByText(idp.issuer, { exact: true })).toBeVisible();

      // Group mappings: Administrator is refused while "SSO users may be Admin" is off; Operator and Auditor are mapped.
      const mapGroup = async (group: string, role: 'admin' | 'operator' | 'auditor') => {
        await field(provider, t('sso.group')).fill(group);
        await field(provider, t('sso.role')).selectOption(role);
        await provider.getByRole('button', { name: t('sso.addMapping'), exact: true }).click();
      };
      await mapGroup('alice-admins', 'admin');
      await expect(provider.getByRole('alert').filter({ hasText: t('errors.sso.admin_mapping_disabled.title') })).toBeVisible();
      await mapGroup('alice-operators', 'operator');
      await expect(provider.getByRole('row').filter({ has: page.getByText('alice-operators', { exact: true }) })).toContainText(t('enum.role.operator'));
      await expect(provider.getByRole('alert')).toHaveCount(0);
      await expect(provider.getByText('alice-admins', { exact: true })).toHaveCount(0);
      await mapGroup('alice-auditors', 'auditor');
      const removeAuditors = provider.getByRole('button', { name: t('sso.removeMapping', { group: 'alice-auditors' }) });
      await expect(removeAuditors).toBeVisible();
      // Removing asks first: Escape keeps the mapping, the confirm button removes it.
      await removeAuditors.focus();
      await page.keyboard.press('Enter');
      const removeDialog = page.getByRole('dialog', { name: t('sso.removeMappingTitle', { group: 'alice-auditors' }) });
      await dialogCheck(page, 'Remove the mapping', removeDialog);
      await page.keyboard.press('Escape');
      await expect(removeDialog).toHaveCount(0);
      await expect(provider.getByText('alice-auditors', { exact: true })).toBeVisible();
      await removeAuditors.click();
      await removeDialog.getByRole('button', { name: t('sso.removeMappingConfirm'), exact: true }).click();
      await expect(provider.getByText('alice-auditors', { exact: true })).toHaveCount(0);

      // "SSO users may be Admin": switching it on is immediate; switching it off asks first (Escape cancels).
      await allowAdmin.click();
      await expect(allowAdmin).toBeChecked();
      await allowAdmin.focus();
      await page.keyboard.press('Space');
      const switchOff = page.getByRole('dialog', { name: t('sso.switchOffTitle') });
      await dialogCheck(page, 'Switch off SSO users may be Admin', switchOff);
      await page.keyboard.press('Escape');
      await expect(switchOff).toHaveCount(0);
      await expect(allowAdmin).toBeChecked();
      await allowAdmin.click();
      await switchOff.getByRole('button', { name: t('sso.switchOffConfirm'), exact: true }).click();
      await expect(allowAdmin).not.toBeChecked();
      await screen(page, 'settings, single sign-on');

      // SSO refused: the identity provider vouches for a person in no mapped group.
      idpCtl('next-user', '--sub', 'e2e-nobody', '--username', 'nobody', '--name', 'No Body', '--email', 'nobody@example.test', '--groups', 'other-team');
      await signOut(page);
      const ssoButton = page.getByRole('button', { name: t('login.ssoWith', { name: IDP_NAME }), exact: true });
      await expect(ssoButton).toBeVisible();
      await expect(page.getByRole('button', { name: c.signIn, exact: true })).toBeVisible(); // the local form stays
      await screen(page, 'sign-in with single sign-on');
      await ssoButton.click();
      await expect(page).toHaveURL(/\/login\?sso_error=sso\.no_access$/);
      await expect(page.getByTestId('sso-error')).toContainText(t('errors.sso.no_access.title'));
      await expectAccessibleAt(page, 'sign-in, SSO refused', DIALOG_WIDTHS, { soft: true });

      // SSO sign-in as an Operator. Recorded for the report: the main-frame addresses after the identity provider and
      // whether the Strict session cookie went with the first document load and the SPA's session read.
      idpCtl('next-user', '--sub', OMER.sub, '--username', OMER.username, '--name', OMER.name, '--email', OMER.email, '--groups', 'alice-operators');
      const frames: string[] = [];
      const cookieSeen: Promise<string>[] = [];
      page.on('framenavigated', (f) => {
        if (f === page.mainFrame()) frames.push(f.url());
      });
      page.on('request', (r) => {
        const path = new URL(r.url()).pathname;
        if (r.isNavigationRequest() || path === '/api/v1/auth/session') {
          cookieSeen.push(r.allHeaders().then((h) => `${r.method()} ${path}${r.isNavigationRequest() ? ' (document)' : ''}: session cookie ${(h.cookie ?? '').includes(SESSION_COOKIE) ? 'sent' : 'NOT sent'}`));
        }
      });
      await page.goto('/login');
      await ssoButton.click();
      await expect(page.getByRole('heading', { level: 1, name: t('dashboard.welcome', { name: OMER.name }) })).toBeVisible();
      await expect(page.getByTestId('current-user')).toHaveText(OMER.name);
      const afterIdp = frames.slice(frames.findIndex((u) => u.startsWith('https://idp.alice-e2e.test:9444')));
      test.info().annotations.push({ type: 'SSO main-frame addresses', description: afterIdp.join(' -> ') });
      test.info().annotations.push({ type: 'SSO session cookie', description: (await Promise.all(cookieSeen)).join('; ') });
      expect(afterIdp.some((u) => new URL(u).pathname === '/login'), 'the first page after the identity provider is signed in').toBe(false);
      // The first write after the sign-in carries the CSRF token: a saved view (an Operator may save one).
      await page.getByRole('link', { name: t('nav.certificates'), exact: true }).click();
      await page.getByRole('button', { name: t('filters.saveView'), exact: true }).click();
      const firstWrite = page.waitForResponse((r) => r.request().method() === 'POST' && new URL(r.url()).pathname === '/api/v1/views');
      await field(page.getByRole('dialog', { name: t('filters.saveView') }), t('filters.viewName')).fill('SSO first write');
      await page.keyboard.press('Enter');
      expect((await firstWrite).status(), 'the first write after SSO (CSRF token present)').toBe(201);
      await expect(page.getByRole('dialog', { name: t('filters.saveView') })).toHaveCount(0);
      // An Operator: neither Users nor Settings in the navigation.
      const navigation = page.getByRole('navigation', { name: t('nav.label') });
      await expect(navigation.getByRole('link', { name: t('nav.certificates'), exact: true })).toBeVisible();
      await expect(navigation.getByRole('link', { name: t('nav.users'), exact: true })).toHaveCount(0);
      await expect(navigation.getByRole('link', { name: t('nav.settings'), exact: true })).toHaveCount(0);

      // X-05: the identity provider is down; the local Administrator signs in with the password and the authenticator code.
      await signOut(page);
      idpCtl('down');
      await expect(ssoButton).toBeVisible();
      await ssoButton.click();
      await expect(page.getByText('unavailable')).toBeVisible(); // the identity provider's own error page; the browser stays there
      await signIn(page, request, ADA, totpSecret);
      await expect(page.getByRole('heading', { level: 1, name: t('dashboard.welcome', { name: ADA.fullName }) })).toBeVisible();
      idpCtl('up');

      // The SSO user is listed as such; the audit log tells the story.
      await page.getByRole('link', { name: c.navUsers, exact: true }).click();
      const omerRow = page.getByRole('row').filter({ hasText: OMER.username });
      await expect(omerRow.getByText(t('users.sso'), { exact: true })).toBeVisible();
      await expect(omerRow.getByText(t('users.mfa.atProvider'), { exact: true })).toBeVisible();
      await expect(omerRow).toContainText(t('enum.role.operator'));
      await expect(page.getByRole('row').filter({ hasText: 'nobody' })).toHaveCount(0);
      await auditShows(page, lang, t, 'sso.', [
        'sso_provider_created',
        'sso_mapping_denied',
        'sso_mapping_created',
        'sso_mapping_deleted',
        'sso_admin_role_allowed',
        'sso_admin_role_disallowed',
      ]);
      await auditShows(page, lang, t, 'auth.oidc', ['auth_oidc_denied']);
      await auditShows(page, lang, t, 'user.provisioned', ['user_provisioned']);
    });

    test('§26.9 recipients and thresholds; an SSO Administrator confirms at the identity provider; a provider with users cannot be deleted', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      expect(translator('en')('stepUp.ssoTitle')).toBe('Confirm at your identity provider');
      // No authenticator code is asked for in this journey before the SSO step-up: Alice's clock moves only by the
      // step-up window, so the fake identity provider's real-time token stays inside its lifetime and Alice's leeway.
      const { totpSecret } = await runWizard(page, request, lang, ADA);

      // Recipients: Administrators and one more address with its language.
      const administrators = page.getByRole('checkbox', { name: t('settings.recipients.administrators') });
      await openSettings(page, request, lang, totpSecret, 'recipients', administrators);
      await expect(administrators).toBeChecked();
      await page.getByRole('button', { name: t('settings.recipients.add'), exact: true }).click();
      await page.getByRole('textbox', { name: t('settings.recipients.email', { n: 1 }) }).fill('ops@example.test');
      await page.getByRole('combobox', { name: t('settings.recipients.language', { n: 1 }) }).selectOption('tr');
      await page.getByRole('button', { name: t('settings.recipients.save'), exact: true }).click();
      await expect(page.getByText(t('settings.saved'), { exact: true })).toBeVisible();
      await screen(page, 'settings, recipients');

      // Thresholds: Save is off while a row is empty; the saved list comes back from the server.
      await page.getByRole('tab', { name: t('settings.tabs.alerts') }).click();
      const first = page.getByRole('textbox', { name: t('settings.alerts.threshold', { n: 1 }) });
      await expect(first).toHaveValue('60');
      const saveThresholds = page.getByRole('button', { name: t('settings.alerts.save'), exact: true });
      await first.fill('');
      await expect(saveThresholds).toBeDisabled();
      await first.fill('45');
      await expect(saveThresholds).toBeEnabled();
      await saveThresholds.click();
      await expect(page.getByText(t('settings.saved'), { exact: true })).toBeVisible();
      await expect(page.getByRole('textbox', { name: t('settings.alerts.threshold', { n: 1 }) })).toHaveValue('45');
      await screen(page, 'settings, alerts');
      await page.getByRole('tab', { name: t('settings.tabs.general') }).click();
      await expect(field(page, t('settings.general.publicUrl'))).toBeVisible();
      await screen(page, 'settings, general');

      // An identity provider whose group may give Administrator (the switch on first).
      const provider = await addTestProvider(page, request, lang, t, totpSecret);
      const allowAdmin = page.getByRole('switch', { name: t('sso.allowAdmin') });
      await allowAdmin.click();
      await expect(allowAdmin).toBeChecked();
      await field(provider, t('sso.group')).fill('alice-admins');
      await field(provider, t('sso.role')).selectOption('admin');
      await provider.getByRole('button', { name: t('sso.addMapping'), exact: true }).click();
      await expect(provider.getByRole('row').filter({ has: page.getByText('alice-admins', { exact: true }) })).toContainText(t('enum.role.admin'));

      // The SSO Administrator signs in, and after the step-up window confirms again at the identity provider.
      idpCtl('next-user', '--sub', ZEYNEP.sub, '--username', ZEYNEP.username, '--name', ZEYNEP.name, '--email', ZEYNEP.email, '--groups', 'alice-admins');
      await signOut(page);
      await page.getByRole('button', { name: t('login.ssoWith', { name: IDP_NAME }), exact: true }).click();
      await expect(page.getByRole('heading', { level: 1, name: t('dashboard.welcome', { name: ZEYNEP.name }) })).toBeVisible();
      const navigation = page.getByRole('navigation', { name: t('nav.label') });
      await expect(navigation.getByRole('link', { name: t('nav.settings'), exact: true })).toBeVisible();
      await advanceClock(request, STEP_UP_SECONDS + 1);
      await page.goto('/settings?tab=mail');
      const confirm = page.getByRole('dialog', { name: t('stepUp.ssoTitle') });
      const goToIdp = confirm.getByRole('button', { name: t('stepUp.ssoAction', { name: IDP_NAME }), exact: true });
      await expect(goToIdp).toBeFocused();
      await expect(confirm.getByRole('textbox')).toHaveCount(0); // no authenticator code for an SSO user
      await dialogCheck(page, 'Confirm at your identity provider', confirm);
      await page.keyboard.press('Enter');
      // The identity provider sends the person back to the page that asked; the setting is read without a new prompt.
      await expect(page).toHaveURL(/\/settings\?tab=mail$/);
      await expect(field(page, t('settings.mail.host'))).toBeVisible();
      await expect(confirm).toHaveCount(0);
      await expect(page.getByTestId('sso-error')).toHaveCount(0);

      // A provider people signed in with cannot be deleted (ALC-SSO-0005); the dialog says why and nothing changes.
      await page.getByRole('tab', { name: t('settings.tabs.sso') }).click();
      await expect(provider).toBeVisible();
      await provider.getByRole('button', { name: t('sso.delete', { name: IDP_NAME }), exact: true }).click();
      const remove = page.getByRole('dialog', { name: t('sso.deleteTitle', { name: IDP_NAME }) });
      await remove.getByRole('button', { name: t('sso.deleteConfirm'), exact: true }).click();
      await expect(remove.getByRole('alert')).toContainText(t('errors.sso.provider_in_use.title'));
      await dialogCheck(page, 'Delete identity provider, refused', remove);
      await remove.getByRole('button', { name: t('ui.cancel'), exact: true }).click();
      await expect(remove).toHaveCount(0);
      await expect(provider).toBeVisible();

      // The users list shows the SSO Administrator; the audit log has the changes and the step-up.
      await navigation.getByRole('link', { name: c.navUsers, exact: true }).click();
      const zeynepRow = page.getByRole('row').filter({ hasText: ZEYNEP.username });
      await expect(zeynepRow.getByText(t('users.sso'), { exact: true })).toBeVisible();
      await expect(zeynepRow).toContainText(t('enum.role.admin'));
      // Not a Phase 7 screen: checked at the widths of the earlier phases (its table overflows a 375 px phone since Phase 1;
      // reported, not a Phase 7 requirement).
      await expectAccessibleAt(page, 'users, with an SSO user', [640, 1280, 1920], { soft: true });
      await auditShows(page, lang, t, 'settings.', ['settings_recipients_changed', 'settings_thresholds_changed', 'settings_general_changed']);
      await auditShows(page, lang, t, 'auth.stepup', ['auth_stepup']);
    });
  });
}
