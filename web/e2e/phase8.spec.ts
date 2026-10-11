import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect } from 'node:tls';
import type { APIRequestContext, Download, Locator, Page } from '@playwright/test';
import {
  ADMIN,
  COPY,
  PASSPHRASE,
  advanceClock,
  answerStepUp,
  apiAs,
  browserLocale,
  enrollTotp,
  expect,
  expectAccessible,
  expectWide,
  field,
  fingerprintHex,
  firstSignIn,
  freshCode,
  newCert,
  resetInstall,
  runWizard,
  setupCode,
  signIn,
  signOut,
  test,
  translator,
  uploadHttpsPair,
  type Account,
  type Lang,
  type Translate,
} from './helpers';

// Phase 8 journeys on the e2e stack, each in English and Turkish: the wizard with every step (the recovery passphrase
// strength rule, the HTTPS upload, Back, a reload that resumes, Skip), "Finish setting up" on the dashboard, Settings →
// Backups (Back up now, the download behind the authenticator code, the schedule), the 48-hour banner, Settings → Audit
// forwarding (refused address, unreachable receiver, the stored CA and its removal) and Settings → HTTPS certificate
// (wrong PFX password, an upload served at once). Every new screen is checked with axe and for overflow at 375 px and
// the desktop widths (expectWide, soft: one run lists every finding).
//
// Every test starts on a reset installation (/test/reset also serves a temporary HTTPS certificate again), so the
// tests share nothing and need no serial mode.
//
// No secret in artefacts: tracing, video and screenshots are off for this file. The certificate keys and the PFX are
// made at test time (the e2e target's test CA, openssl in a temporary directory removed in finally); the downloaded
// backup is read and deleted in finally.

const JOURNEY_TIMEOUT = 8 * 60_000;
// auth.StepUpWindow: a sign-in or step-up confirms the session for this long.
const STEP_UP_SECONDS = 5 * 60;
const HOUR_SECONDS = 3600;
const OPERATOR: Account = { username: 'olcay', fullName: 'Olcay Öztürk', password: 'operator-password-2026' };
// 17 lower-case letters: long enough, but rated "fair" (web/src/pages/setup/strength.ts), which the server refuses.
const FAIR_PASSPHRASE = 'abcdefghijklmnopq';

test.use({ trace: 'off', video: 'off', screenshot: 'off', ignoreHTTPSErrors: true });

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// textWith matches a text with one {{param}} filled by anything (a count, a time, a size).
function textWith(t: Translate, key: string, param: string): RegExp {
  const marker = '\u0000';
  const [before, after] = t(key, { [param]: marker }).split(marker);
  return new RegExp(`^${escapeRegExp(before)}.+${escapeRegExp(after)}$`);
}

// servedFingerprint is the SHA-256 (lower-case hex) of the certificate the server presents in a new TLS handshake:
// proof independent of the page.
function servedFingerprint(baseURL: string): Promise<string> {
  const url = new URL(baseURL);
  return new Promise((resolve, reject) => {
    const socket = connect({ host: url.hostname, port: Number(url.port || 443), servername: url.hostname, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      resolve(cert.fingerprint256.replace(/:/g, '').toLocaleLowerCase('en-US'));
    });
    socket.on('error', reject);
  });
}

// pfxOf packs a PEM pair into a PFX with password, with openssl in a temporary directory that is removed at once.
function pfxOf(pair: { cert: string; key: string }, password: string): Buffer {
  const dir = mkdtempSync(join(tmpdir(), 'alice-e2e-pfx-'));
  try {
    writeFileSync(join(dir, 'tls.crt'), pair.cert, { mode: 0o600 });
    writeFileSync(join(dir, 'tls.key'), pair.key, { mode: 0o600 });
    execFileSync('openssl', ['pkcs12', '-export', '-in', join(dir, 'tls.crt'), '-inkey', join(dir, 'tls.key'), '-out', join(dir, 'tls.pfx'), '-passout', 'env:PFX_PASSWORD'], {
      env: { ...process.env, PFX_PASSWORD: password },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    return readFileSync(join(dir, 'tls.pfx'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// firstBytes reads the first n bytes of a download (the caller deletes it).
async function firstBytes(download: Download, n: number): Promise<Buffer> {
  const stream = await download.createReadStream();
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    chunks.push(chunk as Buffer);
    size += (chunk as Buffer).length;
    if (size >= n) break;
  }
  stream.destroy();
  return Buffer.concat(chunks).subarray(0, n);
}

async function wide(page: Page, screen: string): Promise<void> {
  await expectWide(page, screen, { soft: true });
}

// openSettings opens a Settings tab by its address and answers the step-up prompt the first read may raise.
async function openSettings(page: Page, request: APIRequestContext, lang: Lang, secret: string, tab: string, done: Locator): Promise<void> {
  const t = translator(lang);
  await page.goto(`/settings?tab=${tab}`);
  await answerStepUp(page, request, lang, secret, done);
  await expect(page.getByRole('tab', { name: t(`settings.tabs.${tab}`), selected: true })).toBeVisible();
}

// confirmStepUp answers the open "Confirm it's you" dialog with a fresh code.
async function confirmStepUp(page: Page, request: APIRequestContext, lang: Lang, secret: string): Promise<void> {
  const c = COPY[lang];
  const dialog = page.getByRole('dialog', { name: c.stepUpHeading });
  await expect(dialog).toBeVisible();
  await field(dialog, c.code).fill(await freshCode(request, secret));
  await dialog.getByRole('button', { name: c.stepUpConfirm }).click();
  await expect(dialog).toHaveCount(0);
}

function backupsHeadingDone(page: Page): Locator {
  return page.getByTestId('backup-now');
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const t = translator(lang);
  const c = COPY[lang];

  test.describe(`Phase 8 packaging journeys (${lang})`, () => {
    test.use({ locale: browserLocale(lang), actionTimeout: 30_000 });
    test.beforeEach(async ({ request }) => {
      await resetInstall(request);
    });

    test('wizard with every step: a fair passphrase is refused, HTTPS upload, Back, a reload resumes, Skip', async ({ page, request, baseURL }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      // The contract's pinned texts are what the app shows.
      expect(t('setup.https.title')).toBe(lang === 'en' ? 'HTTPS certificate' : 'HTTPS sertifikası');
      expect(t('setup.mail.title')).toBe(lang === 'en' ? 'Mail server (optional)' : 'E-posta sunucusu (isteğe bağlı)');
      expect(t('setup.back')).toBe(lang === 'en' ? 'Back' : 'Geri');
      expect(t('setup.skip')).toBe(lang === 'en' ? 'Skip' : 'Atla');
      expect(t('https.applied')).toBe(lang === 'en' ? 'The new certificate is in use.' : 'Yeni sertifika kullanımda.');

      const before = await servedFingerprint(baseURL!);
      await page.goto('/');
      await expect(page).toHaveURL(/\/setup$/);
      await field(page, c.setupCode).fill(await setupCode(request));
      await page.getByRole('button', { name: c.continue }).click();
      await expect(page.getByRole('heading', { name: c.languageHeading })).toBeVisible();
      await page.getByRole('button', { name: c.continue }).click();
      await expect(page.getByRole('heading', { name: c.adminHeading })).toBeVisible();
      await field(page, c.username).fill(ADMIN.username);
      await field(page, c.fullName).fill(ADMIN.fullName);
      await field(page, c.password).fill(ADMIN.password);
      await field(page, c.repeatPassword).fill(ADMIN.password);
      await page.getByRole('button', { name: c.continue }).click();
      const { totpSecret } = await enrollTotp(page, request, c);

      // The recovery passphrase: "fair" keeps the button disabled and says why; a good one continues.
      await expect(page.getByRole('heading', { name: c.passphraseHeading })).toBeVisible();
      const save = page.getByRole('button', { name: c.savePassphrase });
      await field(page, c.passphrase).fill(FAIR_PASSPHRASE);
      await field(page, c.repeatPassphrase).fill(FAIR_PASSPHRASE);
      await page.getByLabel(c.storedPassphrase).check();
      await expect(page.getByTestId('passphrase-strength')).toHaveText(t('setup.passphrase.strength.fair'));
      await expect(page.getByText(t('setup.passphrase.tooWeak'), { exact: true })).toBeVisible();
      await expect(save).toBeDisabled();
      await expectAccessible(page, 'wizard passphrase, too easy to guess', { soft: true });
      await field(page, c.passphrase).fill(PASSPHRASE);
      await field(page, c.repeatPassphrase).fill(PASSPHRASE);
      await expect(page.getByText(t('setup.passphrase.tooWeak'), { exact: true })).toHaveCount(0);
      await expect(save).toBeEnabled();
      await save.click();

      // HTTPS: the organisation's PEM pair is applied at once, without a restart.
      const httpsHeading = page.getByRole('heading', { name: t('setup.https.title'), exact: true });
      await expect(httpsHeading).toBeVisible();
      await expect(page.getByTestId('https-temporary')).toHaveText(t('https.temporary'));
      await wide(page, 'wizard HTTPS certificate');
      const pair = newCert('localhost');
      await uploadHttpsPair(page, lang, pair);
      await expect(page.getByRole('status').filter({ hasText: t('https.applied') })).toBeVisible();
      await expect(page.getByTestId('https-done')).toHaveText(t('setup.https.uploadedDone'));
      await expect(page.getByText(fingerprintHex(pair.cert), { exact: true })).toBeVisible();
      expect(await servedFingerprint(baseURL!), 'a new TLS handshake presents the uploaded certificate').toBe(fingerprintHex(pair.cert));
      expect(before).not.toBe(fingerprintHex(pair.cert));
      await wide(page, 'wizard HTTPS certificate, uploaded');
      await page.getByRole('button', { name: t('ui.continue'), exact: true }).click();

      // Mail: a reload in the middle resumes here.
      const mailHeading = page.getByRole('heading', { name: t('setup.mail.title'), exact: true });
      await expect(mailHeading).toBeVisible();
      await wide(page, 'wizard mail server');
      await page.reload();
      await expect(mailHeading).toBeVisible();
      await expect(page.getByTestId('setup-skip')).toBeVisible();

      // Back: the HTTPS step shows the choice made, and before it the passphrase shows its done state.
      await page.getByTestId('setup-back').click();
      await expect(httpsHeading).toBeVisible();
      await expect(page.getByTestId('https-done')).toHaveText(t('setup.https.uploadedDone'));
      await expect(page.getByTestId('https-keep-temporary')).toHaveCount(0);
      await page.getByTestId('setup-back').click();
      await expect(page.getByRole('heading', { name: c.passphraseHeading })).toBeVisible();
      await expect(page.getByText(t('setup.passphrase.doneState'), { exact: true })).toBeVisible();
      await expect(field(page, c.passphrase)).toHaveCount(0);
      await expect(page.getByTestId('setup-back')).toHaveCount(0);
      await expectAccessible(page, 'wizard passphrase, done', { soft: true });

      // Forward again: HTTPS (done), then mail → Skip.
      await page.getByRole('button', { name: t('ui.continue'), exact: true }).click();
      await expect(httpsHeading).toBeVisible();
      await page.getByRole('button', { name: t('ui.continue'), exact: true }).click();
      await expect(mailHeading).toBeVisible();
      await page.getByTestId('setup-skip').click();

      await expect(page.getByRole('heading', { name: c.licenseHeading })).toBeVisible();
      await page.getByRole('button', { name: c.startEvaluation }).click();
      await expect(page.getByRole('heading', { name: c.platformHeading })).toBeVisible();
      await page.getByRole('button', { name: c.continue, exact: true }).click();
      await expect(page.getByRole('heading', { name: c.doneHeading })).toBeVisible();
      await page.getByRole('button', { name: c.toDashboard }).click();
      await expect(page.getByRole('heading', { name: c.welcome(ADMIN.fullName) })).toBeVisible();

      // The uploaded certificate is done on the checklist; the skipped mail server is not.
      const checklist = page.getByTestId('setup-checklist');
      await expect(checklist).toBeVisible();
      const httpsItem = checklist.getByRole('listitem').filter({ hasText: t('dashboard.checklist.https') });
      await expect(httpsItem).toContainText(t('dashboard.checklist.done'));
      const mailItem = checklist.getByRole('listitem').filter({ hasText: t('dashboard.checklist.mail') });
      await expect(mailItem).not.toContainText(t('dashboard.checklist.done'));

      // The audit log has the upload and the skip.
      const api = await apiAs(page);
      await api.stepUp(totpSecret);
      const audit = await api.get('/api/v1/audit?limit=200');
      expect(audit.ok(), await audit.text()).toBe(true);
      const actions = ((await audit.json()) as { items: { action: string }[] }).items.map((i) => i.action);
      expect(actions).toEqual(expect.arrayContaining(['https.certificate_replaced', 'setup.mail_skipped']));
      expect(actions).not.toContain('setup.https_kept_temporary');
    });

    test('finish setting up: after keeping the temporary certificate and skipping mail, the dashboard lists both', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      expect(t('dashboard.checklist.title')).toBe(lang === 'en' ? 'Finish setting up' : 'Kurulumu tamamlayın');
      const { totpSecret } = await runWizard(page, request, lang, ADMIN, { a11y: true });

      const checklist = page.getByTestId('setup-checklist');
      await expect(checklist).toBeVisible();
      await expect(checklist.getByRole('heading', { name: t('dashboard.checklist.title') })).toBeVisible();
      const httpsItem = checklist.getByRole('listitem').filter({ has: page.getByRole('link', { name: t('dashboard.checklist.https'), exact: true }) });
      const mailItem = checklist.getByRole('listitem').filter({ has: page.getByRole('link', { name: t('dashboard.checklist.mail'), exact: true }) });
      await expect(httpsItem).toContainText(t('dashboard.checklist.required'));
      await expect(httpsItem).not.toContainText(t('dashboard.checklist.done'));
      await expect(mailItem).toBeVisible();
      await expect(mailItem).not.toContainText(t('dashboard.checklist.required'));
      await expect(mailItem).not.toContainText(t('dashboard.checklist.done'));
      await wide(page, 'dashboard with Finish setting up');

      await httpsItem.getByRole('link').click();
      await expect(page).toHaveURL(/\/settings\?tab=https$/);
      await answerStepUp(page, request, lang, totpSecret, page.getByTestId('https-temporary'));
      await expect(page.getByRole('tab', { name: t('settings.tabs.https'), selected: true })).toBeVisible();

      await page.goto('/');
      await mailItem.getByRole('link').click();
      await expect(page).toHaveURL(/\/settings\?tab=mail$/);
      await expect(page.getByRole('tab', { name: t('settings.tabs.mail'), selected: true })).toBeVisible();
      await answerStepUp(page, request, lang, totpSecret, field(page, t('settings.mail.host')));
    });

    test('backups: Back up now, the download behind the authenticator code, the schedule, the dashboard card', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      expect(t('backups.backUpNow')).toBe(lang === 'en' ? 'Back up now' : 'Şimdi yedekle');
      expect(t('backups.download')).toBe(lang === 'en' ? 'Download' : 'İndir');
      const { totpSecret } = await runWizard(page, request, lang);

      await openSettings(page, request, lang, totpSecret, 'backups', backupsHeadingDone(page));
      await expect(page.getByText(t('backups.empty'), { exact: true })).toBeVisible();
      await expect(page.getByText(t('backups.never'), { exact: true })).toBeVisible();
      await expect(page.getByText(t('backups.offHost'), { exact: true })).toBeVisible();
      await expect(page.getByText(textWith(t, 'backups.freeSpace', 'size'))).toBeVisible();
      await expect(page.getByTestId('backup-now')).toHaveText(t('backups.backUpNow'));
      await page.getByTestId('backup-now').click();

      const table = page.getByTestId('backups-table');
      const row = table.locator('tbody tr');
      await expect(row).toHaveCount(1);
      const name = ((await row.locator('code').textContent()) ?? '').trim();
      expect(name).toMatch(/^alice-backup-[0-9A-Z]{8}-\d{8}T\d{6}Z-manual\.alicebak$/);
      await expect(row.getByRole('cell').nth(1)).toHaveText(t('backups.kinds.manual'));
      await expect(row.getByRole('cell').nth(4)).toHaveText(t('backups.checks.ok'));
      await expect(page.getByRole('status').filter({ hasText: name })).toBeVisible();
      await expect(page.getByText(textWith(t, 'backups.lastSuccess', 'time'))).toBeVisible();
      await wide(page, 'settings, backups');

      // The download needs a fresh step-up: once the session's has run out, the authenticator code is asked first.
      await advanceClock(request, STEP_UP_SECONDS + 1);
      const downloaded = page.waitForEvent('download');
      const button = page.getByTestId(`backup-download-${name}`);
      await expect(button).toHaveText(t('backups.download'));
      await button.click();
      await confirmStepUp(page, request, lang, totpSecret);
      const download = await downloaded;
      try {
        expect(download.suggestedFilename()).toBe(name);
        expect((await firstBytes(download, 8)).toString('latin1'), 'the file starts with the backup magic').toBe('ALICEBK1');
      } finally {
        await download.delete();
      }
      await expect(page.getByRole('alert')).toHaveCount(0);

      // The schedule: 61 backups to keep are refused with the catalogue's text, 21 are saved.
      const retention = field(page, t('backups.schedule.retention'));
      const saveSchedule = page.getByRole('button', { name: t('backups.schedule.save'), exact: true });
      await retention.fill('61');
      await saveSchedule.click();
      await expect(page.getByText(t('backups.schedule.retentionInvalid'), { exact: true })).toBeVisible();
      await expect(retention).toHaveAttribute('aria-invalid', 'true');
      await expect(page.getByText(t('settings.saved'), { exact: true })).toHaveCount(0);
      await retention.fill('21');
      await saveSchedule.click();
      await expect(page.getByText(t('settings.saved'), { exact: true })).toBeVisible();
      await expect(page.getByText(t('backups.schedule.retentionInvalid'), { exact: true })).toHaveCount(0);
      await page.reload();
      await answerStepUp(page, request, lang, totpSecret, backupsHeadingDone(page));
      await expect(field(page, t('backups.schedule.retention'))).toHaveValue('21');

      // The dashboard's backup card shows the last success.
      await page.goto('/');
      const card = page.getByTestId('backup-card');
      await expect(card).toBeVisible();
      await expect(card.getByText(textWith(t, 'backups.lastSuccess', 'time'))).toBeVisible();
      await expect(card.getByText(t('backups.never'), { exact: true })).toHaveCount(0);
      await expect(card.getByRole('link', { name: t('dashboard.backup.open'), exact: true })).toBeVisible();
    });

    test('48-hour banner: Administrators see it after 49 hours without a backup, an Operator does not, Back up now clears it', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      expect(t('backups.alarm')).toBe(lang === 'en' ? 'No successful backup for 48 hours' : '48 saattir başarılı yedek yok');
      const { totpSecret } = await runWizard(page, request, lang);
      const banner = page.getByTestId('backup-alarm-banner');
      await expect(banner).toHaveCount(0);
      const api = await apiAs(page);
      await api.stepUp(totpSecret);
      const created = await api.post('/api/v1/users', { username: OPERATOR.username, display_name: OPERATOR.fullName, email: '', role: 'operator', password: OPERATOR.password });
      expect(created.status(), await created.text()).toBe(201);
      await page.reload();
      await signOut(page);

      // No backup in between: the scheduled backup task is not run.
      await advanceClock(request, 49 * HOUR_SECONDS);
      await signIn(page, request, ADMIN, totpSecret);
      await expect(banner).toBeVisible();
      await expect(banner).toHaveText(t('backups.alarm'));
      await expect(page.getByTestId('backup-card').getByText(t('backups.alarm'), { exact: true })).toBeVisible();
      await wide(page, 'dashboard with the 48-hour banner');
      await signOut(page);

      const summary = page.waitForResponse((r) => r.url().endsWith('/api/v1/dashboard/summary') && r.request().method() === 'GET');
      await firstSignIn(page, request, OPERATOR);
      const answer = (await (await summary).json()) as { backup?: unknown };
      expect(answer.backup ?? null, 'an Operator gets no backup state').toBeNull();
      await expect(page.getByRole('heading', { name: either(OPERATOR.fullName) })).toBeVisible();
      await expect(banner).toHaveCount(0);
      await expect(page.getByTestId('backup-card')).toHaveCount(0);
      await signOut(page);

      await signIn(page, request, ADMIN, totpSecret);
      await expect(banner).toBeVisible();
      await banner.getByRole('link', { name: t('backups.alarm') }).click();
      await expect(page).toHaveURL(/\/settings\?tab=backups$/);
      await answerStepUp(page, request, lang, totpSecret, backupsHeadingDone(page));
      await page.getByTestId('backup-now').click();
      await expect(page.getByTestId('backups-table').locator('tbody tr')).toHaveCount(1);
      await expect(banner).toHaveCount(0);
      await page.goto('/');
      await expect(page.getByRole('heading', { name: c.welcome(ADMIN.fullName) })).toBeVisible();
      await expect(page.getByTestId('backup-card').getByText(textWith(t, 'backups.lastSuccess', 'time'))).toBeVisible();
      await expect(banner).toHaveCount(0);
    });

    test('audit forwarding: a refused address, an unreachable receiver, the backlog, a stored CA removed', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      expect(t('forwarding.test')).toBe(lang === 'en' ? 'Send test message' : 'Test mesajı gönder');
      const { totpSecret } = await runWizard(page, request, lang);
      const form = page.getByTestId('forwarding-form');
      await openSettings(page, request, lang, totpSecret, 'forwarding', form);
      await expect(page.getByText(textWith(t, 'forwarding.backlog', 'count'))).toBeVisible();
      await wide(page, 'settings, audit forwarding');

      const host = field(form, t('forwarding.host'));
      const port = field(form, t('forwarding.port'));
      const saveButton = form.getByRole('button', { name: t('forwarding.save'), exact: true });
      await form.getByLabel(t('forwarding.enabled'), { exact: true }).check();
      // The cloud metadata address is never connected to (ALC-AUD-0002).
      await host.fill('169.254.169.254');
      await saveButton.click();
      await expect(form.getByRole('alert').filter({ hasText: t('errors.audit.forwarding_address_refused.title') })).toBeVisible();
      await expect(page.getByText(t('settings.saved'), { exact: true })).toHaveCount(0);

      // Nothing listens on port 1 (ALC-AUD-0003).
      await host.fill('127.0.0.1');
      await port.fill('1');
      await form.getByRole('button', { name: t('forwarding.test'), exact: true }).click();
      await expect(form.getByRole('alert').filter({ hasText: t('errors.audit.forwarding_unreachable.title') })).toBeVisible();
      await expect(page.getByText(t('forwarding.testSent'), { exact: true })).toHaveCount(0);

      // A CA certificate is stored, never shown again, and removed with its own checkbox.
      await field(form, t('forwarding.caPem')).fill(newCert('syslog.example.test').cert);
      await saveButton.click();
      await expect(page.getByText(t('settings.saved'), { exact: true })).toBeVisible();
      await expect(form.getByTestId('forwarding-ca-set')).toHaveText(t('forwarding.caSet'));
      await expect(field(form, t('forwarding.caPem'))).toHaveValue('');
      await expect(host).toHaveValue('127.0.0.1');
      await expect(page.getByText(textWith(t, 'forwarding.backlog', 'count'))).toBeVisible();
      await wide(page, 'settings, audit forwarding with a CA');
      await form.getByLabel(t('forwarding.removeCa'), { exact: true }).check();
      await expect(field(form, t('forwarding.caPem'))).toBeDisabled();
      await saveButton.click();
      await expect(form.getByTestId('forwarding-ca-set')).toHaveCount(0);
      await expect(form.getByLabel(t('forwarding.removeCa'), { exact: true })).toHaveCount(0);
      await page.reload();
      await answerStepUp(page, request, lang, totpSecret, form);
      await expect(form.getByTestId('forwarding-ca-set')).toHaveCount(0);
      await expect(field(form, t('forwarding.host'))).toHaveValue('127.0.0.1');
    });

    test('HTTPS in Settings: the temporary state, a wrong PFX password, an upload served at once', async ({ page, request, baseURL, browser }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      expect(t('https.upload')).toBe(lang === 'en' ? 'Upload certificate' : 'Sertifika yükle');
      const { totpSecret } = await runWizard(page, request, lang);
      await openSettings(page, request, lang, totpSecret, 'https', page.getByTestId('https-temporary'));
      await expect(page.getByTestId('https-temporary')).toHaveText(t('https.temporary'));
      const temporary = await servedFingerprint(baseURL!);
      await expect(page.getByText(temporary, { exact: true })).toBeVisible();
      await wide(page, 'settings, HTTPS certificate');

      // A PFX opened with the wrong password is refused (ALC-TLS-0004); the served certificate stays.
      const pair = newCert('localhost');
      const form = page.getByTestId('https-upload-form');
      await form.getByRole('radio', { name: t('https.formatPfx'), exact: true }).check();
      await form.getByLabel(t('https.pfxFile'), { exact: true }).setInputFiles({ name: 'alice.pfx', mimeType: 'application/x-pkcs12', buffer: pfxOf(pair, 'the-right-pfx-password') });
      await field(form, t('https.pfxPassword')).fill('a-wrong-pfx-password');
      await form.getByRole('button', { name: t('https.upload'), exact: true }).click();
      await expect(form.getByRole('alert').filter({ hasText: t('errors.tls.pfx_password.title') })).toBeVisible();
      await expect(field(form, t('https.pfxPassword'))).toHaveValue('');
      expect(await servedFingerprint(baseURL!)).toBe(temporary);
      await wide(page, 'settings, HTTPS certificate, wrong PFX password');

      // A valid upload: the new fingerprint is shown and served in the next handshake, without a restart.
      await uploadHttpsPair(page, lang, pair);
      const fingerprint = fingerprintHex(pair.cert);
      await expect(form.getByRole('status').filter({ hasText: t('https.applied') })).toBeVisible();
      await expect(page.getByText(fingerprint, { exact: true })).toBeVisible();
      await expect(page.getByTestId('https-temporary')).toHaveCount(0);
      await expect(page.getByText(t('https.ownCertificate'), { exact: true })).toBeVisible();
      expect(await servedFingerprint(baseURL!)).toBe(fingerprint);

      // A new page load, and a new browser context (certainly a new TLS handshake), still work.
      await page.reload();
      await answerStepUp(page, request, lang, totpSecret, page.getByText(fingerprint, { exact: true }));
      const other = await browser.newContext({ baseURL, ignoreHTTPSErrors: true, locale: browserLocale(lang) });
      try {
        const fresh = await other.newPage();
        await fresh.goto('/login');
        await expect(fresh.getByRole('heading', { name: c.loginHeading })).toBeVisible();
      } finally {
        await other.close();
      }
    });
  });
}

// either matches a welcome heading in English or Turkish: a new account starts in English, whatever the test language.
function either(name: string): RegExp {
  return new RegExp(`^(${escapeRegExp(COPY.en.welcome(name))}|${escapeRegExp(COPY.tr.welcome(name))})$`);
}
