import type { APIRequestContext, Locator, Page } from '@playwright/test';
import {
  ADMIN,
  COPY,
  advanceClock,
  browserLocale,
  expect,
  expectAccessible,
  field,
  freshCode,
  resetInstall,
  runWizard,
  seriousViolations,
  serverNow,
  signIn,
  test,
  type Account,
  type Copy,
  type Lang,
} from './helpers';

const ADA: Account = { ...ADMIN, email: 'ada@example.com' };
const NEWCOMER: Account = { username: 'newcomer', fullName: 'Deniz Kaya', password: 'newcomer-password-2026' };
const LATECOMER: Account = { username: 'latecomer', fullName: 'Çağla Öztürk', password: 'latecomer-password-2026' };
const DAY = 24 * 3600 * 1000;
const HOUR = 3600 * 1000;

// Exact UI copy of Tasks 18–20 (and the shared error texts of Task 14).
const L = {
  en: {
    navLicense: 'License',
    evaluation: 'Evaluation mode: 30 days left, up to 5 targets.',
    evaluationDays: (days: number) => (days === 1 ? 'Evaluation mode: 1 day left, up to 5 targets.' : `Evaluation mode: ${days} days left, up to 5 targets.`),
    evaluationEnded: 'The evaluation period has ended.',
    notValid: 'This file is not a valid Alice license.',
    otherInstallation: /This license file was made for a different installation \(ending in [0-9A-Z]{6}\)\./,
    summary: (n: number) => new RegExp(`^Valid until .+, ${n} targets$`),
    activated: 'License activated. All features are available again.',
    installedPending: 'The license is installed and starts on ',
    warning: (days: number) => (days === 1 ? 'Your license expires in 1 day (' : `Your license expires in ${days} days (`),
    grace: (day: number) => `Grace day ${day} of 7.`,
    locked: 'License expired. Automatic tasks are paused.',
    clockBehind: 'The server clock changed unexpectedly',
    clockJump: (days: number) => `The server clock jumped forward by ${days} days.`,
    pending: (id: string) => `A new license (${id}) starts on `,
    phaseActive: 'Active',
    phaseLocked: 'Expired, locked',
  },
  tr: {
    navLicense: 'Lisans',
    evaluation: 'Deneme modu: 30 gün kaldı, en fazla 5 hedef.',
    evaluationDays: (days: number) => `Deneme modu: ${days} gün kaldı, en fazla 5 hedef.`,
    evaluationEnded: 'Deneme süresi sona erdi.',
    notValid: 'Bu dosya geçerli bir Alice lisansı değil.',
    otherInstallation: /Bu lisans dosyası başka bir kurulum için hazırlanmış \(sonu: [0-9A-Z]{6}\)\./,
    summary: (n: number) => new RegExp(`^Geçerlilik sonu .+, ${n} hedef$`),
    activated: 'Lisans etkinleştirildi. Tüm özellikler yeniden kullanılabilir.',
    installedPending: 'Lisans yüklendi; şu tarihte başlıyor: ',
    warning: (days: number) => `Lisansınızın süresi ${days} gün sonra doluyor (`,
    grace: (day: number) => `Ek süre günü: ${day} / 7.`,
    locked: 'Lisans süresi doldu. Otomatik işler duraklatıldı.',
    clockBehind: 'Sunucu saati beklenmedik biçimde değişti',
    clockJump: (days: number) => `Sunucu saati ${days} gün ileri atladı.`,
    pending: (id: string) => `Yeni bir lisans (${id}) şu tarihte başlıyor: `,
    phaseActive: 'Etkin',
    phaseLocked: 'Süresi doldu, kilitli',
  },
} as const;

// Subjects of the license emails in both languages (the admin's language decides).
const SUBJECT = {
  warning: /Alice license expires on|Alice lisansının süresi doluyor/,
  grace: /Alice license expired: automatic tasks stop on|Alice lisansının süresi doldu: otomatik işler duracak/,
  locked: /Alice license expired: automatic tasks are paused|Alice lisansının süresi doldu: otomatik işler duraklatıldı/,
  evaluationWarning: /Alice evaluation ends on|Alice deneme süresi bitiyor/,
  evaluationEnded: /Alice evaluation has ended|Alice deneme süresi sona erdi/,
};

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

// otherInstallationId is a valid installation ID (Luhn mod 32 check character) of no real installation.
function otherInstallationId(): string {
  const vals = Array.from({ length: 15 }, () => Math.floor(Math.random() * 32));
  let factor = 2;
  let sum = 0;
  for (let i = vals.length - 1; i >= 0; i--) {
    const a = factor * vals[i];
    sum += Math.floor(a / 32) + (a % 32);
    factor = 3 - factor;
  }
  vals.push((32 - (sum % 32)) % 32);
  const s = vals.map((v) => CROCKFORD[v]).join('');
  return `ALICE-${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}-${s.slice(12)}`;
}

async function testLicense(request: APIRequestContext, body: Record<string, unknown> = {}): Promise<string> {
  const res = await request.post('/test/license', { data: body });
  expect(res.ok(), await res.text()).toBe(true);
  return ((await res.json()) as { license: string }).license;
}

function licensePayload(file: string): { valid_until: string; license_id: string } {
  return (JSON.parse(file) as { payload: { valid_until: string; license_id: string } }).payload;
}

function validUntil(file: string): number {
  return Date.parse(licensePayload(file).valid_until);
}

async function mails(request: APIRequestContext): Promise<{ to: string; subject: string }[]> {
  const res = await request.get('/test/mail');
  expect(res.ok()).toBe(true);
  return ((await res.json()) as { messages: { to: string; subject: string }[] }).messages;
}

// advanceTo moves the demo clock to an absolute server time (ms since the epoch).
async function advanceTo(request: APIRequestContext, target: number): Promise<void> {
  await advanceClock(request, Math.round((target - (await serverNow(request))) / 1000));
}

// jumpWall moves only the server's wall clock (no uptime passes): a suspicious forward jump.
async function jumpWall(request: APIRequestContext, seconds: number): Promise<void> {
  const res = await request.post('/test/clock', { data: { advance_seconds: seconds, wall_only: true } });
  expect(res.ok()).toBe(true);
}

// expectBannerAccessible checks a screen showing license banners with axe and for horizontal
// overflow on a 375 px phone as well as at every width of expectAccessible.
async function expectBannerAccessible(page: Page, screen: string): Promise<void> {
  const original = page.viewportSize();
  try {
    await page.setViewportSize({ width: 375, height: original?.height ?? 720 });
    expect(await seriousViolations(page), `axe: ${screen} at 375 px`).toEqual([]);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, `horizontal overflow: ${screen} at 375 px`).toBeLessThanOrEqual(0);
  } finally {
    if (original) await page.setViewportSize(original);
  }
  await expectAccessible(page, screen);
}

// answerStepUp confirms a step-up dialog with a fresh code if the server asks for one before done appears.
async function answerStepUp(page: Page, request: APIRequestContext, c: Copy, secret: string, done: Locator): Promise<void> {
  const stepUp = page.getByRole('dialog', { name: c.stepUpHeading });
  await expect(stepUp.or(done).first()).toBeVisible();
  if (await stepUp.isVisible()) {
    await field(stepUp, c.code).fill(await freshCode(request, secret));
    await stepUp.getByRole('button', { name: c.stepUpConfirm }).click();
  }
  await expect(done).toBeVisible();
}

async function openLicensePage(page: Page, lang: Lang): Promise<void> {
  // The navigation's link: since Phase 7 the dashboard's License card links to the License page too.
  await page.getByRole('navigation').getByRole('link', { name: L[lang].navLicense, exact: true }).click();
  await expect(page.getByRole('heading', { name: L[lang].navLicense, level: 1 })).toBeVisible();
}

// chooseAndCheck selects a license file on the License page and asks the server to check it.
async function chooseAndCheck(page: Page, c: Copy, fileText: string): Promise<void> {
  await field(page, c.licenseFile).setInputFiles({ name: 'alice-license.alicelic', mimeType: 'application/json', buffer: Buffer.from(fileText) });
  await page.getByRole('button', { name: c.checkFile }).click();
}

// installOnPage uploads a license on the License page, confirms it and waits for the result message.
async function installOnPage(
  page: Page,
  request: APIRequestContext,
  lang: Lang,
  secret: string,
  fileText: string,
  opts: { a11y?: boolean; result?: string } = {},
): Promise<void> {
  const c = COPY[lang];
  await chooseAndCheck(page, c, fileText);
  const dialog = page.getByRole('dialog', { name: c.confirmLicense });
  await answerStepUp(page, request, c, secret, dialog);
  if (opts.a11y) await expectAccessible(page, 'license preview dialog');
  await dialog.getByRole('button', { name: c.installLicense }).click();
  await expect(page.getByTestId('license-installed')).toContainText(opts.result ?? L[lang].activated);
}

// platformAdministrationWorks proves what stays available in every license state (R9): adding a
// user (a change, with step-up) and verifying the audit log.
async function platformAdministrationWorks(page: Page, request: APIRequestContext, c: Copy, secret: string, account: Account) {
  await page.getByRole('link', { name: c.navUsers, exact: true }).click();
  await expect(page.getByRole('heading', { name: c.usersHeading })).toBeVisible();
  await page.getByRole('button', { name: c.addUser }).click();
  const dialog = page.getByRole('dialog', { name: c.addUser });
  await field(dialog, c.username).fill(account.username);
  await field(dialog, c.fullName).fill(account.fullName);
  await field(dialog, c.role).selectOption('operator');
  await field(dialog, c.initialPassword).fill(account.password);
  await dialog.getByRole('button', { name: c.createUser }).click();
  await answerStepUp(page, request, c, secret, page.getByRole('row').filter({ hasText: account.username }));

  await page.getByRole('link', { name: c.navAudit, exact: true }).click();
  await expect(page.getByRole('heading', { name: c.auditHeading })).toBeVisible();
  await expect(page.getByText(c.userCreatedAction).first()).toBeVisible();
  await page.getByRole('button', { name: c.verifyIntegrity }).click();
  await expect(page.getByText(c.intact)).toBeVisible();
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const c = COPY[lang];
  const l = L[lang];

  test.describe(`Phase 2 licensing (${lang})`, () => {
    test.use({ locale: browserLocale(lang) });
    test.beforeEach(async ({ request }) => {
      await resetInstall(request);
    });

    test('wizard license step, evaluation banner and License page', async ({ page, request }) => {
      await runWizard(page, request, lang, ADMIN, { a11y: true });
      await expect(page.getByTestId('license-banner-evaluation')).toContainText(l.evaluation);
      // Carry 2e: with the evaluation banner the header and the page also fit a 375 px phone.
      await expectBannerAccessible(page, 'home with the evaluation banner');

      await openLicensePage(page, lang);
      await expect(page.getByTestId('installation-id')).toHaveText(/^ALICE(-[0-9A-Z]{4}){4}$/);
      await expectBannerAccessible(page, 'license page');
    });

    test('the wizard installs a license file instead of the evaluation', async ({ page, request }) => {
      await runWizard(page, request, lang, ADMIN, { license: await testLicense(request, { max_targets: 7 }) });
      await expect(page.getByTestId(/^license-banner-/)).toHaveCount(0);
      await openLicensePage(page, lang);
      await expect(page.getByTestId('license-phase')).toHaveText(l.phaseActive);
      await expect(page.getByTestId('license-summary')).toHaveText(l.summary(7));
    });

    test('upload a valid, an edited and a foreign license file', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang);
      await openLicensePage(page, lang);

      const good = await testLicense(request, { max_targets: 10 });
      const edited = good.replace('"max_targets": 10', '"max_targets": 1000');
      expect(edited).not.toEqual(good);
      await chooseAndCheck(page, c, edited);
      await answerStepUp(page, request, c, totpSecret, page.getByRole('alert').filter({ hasText: l.notValid }));

      await chooseAndCheck(page, c, await testLicense(request, { installation_id: otherInstallationId() }));
      await expect(page.getByRole('alert').filter({ hasText: l.otherInstallation })).toBeVisible();
      await expectAccessible(page, 'license page with an upload error');

      await installOnPage(page, request, lang, totpSecret, good, { a11y: true });
      await expect(page.getByTestId('license-summary')).toHaveText(l.summary(10));

      // Owner step 3: an edited file is refused and the installed license stays.
      await chooseAndCheck(page, c, edited);
      await expect(page.getByRole('alert').filter({ hasText: l.notValid })).toBeVisible();
      await expect(page.getByTestId('license-summary')).toHaveText(l.summary(10));
      await page.reload();
      await expect(page.getByTestId('license-summary')).toHaveText(l.summary(10));
    });

    test('warnings at each threshold, grace, lock and renewal (demo clock)', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang, ADA);
      await openLicensePage(page, lang);
      const file = await testLicense(request, { valid_days: 61 });
      const end = validUntil(file);
      await installOnPage(page, request, lang, totpSecret, file);
      expect(await mails(request)).toHaveLength(0);

      let sent = 0;
      for (const days of [60, 30, 14, 7, 1]) {
        await advanceTo(request, end - days * DAY + HOUR);
        await signIn(page, request, ADA, totpSecret);
        await expect(page.getByTestId('license-banner-expiry_warning')).toContainText(l.warning(days));
        sent += 1;
        const got = await mails(request);
        expect(got, `one email at ${days} days`).toHaveLength(sent);
        expect(got[sent - 1].to).toBe('ada@example.com');
        expect(got[sent - 1].subject).toMatch(SUBJECT.warning);
        // Yellow at 60 days, orange from 7 days on.
        if (days === 60 || days === 7) await expectBannerAccessible(page, `home with the ${days}-day warning`);
      }

      // Grace: a red banner for everyone, and everything works.
      await advanceTo(request, end + HOUR);
      await signIn(page, request, ADA, totpSecret);
      await expect(page.getByTestId('license-banner-grace')).toContainText(l.grace(1));
      await expectBannerAccessible(page, 'home in the grace period');
      expect((await mails(request)).at(-1)?.subject).toMatch(SUBJECT.grace);
      await platformAdministrationWorks(page, request, c, totpSecret, NEWCOMER);
      await expect(page.getByTestId('license-banner-grace')).toBeVisible();

      // Lock: the red locked banner; sign-in, user administration and the audit log still work
      // (Phase 2 has no route that lock mode refuses: those arrive with targets in Phase 3).
      await advanceTo(request, end + 169 * HOUR);
      await signIn(page, request, ADA, totpSecret);
      await expect(page.getByTestId('license-banner-locked')).toContainText(l.locked);
      await expect(page.getByTestId('license-banner-locked')).toHaveAttribute('role', 'alert');
      expect((await mails(request)).at(-1)?.subject).toMatch(SUBJECT.locked);
      await expectBannerAccessible(page, 'home in lock');
      await platformAdministrationWorks(page, request, c, totpSecret, LATECOMER);
      await expect(page.getByTestId('license-banner-locked')).toBeVisible();

      // Renewal: everything works again at once (L-30).
      await openLicensePage(page, lang);
      await expect(page.getByTestId('license-phase')).toHaveText(l.phaseLocked);
      await installOnPage(page, request, lang, totpSecret, await testLicense(request, { valid_days: 365 }));
      await expect(page.getByTestId('license-phase')).toHaveText(l.phaseActive);
      await expect(page.getByTestId(/^license-banner-/)).toHaveCount(0);
      await page.goto('/');
      await expect(page.getByRole('heading', { name: c.welcome(ADA.fullName) })).toBeVisible();
      await expect(page.getByTestId(/^license-banner-/)).toHaveCount(0);
    });

    test('the evaluation warns, ends without grace and a license ends the lock', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang, ADA);
      const start = await serverNow(request);

      // Seven days before the end the banner turns yellow and Ada gets an email.
      await advanceTo(request, start + 23 * DAY + HOUR);
      await signIn(page, request, ADA, totpSecret);
      await expect(page.getByTestId('license-banner-evaluation')).toContainText(l.evaluationDays(7));
      expect((await mails(request)).at(-1)?.subject).toMatch(SUBJECT.evaluationWarning);
      await expectBannerAccessible(page, 'home with the evaluation warning');

      // The evaluation ends directly in lock (no grace period).
      await advanceTo(request, start + 30 * DAY + HOUR);
      await signIn(page, request, ADA, totpSecret);
      await expect(page.getByTestId('license-banner-evaluation_ended')).toContainText(l.evaluationEnded);
      await expect(page.getByTestId('license-banner-grace')).toHaveCount(0);
      expect((await mails(request)).at(-1)?.subject).toMatch(SUBJECT.evaluationEnded);
      await expectBannerAccessible(page, 'home after the evaluation');

      await openLicensePage(page, lang);
      await installOnPage(page, request, lang, totpSecret, await testLicense(request, { valid_days: 365 }));
      await expect(page.getByTestId(/^license-banner-/)).toHaveCount(0);
    });

    test('a clock set back warns and does not extend the license', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang);
      await openLicensePage(page, lang);
      await installOnPage(page, request, lang, totpSecret, await testLicense(request, { valid_days: 30 }));

      await advanceClock(request, 10 * 24 * 3600);
      await signIn(page, request, ADMIN, totpSecret);
      await expect(page.getByTestId('license-banner-expiry_warning')).toContainText(l.warning(20));

      // Back by five days: the session stays valid (its idle limit lies in the future), so the page is simply reloaded.
      await advanceClock(request, -5 * 24 * 3600);
      await page.reload();
      await expect(page.getByTestId('license-banner-clock_behind')).toContainText(l.clockBehind);
      await expect(page.getByTestId('license-banner-expiry_warning')).toContainText(l.warning(20));
      await expectBannerAccessible(page, 'home with the clock warning');
    });

    test('a license that starts later and a clock that jumps forward are announced', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang);
      await openLicensePage(page, lang);
      const from = new Date((await serverNow(request)) + 10 * DAY).toISOString().replace(/\.\d{3}Z$/, 'Z');
      const later = await testLicense(request, { valid_from: from, valid_days: 365 });
      await installOnPage(page, request, lang, totpSecret, later, { result: l.installedPending });
      await page.goto('/');
      await expect(page.getByTestId('license-banner-pending')).toContainText(l.pending(licensePayload(later).license_id));
      await expect(page.getByTestId('license-banner-evaluation')).toBeVisible();
      await expectBannerAccessible(page, 'home with a license that starts later');

      // Three and a half days of wall-clock time without uptime is a suspicious jump (R26); the
      // banner shows whole days, and the half day keeps the count at 3 whatever real time passes.
      await jumpWall(request, 3.5 * 24 * 3600);
      await signIn(page, request, ADMIN, totpSecret);
      await expect(page.getByTestId('license-banner-clock_jump')).toContainText(l.clockJump(3));
      await expectBannerAccessible(page, 'home with the clock jump warning');
    });
  });
}
