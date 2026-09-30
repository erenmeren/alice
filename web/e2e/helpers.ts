import { createHmac } from 'node:crypto';
import AxeBuilder from '@axe-core/playwright';
import { test as base, expect, type APIRequestContext, type Locator, type Page } from '@playwright/test';

declare global {
  interface Window {
    __aliceCspViolation?: (report: string) => void;
  }
}

// test is Playwright's test with one automatic check: a Content Security Policy violation on any
// page the test visits fails the test (the SPA must run under the strict CSP). It watches both the
// console ("… violates the following Content Security Policy directive …") and the DOM
// securitypolicyviolation event, which also fires for violations Chromium does not log.
export const test = base.extend<{ cspGuard: void }>({
  cspGuard: [
    async ({ page }, use) => {
      const violations: string[] = [];
      page.on('console', (m) => {
        if (m.type() === 'error' && /Content Security Policy/i.test(m.text())) violations.push(`console on ${page.url()}: ${m.text()}`);
      });
      await page.exposeFunction('__aliceCspViolation', (report: string) => violations.push(`event: ${report}`));
      await page.addInitScript(() => {
        document.addEventListener('securitypolicyviolation', (e) => {
          window.__aliceCspViolation?.(`${e.effectiveDirective} blocked ${e.blockedURI || 'inline'} on ${e.documentURI}`);
        });
      });
      await use();
      expect(violations, 'CSP violations').toEqual([]);
    },
    { auto: true },
  ],
});
export { expect };

export type Lang = 'en' | 'tr';

// UI copy from the Phase 1 plan (exact strings shown by the web app).
export const COPY = {
  en: {
    wizardHeading: 'Set up Alice',
    setupCode: 'Setup code',
    continue: 'Continue',
    languageHeading: 'Choose your language',
    adminHeading: 'Create the administrator account',
    username: 'Username',
    fullName: 'Full name',
    email: 'Email (optional)',
    password: 'Password',
    repeatPassword: 'Repeat password',
    totpHeading: 'Set up your authenticator app',
    code: '6-digit code',
    verify: 'Verify',
    recoveryHeading: 'Save your recovery codes',
    savedCodes: 'I saved these codes in a safe place',
    passphraseHeading: 'Choose a recovery passphrase',
    passphrase: 'Recovery passphrase',
    repeatPassphrase: 'Repeat the passphrase',
    storedPassphrase: 'I stored the passphrase safely',
    savePassphrase: 'Save passphrase',
    doneHeading: 'Alice is ready',
    toDashboard: 'Go to the dashboard',
    loginHeading: 'Sign in to Alice',
    signIn: 'Sign in',
    mfaHeading: 'Enter your verification code',
    invalidCredentials: 'Incorrect username or password.',
    mfaInvalid: 'The verification code is not correct.',
    sessionEnded: 'Your session ended. Please sign in again.',
    navHome: 'Home',
    navUsers: 'Users',
    navAudit: 'Audit log',
    navTokens: 'API tokens',
    navAccount: 'My account',
    signOut: 'Sign out',
    welcome: (name: string) => `Welcome, ${name}`,
    noAccess: 'You do not have access to this page.',
    usersHeading: 'Users',
    addUser: 'Add user',
    role: 'Role',
    initialPassword: 'Initial password',
    createUser: 'Create user',
    stepUpHeading: "Confirm it's you",
    stepUpConfirm: 'Confirm',
    auditHeading: 'Audit log',
    verifyIntegrity: 'Verify integrity',
    intact: 'The audit log is intact.',
    userCreatedAction: 'User created',
    tokensHeading: 'API tokens',
    accountHeading: 'My account',
  },
  tr: {
    wizardHeading: 'Alice kurulumu',
    setupCode: 'Kurulum kodu',
    continue: 'Devam',
    languageHeading: 'Dilinizi seçin',
    adminHeading: 'Yönetici hesabını oluşturun',
    username: 'Kullanıcı adı',
    fullName: 'Ad soyad',
    email: 'E-posta (isteğe bağlı)',
    password: 'Parola',
    repeatPassword: 'Parolayı tekrar girin',
    totpHeading: 'Doğrulama uygulamanızı kurun',
    code: '6 haneli kod',
    verify: 'Doğrula',
    recoveryHeading: 'Kurtarma kodlarınızı kaydedin',
    savedCodes: 'Bu kodları güvenli bir yere kaydettim',
    passphraseHeading: 'Kurtarma parolası belirleyin',
    passphrase: 'Kurtarma parolası',
    repeatPassphrase: 'Kurtarma parolasını tekrar girin',
    storedPassphrase: 'Kurtarma parolasını güvenli bir yerde sakladım',
    savePassphrase: 'Parolayı kaydet',
    doneHeading: 'Alice hazır',
    toDashboard: 'Ana sayfaya git',
    loginHeading: "Alice'e giriş yapın",
    signIn: 'Giriş yap',
    mfaHeading: 'Doğrulama kodunuzu girin',
    invalidCredentials: 'Kullanıcı adı veya parola hatalı.',
    mfaInvalid: 'Doğrulama kodu hatalı.',
    sessionEnded: 'Oturumunuz sona erdi. Lütfen yeniden giriş yapın.',
    navHome: 'Ana sayfa',
    navUsers: 'Kullanıcılar',
    navAudit: 'Denetim kaydı',
    navTokens: 'API anahtarları',
    navAccount: 'Hesabım',
    signOut: 'Çıkış yap',
    welcome: (name: string) => `Hoş geldiniz, ${name}`,
    noAccess: 'Bu sayfaya erişim yetkiniz yok.',
    usersHeading: 'Kullanıcılar',
    addUser: 'Kullanıcı ekle',
    role: 'Rol',
    initialPassword: 'İlk parola',
    createUser: 'Kullanıcıyı oluştur',
    stepUpHeading: 'Kimliğinizi doğrulayın',
    stepUpConfirm: 'Onayla',
    auditHeading: 'Denetim kaydı',
    verifyIntegrity: 'Bütünlüğü doğrula',
    intact: 'Denetim kaydı sağlam.',
    userCreatedAction: 'Kullanıcı oluşturuldu',
    tokensHeading: 'API anahtarları',
    accountHeading: 'Hesabım',
  },
} as const;

export type Copy = (typeof COPY)[Lang];

export function browserLocale(lang: Lang): string {
  return lang === 'tr' ? 'tr-TR' : 'en-US';
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// field finds an input by its exact label; Mantine appends " *" to required labels.
export function field(scope: Page | Locator, label: string): Locator {
  return scope.getByLabel(new RegExp(`^${escapeRegExp(label)}( \\*)?$`));
}

// either matches a copy string in English or Turkish (substring), for screens reached before the
// language is known or after a user's own language setting may have switched it.
export function either(key: 'loginHeading' | 'noAccess' | 'sessionEnded' | 'wizardHeading'): RegExp {
  return new RegExp(`${escapeRegExp(COPY.en[key])}|${escapeRegExp(COPY.tr[key])}`);
}

// uiLang reads the language the app is currently rendered in (<html lang>).
export async function uiLang(page: Page): Promise<Lang> {
  return (await page.locator('html').getAttribute('lang')) === 'tr' ? 'tr' : 'en';
}

export async function resetInstall(request: APIRequestContext): Promise<void> {
  const res = await request.post('/test/reset');
  expect(res.status(), 'POST /test/reset (is this the e2e build? run make e2e-up)').toBe(204);
}

export async function serverNow(request: APIRequestContext): Promise<number> {
  const res = await request.get('/test/clock');
  expect(res.ok()).toBe(true);
  const { now } = (await res.json()) as { now: string };
  return Date.parse(now.replace(/(\.\d{3})\d+/, '$1'));
}

export async function advanceClock(request: APIRequestContext, seconds: number): Promise<void> {
  const res = await request.post('/test/clock', { data: { advance_seconds: seconds } });
  expect(res.ok()).toBe(true);
}

export async function setupCode(request: APIRequestContext): Promise<string> {
  const res = await request.post('/test/setup-token');
  expect(res.ok()).toBe(true);
  return ((await res.json()) as { code: string }).code;
}

function base32Decode(input: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of input.replace(/[\s=]/g, '')) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base32 character ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// totp computes the RFC 6238 code (SHA-1, 6 digits, 30 s) for the given instant.
export function totp(secretBase32: string, atMs: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(atMs / 1000 / 30)));
  const mac = createHmac('sha1', base32Decode(secretBase32)).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(bin % 1_000_000).padStart(6, '0');
}

// freshCode moves the server clock past the last used 30 s step, so a code is never replayed,
// and returns the code for the server's current time.
export async function freshCode(request: APIRequestContext, secret: string): Promise<string> {
  await advanceClock(request, 31);
  return totp(secret, await serverNow(request));
}

// enrollTotp completes the "Set up your authenticator app" and recovery-code screens.
// With a11y set, each screen is also checked with axe (expectAccessible).
export async function enrollTotp(
  page: Page,
  request: APIRequestContext,
  c: Copy,
  a11y = false,
): Promise<{ totpSecret: string; recoveryCodes: string[] }> {
  await expect(page.getByRole('heading', { name: c.totpHeading })).toBeVisible();
  await expect(page.locator('img[src^="data:image/png;base64,"]')).toBeVisible();
  if (a11y) await expectAccessible(page, 'authenticator setup');
  const totpSecret = ((await page.getByTestId('totp-secret').textContent()) ?? '').replace(/\s/g, '');
  expect(totpSecret).toMatch(/^[A-Z2-7]{32}$/);
  await field(page, c.code).fill(totp(totpSecret, await serverNow(request)));
  await page.getByRole('button', { name: c.verify }).click();
  await expect(page.getByRole('heading', { name: c.recoveryHeading })).toBeVisible();
  const text = (await page.getByTestId('recovery-codes').textContent()) ?? '';
  const recoveryCodes = text.match(/[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}/g) ?? [];
  expect(recoveryCodes).toHaveLength(10);
  if (a11y) await expectAccessible(page, 'recovery codes');
  await page.getByLabel(c.savedCodes).check();
  await page.getByRole('button', { name: c.continue }).click();
  return { totpSecret, recoveryCodes };
}

export interface Account {
  username: string;
  fullName: string;
  password: string;
}

export const ADMIN: Account = { username: 'admin', fullName: 'Ada Yılmaz', password: 'correct-horse-battery-2026' };
export const PASSPHRASE = 'kırmızı-kedi-mavi-deniz-2026';

// runWizard installs Alice from scratch through the setup wizard (Phase 1 steps).
// With opts.a11y, every wizard screen is also checked with axe (expectAccessible).
export async function runWizard(
  page: Page,
  request: APIRequestContext,
  lang: Lang,
  admin: Account = ADMIN,
  opts: { a11y?: boolean } = {},
): Promise<{ totpSecret: string; recoveryCodes: string[] }> {
  const c = COPY[lang];
  const code = await setupCode(request);
  await page.goto('/');
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByRole('heading', { name: c.wizardHeading })).toBeVisible();
  await field(page, c.setupCode).fill(code);
  await page.getByRole('button', { name: c.continue }).click();

  await expect(page.getByRole('heading', { name: c.languageHeading })).toBeVisible();
  if (opts.a11y) await expectAccessible(page, 'wizard language');
  await page.getByRole('button', { name: c.continue }).click(); // keeps the preselected (current) language

  await expect(page.getByRole('heading', { name: c.adminHeading })).toBeVisible();
  if (opts.a11y) await expectAccessible(page, 'wizard administrator');
  await field(page, c.username).fill(admin.username);
  await field(page, c.fullName).fill(admin.fullName);
  await field(page, c.password).fill('too-short11');
  await field(page, c.repeatPassword).fill('too-short11');
  await page.getByRole('button', { name: c.continue }).click();
  // Alice refuses a password shorter than 12 characters and says why (the minimum is shown).
  await expect(page.getByRole('alert').or(page.locator('input[aria-invalid="true"]')).first()).toBeVisible();
  await expect(page.getByText(/\b12\b/).first()).toBeVisible();
  await expect(page.getByRole('heading', { name: c.totpHeading })).toHaveCount(0);
  if (opts.a11y) await expectAccessible(page, 'wizard administrator with error');

  await field(page, c.password).fill(admin.password);
  await field(page, c.repeatPassword).fill(admin.password);
  await page.getByRole('button', { name: c.continue }).click();
  const enrolled = await enrollTotp(page, request, c, opts.a11y);

  await expect(page.getByRole('heading', { name: c.passphraseHeading })).toBeVisible();
  if (opts.a11y) await expectAccessible(page, 'wizard passphrase');
  await field(page, c.passphrase).fill(PASSPHRASE);
  await field(page, c.repeatPassphrase).fill(PASSPHRASE);
  await page.getByLabel(c.storedPassphrase).check();
  await page.getByRole('button', { name: c.savePassphrase }).click();

  await expect(page.getByRole('heading', { name: c.doneHeading })).toBeVisible();
  if (opts.a11y) await expectAccessible(page, 'wizard done');
  await page.getByRole('button', { name: c.toDashboard }).click();
  await expect(page.getByRole('heading', { name: c.welcome(admin.fullName) })).toBeVisible();
  return enrolled;
}

// submitLogin fills the sign-in form and returns the HTTP status of POST /auth/login.
export async function submitLogin(page: Page, c: Copy, username: string, password: string): Promise<number> {
  await expect(page.getByRole('heading', { name: c.loginHeading })).toBeVisible();
  await field(page, c.username).fill(username);
  await field(page, c.password).fill(password);
  const [res] = await Promise.all([
    page.waitForResponse((r) => r.url().endsWith('/api/v1/auth/login') && r.request().method() === 'POST'),
    page.getByRole('button', { name: c.signIn }).click(),
  ]);
  return res.status();
}

// signIn signs an enrolled user in with password and a fresh TOTP code.
export async function signIn(page: Page, request: APIRequestContext, account: Account, totpSecret: string): Promise<void> {
  await page.goto('/login');
  await expect(page.getByRole('heading', { name: either('loginHeading') })).toBeVisible();
  const c = COPY[await uiLang(page)];
  expect(await submitLogin(page, c, account.username, account.password)).toBe(200);
  await expect(page.getByRole('heading', { name: c.mfaHeading })).toBeVisible();
  await field(page, c.code).fill(await freshCode(request, totpSecret));
  await page.getByRole('button', { name: c.verify }).click();
  await expect(page.getByRole('button', { name: c.signOut })).toBeVisible();
}

// firstSignIn signs in a user created by an administrator; they enroll TOTP at the first sign-in.
export async function firstSignIn(page: Page, request: APIRequestContext, account: Account): Promise<string> {
  await page.goto('/login');
  await expect(page.getByRole('heading', { name: either('loginHeading') })).toBeVisible();
  const c = COPY[await uiLang(page)];
  expect(await submitLogin(page, c, account.username, account.password)).toBe(200);
  const { totpSecret } = await enrollTotp(page, request, c);
  await expect(page.getByRole('button', { name: COPY[await uiLang(page)].signOut })).toBeVisible();
  return totpSecret;
}

// tabTo presses Tab (and nothing else) until the target has keyboard focus.
export async function tabTo(page: Page, target: Locator, maxPresses = 25): Promise<void> {
  for (let i = 0; i < maxPresses; i++) {
    if (await target.evaluate((el) => el === document.activeElement)) return;
    await page.keyboard.press('Tab');
  }
  await expect(target, `reachable with Tab within ${maxPresses} presses`).toBeFocused({ timeout: 1 });
}

// signOut signs out and proves the server session ended: reloading the app shows the sign-in page.
export async function signOut(page: Page): Promise<void> {
  const c = COPY[await uiLang(page)];
  await page.getByRole('button', { name: c.signOut }).click();
  await expect(page.getByRole('heading', { name: either('loginHeading') })).toBeVisible();
  await page.goto('/');
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole('heading', { name: either('loginHeading') })).toBeVisible();
  await expect(page.getByRole('button', { name: c.signOut })).toHaveCount(0);
}

// AXE_WIDTHS are the desktop widths every screen must work at (spec §26.1 item 9).
export const AXE_WIDTHS = [1280, 1920] as const;

// expectAccessible checks the current screen at each width in AXE_WIDTHS and restores the viewport.
export async function expectAccessible(page: Page, screen: string): Promise<void> {
  const original = page.viewportSize();
  try {
    for (const width of AXE_WIDTHS) {
      await page.setViewportSize({ width, height: original?.height ?? 720 });
      expect(await seriousViolations(page), `axe: ${screen} at ${width} px`).toEqual([]);
      // The screen fits the width: no horizontal scrolling.
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow, `horizontal overflow: ${screen} at ${width} px`).toBeLessThanOrEqual(0);
    }
  } finally {
    if (original) await page.setViewportSize(original);
  }
}

export async function seriousViolations(page: Page): Promise<string[]> {
  const results = await new AxeBuilder({ page }).analyze();
  return results.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => `${v.impact}: ${v.id} (${v.nodes.map((n) => n.target.join(' ')).join(', ')})`);
}
