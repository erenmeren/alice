import {
  ADMIN,
  COPY,
  advanceClock,
  expect,
  browserLocale,
  either,
  expectAccessible,
  field,
  firstSignIn,
  freshCode,
  resetInstall,
  runWizard,
  signIn,
  signOut,
  submitLogin,
  tabTo,
  test,
  totp,
  serverNow,
  uiLang,
  type Account,
  type Copy,
  type Lang,
} from './helpers';
import type { Page, APIRequestContext } from '@playwright/test';

const OPERATOR: Account = { username: 'operator1', fullName: 'Oğuz Işık', password: 'operator-password-2026' };
const AUDITOR: Account = { username: 'auditor1', fullName: 'Ayşe Denetçi', password: 'auditor-password-2026' };

async function openNav(page: Page, name: string) {
  await page.getByRole('link', { name, exact: true }).click();
}

// createUser adds a user on the Users page. With expectStepUp the server must ask for a fresh
// authenticator code first (SEC-009: user administration needs step-up); without it a prompt is
// answered only if it appears. With a11y, the Add user and step-up dialogs are checked with axe.
async function createUser(
  page: Page,
  request: APIRequestContext,
  c: Copy,
  account: Account,
  role: 'operator' | 'auditor',
  totpSecret: string,
  opts: { expectStepUp: boolean; a11y?: boolean },
) {
  await page.getByRole('button', { name: c.addUser }).click();
  const dialog = page.getByRole('dialog', { name: c.addUser });
  await field(dialog, c.username).fill(account.username);
  await field(dialog, c.fullName).fill(account.fullName);
  await field(dialog, c.role).selectOption(role);
  await field(dialog, c.initialPassword).fill(account.password);
  if (opts.a11y) await expectAccessible(page, 'add user dialog');
  await dialog.getByRole('button', { name: c.createUser }).click();
  const stepUp = page.getByRole('dialog', { name: c.stepUpHeading });
  const row = page.getByRole('row').filter({ hasText: account.username });
  if (opts.expectStepUp) {
    await expect(stepUp).toBeVisible();
    await expect(row).toHaveCount(0); // nothing is created before the code is confirmed
  } else {
    await expect(stepUp.or(row).first()).toBeVisible();
  }
  if (await stepUp.isVisible()) {
    if (opts.a11y) await expectAccessible(page, 'step-up dialog');
    await field(stepUp, c.code).fill(await freshCode(request, totpSecret));
    await stepUp.getByRole('button', { name: c.stepUpConfirm }).click();
  }
  await expect(row).toBeVisible();
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const c = COPY[lang];

  test.describe(`Phase 1 owner journey (${lang})`, () => {
    test.use({ locale: browserLocale(lang) });
    test.beforeEach(async ({ request }) => {
      await resetInstall(request);
    });

    test('wizard creates the admin, TOTP sign-in, wrong code, sign-out and idle timeout', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang);
      expect(await uiLang(page)).toBe(lang);
      await signOut(page);

      // Wrong verification code, then the right one.
      await page.goto('/login');
      expect(await submitLogin(page, c, ADMIN.username, ADMIN.password)).toBe(200);
      await expect(page.getByRole('heading', { name: c.mfaHeading })).toBeVisible();
      const good = await freshCode(request, totpSecret);
      const wrong = String((Number(good) + 500_000) % 1_000_000).padStart(6, '0');
      await field(page, c.code).fill(wrong);
      await page.getByRole('button', { name: c.verify }).click();
      await expect(page.getByText(c.mfaInvalid)).toBeVisible();
      await field(page, c.code).fill(totp(totpSecret, await serverNow(request)));
      await page.getByRole('button', { name: c.verify }).click();
      await expect(page.getByRole('heading', { name: c.welcome(ADMIN.fullName) })).toBeVisible();

      // Idle timeout: 31 minutes without activity ends the session.
      await advanceClock(request, 31 * 60);
      await openNav(page, c.navUsers);
      await expect(page.getByRole('heading', { name: either('loginHeading') })).toBeVisible();
      await expect(page.getByText(either('sessionEnded'))).toBeVisible();

      // Signing in again works.
      await signIn(page, request, ADMIN, totpSecret);
    });

    test('repeated wrong passwords slow down and then lock the account for 15 minutes', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang);
      await signOut(page);
      await page.goto('/login');

      for (let i = 1; i <= 5; i++) {
        expect(await submitLogin(page, c, ADMIN.username, 'wrong-password-123')).toBe(401);
      }
      await expect(page.getByText(c.invalidCredentials)).toBeVisible();
      for (let i = 6; i <= 9; i++) {
        await advanceClock(request, 61); // wait out the progressive delay
        expect(await submitLogin(page, c, ADMIN.username, 'wrong-password-123')).toBe(401);
      }
      // Still inside the 16 s delay after the 9th failure: even the right password is refused.
      expect(await submitLogin(page, c, ADMIN.username, ADMIN.password)).toBe(401);
      await expect(page.getByRole('heading', { name: c.mfaHeading })).toHaveCount(0);

      await advanceClock(request, 61);
      expect(await submitLogin(page, c, ADMIN.username, 'wrong-password-123')).toBe(401); // 10th: locked
      await advanceClock(request, 61);
      expect(await submitLogin(page, c, ADMIN.username, ADMIN.password)).toBe(401);
      await expect(page.getByText(c.invalidCredentials)).toBeVisible();

      await advanceClock(request, 15 * 60);
      expect(await submitLogin(page, c, ADMIN.username, ADMIN.password)).toBe(200);
      await expect(page.getByRole('heading', { name: c.mfaHeading })).toBeVisible();
      await field(page, c.code).fill(await freshCode(request, totpSecret));
      await page.getByRole('button', { name: c.verify }).click();
      await expect(page.getByRole('heading', { name: c.welcome(ADMIN.fullName) })).toBeVisible();
    });

    test('three roles behave differently and the audit chain verifies', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang);

      // Let the step-up window from the wizard sign-in expire, so creating a user asks for a code.
      await advanceClock(request, 6 * 60);
      await openNav(page, c.navUsers);
      await expect(page.getByRole('heading', { name: c.usersHeading })).toBeVisible();
      await createUser(page, request, c, OPERATOR, 'operator', totpSecret, { expectStepUp: true });
      // The step-up window lasts 5 minutes; after it closes the next change asks again.
      await advanceClock(request, 6 * 60);
      await createUser(page, request, c, AUDITOR, 'auditor', totpSecret, { expectStepUp: true });

      await openNav(page, c.navAudit);
      await expect(page.getByRole('heading', { name: c.auditHeading })).toBeVisible();
      await expect(page.getByText(c.userCreatedAction).first()).toBeVisible();
      await page.getByRole('button', { name: c.verifyIntegrity }).click();
      await expect(page.getByText(c.intact)).toBeVisible();
      await signOut(page);

      // Operator: no Users, no Audit log.
      await firstSignIn(page, request, OPERATOR);
      let u = COPY[await uiLang(page)];
      await expect(page.getByRole('link', { name: u.navTokens, exact: true })).toBeVisible();
      await expect(page.getByRole('link', { name: u.navUsers, exact: true })).toHaveCount(0);
      await expect(page.getByRole('link', { name: u.navAudit, exact: true })).toHaveCount(0);
      await page.goto('/users');
      await expect(page.getByText(either('noAccess'))).toBeVisible();
      await page.goto('/audit');
      await expect(page.getByText(either('noAccess'))).toBeVisible();
      await signOut(page);

      // Auditor: sees the Audit log and can verify it, but cannot manage users.
      await firstSignIn(page, request, AUDITOR);
      u = COPY[await uiLang(page)];
      await expect(page.getByRole('link', { name: u.navUsers, exact: true })).toHaveCount(0);
      await openNav(page, u.navAudit);
      await expect(page.getByRole('heading', { name: u.auditHeading })).toBeVisible();
      await page.getByRole('button', { name: u.verifyIntegrity }).click();
      await expect(page.getByText(u.intact)).toBeVisible();
      await expect(page.getByRole('button', { name: u.addUser })).toHaveCount(0);
      await page.goto('/users');
      await expect(page.getByText(either('noAccess'))).toBeVisible();
    });

    test('sign-in works with the keyboard only (Tab and Enter)', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang);
      await signOut(page);
      await page.goto('/login');
      await expect(page.getByRole('heading', { name: c.loginHeading })).toBeVisible();

      await tabTo(page, field(page, c.username));
      await page.keyboard.type(ADMIN.username);
      await page.keyboard.press('Tab');
      await expect(field(page, c.password)).toBeFocused();
      await page.keyboard.type(ADMIN.password);
      await page.keyboard.press('Enter');

      await expect(page.getByRole('heading', { name: c.mfaHeading })).toBeVisible();
      await tabTo(page, field(page, c.code));
      await page.keyboard.type(await freshCode(request, totpSecret));
      await page.keyboard.press('Enter');
      await expect(page.getByRole('heading', { name: c.welcome(ADMIN.fullName) })).toBeVisible();

      // The navigation is keyboard-operable too.
      await tabTo(page, page.getByRole('link', { name: c.navUsers, exact: true }));
      await page.keyboard.press('Enter');
      await expect(page.getByRole('heading', { name: c.usersHeading })).toBeVisible();
    });

    test('new screens have no serious accessibility violations', async ({ page, request }) => {
      await page.goto('/');
      await expect(page.getByRole('heading', { name: c.wizardHeading })).toBeVisible();
      await expectAccessible(page, 'setup');

      const { totpSecret } = await runWizard(page, request, lang, ADMIN, { a11y: true });
      await expectAccessible(page, 'home');

      await openNav(page, c.navUsers);
      await expect(page.getByRole('heading', { name: c.usersHeading })).toBeVisible();
      await expectAccessible(page, 'users');
      await advanceClock(request, 6 * 60); // so the Add user dialog is followed by the step-up dialog
      await createUser(page, request, c, OPERATOR, 'operator', totpSecret, { expectStepUp: true, a11y: true });

      await openNav(page, c.navTokens);
      await expect(page.getByRole('heading', { name: c.tokensHeading })).toBeVisible();
      await expectAccessible(page, 'tokens');

      await openNav(page, c.navAccount);
      await expect(page.getByRole('heading', { name: c.accountHeading })).toBeVisible();
      await expectAccessible(page, 'account');

      await openNav(page, c.navAudit);
      await expect(page.getByRole('heading', { name: c.auditHeading })).toBeVisible();
      await page.getByRole('button', { name: c.verifyIntegrity }).click();
      await expect(page.getByText(c.intact)).toBeVisible();
      await expectAccessible(page, 'audit');

      await signOut(page);
      await expectAccessible(page, 'login');

      expect(await submitLogin(page, c, ADMIN.username, ADMIN.password)).toBe(200);
      await expect(page.getByRole('heading', { name: c.mfaHeading })).toBeVisible();
      await expectAccessible(page, 'verification code');
    });
  });
}
