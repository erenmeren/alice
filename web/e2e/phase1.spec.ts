import {
  ADMIN,
  COPY,
  advanceClock,
  expect,
  browserLocale,
  either,
  expectAccessible,
  expectWide,
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
  translator,
  serverNow,
  uiLang,
  type Account,
  type Copy,
  type Lang,
} from './helpers';
import type { Page, APIRequestContext, Locator } from '@playwright/test';

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

// confirmWithStepUp waits until done is visible, answering the step-up dialog with a fresh code if
// the server asks for one first (the step-up window lasts 5 minutes).
async function confirmWithStepUp(page: Page, request: APIRequestContext, c: Copy, totpSecret: string, done: Locator) {
  const stepUp = page.getByRole('dialog', { name: c.stepUpHeading });
  await expect(stepUp.or(done).first()).toBeVisible();
  if (await stepUp.isVisible()) {
    await field(stepUp, c.code).fill(await freshCode(request, totpSecret));
    await stepUp.getByRole('button', { name: c.stepUpConfirm }).click();
  }
  await expect(done).toBeVisible();
}

// AUD-01: the session's idle timeout moves only on a person's activity. A read carries it as
// X-Alice-Activity: 1 when it is the first request after real input (a click, a key, the wheel, a
// touch); polls without input never do.
const LICENSE_STATUS = '/api/v1/license/status';
const IDLE_MINUTES = 30;

// watchActivity records, for every API request of the page, whether it carried the activity mark.
function watchActivity(page: Page): { path: string; marked: boolean }[] {
  const seen: { path: string; marked: boolean }[] = [];
  page.on('request', (r) => {
    const path = new URL(r.url()).pathname;
    if (path.startsWith('/api/v1/')) seen.push({ path, marked: r.headers()['x-alice-activity'] === '1' });
  });
  return seen;
}

// backgroundRead makes the open page read again what it shows, as it does by itself every minute
// and whenever the tab becomes visible: TanStack Query refetches on visibilitychange. The event
// comes from a script, so it is not input. It returns the status of the license status read, which
// every signed-in page polls.
async function backgroundRead(page: Page): Promise<number> {
  const res = page.waitForResponse((r) => new URL(r.url()).pathname === LICENSE_STATUS);
  await page.evaluate(() => window.dispatchEvent(new Event('visibilitychange')));
  return (await res).status();
}

// readAfterInput reads in the background until a request carries the input just given (the
// browser delivers a wheel event to the page asynchronously, after page.mouse.wheel returns) and
// checks that exactly one did: the first after the input, whichever query that was.
async function readAfterInput(page: Page, reads: { path: string; marked: boolean }[]) {
  await expect.poll(async () => (await backgroundRead(page)) === 200 && reads.some((r) => r.marked)).toBe(true);
  expect(reads.filter((r) => r.marked), JSON.stringify(reads)).toHaveLength(1);
}

// expectSessionEnded checks the signed-out path: the sign-in page, with the notice shown once.
async function expectSessionEnded(page: Page) {
  await expect(page.getByRole('heading', { name: either('loginHeading') })).toBeVisible();
  await expect(page).toHaveURL(/\/login\?ended=1$/);
  await expect(page.getByText(either('sessionEnded'))).toHaveCount(1);
}

// closeDialog closes an open dialog with Escape and waits until it is gone.
async function closeDialog(page: Page, dialog: Locator) {
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const c = COPY[lang];
  const tr = translator(lang);

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

    test('a tab left open is signed out 30 minutes after the last input although it keeps polling (AUD-01)', async ({ page, request }) => {
      await runWizard(page, request, lang);
      const reads = watchActivity(page);
      // The wizard's last click may still mark one request: let it go out. From here on, nobody
      // touches the page; the server clock moves in steps shorter than the idle timeout.
      expect(await backgroundRead(page)).toBe(200);
      reads.length = 0;
      for (const minutes of [10, 10, 9]) {
        await advanceClock(request, minutes * 60);
        expect(await backgroundRead(page)).toBe(200); // still signed in, 29 minutes after the last input
      }
      expect(reads.length).toBeGreaterThan(0);
      expect(reads.filter((r) => r.marked), 'a request without input carried the activity mark').toEqual([]);
      await expect(page.getByRole('heading', { name: c.welcome(ADMIN.fullName) })).toBeVisible();

      await advanceClock(request, 2 * 60); // 31 minutes after the last input, 2 after the last poll
      expect(await backgroundRead(page)).toBe(401);
      await expectSessionEnded(page);
    });

    test('a person who keeps reading stays signed in until the 12-hour limit (AUD-01)', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang);
      await signOut(page);
      await signIn(page, request, ADMIN, totpSecret); // a new session: its 12 hours start now
      const signedInAt = await serverNow(request);
      const home = page.getByRole('heading', { name: c.welcome(ADMIN.fullName) });
      await expect(home).toBeVisible();
      const reads = watchActivity(page);
      // Real input between the clock steps, the kinds a person reading gives: a scroll, a key, a click.
      const inputs = [() => page.mouse.wheel(0, 40), () => page.keyboard.press('Shift'), () => home.click()];
      for (let i = 0; i < 4; i++) {
        await advanceClock(request, 10 * 60);
        reads.length = 0;
        await inputs[i % inputs.length]();
        await readAfterInput(page, reads);
      }
      // 40 minutes after the sign-in (the last state change), only reads in between.
      await expect(home).toBeVisible();

      // The absolute lifetime still ends the session, however active the person is.
      const end = signedInAt + 12 * 3600 * 1000;
      const step = (IDLE_MINUTES - 5) * 60;
      while ((await serverNow(request)) + step * 1000 < end) {
        await advanceClock(request, step);
        reads.length = 0;
        await page.mouse.wheel(0, 40);
        await readAfterInput(page, reads);
      }
      await advanceClock(request, Math.ceil((end - (await serverNow(request))) / 1000) + 60);
      await page.mouse.wheel(0, 40);
      expect(await backgroundRead(page)).toBe(401);
      await expectSessionEnded(page);
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
      // AUD-25 d: an entry's object and details; the table scrolls inside its container on a phone.
      const detailsToggle = new RegExp(`^${tr('audit.detailsToggle', { n: 0 }).replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace('0', '\\d+')}$`);
      await page.getByRole('button', { name: detailsToggle }).first().click();
      await expect(page.getByRole('group', { name: tr('audit.columns.details') }).first()).toBeVisible();
      await expect(page.getByRole('columnheader', { name: tr('audit.columns.object') })).toBeVisible();
      await expectWide(page, 'audit entry details');

      await signOut(page);
      await expectAccessible(page, 'login');

      expect(await submitLogin(page, c, ADMIN.username, ADMIN.password)).toBe(200);
      await expect(page.getByRole('heading', { name: c.mfaHeading })).toBeVisible();
      await expectAccessible(page, 'verification code');
    });

    test('dialogs, recovery sign-in, not-found and no-access pages have no serious accessibility violations', async ({
      page,
      request,
    }) => {
      const { totpSecret } = await runWizard(page, request, lang);

      // API tokens: create dialog, the one-time token alert and the revoke dialog.
      await openNav(page, c.navTokens);
      await expect(page.getByRole('heading', { name: c.tokensHeading })).toBeVisible();
      await page.getByRole('button', { name: c.createToken }).click();
      const create = page.getByRole('dialog', { name: c.createToken });
      await field(create, c.tokenName).fill('deploy bot');
      await expectAccessible(page, 'create token dialog');
      await create.getByRole('button', { name: c.tokenSubmit }).click();
      const created = page.getByTestId('new-token');
      await confirmWithStepUp(page, request, c, totpSecret, created);
      await expect(page.getByText(c.tokenCreatedTitle)).toBeVisible();
      await expectAccessible(page, 'new token');
      await page.getByRole('button', { name: c.tokenDone }).click();
      await expect(created).toHaveCount(0);
      await page.getByRole('button', { name: c.revokeNamed('deploy bot') }).click();
      const revoke = page.getByRole('dialog', { name: c.revokeTitle('deploy bot') });
      await expect(revoke).toBeVisible();
      await expectAccessible(page, 'revoke token dialog');
      await revoke.getByRole('button', { name: c.revokeConfirm }).click();
      await expect(page.getByRole('button', { name: c.revokeNamed('deploy bot') })).toHaveCount(0);

      // Users: manage, edit, set-password and confirmation dialogs.
      await openNav(page, c.navUsers);
      await expect(page.getByRole('heading', { name: c.usersHeading })).toBeVisible();
      await createUser(page, request, c, OPERATOR, 'operator', totpSecret, { expectStepUp: false });
      const manage = page.getByRole('dialog', { name: c.manageTitle(OPERATOR.username) });
      const openManage = async () => {
        await page.getByRole('button', { name: c.manageNamed(OPERATOR.username) }).click();
        await expect(manage).toBeVisible();
      };
      await openManage();
      await expectAccessible(page, 'manage user dialog');
      await manage.getByRole('button', { name: c.edit }).click();
      const edit = page.getByRole('dialog', { name: c.editTitle(OPERATOR.username) });
      await expect(edit).toBeVisible();
      await expectAccessible(page, 'edit user dialog');
      await closeDialog(page, edit);
      await openManage();
      await manage.getByRole('button', { name: c.setNewPassword }).click();
      const setPassword = page.getByRole('dialog', { name: c.setPasswordTitle(OPERATOR.username) });
      await expect(setPassword).toBeVisible();
      await expectAccessible(page, 'set password dialog');
      // AUD-12: setting a new password and signing out everywhere also revoke the API tokens.
      await expect(setPassword).toContainText(tr('users.resetPasswordText'));
      await closeDialog(page, setPassword);
      await openManage();
      await manage.getByRole('button', { name: tr('users.actions.revokeSessions') }).click();
      const revokeAll = page.getByRole('dialog', { name: tr('users.confirm.revokeTitle', { name: OPERATOR.username }) });
      await expect(revokeAll).toContainText(tr('users.confirm.revokeText'));
      await revokeAll.getByRole('button', { name: c.cancel }).click();
      await expect(revokeAll).toHaveCount(0);
      await openManage();
      await manage.getByRole('button', { name: c.resetMfa }).click();
      const confirm = page.getByRole('dialog', { name: c.resetMfaTitle(OPERATOR.username) });
      await expect(confirm).toBeVisible();
      await expectAccessible(page, 'confirm dialog');
      await confirm.getByRole('button', { name: c.cancel }).click();
      await expect(confirm).toHaveCount(0);

      // My account: a new set of recovery codes.
      await openNav(page, c.navAccount);
      await expect(page.getByRole('heading', { name: c.accountHeading })).toBeVisible();
      await page.getByRole('button', { name: c.newRecoveryCodes }).click();
      const list = page.getByTestId('recovery-codes');
      await confirmWithStepUp(page, request, c, totpSecret, list);
      const recoveryCodes = ((await list.textContent()) ?? '').match(/[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}/g) ?? [];
      expect(recoveryCodes).toHaveLength(10);
      await expectAccessible(page, 'regenerated recovery codes');
      await page.getByLabel(c.savedCodes).check();
      await page.getByRole('button', { name: c.continue }).click();
      await expect(page.getByText(c.recoveryCodesActive)).toBeVisible();

      // Sign-in with a recovery code instead of the app.
      await signOut(page);
      expect(await submitLogin(page, c, ADMIN.username, ADMIN.password)).toBe(200);
      await expect(page.getByRole('heading', { name: c.mfaHeading })).toBeVisible();
      await page.getByRole('button', { name: c.useRecovery }).click();
      await field(page, c.recoveryCode).fill(recoveryCodes[0] ?? '');
      await expectAccessible(page, 'sign-in with a recovery code');
      await page.getByRole('button', { name: c.verify }).click();
      await expect(page.getByRole('heading', { name: c.welcome(ADMIN.fullName) })).toBeVisible();

      await page.goto('/no-such-page');
      await expect(page.getByRole('heading', { name: c.notFoundTitle })).toBeVisible();
      await expectAccessible(page, 'not found');
      await page.goto('/'); // the not-found page has no app shell and so no Sign out button
      await expect(page.getByRole('heading', { name: c.welcome(ADMIN.fullName) })).toBeVisible();
      await signOut(page);

      // No-access page, as an operator.
      await firstSignIn(page, request, OPERATOR);
      await page.goto('/users');
      await expect(page.getByText(either('noAccess'))).toBeVisible();
      await expectAccessible(page, 'no access');
    });

    test('at 640 px the navigation opens from the menu button and never covers the page', async ({ page, request }) => {
      await runWizard(page, request, lang);
      await page.setViewportSize({ width: 640, height: 800 });
      const nav = page.getByRole('navigation', { name: c.navLabel });
      const usersLink = nav.getByRole('link', { name: c.navUsers, exact: true });
      await expect(usersLink).not.toBeInViewport();

      // The page content is reachable: a button in the main area takes the click.
      await page.getByRole('button', { name: c.openNav }).click();
      await expect(usersLink).toBeInViewport();
      await usersLink.click();
      await expect(page.getByRole('heading', { name: c.usersHeading })).toBeVisible();
      await expect(usersLink).not.toBeInViewport();
      await expect(page.getByRole('button', { name: c.openNav })).toHaveAttribute('aria-expanded', 'false');
      await page.getByRole('button', { name: c.addUser }).click();
      await expect(page.getByRole('dialog', { name: c.addUser })).toBeVisible();
      await closeDialog(page, page.getByRole('dialog', { name: c.addUser }));

      // Opening and closing the menu without choosing a page works too.
      await page.getByRole('button', { name: c.openNav }).click();
      await page.getByRole('button', { name: c.closeNav }).click();
      await expect(usersLink).not.toBeInViewport();
      await page.getByRole('button', { name: c.addUser }).click();
      await expect(page.getByRole('dialog', { name: c.addUser })).toBeVisible();
    });
  });
}
