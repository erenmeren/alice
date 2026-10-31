import { randomBytes } from 'node:crypto';
import type { Locator, Page } from '@playwright/test';
import {
  advanceClock,
  browserLocale,
  COPY,
  expect,
  expectAccessible,
  field,
  freshCode,
  newCert,
  resetInstall,
  runWizard,
  settle,
  test,
  translator,
  windowsExec,
  type Copy,
  type Lang,
  type PemPair,
  type Translate,
} from './helpers';

// R71 Ruling 23: a Windows server reached over WinRM, against the emulated Windows server of the compose service
// fakewindows (cmd/alice-fakewindows). Its WinRM listener is the demo host's http.sys record 0.0.0.0:5986 (Ruling 20):
// HTTPS with the record's certificate, NTLMv2 checked against the one account "ctl winrm-account" sets, and WinRS shells
// that run the helper's forced entry. The journey: add the server with WinRM (the WN-26 warning, port 5986), read its
// setup script, give the emulator the account and a password made now, set the same password in Alice with a step-up,
// confirm the listener's TLS key, see the bindings, deploy to the demo binding 0.0.0.0:9444 (used by this journey
// only) and roll back with stale TLS, then a wrong password makes the connection test fail with ALC-WIN-0024, and
// removing the password (R72) makes it fail with ALC-WIN-0025. Every visible text is read from the locale files at run
// time (translator).

const SERVER = 'e2e-windows-winrm';
const ACCOUNT = 'alice';
const SUBJECT = 'winrm.win.example.test';
const JOURNEY = 'http.sys/ipport/0.0.0.0:9444';
const WINRM = 'http.sys/ipport/0.0.0.0:5986';
const STEP_UP_SECONDS = 5 * 60;
// The journey runs six jobs (the first test, the test after the password, the confirmation, a discovery, the test with
// the wrong password, the test without a password) and two deployments.
const JOURNEY_TIMEOUT = 8 * 60_000;
const DEPLOY_STEPS = ['import_chain', 'import_certificate', 'bind', 'verify'];

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// newPassword is a password made at run time (never a literal): 24 characters of Alice's rule (base64url).
function newPassword(): string {
  return randomBytes(18).toString('base64url');
}

async function nav(page: Page, t: Translate, key: string): Promise<void> {
  await page.getByRole('link', { name: t(key), exact: true }).click();
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
}

function bindingRow(page: Page, t: Translate, text: string): Locator {
  return page
    .getByRole('table', { name: t('locations.tableLabel') })
    .getByTestId('location-row')
    .filter({ has: page.locator('code', { hasText: new RegExp(`^${escapeRegExp(text)}$`) }) });
}

function fact(page: Page, label: string): Locator {
  return page.locator('dt', { hasText: new RegExp(`^${escapeRegExp(label)}$`) }).locator('xpath=following-sibling::dd[1]');
}

// setPassword sets the WinRM password in the panel, through a step-up the expired session asks for.
async function setPassword(page: Page, t: Translate, c: Copy, request: Parameters<typeof settle>[0], totpSecret: string, panel: Locator, password: string): Promise<void> {
  await advanceClock(request, STEP_UP_SECONDS + 1);
  const input = panel.getByLabel(t('winrm.field'), { exact: true });
  await input.fill(password);
  const set = panel.getByRole('button', { name: t('ccs.set'), exact: true });
  await ((await set.count()) > 0 ? set : panel.getByRole('button', { name: t('ccs.replace'), exact: true })).click();
  const stepUp = page.getByRole('dialog', { name: c.stepUpHeading });
  await field(stepUp, c.code).fill(await freshCode(request, totpSecret));
  await stepUp.getByRole('button', { name: c.stepUpConfirm }).click();
  await expect(stepUp).toHaveCount(0);
  // In the Add server dialog the panel goes away at once (the connection test starts); on the server page it stays.
  await expect(input.or(page.getByRole('dialog', { name: t('hostKeys.confirmTitle') })).or(page.getByRole('status').filter({ hasText: t('targets.connecting') })).first()).toBeVisible();
  if ((await input.count()) > 0) await expect(input).toHaveValue('');
  expect(await page.content(), 'the password is never shown').not.toContain(password);
}

async function uploadPair(page: Page, t: Translate, pair: PemPair, label: string): Promise<void> {
  await nav(page, t, 'nav.certificates');
  await page.getByRole('button', { name: t('certificates.uploadButton') }).click();
  const dialog = page.getByRole('dialog', { name: t('certificates.upload.title') });
  await field(dialog, t('certificates.upload.certificate')).fill(pair.cert);
  await field(dialog, t('certificates.upload.privateKey')).fill(pair.key);
  await field(dialog, t('certificates.upload.label')).fill(label);
  await dialog.getByRole('button', { name: t('certificates.upload.submit') }).click();
  await expect(dialog.getByText(t('certificates.upload.uploaded'))).toBeVisible();
  await dialog.getByRole('button', { name: t('ui.close') }).last().click();
  await expect(dialog).toHaveCount(0);
}

async function openServer(page: Page, t: Translate): Promise<void> {
  await nav(page, t, 'nav.servers');
  await page.getByRole('link', { name: SERVER, exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: SERVER })).toBeVisible();
}

// deployToJourney deploys the certificate named label to the 9444 binding alone.
async function deployToJourney(page: Page, t: Translate, label: string): Promise<Locator> {
  const prefix = t('locations.deployNamed', { site: '\u0000' }).split('\u0000')[0];
  await bindingRow(page, t, JOURNEY).getByRole('button', { name: new RegExp(`^${escapeRegExp(prefix)}`) }).click();
  const dialog = page.getByRole('dialog', { name: t('deploy.title') });
  const group = dialog.getByTestId('deploy-certificate-group').filter({ has: page.getByRole('heading', { level: 3, name: SUBJECT, exact: true }) });
  await expect(group).toHaveCount(1);
  await group.getByRole('button', { name: t('deploy.selectGroupNamed', { name: SUBJECT }) }).click();
  await expect(dialog.getByRole('checkbox', { checked: true })).toHaveCount(1);
  const select = field(dialog, t('deploy.certificate'));
  const value = await select.locator('option', { hasText: label }).getAttribute('value');
  expect(value, `certificate ${label} offered`).toBeTruthy();
  await select.selectOption(value!);
  await dialog.getByRole('button', { name: t('deploy.submit'), exact: true }).click();
  return dialog;
}

async function expectStep(scope: Locator, t: Translate, step: string, status: 'ok' | 'failed'): Promise<void> {
  const row = scope.getByRole('list', { name: t('deployments.stepsTitle') }).locator(`li[data-step="${step}"]`);
  await expect(row, step).toHaveAttribute('data-status', status);
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const t = translator(lang);
  const c = COPY[lang];

  test.describe(`Windows server over WinRM (${lang})`, () => {
    test.use({ locale: browserLocale(lang) });

    test.beforeEach(async ({ request }) => {
      windowsExec(['ctl', 'stale-tls-off']);
      await resetInstall(request);
    });
    test.afterEach(() => {
      windowsExec(['ctl', 'stale-tls-off']);
    });

    test('add a server with WinRM, set its password with step-up, confirm the TLS key, deploy, roll back, refuse a wrong password', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const { totpSecret } = await runWizard(page, request, lang);

      // 1. The WinRM choice: port 5986, the WN-26 warning, and no SSH script.
      await nav(page, t, 'nav.servers');
      await page.getByRole('button', { name: t('targets.add') }).click();
      const dialog = page.getByRole('dialog', { name: t('targets.add') });
      await field(dialog, t('targets.form.type')).selectOption('windows');
      await expect(field(dialog, t('targets.form.transport'))).toHaveValue('ssh');
      await field(dialog, t('targets.form.transport')).selectOption('winrm');
      await expect(field(dialog, t('targets.form.portWinrm'))).toHaveValue('5986');
      await expect(dialog.getByText(t('targets.form.winrmWarning'), { exact: true })).toBeVisible();
      await expect(dialog.getByTestId('add-server-script')).toHaveCount(0);
      await expectAccessible(page, 'add server, WinRM');
      await field(dialog, t('targets.form.name')).fill(SERVER);
      await field(dialog, t('targets.form.host')).fill('fakewindows');
      await field(dialog, t('targets.form.usernameWindows')).fill(ACCOUNT);
      await dialog.getByRole('button', { name: t('targets.form.submit') }).click();

      // 2. The server's WinRM setup script; the administrator prepares the account on the server with a password.
      await expect(dialog.getByTestId('winrm-setup-script')).toBeVisible();
      await expect(dialog.getByText(t('targets.winrm.setupTitle'), { exact: true })).toBeVisible();
      const password = newPassword();
      expect(JSON.parse(windowsExec(['ctl', 'winrm-account'], `${ACCOUNT} ${password}\n`))).toEqual({ ok: true });

      // 3. The same password in Alice, with a step-up; then the connection test finds the listener's TLS key.
      const panel = dialog.getByTestId('winrm-password');
      await expect(panel.getByTestId('winrm-password-state')).toHaveText(t('ccs.notSet'));
      await setPassword(page, t, c, request, totpSecret, panel, password);
      const confirm = page.getByRole('dialog', { name: t('hostKeys.confirmTitle') });
      await settle(request, confirm);
      await expect(confirm.getByText(t('hostKeys.tlsLabel'), { exact: true })).toBeVisible();
      const onServer = windowsExec(['ctl', 'winrm-fingerprint']).trim();
      expect(onServer).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);
      await expect(confirm.getByTestId('host-key-fingerprint')).toHaveText(onServer);
      await expectAccessible(page, 'WinRM listener identity');
      await confirm.getByRole('button', { name: t('hostKeys.yes') }).click();
      await settle(request, page.getByText(t('targets.added')));
      await expect(page.getByTestId('target-status')).toHaveText(t('enum.targetStatus.ok'));

      // 4. The server page: the transport, the account, the password's date; discovery lists the bindings.
      await expect(fact(page, t('targets.page.facts.transport'))).toHaveText(t('targets.page.facts.transportWinrm'));
      await expect(fact(page, t('targets.page.facts.user'))).toHaveText(ACCOUNT);
      await expect(page.getByTestId('winrm-password-state')).not.toHaveText(t('ccs.notSet'));
      await page.getByRole('button', { name: t('locations.discover'), exact: true }).click();
      await settle(request, page.getByText(t('targets.jobDone')));
      await expect(bindingRow(page, t, JOURNEY)).toHaveCount(1);
      await expect(bindingRow(page, t, JOURNEY)).toContainText('WinRM Journey');
      await expect(bindingRow(page, t, WINRM)).toContainText(t('locations.notSupported'));
      await page.getByRole('button', { name: t('targets.winrm.showScript'), exact: true }).click();
      const again = page.getByRole('dialog', { name: t('targets.winrm.setupTitle') });
      await expect(again.getByTestId('winrm-setup-script')).toBeVisible();
      await again.getByRole('button', { name: t('ui.close') }).first().click();
      await expect(again).toHaveCount(0);
      await expectAccessible(page, 'windows server over WinRM');

      // 5. A deployment to the 9444 binding over WinRS commits and verifies.
      const first = newCert(SUBJECT);
      const firstLabel = `winrm-renewal-1-${lang}`;
      await uploadPair(page, t, first, firstLabel);
      await openServer(page, t);
      const deploying = await deployToJourney(page, t, firstLabel);
      await settle(request, deploying.getByText(t('deploy.succeeded'), { exact: true }));
      for (const step of DEPLOY_STEPS) await expectStep(deploying, t, step, 'ok');
      await deploying.getByRole('button', { name: t('deploy.close') }).last().click();
      await expect(deploying).toHaveCount(0);

      // 6. A website that keeps serving its previous certificate: the verification fails and the binding is restored.
      const second = newCert(SUBJECT);
      const secondLabel = `winrm-renewal-2-${lang}`;
      await uploadPair(page, t, second, secondLabel);
      await openServer(page, t);
      windowsExec(['ctl', 'stale-tls-on']);
      const rollback = await deployToJourney(page, t, secondLabel);
      await settle(request, rollback.getByText(t('deploy.rolledBack'), { exact: true }));
      await expectStep(rollback, t, 'verify', 'failed');
      await expectStep(rollback, t, 'restore', 'ok');
      await rollback.getByRole('button', { name: t('deploy.close') }).last().click();
      await expect(rollback).toHaveCount(0);
      windowsExec(['ctl', 'stale-tls-off']);

      // 7. A password in Alice that differs from the server's: the connection test is refused with ALC-WIN-0024.
      await openServer(page, t);
      await setPassword(page, t, c, request, totpSecret, page.getByTestId('winrm-password'), newPassword());
      await page.getByRole('button', { name: t('targets.test'), exact: true }).click();
      const refused = page.getByRole('alert').filter({ hasText: 'ALC-WIN-0024' });
      await settle(request, refused);
      await expect(refused).toContainText(t('errors.windows.winrm_auth_refused.title'));
      await expectAccessible(page, 'windows server over WinRM, sign-in refused');

      // 8. Remove the password (R72 Ruling 7-10), with a fresh step-up: the state reads "not set" and the connection test
      // is refused with ALC-WIN-0025 before any dial.
      const winrmPanel = page.getByTestId('winrm-password');
      await advanceClock(request, STEP_UP_SECONDS + 1);
      await winrmPanel.getByRole('button', { name: t('ccs.remove'), exact: true }).click();
      const removeConfirm = page.getByRole('dialog', { name: t('ccs.remove') });
      await expect(removeConfirm.getByText(t('winrm.removeConfirm'), { exact: true })).toBeVisible();
      await removeConfirm.getByRole('button', { name: t('ccs.remove'), exact: true }).click();
      const removeStepUp = page.getByRole('dialog', { name: c.stepUpHeading });
      await field(removeStepUp, c.code).fill(await freshCode(request, totpSecret));
      await removeStepUp.getByRole('button', { name: c.stepUpConfirm }).click();
      await expect(removeStepUp).toHaveCount(0);
      await expect(page.getByTestId('winrm-password-state')).toHaveText(t('ccs.notSet'));
      await expect(winrmPanel.getByRole('status')).toHaveText(t('ccs.removed'));
      await page.getByRole('button', { name: t('targets.test'), exact: true }).click();
      const missing = page.getByRole('alert').filter({ hasText: 'ALC-WIN-0025' });
      await settle(request, missing);
      await expect(missing).toContainText(t('errors.windows.winrm_password_missing.title'));
      await expectAccessible(page, 'windows server over WinRM, password removed');
    });
  });
}
