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
  type Lang,
  type PemPair,
  type Translate,
} from './helpers';

// R68, W5 Ruling 25: the Centralized Certificate Store (CCS) of the emulated Windows server (compose service
// fakewindows, the demo host of internal/providers/windows/wintest). Its IIS uses a CCS at C:\CCS with
// ccs.example.test.pfx (served for the site "CCS Site", https *:443:ccs.example.test with the CCS flag) and
// _.unlinked.test.pfx (no site), both under a password the fake makes at start and prints on "ctl ccs-password". The
// journey: no file is listed until an Administrator sets the CCS password (with step-up); after a scan the linked file
// shows its site and the unlinked one its warning; a deployment to the file commits and verifies; with the website
// serving stale certificates, a deployment is rolled back to the file's backup. Separate from windows.spec.ts, so the
// W2 journey keeps its own state. Every visible text is read from the locale files at run time (translator).

const SERVER = 'e2e-windows-ccs';
const HOST = 'ccs.example.test';
const LINKED = String.raw`C:\CCS\ccs.example.test.pfx`;
const UNLINKED = String.raw`C:\CCS\_.unlinked.test.pfx`;
const STEP_UP_SECONDS = 5 * 60;
// The journey adds a server, runs four jobs (the connection test, two discoveries, a rescan) and two deployments.
const JOURNEY_TIMEOUT = 8 * 60_000;
// The steps of a deployment to a CCS file, in order (R68).
const CCS_STEPS = ['import_chain', 'write_file', 'verify'];

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function nav(page: Page, t: Translate, key: string): Promise<void> {
  await page.getByRole('link', { name: t(key), exact: true }).click();
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
}

// placeRow is the row of the locations panel whose place column is exactly text (a CCS file's path).
function placeRow(page: Page, t: Translate, text: string): Locator {
  return page
    .getByRole('table', { name: t('locations.tableLabel') })
    .getByTestId('location-row')
    .filter({ has: page.locator('code', { hasText: new RegExp(`^${escapeRegExp(text)}$`) }) });
}

// addServer adds the emulated Windows server through Servers -> Add server, confirms its host key and scans it.
async function addServer(page: Page, t: Translate, request: Parameters<typeof settle>[0]): Promise<void> {
  await nav(page, t, 'nav.servers');
  await page.getByRole('button', { name: t('targets.add') }).click();
  const dialog = page.getByRole('dialog', { name: t('targets.add') });
  await field(dialog, t('targets.form.type')).selectOption('windows');
  const script = (await dialog.getByTestId('add-server-script').textContent()) ?? '';
  expect(JSON.parse(windowsExec(['ctl', 'prepare'], script))).toEqual({ ok: true });
  await field(dialog, t('targets.form.name')).fill(SERVER);
  await field(dialog, t('targets.form.host')).fill('fakewindows');
  await field(dialog, t('targets.form.usernameWindows')).fill('alice');
  await dialog.getByRole('button', { name: t('targets.form.submit') }).click();
  const confirm = page.getByRole('dialog', { name: t('hostKeys.confirmTitle') });
  await settle(request, confirm);
  await confirm.getByRole('button', { name: t('hostKeys.yes') }).click();
  await settle(request, page.getByText(t('targets.added')));
  await discover(page, t, request);
}

async function discover(page: Page, t: Translate, request: Parameters<typeof settle>[0]): Promise<void> {
  await page.getByRole('button', { name: t('locations.discover'), exact: true }).click();
  await settle(request, page.getByText(t('targets.jobDone')));
}

// uploadPair uploads a certificate with its key under label and closes the result.
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

// deployToFile opens the deploy dialog from the linked CCS file's row (the file alone is picked), chooses the
// certificate named label and starts the deployment.
async function deployToFile(page: Page, t: Translate, label: string): Promise<Locator> {
  const prefix = t('locations.deployNamed', { site: '\u0000' }).split('\u0000')[0];
  await placeRow(page, t, LINKED).getByRole('button', { name: new RegExp(`^${escapeRegExp(prefix)}`) }).click();
  const dialog = page.getByRole('dialog', { name: t('deploy.title') });
  await expect(dialog.getByRole('checkbox', { checked: true })).toHaveCount(1);
  await expect(dialog.getByRole('checkbox', { name: new RegExp(escapeRegExp(LINKED)), checked: true })).toHaveCount(1);
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
  await expect(row).toContainText(t(`deployments.steps.${step}`));
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const t = translator(lang);
  const c = COPY[lang];

  test.describe(`Windows server CCS (${lang})`, () => {
    test.use({ locale: browserLocale(lang) });

    test.beforeEach(async ({ request }) => {
      windowsExec(['ctl', 'stale-tls-off']);
      await resetInstall(request);
    });
    test.afterEach(() => {
      windowsExec(['ctl', 'stale-tls-off']);
    });

    test('set the CCS password with step-up, see the CCS files, deploy to a file and roll back to its backup', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const { totpSecret } = await runWizard(page, request, lang);
      await addServer(page, t, request);

      // 1. CCS is on, but without its password Alice lists none of its files: the warnings and the panel say so.
      await expect(page.getByText(t('warnings.win_ccs_enabled'), { exact: true })).toBeVisible();
      await expect(page.getByText(t('warnings.win_ccs_password_missing'), { exact: true })).toBeVisible();
      const panel = page.getByTestId('ccs-password');
      await expect(panel.getByRole('heading', { name: t('ccs.title'), level: 2 })).toBeVisible();
      await expect(panel.getByTestId('ccs-password-state')).toHaveText(t('ccs.notSet'));
      await expect(placeRow(page, t, LINKED)).toHaveCount(0);
      await expect(placeRow(page, t, UNLINKED)).toHaveCount(0);
      await expectAccessible(page, 'windows server, CCS without password');

      // 2. Setting the password asks for a fresh step-up; the panel then shows the date and the field is empty.
      const password = windowsExec(['ctl', 'ccs-password']).trim();
      expect(password.length).toBeGreaterThanOrEqual(12);
      await advanceClock(request, STEP_UP_SECONDS + 1);
      const input = panel.getByLabel(t('ccs.field'), { exact: true });
      await input.fill(password);
      await panel.getByRole('button', { name: t('ccs.set'), exact: true }).click();
      const stepUp = page.getByRole('dialog', { name: c.stepUpHeading });
      await field(stepUp, c.code).fill(await freshCode(request, totpSecret));
      await stepUp.getByRole('button', { name: c.stepUpConfirm }).click();
      await expect(stepUp).toHaveCount(0);
      await expect(panel.getByText(t('ccs.saved'), { exact: true })).toBeVisible();
      await expect(panel.getByTestId('ccs-password-state')).not.toHaveText(t('ccs.notSet'));
      await expect(input).toHaveValue('');
      await expect(panel.getByRole('button', { name: t('ccs.replace'), exact: true })).toBeVisible();
      expect(await page.content(), 'the password is never shown').not.toContain(password);
      await page.reload();
      await expect(page.getByTestId('ccs-password').getByTestId('ccs-password-state')).not.toHaveText(t('ccs.notSet'));

      // 3. After the scan, the linked file shows its site and host, the unlinked one its warning.
      await discover(page, t, request);
      await expect(page.getByText(t('warnings.win_ccs_password_missing'), { exact: true })).toHaveCount(0);
      const table = page.getByRole('table', { name: t('locations.tableLabel') });
      // R69: the server's Remote Desktop listener is listed too, so the column names a place.
      await expect(table.getByRole('columnheader', { name: t('locations.columns.place'), exact: true })).toBeVisible();
      await expect(placeRow(page, t, LINKED)).toHaveCount(1);
      await expect(placeRow(page, t, LINKED)).toContainText('CCS Site');
      await expect(placeRow(page, t, LINKED).locator('code', { hasText: new RegExp(`^${escapeRegExp(HOST)}$`) })).toBeVisible();
      await expect(placeRow(page, t, LINKED)).toContainText(t('locations.ready'));
      await expect(placeRow(page, t, LINKED)).not.toContainText(t('locations.warnings.win_ccs_unlinked'));
      await expect(placeRow(page, t, UNLINKED)).toContainText(t('locations.warnings.win_ccs_unlinked'));
      await expectAccessible(page, 'windows server, CCS files');

      // 4. A deployment to the linked file: the chain, the file, the verification through its site; committed.
      const first = newCert(HOST);
      const firstLabel = `ccs-renewal-1-${lang}`;
      await uploadPair(page, t, first, firstLabel);
      await openServer(page, t);
      const deploying = await deployToFile(page, t, firstLabel);
      await settle(request, deploying.getByText(t('deploy.succeeded'), { exact: true }));
      for (const step of CCS_STEPS) await expectStep(deploying, t, step, 'ok');
      await expectAccessible(page, 'windows CCS deployment, verified');
      await deploying.getByRole('button', { name: t('deploy.close') }).last().click();
      await expect(deploying).toHaveCount(0);

      // 5. A website that keeps serving the file's previous certificate: the verification fails and the provider
      // restores the backup; the deployment is rolled back.
      const second = newCert(HOST);
      const secondLabel = `ccs-renewal-2-${lang}`;
      await uploadPair(page, t, second, secondLabel);
      await openServer(page, t);
      windowsExec(['ctl', 'stale-tls-on']);
      const rollback = await deployToFile(page, t, secondLabel);
      await settle(request, rollback.getByText(t('deploy.rolledBack'), { exact: true }));
      await expectStep(rollback, t, 'write_file', 'ok');
      await expectStep(rollback, t, 'verify', 'failed');
      await expectStep(rollback, t, 'restore', 'ok');
      await rollback.getByRole('button', { name: t('deploy.close') }).last().click();
      await expect(rollback).toHaveCount(0);
      windowsExec(['ctl', 'stale-tls-off']);

      // 6. The server page stays accessible with the CCS panel and files at every width.
      await openServer(page, t);
      await expectAccessible(page, 'windows server, CCS after the deployments');
    });
  });
}
