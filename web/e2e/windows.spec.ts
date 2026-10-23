import { X509Certificate } from 'node:crypto';
import type { Locator, Page } from '@playwright/test';
import {
  browserLocale,
  expect,
  expectAccessible,
  field,
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

// A Windows server on the e2e stack (R60, phase W1: connection and discovery; R61, phase W2: deployment, verification
// and rollback): the emulated Windows server of the
// compose service fakewindows (cmd/alice-fakewindows, the demo host of internal/providers/windows/wintest): Windows
// Server 2022 Datacenter 10.0.20348.2700 with IIS 10.0, the sites "Default Web Site" (https *:443:www.win.example.test,
// SNI) and "Intranet" (https *:8443:), and the http.sys entries hostnameport www.win.example.test:443 (IIS, My), ipport
// 0.0.0.0:8443 (IIS, WebHosting), ipport 0.0.0.0:5986 (WinRM: another application) and ccs 443. Its helper answers come
// from the helper's own code behind an SSH server that behaves like Windows OpenSSH. Every visible text is read from the
// locale files at run time (translator).

const SERVER = 'e2e-windows';
const PRODUCT = 'Windows Server 2022 Datacenter';
const BUILD = '10.0.20348.2700';
const HOST = 'www.win.example.test';
const WEB = `http.sys/hostnameport/${HOST}:443`;
const INTRANET = 'http.sys/ipport/0.0.0.0:8443';
const WINRM = 'http.sys/ipport/0.0.0.0:5986';
const CCS = 'http.sys/ccs/443';
// The Windows journey adds a server, runs two jobs (the connection test, the first discovery) and two deployments
// (R61: one committed and verified, one whose verification fails and is rolled back).
const JOURNEY_TIMEOUT = 8 * 60_000;
// The Windows steps of a deployment that reach the server, in order (R61).
const DEPLOY_STEPS = ['import_chain', 'import_certificate', 'bind', 'verify'];

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function nav(page: Page, t: Translate, key: string): Promise<void> {
  await page.getByRole('link', { name: t(key), exact: true }).click();
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
}

// bindingRow is the row of the locations panel whose binding column is the http.sys entry's canonical text.
function bindingRow(page: Page, t: Translate, text: string) {
  return page
    .getByRole('table', { name: t('locations.tableLabel') })
    .getByTestId('location-row')
    .filter({ has: page.locator('code', { hasText: new RegExp(`^${escapeRegExp(text)}$`) }) });
}

// fact is the value of the server page's fact with this label.
function fact(page: Page, label: string) {
  return page.locator('dt', { hasText: new RegExp(`^${escapeRegExp(label)}$`) }).locator('xpath=following-sibling::dd[1]');
}

// uploadPair uploads a certificate with its key on Certificates -> Upload certificate under label and closes the result.
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
  await expect(page.getByRole('heading', { level: 1, name: label })).toBeVisible();
}

// openServer opens the Windows server's page from the server list.
async function openServer(page: Page, t: Translate): Promise<void> {
  await nav(page, t, 'nav.servers');
  await page.getByRole('link', { name: SERVER, exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: SERVER })).toBeVisible();
}

// deployToWeb opens the deploy dialog from the www.win.example.test binding's row, checks the grouped binding picker
// (the binding's group selected with its own control: exactly that binding), picks the certificate named label and
// starts the deployment.
async function deployToWeb(page: Page, t: Translate, subject: string, label: string): Promise<Locator> {
  const prefix = t('locations.deployNamed', { site: '\u0000' }).split('\u0000')[0];
  await bindingRow(page, t, WEB).getByRole('button', { name: new RegExp(`^${escapeRegExp(prefix)}`) }).click();
  const dialog = page.getByRole('dialog', { name: t('deploy.title') });
  const groups = dialog.getByTestId('deploy-certificate-group');
  await expect(groups, 'the picker groups the bindings by the certificate they serve').toHaveCount(4);
  const group = groups.filter({ has: page.getByRole('heading', { level: 3, name: subject, exact: true }) });
  await expect(group).toHaveCount(1);
  await group.getByRole('button', { name: t('deploy.selectGroupNamed', { name: subject }) }).click();
  await expect(dialog.getByRole('checkbox', { checked: true })).toHaveCount(1);
  await expect(group.getByRole('checkbox', { checked: true })).toHaveCount(1);
  const select = field(dialog, t('deploy.certificate'));
  const value = await select.locator('option', { hasText: label }).getAttribute('value');
  expect(value, `certificate ${label} offered`).toBeTruthy();
  await select.selectOption(value!);
  await dialog.getByRole('button', { name: t('deploy.submit'), exact: true }).click();
  return dialog;
}

function steps(scope: Locator, t: Translate): Locator {
  return scope.getByRole('list', { name: t('deployments.stepsTitle') });
}

// expectStep checks one step row: its status and its Windows name.
async function expectStep(scope: Locator, t: Translate, step: string, status: 'ok' | 'failed'): Promise<void> {
  const row = steps(scope, t).locator(`li[data-step="${step}"]`);
  await expect(row, step).toHaveAttribute('data-status', status);
  await expect(row).toContainText(t(`deployments.steps.${step}`));
}

// openDeployment opens a deployment from the history by its certificate's label.
async function openDeployment(page: Page, t: Translate, label: string): Promise<void> {
  await nav(page, t, 'nav.deployments');
  const name = new RegExp(`^${escapeRegExp(t('deployments.openNamed', { name: `${label}, ` }))}`);
  await page.getByTestId('deployment-row').getByRole('link', { name }).click();
  await expect(page.getByRole('heading', { level: 1, name: t('deployments.detailTitle') })).toBeVisible();
}

// sha1Of is a certificate's SHA-1 thumbprint as Windows names it, without separators (compared ignoring case).
function sha1Of(pem: string): string {
  return new X509Certificate(pem).fingerprint.replace(/:/g, '');
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const t = translator(lang);

  test.describe(`Windows server (${lang})`, () => {
    test.use({ locale: browserLocale(lang) });

    test.beforeEach(async ({ request }) => {
      windowsExec(['ctl', 'stale-tls-off']);
      await resetInstall(request);
    });
    test.afterEach(() => {
      windowsExec(['ctl', 'stale-tls-off']);
    });

    test('add a Windows server, confirm its host key, see its http.sys bindings and IIS sites, deploy and roll back', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      await runWizard(page, request, lang);
      expect(JSON.parse(windowsExec(['ctl', 'ping']))).toEqual({ ok: true });

      // 1. Servers -> Add server, type Windows server: the PowerShell setup script with the helper's checksums.
      await nav(page, t, 'nav.servers');
      await page.getByRole('button', { name: t('targets.add') }).click();
      const dialog = page.getByRole('dialog', { name: t('targets.add') });
      await field(dialog, t('targets.form.type')).selectOption('windows');
      const scriptBlock = dialog.getByTestId('add-server-script');
      await expect(scriptBlock).toContainText('$AuthorizedKey = ');
      await expect(dialog.getByText(t('targets.form.scriptWindowsHelp'))).toBeVisible();
      const script = (await scriptBlock.textContent()) ?? '';
      expect(script, 'the helper checksum for AMD64 is embedded (the image is built with make winhelper sums)').toMatch(/'AMD64' = '[0-9a-f]{64}'/);
      expect(script).toMatch(/'ARM64' = '[0-9a-f]{64}'/);
      expect(script, 'a build with checksums never installs an unchecked helper').not.toContain('cannot verify alice-helper.exe');
      expect(script).toContain("$AliceUser = 'alice'");
      // The key line itself forces the helper, on every administrator account (final review C1).
      expect(script).toContain(String.raw`$AuthorizedKey = 'restrict,command="\"C:\Program Files\Alice\alice-helper.exe\" ssh" ssh-`);
      // The administrator runs it on the server: the emulated server authorizes the key of its $AuthorizedKey line.
      expect(JSON.parse(windowsExec(['ctl', 'prepare'], script))).toEqual({ ok: true });

      // 2. Name, address, port and account; the host key confirmation shows the server's own fingerprint.
      await field(dialog, t('targets.form.name')).fill(SERVER);
      await field(dialog, t('targets.form.host')).fill('fakewindows');
      await expect(field(dialog, t('targets.form.port'))).toHaveValue('22');
      const account = field(dialog, t('targets.form.usernameWindows'));
      await expect(account, 'the Windows type proposes the account the script creates').toHaveValue('alice');
      await account.fill('alice');
      await dialog.getByRole('button', { name: t('targets.form.submit') }).click();
      const confirm = page.getByRole('dialog', { name: t('hostKeys.confirmTitle') });
      await settle(request, confirm);
      const onServer = windowsExec(['ctl', 'hostkey']).trim();
      expect(onServer).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);
      await expect(confirm.getByTestId('host-key-fingerprint')).toHaveText(onServer);
      await confirm.getByRole('button', { name: t('hostKeys.yes') }).click();
      await settle(request, page.getByText(t('targets.added')));
      await expect(page.getByTestId('target-status')).toHaveText(t('enum.targetStatus.ok'));
      await page.getByRole('button', { name: t('locations.discover'), exact: true }).click();
      await settle(request, page.getByText(t('targets.jobDone')));

      // 3. The server page: a Windows server, its product, build and IIS version, and an elevated sign-in.
      await expect(page.locator('dd', { hasText: new RegExp(`^${escapeRegExp(t('targets.typeLabel.windows'))}$`) })).toBeVisible();
      await expect(fact(page, t('targets.page.facts.windowsVersion'))).toHaveText(PRODUCT);
      await expect(fact(page, t('targets.page.facts.windowsBuild'))).toHaveText(BUILD);
      await expect(fact(page, t('targets.page.facts.iis'))).toHaveText(t('targets.facts.iisVersion', { version: '10.0' }));
      await expect(fact(page, t('targets.page.facts.elevated'))).toHaveText(t('targets.facts.yes'));
      await expect(page.getByText(t('targets.page.operationsTextWindows'))).toBeVisible();

      // 4. One row per http.sys binding, with its IIS site; the WinRM and the CCS bindings are listed, not supported.
      const table = page.getByRole('table', { name: t('locations.tableLabel') });
      await expect(table.getByRole('columnheader', { name: t('webServer.siteColumn.windows'), exact: true })).toBeVisible();
      await expect(table.getByRole('columnheader', { name: t('locations.columns.binding'), exact: true })).toBeVisible();
      await expect(table.getByTestId('location-row')).toHaveCount(4);
      for (const text of [WEB, INTRANET, WINRM, CCS]) await expect(bindingRow(page, t, text), text).toHaveCount(1);
      await expect(bindingRow(page, t, WEB)).toContainText('Default Web Site');
      await expect(bindingRow(page, t, WEB).getByRole('link', { name: 'www.win.example.test', exact: true })).toBeVisible();
      await expect(bindingRow(page, t, INTRANET)).toContainText('Intranet');
      for (const text of [WEB, INTRANET]) {
        await expect(bindingRow(page, t, text).getByText(t('locations.notSupported'), { exact: true }), text).toHaveCount(0);
      }
      await expect(bindingRow(page, t, WINRM)).toContainText(t('locations.notSupported'));
      await expect(bindingRow(page, t, WINRM)).toContainText(t('locations.unsupported.win_foreign_app', { application: 'WinRM' }));
      await expect(bindingRow(page, t, CCS)).toContainText(t('locations.notSupported'));
      await expect(bindingRow(page, t, CCS)).toContainText(t('locations.unsupported.win_ccs'));

      // 5. Accessible at every width.
      await expectAccessible(page, 'windows server');

      // 6. Certificates: www.win.example.test, found on e2e-windows at its http.sys binding.
      await nav(page, t, 'nav.certificates');
      const link = page.getByTestId('certificates-table').getByRole('link', { name: 'www.win.example.test', exact: true });
      await expect(link).toBeVisible();
      await link.click();
      const usedWhere = page.getByRole('table', { name: t('certificates.detail.usedWhere') });
      await expect(usedWhere.getByRole('link', { name: SERVER, exact: true })).toBeVisible();
      await expect(usedWhere.locator('code', { hasText: new RegExp(`^${escapeRegExp(WEB)}$`) })).toBeVisible();

      // 7. R61: the bindings grouped by the certificate they serve (three certificates, and the CCS entry without one).
      const first = newCert(HOST);
      const firstLabel = `win-renewal-1-${lang}`;
      await uploadPair(page, t, first, firstLabel);
      await openServer(page, t);
      const groups = page.getByTestId('certificate-group');
      await expect(groups).toHaveCount(4);
      const webGroup = groups.filter({ has: page.locator('code', { hasText: new RegExp(`^${escapeRegExp(WEB)}$`) }) });
      await expect(webGroup.getByTestId('certificate-group-row')).toContainText(HOST);
      await expect(webGroup.getByTestId('certificate-group-row')).toContainText(t('locations.group.count', { count: 1 }));
      await expect(groups.last().getByTestId('certificate-group-row')).toContainText(t('locations.group.noCertificate'));
      await expect(groups.last()).toContainText(CCS);

      // 8. Deploy to the hostnameport binding: chain, certificate, bind, verify; committed, served and trusted.
      const deploying = await deployToWeb(page, t, HOST, firstLabel);
      await settle(request, deploying.getByText(t('deploy.succeeded'), { exact: true }));
      for (const step of DEPLOY_STEPS) await expectStep(deploying, t, step, 'ok');
      await deploying.getByRole('button', { name: t('deploy.close') }).last().click();
      await expect(deploying).toHaveCount(0);
      await openDeployment(page, t, firstLabel);
      await expect(page.getByTestId('deployment-status')).toHaveText(t('enum.deploymentStatus.succeeded'));
      const main = page.getByRole('main');
      for (const step of DEPLOY_STEPS) await expectStep(main, t, step, 'ok');
      await expect(main.getByText(t('deployments.level.trusted'), { exact: true })).toBeVisible();
      await expect(main.getByText(t('deployments.bindingLabel'), { exact: true })).toBeVisible();
      await expectAccessible(page, 'windows deployment, verified');

      // 8b. R62: the page of the deployment reads the location's kind (the binding, the Windows previous-certificate line
      // and no backup folder); the server page names the certificate Alice imported, and its cleanup switch is on, saved
      // off and on again, each read back after a reload.
      await expect(page.getByTestId('windows-previous')).toBeVisible();
      await expect(main.getByText(t('deployments.bindingLabel'), { exact: true })).toBeVisible();
      await openServer(page, t);
      await page.getByRole('button', { name: t('locations.discover'), exact: true }).click();
      await settle(request, page.getByText(t('targets.jobDone')));
      await expect(bindingRow(page, t, WEB).getByText(t('locations.importedByAlice'), { exact: true })).toBeVisible();
      await expect(bindingRow(page, t, INTRANET).getByText(t('locations.importedByAlice'), { exact: true })).toHaveCount(0);
      const cleanup = page.getByRole('switch', { name: new RegExp(`^${escapeRegExp(t('targets.page.cleanup.label'))}`) });
      await expect(cleanup, 'new servers remove what Alice imported by default').toBeChecked();
      await expectAccessible(page, 'windows server, cleanup switch');
      await cleanup.click();
      await expect(page.getByText(t('targets.page.cleanup.saved'), { exact: true })).toBeVisible();
      await expect(cleanup).not.toBeChecked();
      await page.reload();
      await expect(cleanup, 'the saved value is read back after a reload').not.toBeChecked();
      await cleanup.click();
      await expect(page.getByText(t('targets.page.cleanup.saved'), { exact: true })).toBeVisible();
      await page.reload();
      await expect(cleanup).toBeChecked();

      // 9. A website that does not take the change (the fake keeps serving the certificate it served before the bind):
      // the verification fails, the provider's iis-restore points the binding back, the deployment is rolled back.
      const second = newCert(HOST);
      const secondLabel = `win-renewal-2-${lang}`;
      await uploadPair(page, t, second, secondLabel);
      await openServer(page, t);
      windowsExec(['ctl', 'stale-tls-on']);
      const rollback = await deployToWeb(page, t, HOST, secondLabel);
      await settle(request, rollback.getByText(t('deploy.rolledBack'), { exact: true }));
      await expect(rollback.getByRole('alert').first()).toContainText(t('errors.deployment.verify_failed.title'));
      await expect(rollback.getByRole('alert').first()).toContainText(t('deployments.windowsErrors.deployment.verify_failed.cause'));
      await expectStep(rollback, t, 'bind', 'ok');
      await expectStep(rollback, t, 'verify', 'failed');
      await expectStep(rollback, t, 'restore', 'ok');
      await rollback.getByRole('button', { name: t('deploy.close') }).last().click();
      await expect(rollback).toHaveCount(0);
      windowsExec(['ctl', 'stale-tls-off']);
      await openDeployment(page, t, secondLabel);
      await expect(page.getByTestId('deployment-status')).toHaveText(t('enum.deploymentStatus.rolled_back'));
      await expectStep(main, t, 'restore', 'ok');
      await expectStep(main, t, 'verify_old', 'ok');
      await expect(main.getByText(t('deployments.windowsErrors.deployment.verify_failed.cause'))).toBeVisible();
      // The previous certificate the binding names again: its store and SHA-1 thumbprint.
      const previous = t('deployments.previousWindows', { store: 'My', sha1: sha1Of(first.cert) });
      await expect(page.getByTestId('windows-previous')).toHaveText(new RegExp(`^${escapeRegExp(previous)}$`, 'i'));
      await expectAccessible(page, 'windows deployment, rolled back');
    });
  });
}
