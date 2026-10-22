import type { Page } from '@playwright/test';
import {
  browserLocale,
  expect,
  expectAccessible,
  field,
  resetInstall,
  runWizard,
  settle,
  test,
  translator,
  windowsExec,
  type Lang,
  type Translate,
} from './helpers';

// A Windows server on the e2e stack (R60, phase W1: connection and discovery only): the emulated Windows server of the
// compose service fakewindows (cmd/alice-fakewindows, the demo host of internal/providers/windows/wintest): Windows
// Server 2022 Datacenter 10.0.20348.2700 with IIS 10.0, the sites "Default Web Site" (https *:443:www.win.example.test,
// SNI) and "Intranet" (https *:8443:), and the http.sys entries hostnameport www.win.example.test:443 (IIS, My), ipport
// 0.0.0.0:8443 (IIS, WebHosting), ipport 0.0.0.0:5986 (WinRM: another application) and ccs 443. Its helper answers come
// from the helper's own code behind an SSH server that behaves like Windows OpenSSH. Every visible text is read from the
// locale files at run time (translator).

const SERVER = 'e2e-windows';
const PRODUCT = 'Windows Server 2022 Datacenter';
const BUILD = '10.0.20348.2700';
const WEB = 'http.sys/hostnameport/www.win.example.test:443';
const INTRANET = 'http.sys/ipport/0.0.0.0:8443';
const WINRM = 'http.sys/ipport/0.0.0.0:5986';
const CCS = 'http.sys/ccs/443';
// The Windows journey adds a server and runs two jobs (the connection test, the first discovery).
const JOURNEY_TIMEOUT = 4 * 60_000;

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

for (const lang of ['en', 'tr'] as Lang[]) {
  const t = translator(lang);

  test.describe(`Windows server (${lang})`, () => {
    test.use({ locale: browserLocale(lang) });

    test.beforeEach(async ({ request }) => {
      await resetInstall(request);
    });

    test('add a Windows server, confirm its host key and see its http.sys bindings and IIS sites', async ({ page, request }) => {
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
      await expect(bindingRow(page, t, WINRM)).toContainText(t('locations.unsupported.win_foreign_app', { application: 'winrm' }));
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
    });
  });
}
