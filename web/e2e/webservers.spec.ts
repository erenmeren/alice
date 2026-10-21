import type { APIResponse, Page } from '@playwright/test';
import {
  apiAs,
  browserLocale,
  expect,
  expectAccessible,
  field,
  fingerprintOf,
  resetInstall,
  runWizard,
  settle,
  tabTo,
  targetExec,
  test,
  translator,
  type Lang,
  type Translate,
} from './helpers';

// Web server providers on the e2e stack: an Apache server (discovery only, Phase B) and an HAProxy server (discovery
// only, Phase C). The SSH target has the distribution's Apache with the websites of
// test/images/e2e-target/apache-sites.conf and the distribution's HAProxy with the sections of
// test/images/e2e-target/haproxy.cfg, both configured and never started. Alice reads their configuration and
// certificate files; deployment is shown, aria-disabled, with the note why. Every visible text is read from the locale
// files at run time (translator), except the pinned notes below.

const HOST_KEY_PUB = '/etc/ssh/ssh_host_ed25519_key.pub';
const SERVER = 'e2e-apache';
const SITES = { 'apache.example.test': '/etc/apache2/ssl/apache.crt', 'combined.example.test': '/etc/apache2/ssl/combined.pem' } as const;
type Site = keyof typeof SITES;
const APACHE_DUMP_LINE = '/usr/local/libexec/alice-helper apache-dump';
const HAPROXY_SERVER = 'e2e-haproxy';
const HAPROXY_DUMP_LINE = '/usr/local/libexec/alice-helper haproxy-dump';
// fe_https names no website (its certificate is found through crt-base): the row shows its frontend. li_sni serves
// sni.example.test through a crt-list.
const HAPROXY_FILES = { fe_https: '/etc/haproxy/certs/haproxy.pem', 'sni.example.test': '/etc/haproxy/certs/sni.pem' } as const;
const HAPROXY_CERTS = ['haproxy.example.test', 'sni.example.test'] as const;
// The journey prepares the server twice (Apache, then Nginx again) and runs several jobs.
const JOURNEY_TIMEOUT = 6 * 60_000;

// The disabled note is a contract (global constraints of Phases B and C): pinned as literals in both languages.
const PINNED_NOTE: Record<Lang, string> = {
  en: 'Not available for Apache servers yet',
  tr: 'Apache sunucularında henüz kullanılamıyor',
};
const HAPROXY_NOTE: Record<Lang, string> = {
  en: 'Not available for HAProxy servers yet',
  tr: 'HAProxy sunucularında henüz kullanılamıyor',
};

async function json<T>(res: APIResponse): Promise<T> {
  const text = await res.text();
  expect(res.ok(), `${res.status()} ${text}`).toBe(true);
  return JSON.parse(text) as T;
}

function sudoers(): string {
  return targetExec(['sh', '-c', 'cat /etc/sudoers.d/*']);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function nav(page: Page, t: Translate, key: string): Promise<void> {
  await page.getByRole('link', { name: t(key), exact: true }).click();
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
}

function websiteRow(page: Page, t: Translate, site: string) {
  return page
    .getByRole('table', { name: t('locations.tableLabel') })
    .getByTestId('location-row')
    .filter({ has: page.locator('code', { hasText: new RegExp(`^${escapeRegExp(site)}$`) }) });
}

// frontendRow is the row of an HAProxy section that names no website: it shows "Frontend: <name>".
function frontendRow(page: Page, t: Translate, name: string) {
  return page
    .getByRole('table', { name: t('locations.tableLabel') })
    .getByTestId('location-row')
    .filter({ has: page.getByText(t('locations.frontend', { name }), { exact: true }) });
}

// restoreNginx runs the Nginx profile's script again, so later specs find the target with the Nginx profile, as they
// expect; the profile prepared for the journey (its dump line) is gone.
function restoreNginx(nginxScript: string, dumpLine: string): void {
  if (!nginxScript) return;
  targetExec(['/usr/local/sbin/alice-e2e-prepare'], nginxScript);
  const installed = sudoers();
  expect(installed, 'the Nginx profile is back on the target').toContain('/usr/local/libexec/alice-helper nginx-dump');
  expect(installed).not.toContain(dumpLine);
}

// deployWordIn is the first word of the locale's Deploy button (the word the page must not use outside the disabled
// controls).
function deployWordIn(t: Translate, lang: Lang): string {
  const word = t('deploy.submit').split(/\s+/)[0].toLocaleLowerCase(lang);
  expect(word.length).toBeGreaterThan(3);
  return word;
}

// textOutsideDisabled is the text of the page's main region without the disabled controls. The SSH keys table is
// data, not copy: the target's fixture account is named deploy (/home/deploy, deploy@laptop).
function textOutsideDisabled(page: Page): Promise<string> {
  return page.getByRole('main').evaluate((main) => {
    const copy = main.cloneNode(true) as HTMLElement;
    for (const el of copy.querySelectorAll('[data-testid="disabled-feature"], [data-testid="target-keys"]')) el.remove();
    return copy.textContent ?? '';
  });
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const t = translator(lang);
  const software = t('webServer.software.apache');

  test.describe(`Web server providers: Apache (${lang})`, () => {
    test.use({ locale: browserLocale(lang) });
    // The Nginx profile's script of this install, read before the target is prepared for Apache: afterAll runs it
    // again so later specs find the target with the Nginx profile, as they expect.
    let nginxScript = '';

    test.beforeEach(async ({ request }) => {
      await resetInstall(request);
    });

    test.afterAll(() => {
      restoreNginx(nginxScript, APACHE_DUMP_LINE);
    });

    test('add an Apache server, see its websites and certificates, deploy controls disabled with the note', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      await runWizard(page, request, lang);
      const api = await apiAs(page);
      const key = await json<{ profiles: { nginx: { script: string } } }>(await api.get('/api/v1/ssh-keys/platform-key'));
      nginxScript = key.profiles.nginx.script;
      expect(nginxScript).toContain('nginx-dump');

      // 1. Prepare the server with the Apache profile's commands from the Servers page.
      await nav(page, t, 'nav.servers');
      await field(page, t('targets.prepare.profile')).selectOption('apache');
      const script = (await page.getByTestId('setup-script').textContent()) ?? '';
      expect(script).toContain(APACHE_DUMP_LINE);
      expect(script, 'the Apache profile grants no Nginx command').not.toContain('nginx-');
      targetExec(['/usr/local/sbin/alice-e2e-prepare'], script);
      const installed = sudoers();
      expect(installed, 'sudoers of the target grant apache-dump').toContain(APACHE_DUMP_LINE);
      expect(installed).not.toContain('nginx-dump');
      const helper = JSON.parse(targetExec(['/usr/local/libexec/alice-helper', 'version'])) as { helper: string; protocol: number };
      expect(helper.protocol, `alice-helper ${helper.helper} on the target`).toBe(11);

      // 2. Add the server with the type Apache server; compare the fingerprint with the server's own.
      await page.getByRole('button', { name: t('targets.add') }).click();
      const dialog = page.getByRole('dialog', { name: t('targets.add') });
      await field(dialog, t('targets.form.type')).selectOption('apache');
      await expect(dialog.getByTestId('add-server-script')).toHaveText(script);
      await field(dialog, t('targets.form.name')).fill(SERVER);
      await field(dialog, t('targets.form.host')).fill('sshtarget');
      await dialog.getByRole('button', { name: t('targets.form.submit') }).click();
      const confirm = page.getByRole('dialog', { name: t('hostKeys.confirmTitle') });
      await settle(request, confirm);
      const onServer = fingerprintOf(targetExec(['ssh-keygen', '-lf', HOST_KEY_PUB]));
      await expect(confirm.getByTestId('host-key-fingerprint')).toHaveText(onServer);
      await confirm.getByRole('button', { name: t('hostKeys.yes') }).click();
      await settle(request, page.getByText(t('targets.added')));
      await expect(page.getByTestId('target-status')).toHaveText(t('enum.targetStatus.ok'));
      const targetId = new URL(page.url()).pathname.split('/').pop() ?? '';
      await page.getByRole('button', { name: t('locations.discover'), exact: true }).click();
      await settle(request, page.getByText(t('targets.jobDone')));

      // 3. The server page: Apache server, the version Apache reports, and a valid configuration.
      const version = /Server version: Apache\/(\S+)/.exec(targetExec(['apache2ctl', '-v']))?.[1] ?? '';
      expect(version).toMatch(/^2\.4\.\d+$/);
      await expect(page.locator('dd', { hasText: new RegExp(`^${escapeRegExp(t('targets.typeLabel.apache'))}$`) })).toBeVisible();
      await expect(page.locator('dt', { hasText: new RegExp(`^${escapeRegExp(t('targets.page.facts.webServer', { software }))}$`) }).locator('xpath=following-sibling::dd[1]')).toHaveText(version);
      const target = await json<{ facts: { web_server: { software: string; version: string; config_valid: boolean; found: boolean } } }>(await api.get(`/api/v1/targets/${targetId}`));
      expect(target.facts.web_server).toMatchObject({ software: 'apache', version, config_valid: true, found: true });
      await expect(page.getByTestId('config-invalid')).toHaveCount(0);
      await expect(page.getByText(t('warnings.web_server_config_invalid_discovery', { software }))).toHaveCount(0);

      // 4. The websites, each with its certificate file, and their certificates on the Certificates page.
      for (const [site, file] of Object.entries(SITES) as [Site, string][]) {
        await expect(websiteRow(page, t, site)).toHaveCount(1);
        await expect(websiteRow(page, t, site)).toContainText(file);
      }
      // The texts follow the capabilities: the discovery-only ones, never those that promise deployment.
      await expect(page.getByText(t('locations.introDiscovery', { software }))).toBeVisible();
      await expect(page.getByText(t('targets.page.operationsTextDiscovery', { software }))).toBeVisible();
      for (const text of [t('locations.intro', { software }), t('targets.page.operationsText', { software }), t('locations.deployUnavailable')]) {
        await expect(page.getByText(text), text).toHaveCount(0);
      }

      // 5. The Deploy control of a row is reached with Tab: focused, aria-disabled, and its tooltip is the note.
      expect(t('webServer.notAvailable', { software })).toBe(PINNED_NOTE[lang]);
      const deploy = page.getByRole('button', { name: t('locations.deployNamed', { site: 'apache.example.test' }) });
      await expect(deploy).toHaveAttribute('aria-disabled', 'true');
      await expect(deploy).not.toHaveAttribute('disabled');
      await expect(deploy).toHaveAccessibleDescription(PINNED_NOTE[lang]);
      await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
      await tabTo(page, deploy, 150);
      await expect(deploy).toBeFocused();
      await expect(page.getByRole('tooltip')).toHaveText(PINNED_NOTE[lang]);
      // Enter on it starts nothing.
      await page.keyboard.press('Enter');
      await expect(page.getByRole('dialog')).toHaveCount(0);
      for (const site of Object.keys(SITES)) {
        for (const name of [t('locations.deployNamed', { site }), t('locations.settingsNamed', { site })]) {
          const control = page.getByRole('button', { name });
          await expect(control, name).toHaveAttribute('aria-disabled', 'true');
          await expect(control, name).toHaveAccessibleDescription(PINNED_NOTE[lang]);
        }
      }

      // 6. Outside the disabled controls no text on the page mentions deploying (the word is the locale's own). The SSH
      // keys table is data, not copy: the target's fixture account is named deploy (/home/deploy, deploy@laptop).
      const deployWord = deployWordIn(t, lang);
      const outside = await textOutsideDisabled(page);
      expect(outside).toContain('apache.example.test');
      expect(outside.toLocaleLowerCase(lang), `the server page outside the disabled controls mentions "${deployWord}"`).not.toContain(deployWord);

      // 7. Accessible at every width.
      await expectAccessible(page, 'apache server');

      // The certificates of both websites are on the Certificates page.
      await nav(page, t, 'nav.certificates');
      const certificates = page.getByTestId('certificates-table');
      for (const site of Object.keys(SITES)) await expect(certificates.getByRole('link', { name: site, exact: true }), site).toBeVisible();
    });
  });

  test.describe(`Web server providers: HAProxy (${lang})`, () => {
    test.use({ locale: browserLocale(lang) });
    const haproxy = t('webServer.software.haproxy');
    // As for Apache: afterAll runs the Nginx profile's script again.
    let nginxScript = '';

    test.beforeEach(async ({ request }) => {
      await resetInstall(request);
    });

    test.afterAll(() => {
      restoreNginx(nginxScript, HAPROXY_DUMP_LINE);
    });

    test('add an HAProxy server, see its frontends and certificates, deploy controls disabled with the note', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      await runWizard(page, request, lang);
      const api = await apiAs(page);
      const key = await json<{ profiles: { nginx: { script: string } } }>(await api.get('/api/v1/ssh-keys/platform-key'));
      nginxScript = key.profiles.nginx.script;
      expect(nginxScript).toContain('nginx-dump');

      // 1. Prepare the server with the HAProxy profile's commands from the Servers page.
      await nav(page, t, 'nav.servers');
      await field(page, t('targets.prepare.profile')).selectOption('haproxy');
      const script = (await page.getByTestId('setup-script').textContent()) ?? '';
      expect(script).toContain(HAPROXY_DUMP_LINE);
      expect(script, 'the HAProxy profile grants no Nginx command').not.toContain('nginx-');
      expect(script, 'the HAProxy profile grants no Apache command').not.toContain('apache-dump');
      targetExec(['/usr/local/sbin/alice-e2e-prepare'], script);
      const installed = sudoers();
      expect(installed, 'sudoers of the target grant haproxy-dump').toContain(HAPROXY_DUMP_LINE);
      expect(installed).not.toContain('nginx-dump');
      const helper = JSON.parse(targetExec(['/usr/local/libexec/alice-helper', 'version'])) as { helper: string; protocol: number };
      expect(helper.protocol, `alice-helper ${helper.helper} on the target`).toBe(11);

      // 2. Add the server with the type HAProxy server; compare the fingerprint with the server's own.
      await page.getByRole('button', { name: t('targets.add') }).click();
      const dialog = page.getByRole('dialog', { name: t('targets.add') });
      await field(dialog, t('targets.form.type')).selectOption('haproxy');
      await expect(dialog.getByTestId('add-server-script')).toHaveText(script);
      await field(dialog, t('targets.form.name')).fill(HAPROXY_SERVER);
      await field(dialog, t('targets.form.host')).fill('sshtarget');
      await dialog.getByRole('button', { name: t('targets.form.submit') }).click();
      const confirm = page.getByRole('dialog', { name: t('hostKeys.confirmTitle') });
      await settle(request, confirm);
      const onServer = fingerprintOf(targetExec(['ssh-keygen', '-lf', HOST_KEY_PUB]));
      await expect(confirm.getByTestId('host-key-fingerprint')).toHaveText(onServer);
      await confirm.getByRole('button', { name: t('hostKeys.yes') }).click();
      await settle(request, page.getByText(t('targets.added')));
      await expect(page.getByTestId('target-status')).toHaveText(t('enum.targetStatus.ok'));
      const targetId = new URL(page.url()).pathname.split('/').pop() ?? '';
      await page.getByRole('button', { name: t('locations.discover'), exact: true }).click();
      await settle(request, page.getByText(t('targets.jobDone')));

      // 3. The server page: HAProxy server, the version HAProxy reports, and a valid configuration ("haproxy -c" only
      // checks it: HAProxy is never started on the target).
      const version = /^HAProxy version (\S+)/.exec(targetExec(['haproxy', '-v']))?.[1] ?? '';
      expect(version).toMatch(/^2\.4\.\d+/);
      expect(targetExec(['sh', '-c', 'pgrep -x haproxy || echo none']).trim(), 'HAProxy is not running').toBe('none');
      await expect(page.locator('dd', { hasText: new RegExp(`^${escapeRegExp(t('targets.typeLabel.haproxy'))}$`) })).toBeVisible();
      await expect(page.locator('dt', { hasText: new RegExp(`^${escapeRegExp(t('targets.page.facts.webServer', { software: haproxy }))}$`) }).locator('xpath=following-sibling::dd[1]')).toHaveText(version);
      const target = await json<{ facts: { web_server: { software: string; version: string; config_valid: boolean; found: boolean } } }>(await api.get(`/api/v1/targets/${targetId}`));
      expect(target.facts.web_server).toMatchObject({ software: 'haproxy', version, config_valid: true, found: true });
      await expect(page.getByTestId('config-invalid')).toHaveCount(0);
      await expect(page.getByText(t('warnings.web_server_config_invalid_discovery', { software: haproxy }))).toHaveCount(0);

      // 4. The column is "Frontend"; fe_https's row shows its frontend, li_sni's row its SNI name, each with its file.
      const table = page.getByRole('table', { name: t('locations.tableLabel') });
      await expect(table.getByRole('columnheader', { name: t('webServer.siteColumn.haproxy'), exact: true })).toBeVisible();
      await expect(table.getByRole('columnheader', { name: t('locations.columns.website'), exact: true })).toHaveCount(0);
      await expect(table.getByTestId('location-row')).toHaveCount(2);
      await expect(frontendRow(page, t, 'fe_https')).toHaveCount(1);
      await expect(frontendRow(page, t, 'fe_https')).toContainText(HAPROXY_FILES.fe_https);
      await expect(websiteRow(page, t, 'sni.example.test')).toHaveCount(1);
      await expect(websiteRow(page, t, 'sni.example.test')).toContainText(HAPROXY_FILES['sni.example.test']);
      await expect(websiteRow(page, t, 'sni.example.test')).toContainText(t('locations.frontend', { name: 'li_sni' }));
      // The texts follow the capabilities: the discovery-only ones, never those that promise deployment.
      await expect(page.getByText(t('locations.introDiscovery', { software: haproxy }))).toBeVisible();
      await expect(page.getByText(t('targets.page.operationsTextDiscovery', { software: haproxy }))).toBeVisible();
      for (const text of [t('locations.intro', { software: haproxy }), t('targets.page.operationsText', { software: haproxy }), t('locations.deployUnavailable')]) {
        await expect(page.getByText(text), text).toHaveCount(0);
      }

      // 5. The Deploy control of a row is reached with Tab: focused, aria-disabled, and its tooltip is the note.
      expect(t('webServer.notAvailable', { software: haproxy })).toBe(HAPROXY_NOTE[lang]);
      const deploy = page.getByRole('button', { name: t('locations.deployNamed', { site: 'fe_https' }) });
      await expect(deploy).toHaveAttribute('aria-disabled', 'true');
      await expect(deploy).not.toHaveAttribute('disabled');
      await expect(deploy).toHaveAccessibleDescription(HAPROXY_NOTE[lang]);
      await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
      await tabTo(page, deploy, 150);
      await expect(deploy).toBeFocused();
      // Tab passed the controls of the rows before it: their tooltips close with a short transition.
      await expect(page.getByRole('tooltip')).toHaveCount(1);
      await expect(page.getByRole('tooltip')).toHaveText(HAPROXY_NOTE[lang]);
      // Enter on it starts nothing.
      await page.keyboard.press('Enter');
      await expect(page.getByRole('dialog')).toHaveCount(0);
      for (const site of Object.keys(HAPROXY_FILES)) {
        for (const name of [t('locations.deployNamed', { site }), t('locations.settingsNamed', { site })]) {
          const control = page.getByRole('button', { name });
          await expect(control, name).toHaveAttribute('aria-disabled', 'true');
          await expect(control, name).toHaveAccessibleDescription(HAPROXY_NOTE[lang]);
        }
      }

      // 6. Outside the disabled controls no text on the page mentions deploying.
      const deployWord = deployWordIn(t, lang);
      const outside = await textOutsideDisabled(page);
      expect(outside).toContain('sni.example.test');
      expect(outside).toContain(t('locations.frontend', { name: 'fe_https' }));
      expect(outside.toLocaleLowerCase(lang), `the server page outside the disabled controls mentions "${deployWord}"`).not.toContain(deployWord);

      // 7. Accessible at every width.
      await expectAccessible(page, 'haproxy server');

      // The certificates of both sections are on the Certificates page.
      await nav(page, t, 'nav.certificates');
      const certificates = page.getByTestId('certificates-table');
      for (const cn of HAPROXY_CERTS) await expect(certificates.getByRole('link', { name: cn, exact: true }), cn).toBeVisible();
    });
  });
}
