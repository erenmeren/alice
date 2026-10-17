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

// Web server providers on the e2e stack: an Apache server (discovery only, Phase B). The SSH target has the
// distribution's Apache with the websites of test/images/e2e-target/apache-sites.conf, configured and never started.
// Alice reads its configuration and certificate files; deployment is shown, aria-disabled, with the note why. Every
// visible text is read from the locale files at run time (translator), except the pinned note below.

const HOST_KEY_PUB = '/etc/ssh/ssh_host_ed25519_key.pub';
const SERVER = 'e2e-apache';
const SITES = { 'apache.example.test': '/etc/apache2/ssl/apache.crt', 'combined.example.test': '/etc/apache2/ssl/combined.pem' } as const;
type Site = keyof typeof SITES;
const APACHE_DUMP_LINE = '/usr/local/libexec/alice-helper apache-dump';
// The journey prepares the server twice (Apache, then Nginx again) and runs several jobs.
const JOURNEY_TIMEOUT = 6 * 60_000;

// The disabled note is a contract (global constraints of Phase B): pinned as literals in both languages.
const PINNED_NOTE: Record<Lang, string> = {
  en: 'Not available for Apache servers yet',
  tr: 'Apache sunucularında henüz kullanılamıyor',
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

function websiteRow(page: Page, t: Translate, site: Site) {
  return page
    .getByRole('table', { name: t('locations.tableLabel') })
    .getByTestId('location-row')
    .filter({ has: page.locator('code', { hasText: new RegExp(`^${escapeRegExp(site)}$`) }) });
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
      if (!nginxScript) return;
      targetExec(['/usr/local/sbin/alice-e2e-prepare'], nginxScript);
      const installed = sudoers();
      expect(installed, 'the Nginx profile is back on the target').toContain('/usr/local/libexec/alice-helper nginx-dump');
      expect(installed).not.toContain(APACHE_DUMP_LINE);
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
      expect(helper.protocol, `alice-helper ${helper.helper} on the target`).toBe(8);

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
      const deployWord = t('deploy.submit').split(/\s+/)[0].toLocaleLowerCase(lang);
      expect(deployWord.length).toBeGreaterThan(3);
      const outside = await page.getByRole('main').evaluate((main) => {
        const copy = main.cloneNode(true) as HTMLElement;
        for (const el of copy.querySelectorAll('[data-testid="disabled-feature"], [data-testid="target-keys"]')) el.remove();
        return copy.textContent ?? '';
      });
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
}
