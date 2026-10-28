import type { Locator, Page } from '@playwright/test';
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
  targetExec,
  windowsExec,
  type Lang,
  type PemPair,
  type Translate,
} from './helpers';

// R69, W6 Ruling 25: the Remote Desktop listener RDP-Tcp of the emulated Windows server (compose service fakewindows,
// the demo host of internal/providers/windows/wintest). Its listener is on port 3389 inside the container: on, security
// layer 2, NLA on, the listener's value absent, so it serves Windows' self-signed certificate (CN win-demo01) from the
// Remote Desktop store; Alice reaches it as fakewindows:3389. The journey: the server page shows the listener with its
// port, NLA and the self-signed certificate; a deployment commits and verifies (import chain, import certificate, grant
// key read, set listener, verify); with the listener serving stale certificates, a deployment is rolled back to the
// previous certificate. "ctl rdp-self-signed" puts the listener back on its self-signed certificate before and after
// each journey, so every run starts where a fresh demo host does. Separate from windows.spec.ts and windows-ccs.spec.ts,
// so their serial journeys keep their state. Every visible text is read from the locale files at run time (translator).

const SERVER = 'e2e-windows-rdp';
const LISTENER = 'rdp/RDP-Tcp';
const SELF_SIGNED_CN = 'win-demo01';
const HOST = 'rdp.win.example.test';
// The journey adds a server, runs two jobs (the connection test, the discovery) and two deployments.
const JOURNEY_TIMEOUT = 8 * 60_000;
// The steps of a deployment to the Remote Desktop listener, in order (R69).
const RDP_STEPS = ['import_chain', 'import_certificate', 'grant_key_read', 'set_listener', 'verify'];

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function nav(page: Page, t: Translate, key: string): Promise<void> {
  await page.getByRole('link', { name: t(key), exact: true }).click();
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
}

// listenerRow is the row of the locations panel whose place column is the listener's canonical text.
function listenerRow(page: Page, t: Translate): Locator {
  return page
    .getByRole('table', { name: t('locations.tableLabel') })
    .getByTestId('location-row')
    .filter({ has: page.locator('code', { hasText: new RegExp(`^${escapeRegExp(LISTENER)}$`) }) });
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

// deployToListener opens the deploy dialog from the listener's row (the listener alone is picked, the summary names
// it), chooses the certificate named label and starts the deployment.
async function deployToListener(page: Page, t: Translate, label: string): Promise<Locator> {
  await listenerRow(page, t).getByRole('button', { name: t('locations.deployNamed', { site: t('locations.rdp.name') }), exact: true }).click();
  const dialog = page.getByRole('dialog', { name: t('deploy.title') });
  await expect(dialog.getByText(t('deploy.summaryRDP'), { exact: true })).toBeVisible();
  await expect(dialog.getByRole('group', { name: t('deploy.places') })).toBeVisible();
  await expect(dialog.getByRole('checkbox', { checked: true })).toHaveCount(1);
  await expect(dialog.getByRole('checkbox', { name: new RegExp(escapeRegExp(LISTENER)), checked: true })).toHaveCount(1);
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

// rsaCert is a fresh RSA 2048 certificate for name signed by the SSH target's test CA, with its key. The listener's
// self-signed certificate is RSA, and Alice keeps the key type of a place (ALC-CRT-0007), so the journey deploys RSA
// certificates (newCert makes P-256 ones).
function rsaCert(name: string): PemPair {
  const out = targetExec([
    'sh',
    '-c',
    `t=$(mktemp -d) && trap 'rm -rf "$t"' EXIT && openssl req -new -newkey rsa:2048 -nodes -subj "/CN=${name}" -keyout "$t/k" -out "$t/r" 2>/dev/null && /usr/local/sbin/alice-e2e-pki sign "${name}" < "$t/r" && echo '-----ALICE KEY-----' && cat "$t/k"`,
  ]);
  const [cert, key] = out.split('-----ALICE KEY-----\n');
  expect(cert, 'the signed RSA certificate').toContain('-----BEGIN CERTIFICATE-----');
  expect(key, 'the RSA key').toContain('PRIVATE KEY-----');
  return { cert, key };
}

// resetListener ends stale TLS and puts the listener back on its self-signed certificate (in this order: a stale
// listener would keep serving what it served).
function resetListener(): void {
  windowsExec(['ctl', 'stale-tls-off']);
  expect(JSON.parse(windowsExec(['ctl', 'rdp-self-signed']))).toEqual({ ok: true });
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const t = translator(lang);

  test.describe(`Windows server Remote Desktop (${lang})`, () => {
    test.use({ locale: browserLocale(lang) });

    test.beforeEach(async ({ request }) => {
      resetListener();
      await resetInstall(request);
    });
    test.afterEach(() => {
      resetListener();
    });

    test('see the Remote Desktop listener with its self-signed certificate, deploy to it and roll back to the previous certificate', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      await runWizard(page, request, lang);
      await addServer(page, t, request);

      // 1. The listener: its name, port 3389, NLA on and Windows' self-signed certificate; deployable.
      const table = page.getByRole('table', { name: t('locations.tableLabel') });
      await expect(table.getByRole('columnheader', { name: t('locations.columns.place'), exact: true })).toBeVisible();
      const row = listenerRow(page, t);
      await expect(row).toHaveCount(1);
      await expect(row).toContainText(t('locations.rdp.name'));
      await expect(row.locator('code', { hasText: /^3389$/ })).toBeVisible();
      await expect(row).toContainText(t('locations.rdp.nlaOn'));
      await expect(row.getByTestId('rdp-self-signed')).toHaveText(t('locations.rdp.selfSigned'));
      await expect(row.getByRole('link', { name: SELF_SIGNED_CN, exact: true })).toBeVisible();
      await expect(row).toContainText(t('locations.ready'));
      await expectAccessible(page, 'windows server, Remote Desktop listener');

      // 2. A deployment to the listener: chain, certificate, key read for NETWORK SERVICE, listener, verify; committed.
      const first = rsaCert(HOST);
      const firstLabel = `rdp-renewal-1-${lang}`;
      await uploadPair(page, t, first, firstLabel);
      await openServer(page, t);
      const deploying = await deployToListener(page, t, firstLabel);
      await settle(request, deploying.getByText(t('deploy.succeeded'), { exact: true }));
      for (const step of RDP_STEPS) await expectStep(deploying, t, step, 'ok');
      await expectAccessible(page, 'windows Remote Desktop deployment, verified');
      await deploying.getByRole('button', { name: t('deploy.close') }).last().click();
      await expect(deploying).toHaveCount(0);

      // 3. A listener that keeps serving its previous certificate: the verification fails and the provider points the
      // listener back to the previous certificate; the deployment is rolled back.
      const second = rsaCert(HOST);
      const secondLabel = `rdp-renewal-2-${lang}`;
      await uploadPair(page, t, second, secondLabel);
      await openServer(page, t);
      windowsExec(['ctl', 'stale-tls-on']);
      const rollback = await deployToListener(page, t, secondLabel);
      await settle(request, rollback.getByText(t('deploy.rolledBack'), { exact: true }));
      await expectStep(rollback, t, 'set_listener', 'ok');
      await expectStep(rollback, t, 'verify', 'failed');
      await expectStep(rollback, t, 'restore', 'ok');
      await rollback.getByRole('button', { name: t('deploy.close') }).last().click();
      await expect(rollback).toHaveCount(0);
      windowsExec(['ctl', 'stale-tls-off']);

      // 4. The server page stays accessible with the listener at every width.
      await openServer(page, t);
      await expect(listenerRow(page, t)).toHaveCount(1);
      await expectAccessible(page, 'windows server, Remote Desktop after the deployments');
    });
  });
}
