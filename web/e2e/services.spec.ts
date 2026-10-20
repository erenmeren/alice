import type { APIRequestContext, Locator, Page } from '@playwright/test';
import { answerStepUp, apiAs, browserLocale, expect, expectAccessible, newCert, resetInstall, runWizard, test, translator, type Api, type Lang } from './helpers';

// Services and environments (R49) on the e2e stack: an Administrator adds a service in production, moves a server and its
// certificate there (each move checked first with a dry run), sees the service column and badge, and filters the lists
// by service and by environment. The server is never reached (an .invalid host); every visible text is read from the
// locale files at run time.

const SERVICE = 'Payments';
const SERVER = 'pay-web-1';
const CERT_NAME = 'pay.example.test';
const JOURNEY_TIMEOUT = 5 * 60_000;

async function json<T>(res: Awaited<ReturnType<Api['get']>>, status: number): Promise<T> {
  const text = await res.text();
  expect(res.status(), text).toBe(status);
  return JSON.parse(text) as T;
}

// seed adds the server and uploads its certificate through the API (both land in the Default service).
async function seed(api: Api): Promise<{ targetId: string; certId: string }> {
  const target = await json<{ id: string }>(await api.post('/api/v1/targets', { name: SERVER, type: 'linux', host: 'pay-web-1.invalid', port: 22, username: 'alice-svc' }), 201);
  const pair = newCert(CERT_NAME);
  const cert = await json<{ certificate: { id: string } }>(await api.post('/api/v1/certificates/upload', { label: CERT_NAME, certificate_pem: pair.cert, private_key_pem: pair.key }), 201);
  return { targetId: target.id, certId: cert.certificate.id };
}

// moveCheck runs the dry run of an open move dialog, then the move, answering a step-up when the window has passed.
async function moveCheck(page: Page, request: APIRequestContext, lang: Lang, secret: string, dialog: Locator, line: string): Promise<void> {
  const t = translator(lang);
  await dialog.getByRole('button', { name: t('services.move.check') }).click();
  const preview = dialog.getByTestId('move-preview');
  await answerStepUp(page, request, lang, secret, preview);
  await expect(preview).toContainText(line);
  await dialog.getByRole('button', { name: t('services.move.confirm'), exact: true }).click();
  await expect(dialog).toHaveCount(0);
}

for (const lang of ['en', 'tr'] as Lang[]) {
  test.describe(`Services and environments (${lang})`, () => {
    test.use({ locale: browserLocale(lang), actionTimeout: 30_000 });

    test('an Administrator adds a service in production, moves a server and its certificate there and filters by it', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const t = translator(lang);
      const production = t('services.environmentKeys.production');
      await resetInstall(request);
      const { totpSecret } = await runWizard(page, request, lang);
      const api = await apiAs(page);
      const { certId } = await seed(api);

      // The services page: the Default service owns everything so far.
      await page.goto('/services');
      await expect(page.getByRole('heading', { level: 1, name: t('services.title') })).toBeVisible();
      await expect(page.getByTestId('service-row')).toHaveCount(1);
      await expect(page.getByTestId('service-row')).toContainText(t('services.default'));

      // Add the service in production; the page of the new service opens.
      await page.getByRole('button', { name: t('services.add') }).click();
      const create = page.getByRole('dialog', { name: t('services.dialog.createTitle') });
      await create.getByLabel(t('services.fields.name')).fill(SERVICE);
      await create.getByLabel(t('services.fields.environment')).selectOption({ label: production });
      await create.getByRole('button', { name: t('services.dialog.create') }).click();
      const heading = page.getByRole('heading', { level: 1, name: SERVICE });
      await answerStepUp(page, request, lang, totpSecret, heading);
      await expect(page.getByTestId('policy-version')).toContainText(t('services.policyVersion', { version: 1 }));
      await expectAccessible(page, 'service overview');

      // Move the server here from the Resources tab.
      await page.getByRole('tab', { name: t('services.tabs.resources') }).click();
      await page.getByRole('button', { name: t('services.moveHere') }).click();
      const here = page.getByRole('dialog', { name: t('services.move.hereTitle', { name: SERVICE }) });
      await here.getByLabel(t('services.move.resource')).selectOption({ label: `${SERVER} (Default)` });
      await moveCheck(page, request, lang, totpSecret, here, t('services.move.line', { name: SERVER, from: 'Default', to: SERVICE }));
      await expect(page.getByRole('link', { name: SERVER, exact: true })).toBeVisible();

      // Move the certificate from its own page.
      await page.goto(`/certificates/${certId}`);
      await expect(page.getByTestId('service-badge')).toContainText('Default');
      await page.getByRole('button', { name: t('services.moveTo') }).click();
      const to = page.getByRole('dialog', { name: t('services.move.toTitle', { name: CERT_NAME }) });
      await to.getByLabel(t('services.move.destination')).selectOption({ label: SERVICE });
      await moveCheck(page, request, lang, totpSecret, to, t('services.move.line', { name: CERT_NAME, from: 'Default', to: SERVICE }));
      await expect(page.getByTestId('service-badge')).toContainText(SERVICE);
      await expect(page.getByTestId('service-badge')).toContainText(production);

      // The servers list shows the service column, and its filters keep the server or hide it.
      await page.goto('/servers');
      const servers = page.getByTestId('targets-table');
      const serverRow = servers.getByRole('row').filter({ has: page.getByRole('link', { name: SERVER, exact: true }) });
      await expect(serverRow.getByTestId('service-badge')).toContainText(SERVICE);
      await expect(serverRow.getByTestId('service-badge')).toContainText(production);
      await page.getByLabel(t('services.filter.environment')).selectOption({ label: production });
      await expect(serverRow).toBeVisible();
      await page.getByLabel(t('services.filter.service')).selectOption({ label: 'Default' });
      await expect(servers.getByRole('link', { name: SERVER, exact: true })).toHaveCount(0);
      await expect(servers).toContainText(t('services.filter.noMatch'));

      // The certificates list asks the server for one service.
      await page.goto('/certificates');
      const certs = page.getByRole('table', { name: t('certificates.title') });
      await expect(certs.getByTestId('service-badge')).toContainText(SERVICE);
      await page.getByLabel(t('services.filter.service')).selectOption({ label: SERVICE });
      await expect(page).toHaveURL(/service_id=/);
      await expect(certs.getByTestId('service-badge')).toHaveCount(1);
      await page.getByLabel(t('services.filter.service')).selectOption({ label: 'Default' });
      await expect(certs).toHaveCount(0);

      // The services page now counts what Payments owns.
      await page.goto('/services');
      const row = page.getByTestId('service-row').filter({ hasText: SERVICE });
      await expect(row).toContainText(production);
      await expect(row).toContainText(`${t('services.counts.servers', { count: 1 })}, ${t('services.counts.certificates', { count: 1 })}`);
      await expectAccessible(page, 'services list');
    });
  });
}
