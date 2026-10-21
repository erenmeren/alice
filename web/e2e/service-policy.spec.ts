import { answerStepUp, apiAs, browserLocale, expect, expectAccessible, newCert, resetInstall, runWizard, test, translator, type Lang } from './helpers';

// Service policy (R55) on the e2e stack: an Administrator adds a service, limits its names to one domain and forbids
// automatic deployment on the Policy tab, sees the new version in the history, and an upload into the service with a
// name outside the domain is refused (ALC-SVC-0008) while one inside is stored. Every visible text is read from the
// locale files at run time.

const SERVICE = 'Payments';
const JOURNEY_TIMEOUT = 5 * 60_000;

for (const lang of ['en', 'tr'] as Lang[]) {
  test.describe(`Service policy (${lang})`, () => {
    test.use({ locale: browserLocale(lang), actionTimeout: 30_000 });

    test('an Administrator limits a service to its domain and forbids automatic deployment; an upload outside it is refused', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const t = translator(lang);
      await resetInstall(request);
      const { totpSecret } = await runWizard(page, request, lang);

      await page.goto('/services');
      await page.getByRole('button', { name: t('services.add') }).click();
      const create = page.getByRole('dialog', { name: t('services.dialog.createTitle') });
      await create.getByLabel(t('services.fields.name')).fill(SERVICE);
      await create.getByRole('button', { name: t('services.dialog.create') }).click();
      const heading = page.getByRole('heading', { level: 1, name: SERVICE });
      await answerStepUp(page, request, lang, totpSecret, heading);
      const serviceId = new URL(page.url()).pathname.split('/').pop() ?? '';
      expect(serviceId).not.toBe('');

      // The Policy tab: the empty first version, then the domain and the hold.
      await page.getByRole('tab', { name: t('services.tabs.policy') }).click();
      const history = page.getByTestId('policy-history');
      await expect(history).toContainText(t('services.policyForm.history.first'));
      await page.getByTestId('policy-domains').fill('*.pay.example.test');
      await page.getByTestId('policy-auto-deploy').selectOption('forbidden');
      await page.getByTestId('policy-save').click();
      const saved = page.getByTestId('policy-saved');
      await answerStepUp(page, request, lang, totpSecret, saved);
      await expect(saved).toContainText(t('services.policyForm.saved', { version: 2 }));
      await expect(history.getByRole('row')).toHaveCount(3);
      await expect(history).toContainText(`${t('services.policyForm.keys.domains')}, ${t('services.policyForm.keys.deployment')}`);
      await expect(page.getByTestId('policy-domains')).toHaveValue('*.pay.example.test');
      await expectAccessible(page, 'service policy');

      // Uploads into the service: a name outside the domain is refused before anything is stored.
      const api = await apiAs(page);
      const outside = newCert('shop.example.test');
      const refused = await api.post('/api/v1/certificates/upload', { certificate_pem: outside.cert, private_key_pem: outside.key, service_id: serviceId });
      const body = await refused.text();
      expect(refused.status(), body).toBe(422);
      expect(JSON.parse(body).error.code).toBe('ALC-SVC-0008');
      const inside = newCert('api.pay.example.test');
      const stored = await api.post('/api/v1/certificates/upload', { certificate_pem: inside.cert, private_key_pem: inside.key, service_id: serviceId });
      expect(stored.status(), await stored.text()).toBe(201);
    });
  });
}
