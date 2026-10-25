import { answerStepUp, apiAs, browserLocale, expect, expectAccessible, newCert, resetInstall, runWizard, test, translator, type Lang } from './helpers';

// Hardening batch 1 (R64, D2, HB-07) on the e2e stack: an Administrator starts a key compromise incident for an uploaded
// certificate, finds it on the Incidents page from the navigation, filters the list, opens the incident, closes it and
// returns to the list by the back link, where the closed filter shows it closed. Every visible text is read from the
// locale files at run time.

const NAME = 'hb1-incident.example.test';
const JOURNEY_TIMEOUT = 5 * 60_000;

for (const lang of ['en', 'tr'] as Lang[]) {
  test.describe(`Incidents (${lang})`, () => {
    test.use({ locale: browserLocale(lang), actionTimeout: 30_000 });

    test('start an incident, find it on the Incidents page, filter, open and close it', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const t = translator(lang);
      await resetInstall(request);
      const { totpSecret } = await runWizard(page, request, lang);

      // An uploaded certificate with its key (Alice cannot revoke it: the incident waits for a replacement).
      const api = await apiAs(page);
      await api.stepUp(totpSecret);
      const pair = newCert(NAME);
      const stored = await api.post('/api/v1/certificates/upload', { certificate_pem: pair.cert, private_key_pem: pair.key });
      const body = await stored.text();
      expect(stored.status(), body).toBe(201);
      const certificateId: string = JSON.parse(body).certificate.id;

      // Start the incident from the certificate's page.
      await page.goto(`/certificates/${certificateId}`);
      await page.getByRole('button', { name: t('incidents.start.action') }).click();
      const dialog = page.getByRole('dialog', { name: t('incidents.start.title') });
      await dialog.getByLabel(t('incidents.start.understood')).check();
      await dialog.getByRole('button', { name: t('incidents.start.confirm') }).click();
      const incidentHeading = page.getByRole('heading', { level: 1, name: t('incidents.title') });
      await answerStepUp(page, request, lang, totpSecret, incidentHeading);

      // The Incidents page from the navigation: the incident, waiting for its replacement.
      await page.getByRole('navigation').getByRole('link', { name: t('nav.incidents'), exact: true }).click();
      await expect(page.getByRole('heading', { level: 1, name: t('incidents.list.title') })).toBeVisible();
      const table = page.getByRole('table', { name: t('incidents.list.tableLabel') });
      const row = table.getByRole('row').filter({ hasText: NAME });
      await expect(row).toHaveCount(1);
      await expect(row).toContainText(t('incidents.states.awaiting_replacement'));
      await expectAccessible(page, 'incidents-list');

      // The filter: nothing needs attention; the open filter shows it again.
      const filter = page.getByRole('radiogroup', { name: t('incidents.list.filterLabel') });
      await filter.getByText(t('incidents.list.filter.needs_attention'), { exact: true }).click();
      await expect(page.getByText(t('incidents.list.emptyFiltered'), { exact: true })).toBeVisible();
      await filter.getByText(t('incidents.list.filter.open'), { exact: true }).click();
      await expect(row).toHaveCount(1);

      // Open it and close it.
      await row.getByRole('link', { name: NAME }).click();
      await expect(incidentHeading).toBeVisible();
      await page.getByRole('button', { name: t('incidents.actions.close'), exact: true }).click();
      const confirm = page.getByRole('dialog', { name: t('incidents.close.title') });
      await confirm.getByRole('button', { name: t('incidents.close.confirm') }).click();
      const closedBadge = page.getByTestId('incident-state');
      await answerStepUp(page, request, lang, totpSecret, closedBadge.filter({ hasText: t('incidents.states.closed') }));

      // Back to the list by the back link; the closed filter shows it closed.
      await page.getByRole('main').getByRole('link', { name: t('nav.incidents'), exact: true }).click();
      await expect(page.getByRole('heading', { level: 1, name: t('incidents.list.title') })).toBeVisible();
      await filter.getByText(t('incidents.list.filter.closed'), { exact: true }).click();
      await expect(row).toHaveCount(1);
      await expect(row).toContainText(t('incidents.states.closed'));
    });
  });
}
