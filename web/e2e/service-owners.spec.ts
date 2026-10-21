import { answerStepUp, apiAs, browserLocale, expect, expectAccessible, resetInstall, runWizard, test, translator, type Api, type Lang } from './helpers';

// SR-29 (R56): service owners on the e2e stack. An Administrator adds a service, opens it and, on the Overview, names a
// person without any role as its owner. The person is listed with the warning that they receive the service's e-mails
// but cannot open it (ownership gives no access); the list is saved with a fresh code and is still there after a reload.
// Directory groups need an identity provider or a directory, so this journey names a person only. Every visible text is
// read from the locale files at run time.

const SERVICE = 'Payments';
const OWNER = { username: 'oya', fullName: 'Oya Owner', email: 'oya@example.test', password: 'oya-correct-horse-2026' };
const JOURNEY_TIMEOUT = 5 * 60_000;

async function json<T>(res: Awaited<ReturnType<Api['get']>>, status: number): Promise<T> {
  const text = await res.text();
  expect(res.status(), text).toBe(status);
  return JSON.parse(text) as T;
}

for (const lang of ['en', 'tr'] as Lang[]) {
  test.describe(`Service owners (${lang})`, () => {
    test.use({ locale: browserLocale(lang), actionTimeout: 30_000 });

    test('SR-29 (R56): an Administrator names a person without a role as owner and sees that they cannot open the service', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const t = translator(lang);
      await resetInstall(request);
      const { totpSecret } = await runWizard(page, request, lang);

      // A person with an address and no role anywhere.
      const admin = await apiAs(page);
      await admin.stepUp(totpSecret);
      const owner = await json<{ id: string }>(
        await admin.post('/api/v1/users', { username: OWNER.username, display_name: OWNER.fullName, email: OWNER.email, role: null, password: OWNER.password }),
        201,
      );
      await page.reload(); // the step-up rotated the session: the page reads the new CSRF token

      // The service and its page.
      await page.goto('/services');
      await page.getByRole('button', { name: t('services.add') }).click();
      const create = page.getByRole('dialog', { name: t('services.dialog.createTitle') });
      await create.getByLabel(t('services.fields.name')).fill(SERVICE);
      await create.getByRole('button', { name: t('services.dialog.create') }).click();
      const heading = page.getByRole('heading', { level: 1, name: SERVICE });
      await answerStepUp(page, request, lang, totpSecret, heading);
      const serviceId = new URL(page.url()).pathname.split('/').pop() ?? '';
      expect(serviceId).not.toBe('');

      // No owner yet: the e-mails go to the Administrators.
      const panel = page.getByTestId('service-owners');
      await expect(panel.getByTestId('service-owners-empty')).toHaveText(t('services.owners.empty'));

      // Name the person in the editor and save with a fresh code.
      await panel.getByRole('button', { name: t('services.owners.edit') }).click();
      const dialog = page.getByRole('dialog', { name: t('services.owners.dialogTitle', { name: SERVICE }) });
      await dialog.getByLabel(t('services.owners.person')).selectOption(owner.id);
      await dialog.getByRole('button', { name: t('services.owners.addPerson') }).click();
      await expect(dialog.getByTestId('owners-draft').getByTestId('owner-row')).toHaveCount(1);
      await dialog.getByTestId('owners-save').click();
      const row = panel.getByTestId('service-owners-table').getByTestId('owner-row');
      await answerStepUp(page, request, lang, totpSecret, row);
      await expect(dialog).toHaveCount(0);
      await expect(row).toHaveCount(1);
      await expect(row).toContainText(OWNER.fullName);
      await expect(row.getByTestId('owner-no-reach')).toHaveText(t('services.owners.noReach'));
      await expectAccessible(page, 'service owners');

      // Saved: the owner is still there after a reload, and the API says the same.
      await page.reload();
      await expect(row).toHaveCount(1);
      await expect(row).toContainText(OWNER.fullName);
      await expect(row.getByTestId('owner-no-reach')).toHaveText(t('services.owners.noReach'));
      const api = await apiAs(page);
      const saved = await json<{ items: { user_id: string | null; receives_email: boolean; reaches_service?: boolean }[] }>(await api.get(`/api/v1/services/${serviceId}/owners`), 200);
      expect(saved.items).toEqual([expect.objectContaining({ user_id: owner.id, receives_email: true, reaches_service: false })]);
    });
  });
}
