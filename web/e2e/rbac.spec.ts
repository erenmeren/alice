import { apiAs, browserLocale, expect, firstSignIn, newCert, resetInstall, runWizard, signOut, test, translator, uiLang, type Account, type Api, type Lang } from './helpers';

// Roles on services (R53, scoped access phase 2) on the e2e stack: an Administrator puts a server and a certificate in
// Alpha and another pair in Bravo and gives a person the Operator role on Bravo only. The person signs in, sees Bravo's
// server and certificate and not Alpha's, gets "not found" for Alpha's certificate, adds a certificate (it lands in
// Bravo) and is refused a deployment to Alpha. A person without any role sees only the no-access page. The servers are
// never reached (.invalid hosts); visible texts come from the locale files.

const JOURNEY_TIMEOUT = 5 * 60_000;

async function json<T>(res: Awaited<ReturnType<Api['get']>>, status: number): Promise<T> {
  const text = await res.text();
  expect(res.status(), text).toBe(status);
  return JSON.parse(text) as T;
}

interface Placed { serviceId: string; targetId: string; certId: string }

// place adds a service, a server and a certificate and moves both into the service.
async function place(api: Api, service: string, server: string, cert: string): Promise<Placed> {
  const svc = await json<{ id: string }>(await api.post('/api/v1/services', { name: service }), 201);
  const target = await json<{ target: { id: string } }>(await api.post('/api/v1/targets', { name: server, type: 'linux', host: `${server}.invalid`, port: 22, username: 'alice-svc' }), 201);
  const pair = newCert(cert);
  const c = await json<{ certificate: { id: string } }>(await api.post('/api/v1/certificates/upload', { label: cert, certificate_pem: pair.cert, private_key_pem: pair.key }), 201);
  await json(await api.post(`/api/v1/services/${svc.id}/actions/assign`, {
    resources: [{ type: 'target', id: target.target.id }, { type: 'certificate', id: c.certificate.id }],
  }), 200);
  return { serviceId: svc.id, targetId: target.target.id, certId: c.certificate.id };
}

// person adds a person without a role on all services.
async function person(api: Api, account: Account): Promise<string> {
  const u = await json<{ id: string; role: string | null }>(await api.post('/api/v1/users', {
    username: account.username, display_name: account.fullName, email: '', role: null, password: account.password,
  }), 201);
  expect(u.role).toBeNull();
  return u.id;
}

for (const lang of ['en', 'tr'] as Lang[]) {
  test.describe(`Roles on services (${lang})`, () => {
    test.use({ locale: browserLocale(lang), actionTimeout: 30_000 });

    test('a person with the Operator role on one service sees only that service and is refused another', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);


      await resetInstall(request);
      const { totpSecret } = await runWizard(page, request, lang);
      const admin = await apiAs(page);
      await admin.stepUp(totpSecret);
      const alpha = await place(admin, 'Alpha', 'alpha-web', 'alpha.example.test');
      const bravo = await place(admin, 'Bravo', 'bravo-web', 'bravo.example.test');
      const olga: Account = { username: 'olga', fullName: 'Olga Operator', password: 'olga-correct-horse-2026' };
      const nora: Account = { username: 'nora', fullName: 'Nora Nobody', password: 'nora-correct-horse-2026' };
      const olgaID = await person(admin, olga);
      await person(admin, nora);
      await json(await admin.post('/api/v1/role-bindings', { user_id: olgaID, role: 'operator', service_id: bravo.serviceId }), 201);
      await page.reload(); // the step-up rotated the session: the page reads the new CSRF token
      await signOut(page);

      // The Operator of Bravo: Bravo's server and certificate, nothing of Alpha.
      await firstSignIn(page, request, olga);
      const t = translator(await uiLang(page)); // the person's own language
      await page.goto('/servers');
      const servers = page.getByTestId('targets-table');
      await expect(servers.getByRole('link', { name: 'bravo-web', exact: true })).toBeVisible();
      await expect(servers.getByRole('link', { name: 'alpha-web', exact: true })).toHaveCount(0);
      await page.goto('/certificates');
      const certs = page.getByRole('table', { name: t('certificates.title') });
      await expect(certs).toContainText('bravo.example.test');
      await expect(certs).not.toContainText('alpha.example.test');
      await page.goto(`/certificates/${alpha.certId}`);
      await expect(page.getByRole('alert').filter({ hasText: 'ALC-SYS-0001' })).toBeVisible(); // as if it did not exist
      await page.goto(`/certificates/${bravo.certId}`);
      await expect(page.getByRole('heading', { name: 'bravo.example.test' })).toBeVisible();

      // A certificate the Operator adds lands in Bravo, the only service they may add to; Alpha's are not theirs.
      const api = await apiAs(page);
      const pair = newCert('bravo-two.example.test');
      const added = await json<{ certificate: { service: { name: string } } }>(await api.post('/api/v1/certificates/upload', {
        label: 'bravo-two.example.test', certificate_pem: pair.cert, private_key_pem: pair.key }), 201);
      expect(added.certificate.service.name).toBe('Bravo');
      const refused = await json<{ error: { code: string } }>(await api.post('/api/v1/certificates/upload', {
        label: 'x', certificate_pem: pair.cert, private_key_pem: pair.key, service_id: alpha.serviceId }), 403);
      expect(refused.error.code).toBe('ALC-SVC-0006');
      const hidden = await json<{ error: { code: string } }>(await api.post(`/api/v1/certificates/${alpha.certId}/deploy`, { location_ids: [crypto.randomUUID()] }), 404);
      expect(hidden.error.code).toBe('ALC-SYS-0001');
      await signOut(page);

      // A person without any role: the no-access page only.
      await firstSignIn(page, request, nora);
      await expect(page.getByText(translator(await uiLang(page))('access.none.title'))).toBeVisible();
    });

    // R54 (scoped access phase 3): an Administrator creates an automation account on People & access, gives it the
    // Operator role on Bravo and a token limited to Bravo; the token lists Bravo's server only and is refused People &
    // access. The automation account is not among the people.
    test('an automation account with a token limited to one service sees only that service', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      await resetInstall(request);
      const { totpSecret } = await runWizard(page, request, lang);
      const admin = await apiAs(page);
      await admin.stepUp(totpSecret);
      await place(admin, 'Alpha', 'alpha-web', 'alpha.example.test');
      const bravo = await place(admin, 'Bravo', 'bravo-web', 'bravo.example.test');
      await page.reload(); // the step-up rotated the session: the page reads the new CSRF token
      const t = translator(await uiLang(page));

      await page.goto('/users?tab=automation');
      await page.getByRole('button', { name: t('automation.add') }).first().click();
      const dialog = page.getByRole('dialog');
      await dialog.getByLabel(t('users.fields.username')).fill('ci-deployer');
      await dialog.getByLabel(t('automation.fields.displayName')).fill('CI deployer');
      await dialog.getByRole('button', { name: t('automation.create') }).click();
      await expect(page.getByTestId('automation-table')).toContainText('ci-deployer');

      const api = await apiAs(page);
      const accounts = await json<{ items: { id: string; username: string }[] }>(await api.get('/api/v1/automation-accounts'), 200);
      const robot = accounts.items.find((a) => a.username === 'ci-deployer');
      expect(robot).toBeTruthy();
      await json(await api.post('/api/v1/role-bindings', { user_id: robot!.id, role: 'operator', service_id: bravo.serviceId }), 201);
      const made = await json<{ token: string }>(await api.post(`/api/v1/automation-accounts/${robot!.id}/tokens`, {
        name: 'pipeline', scope: 'operate', expires_in_days: 1, service_ids: [bravo.serviceId] }), 201);
      const bearer = { Authorization: `Bearer ${made.token}` };
      const listed = await json<{ items: { name: string }[] }>(await request.get('/api/v1/targets', { headers: bearer }), 200);
      expect(listed.items.map((x) => x.name)).toEqual(['bravo-web']);
      expect((await request.get('/api/v1/users', { headers: bearer })).status()).toBe(403);
      const people = await json<{ items: { username: string }[] }>(await api.get('/api/v1/users'), 200);
      expect(people.items.map((x) => x.username)).not.toContain('ci-deployer');
    });
  });
}
