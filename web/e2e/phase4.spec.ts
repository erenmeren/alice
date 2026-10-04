import type { APIRequestContext, APIResponse, Locator, Page } from '@playwright/test';
import {
  ADMIN,
  COPY,
  advanceClock,
  apiAs,
  browserLocale,
  configMode,
  drainJobs,
  expect,
  expectAccessible,
  expectWide,
  field,
  fingerprintHex,
  fingerprintOf,
  firstSignIn,
  freshCode,
  newCert,
  nginxReset,
  reloadMode,
  resetInstall,
  runScheduled,
  runWizard,
  served,
  settle,
  signIn,
  signOut,
  signRequest,
  targetExec,
  test,
  testMode,
  translator,
  type Account,
  type Api,
  type Lang,
  type PemPair,
  type Translate,
  uiLang,
} from './helpers';

// Phase 4 owner journeys on the e2e stack: the SSH target runs a real Nginx with the websites of
// test/images/e2e-target/nginx-www.conf. Every visible text is read from the locale files at run
// time (translator), so the journeys follow the copy of the app instead of repeating it.

const HOST_KEY_PUB = '/etc/ssh/ssh_host_ed25519_key.pub';
const WWW = 'www.example.test';
const FILES = 'files.example.test';
const SITES = [1, 2, 3, 4, 5].map((n) => `s${n}.example.test`);
const SERVER = 'e2e-nginx';
const DAY_SECONDS = 24 * 3600;
// The first recovery of an interrupted deployment waits 30 s (deployjobs FirstRecovery).
const FIRST_RECOVERY_SECONDS = 31;
const LANGUAGE_NAMES: Record<Lang, string> = { en: 'English', tr: 'Türkçe' };
const OPERATOR: Account = { username: 'olcay', fullName: 'Olcay Öztürk', password: 'operator-password-2026' };
const AUDITOR: Account = { username: 'deniz', fullName: 'Deniz Aksoy', password: 'auditor-password-2026' };

// A Phase 4 journey prepares, discovers and deploys several times: more than the default 3 minutes.
const JOURNEY_TIMEOUT = 8 * 60_000;

async function json<T>(res: APIResponse, status?: number): Promise<T> {
  const text = await res.text();
  if (status !== undefined) expect(res.status(), text).toBe(status);
  else expect(res.ok(), `${res.status()} ${text}`).toBe(true);
  return (text ? JSON.parse(text) : {}) as T;
}

// expectNginxSudoers proves the target got the nginx profile: its sudoers allow the deploy subcommand.
function expectNginxSudoers(): void {
  const lines = Number(targetExec(['sh', '-c', 'cat /etc/sudoers.d/* | grep -c "alice-helper nginx-deploy" || true']).trim());
  expect(lines, 'nginx-deploy in the sudoers of the target (nginx profile installed)').toBeGreaterThan(0);
}

async function chooseLanguage(page: Page, lang: Lang): Promise<void> {
  if ((await uiLang(page)) === lang) return;
  await page.getByText(LANGUAGE_NAMES[lang], { exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('lang', lang);
}

async function nav(page: Page, t: Translate, key: string): Promise<void> {
  await page.getByRole('link', { name: t(key), exact: true }).click();
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
}

// answerStepUp confirms a step-up dialog with a fresh code if the server asks for one before done appears.
async function answerStepUp(page: Page, request: APIRequestContext, lang: Lang, secret: string, done: Locator): Promise<void> {
  const c = COPY[lang];
  const stepUp = page.getByRole('dialog', { name: c.stepUpHeading });
  await expect(stepUp.or(done).first()).toBeVisible();
  if (await stepUp.isVisible()) {
    await field(stepUp, c.code).fill(await freshCode(request, secret));
    await stepUp.getByRole('button', { name: c.stepUpConfirm }).click();
  }
  await expect(done).toBeVisible();
}

// prepareAndAddInUI is owner steps 1–2 for an Nginx server, as a person does it: the nginx
// profile's commands from the Servers page run on the target, then Add server with the type Nginx
// server and the fingerprint compared with the one the server shows. It returns the server's id.
async function prepareAndAddInUI(page: Page, request: APIRequestContext, t: Translate): Promise<string> {
  await nav(page, t, 'nav.servers');
  await field(page, t('targets.prepare.profile')).selectOption('nginx');
  const script = (await page.getByTestId('setup-script').textContent()) ?? '';
  expect(script).toContain('nginx-deploy');
  await expect(page.getByRole('button', { name: t('targets.prepare.copy') })).toBeVisible();
  targetExec(['/usr/local/sbin/alice-e2e-prepare'], script);
  expectNginxSudoers();

  await page.getByRole('button', { name: t('targets.add') }).click();
  const dialog = page.getByRole('dialog', { name: t('targets.add') });
  await field(dialog, t('targets.form.type')).selectOption('nginx');
  await expect(dialog.getByTestId('add-server-script')).toHaveText(script);
  await expectAccessible(page, 'add server form, Nginx server');
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
  await expect(page.getByText(t('targets.typeLabel.nginx'), { exact: true })).toBeVisible();
  return new URL(page.url()).pathname.split('/').pop() ?? '';
}

interface Target {
  id: string;
}

// prepareAndAddByApi does the same through the API for the journeys that start later: the REAL
// nginx profile script (GET /ssh-keys/platform-key) prepares the target, the server is added and
// its fingerprint confirmed after comparing it with the server's own, and the websites are read.
async function prepareAndAddByApi(api: Api, request: APIRequestContext): Promise<string> {
  const key = await json<{ profiles: { nginx: { script: string } } }>(await api.get('/api/v1/ssh-keys/platform-key'));
  targetExec(['/usr/local/sbin/alice-e2e-prepare'], key.profiles.nginx.script);
  expectNginxSudoers();
  const created = await json<{ target: Target }>(
    await api.post('/api/v1/targets', { type: 'nginx', name: SERVER, host: 'sshtarget', port: 22, username: 'alice-svc' }),
    201,
  );
  const id = created.target.id;
  const onServer = fingerprintOf(targetExec(['ssh-keygen', '-lf', HOST_KEY_PUB]));
  let hostKey: { id: string; fingerprint: string } | undefined;
  await expect(async () => {
    await drainJobs(request);
    const keys = await json<{ items: { id: string; status: string; fingerprint: string }[] }>(await api.get(`/api/v1/targets/${id}/host-keys`));
    hostKey = keys.items.find((k) => k.status === 'observed' && k.fingerprint === onServer);
    expect(hostKey).toBeDefined();
  }).toPass({ timeout: 90_000 });
  await json(await api.post(`/api/v1/targets/${id}/host-keys/${hostKey!.id}/actions/confirm`, { fingerprint: hostKey!.fingerprint }), 202);
  await expect(async () => {
    await drainJobs(request);
    const locs = await json<{ items: { servers: { names: string[] }[] }[] }>(await api.get(`/api/v1/targets/${id}/certificate-locations`));
    expect(locs.items.flatMap((l) => l.servers.flatMap((s) => s.names))).toEqual(expect.arrayContaining([WWW, FILES, ...SITES]));
  }).toPass({ timeout: 90_000 });
  return id;
}

async function uploadByApi(api: Api, pair: PemPair, label: string): Promise<string> {
  const res = await json<{ certificate: { id: string } }>(
    await api.post('/api/v1/certificates/upload', { label, certificate_pem: pair.cert, private_key_pem: pair.key }),
    201,
  );
  return res.certificate.id;
}

async function locationIds(api: Api, targetId: string): Promise<Record<string, string>> {
  const locs = await json<{ items: { id: string; servers: { names: string[] }[] }[] }>(await api.get(`/api/v1/targets/${targetId}/certificate-locations`));
  const out: Record<string, string> = {};
  for (const l of locs.items) for (const s of l.servers) for (const n of s.names) out[n] = l.id;
  return out;
}

// openUpload opens Certificates → Upload certificate and fills the PEM form.
async function openUpload(page: Page, t: Translate, pair: PemPair, label: string): Promise<Locator> {
  await nav(page, t, 'nav.certificates');
  await page.getByRole('button', { name: t('certificates.uploadButton') }).click();
  const dialog = page.getByRole('dialog', { name: t('certificates.upload.title') });
  await field(dialog, t('certificates.upload.certificate')).fill(pair.cert);
  await field(dialog, t('certificates.upload.privateKey')).fill(pair.key);
  await field(dialog, t('certificates.upload.label')).fill(label);
  return dialog;
}

// uploadInUI uploads a good pair, checks the result view and closes it; the app then opens the new
// certificate's page.
async function uploadInUI(page: Page, t: Translate, pair: PemPair, label: string, a11y = false): Promise<void> {
  const dialog = await openUpload(page, t, pair, label);
  if (a11y) await expectAccessible(page, 'upload dialog');
  await dialog.getByRole('button', { name: t('certificates.upload.submit') }).click();
  await expect(dialog.getByText(t('certificates.upload.uploaded'))).toBeVisible();
  await expect(dialog.getByText(t('certificates.upload.chainWarning'))).toHaveCount(0);
  if (a11y) await expectAccessible(page, 'upload dialog, certificate uploaded');
  await dialog.getByRole('button', { name: t('ui.close') }).last().click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole('heading', { level: 1, name: label })).toBeVisible();
}

function websites(page: Page, t: Translate): Locator {
  return page.getByRole('table', { name: t('locations.tableLabel') });
}

function websiteRow(page: Page, t: Translate, site: string): Locator {
  return websites(page, t).getByTestId('location-row').filter({ has: page.locator('code', { hasText: new RegExp(`^${site.replace(/\./g, '\\.')}$`) }) });
}

// openDeployFromWebsite opens "Deploy certificate: site" on the server's page and picks the
// certificate named label.
async function openDeployFromWebsite(page: Page, t: Translate, site: string, label: string): Promise<Locator> {
  await page.getByRole('button', { name: t('locations.deployNamed', { site }) }).click();
  const dialog = page.getByRole('dialog', { name: t('deploy.title') });
  const select = field(dialog, t('deploy.certificate'));
  const value = await select.locator('option', { hasText: label }).getAttribute('value');
  expect(value, `certificate ${label} offered`).toBeTruthy();
  await select.selectOption(value!);
  return dialog;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// openDeployment opens a deployment from the history by its certificate's name ("Open deployment:
// <certificate>, <time>").
async function openDeployment(page: Page, t: Translate, certificate: string): Promise<void> {
  const name = new RegExp(`^${escapeRegExp(t('deployments.openNamed', { name: `${certificate}, ` }))}`);
  await page.getByTestId('deployment-row').getByRole('link', { name }).click();
  await expect(page.getByRole('heading', { level: 1, name: t('deployments.detailTitle') })).toBeVisible();
}

function steps(scope: Locator, t: Translate): Locator {
  return scope.getByRole('list', { name: t('deployments.stepsTitle') });
}

// expectStep checks one step row: its status attribute and the status word shown to the person.
async function expectStep(scope: Locator, t: Translate, step: string, status: 'ok' | 'failed' | 'notRun'): Promise<void> {
  const row = steps(scope, t).locator(`li[data-step="${step}"]`);
  await expect(row).toHaveAttribute('data-status', status);
  await expect(row).toContainText(t(`deployments.steps.${step}`));
  await expect(row.locator('[data-role="step-status"]')).toHaveText(t(status === 'notRun' ? 'deployments.stepStatus.notRun' : `deployments.stepStatus.${status}`));
}

async function closeDeployDialog(dialog: Locator, t: Translate): Promise<void> {
  // The footer button and the dialog's X are both named Close: the footer one is last.
  await dialog.getByRole('button', { name: t('deploy.close') }).last().click();
  await expect(dialog).toHaveCount(0);
}

async function openAuditLog(page: Page, lang: Lang): Promise<void> {
  const c = COPY[lang];
  await page.getByRole('link', { name: c.navAudit, exact: true }).click();
  await expect(page.getByRole('heading', { name: c.auditHeading })).toBeVisible();
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const t = translator(lang);

  test.describe(`Phase 4 certificates and Nginx (${lang})`, () => {
    test.use({ locale: browserLocale(lang) });
    test.beforeEach(async ({ request }) => {
      nginxReset();
      await resetInstall(request);
    });
    test.afterEach(() => {
      nginxReset();
    });

    test('owner journey: discover, upload, deploy, verify, broken pair, rollbacks, history, audit', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      await runWizard(page, request, lang);
      const targetId = await prepareAndAddInUI(page, request, t);

      // Discover: the websites with their state; the one with a variable path is not supported, says
      // why and offers no Deploy.
      await page.getByRole('button', { name: t('locations.discover'), exact: true }).click();
      await settle(request, page.getByText(t('targets.jobDone')));
      const www = websiteRow(page, t, WWW);
      await expect(www).toContainText(t('locations.ready'));
      await expect(www).toContainText(/\d+ (days|gün)/);
      const files = websiteRow(page, t, FILES);
      await expect(files).toContainText(t('locations.notSupported'));
      await expect(files).toContainText(t('locations.unsupported.variable'));
      await expect(page.getByRole('button', { name: t('locations.deployNamed', { site: FILES }) })).toHaveCount(0);
      await expect(page.getByRole('button', { name: t('locations.deployNamed', { site: WWW }) })).toBeEnabled();
      await expectWide(page, 'Nginx server with its websites');
      const original = served(WWW);

      // Owner step 2–3: a renewed certificate is uploaded; from its page the hint leads to the website.
      const renewed = newCert(WWW);
      await uploadInUI(page, t, renewed, 'renewal-1', true);
      await expect(page.getByText(t('certificates.keyHeld'), { exact: true })).toBeVisible();
      await expectAccessible(page, 'certificate page before its first deployment');
      await page.getByTestId('deploy-hint').getByRole('link', { name: t('certificates.detail.openServers') }).click();
      await page.getByRole('link', { name: SERVER, exact: true }).click();
      await expect(page.getByRole('heading', { level: 1, name: SERVER })).toBeVisible();
      const dialog = await openDeployFromWebsite(page, t, WWW, 'renewal-1');
      await expectAccessible(page, 'deploy dialog');
      await dialog.getByRole('button', { name: t('deploy.submit'), exact: true }).click();
      await settle(request, dialog.getByText(t('deploy.succeeded')));
      for (const step of ['backup', 'write', 'config_test', 'reload', 'verify']) await expectStep(dialog, t, step, 'ok');
      await expectAccessible(page, 'deploy dialog, live and verified');
      expect(served(WWW), 'the target serves the uploaded certificate').toBe(fingerprintHex(renewed.cert));
      expect(served(WWW)).not.toBe(original);
      await closeDeployDialog(dialog, t);
      await expect(websiteRow(page, t, WWW).getByRole('link', { name: 'renewal-1' })).toBeVisible();

      // Owner step 4: a certificate with the key of another one is refused at upload; nothing changes.
      const broken = await openUpload(page, t, newCert(WWW, true), 'broken-pair');
      await broken.getByRole('button', { name: t('certificates.upload.submit') }).click();
      await expect(broken.getByRole('alert')).toContainText(t('errors.certificate.key_mismatch.title'));
      await expectAccessible(page, 'upload dialog with the key mismatch');
      await broken.getByRole('button', { name: t('certificates.cancel') }).click();
      expect(served(WWW)).toBe(fingerprintHex(renewed.cert));

      // Automatic rollback after a failed reload (the e2e substitute for F-01): the previous files are back.
      const second = newCert(WWW);
      await uploadInUI(page, t, second, 'renewal-2');
      await page.goto(`/servers/${targetId}`);
      const reloadDialog = await openDeployFromWebsite(page, t, WWW, 'renewal-2');
      await reloadDialog.getByRole('button', { name: t('deploy.submit'), exact: true }).click();
      reloadMode('fail-once');
      await settle(request, reloadDialog.getByText(t('deploy.rolledBack')));
      await expect(reloadDialog.getByRole('alert')).toContainText(t('errors.deployment.reload_failed.title'));
      await expectStep(reloadDialog, t, 'reload', 'failed');
      await expectStep(reloadDialog, t, 'restore', 'ok');
      await expectAccessible(page, 'deploy dialog, restored after a failed reload');
      expect(served(WWW), 'the previous certificate is served again').toBe(fingerprintHex(renewed.cert));
      await closeDeployDialog(reloadDialog, t);

      // nginx -t fails after the write: restored as well, with the configuration test as the reason.
      const third = newCert(WWW);
      await uploadInUI(page, t, third, 'renewal-3');
      await page.goto(`/servers/${targetId}`);
      const testDialog = await openDeployFromWebsite(page, t, WWW, 'renewal-3');
      await testDialog.getByRole('button', { name: t('deploy.submit'), exact: true }).click();
      testMode('fail-once');
      await settle(request, testDialog.getByText(t('deploy.rolledBack')));
      await expect(testDialog.getByRole('alert')).toContainText(t('errors.deployment.config_test_failed.title'));
      await expectStep(testDialog, t, 'config_test', 'failed');
      await expectStep(testDialog, t, 'reload', 'notRun');
      expect(served(WWW), 'the previous certificate is served again').toBe(fingerprintHex(renewed.cert));
      await closeDeployDialog(testDialog, t);

      // Owner step 5: the history lists the three deployments (the broken pair never became one).
      await nav(page, t, 'nav.deployments');
      const rows = page.getByRole('table', { name: t('deployments.tableLabel') }).getByTestId('deployment-row');
      await expect(rows).toHaveCount(3);
      await expect(rows.filter({ hasText: t('enum.deploymentStatus.succeeded') })).toHaveCount(1);
      await expect(rows.filter({ hasText: t('enum.deploymentStatus.rolled_back') })).toHaveCount(2);
      await expectWide(page, 'deployment history');
      await openDeployment(page, t, 'renewal-2');
      await expect(page.getByTestId('deployment-status')).toHaveText(t('enum.deploymentStatus.rolled_back'));
      const detailSteps = page.getByRole('main');
      await expectStep(detailSteps, t, 'restore', 'ok');
      await expectStep(detailSteps, t, 'verify_old', 'ok');
      await expect(page.getByText(t('deploy.rolledBack'))).toBeVisible();
      await expectAccessible(page, 'deployment page, restored');

      // The audit log tells the story.
      await openAuditLog(page, lang);
      for (const action of [
        'certificate_uploaded',
        'certificate_upload_rejected',
        'deployment_requested',
        'deployment_succeeded',
        'deployment_rolled_back',
      ]) {
        await expect(page.getByText(t(`audit.actions.${action}`), { exact: true }).first(), action).toBeVisible();
      }
    });

    test('an interrupted deployment is confirmed by the recovery sweep', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const { totpSecret } = await runWizard(page, request, lang);
      const api = await apiAs(page);
      await api.stepUp(totpSecret);
      const targetId = await prepareAndAddByApi(api, request);
      const pair = newCert(WWW);
      await uploadByApi(api, pair, 'interrupted');
      await page.goto(`/servers/${targetId}`);
      const dialog = await openDeployFromWebsite(page, t, WWW, 'interrupted');
      await dialog.getByRole('button', { name: t('deploy.submit'), exact: true }).click();
      // The connection drops right before the reload: Alice never reads the helper's answer.
      reloadMode('drop-once');
      await settle(request, dialog.getByText(t('deploy.recovering')));
      await expectAccessible(page, 'deploy dialog, outcome being confirmed');
      await dialog.getByRole('link', { name: t('deploy.openDeployment') }).click();
      await expect(page.getByTestId('deployment-state')).toHaveText(t('enum.deploymentState.recovering'));
      const recovery = page.getByTestId('recovery');
      await expect(recovery).toContainText(t('deployments.recovery.running'));
      await expect(recovery).toContainText(t('deployments.recovery.next', { time: '' }).trim());
      await expectAccessible(page, 'deployment page, outcome being confirmed');

      // Past the first-recovery delay the sweep queues the recovery, which reads the server's journal.
      await advanceClock(request, FIRST_RECOVERY_SECONDS);
      await runScheduled(request, 'deployment.recovery_sweep');
      await settle(request, page.getByTestId('deployment-state').filter({ hasText: t('enum.deploymentState.done') }));
      await expect(page.getByTestId('deployment-status')).toHaveText(t('enum.deploymentStatus.succeeded'));
      await expect(recovery).toContainText(t('deployments.recovery.confirmed', { count: 1 }));
      await expectAccessible(page, 'deployment page, confirmed after recovery');
      expect(served(WWW), 'the recovered deployment left the new certificate live').toBe(fingerprintHex(pair.cert));
    });

    test('signing request: create, show again, complete with differing names, deploy', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const { totpSecret } = await runWizard(page, request, lang);
      const api = await apiAs(page);
      await api.stepUp(totpSecret);
      const targetId = await prepareAndAddByApi(api, request);
      await page.reload();

      await nav(page, t, 'nav.certificates');
      await page.getByRole('button', { name: t('certificates.createRequest') }).click();
      const create = page.getByRole('dialog', { name: t('certificates.csr.title') });
      await field(create, t('certificates.csr.commonName')).fill(WWW);
      await expectAccessible(page, 'signing request dialog');
      await create.getByRole('button', { name: t('certificates.csr.submit') }).click();
      await expect(create.getByText(t('certificates.csr.created'))).toBeVisible();
      const csr = await field(create, t('certificates.csr.pem')).inputValue();
      expect(csr).toContain('CERTIFICATE REQUEST');
      await expectAccessible(page, 'signing request dialog, request created');
      await create.getByRole('button', { name: t('ui.close') }).last().click();

      const pending = page.getByTestId('pending-csrs');
      await pending.getByRole('button', { name: `${t('certificates.csr.viewPem')} ${WWW}` }).click();
      const show = page.getByRole('dialog', { name: t('certificates.csr.pem') });
      await expect(field(show, t('certificates.csr.pem'))).toHaveValue(csr);
      await expectAccessible(page, 'signing request shown again');
      await show.getByRole('button', { name: t('ui.close') }).last().click();

      // The CA returns a certificate for another name than the one requested: Alice says so before
      // it leaves the dialog.
      const signed = signRequest(csr, 'other.example.test');
      await pending.getByRole('button', { name: `${t('certificates.csr.complete')} ${WWW}` }).click();
      const complete = page.getByRole('dialog', { name: t('certificates.csr.completeTitle') });
      await field(complete, t('certificates.csr.certificatePem')).fill(signed);
      await expectAccessible(page, 'add signed certificate dialog');
      await complete.getByRole('button', { name: t('certificates.csr.completeSubmit') }).click();
      await expect(complete.getByText(t('certificates.csr.completed'))).toBeVisible();
      await expect(complete.getByText(t('certificates.upload.nameMismatchWarning'))).toBeVisible();
      await expect(page).toHaveURL(/\/certificates$/);
      await expectAccessible(page, 'add signed certificate dialog, names differ');
      await complete.getByRole('button', { name: t('ui.close') }).last().click();
      await expect(page).toHaveURL(/\/certificates\/[0-9a-f-]+$/);
      await expect(page.getByText(t('certificates.keyHeld'), { exact: true })).toBeVisible();

      await page.goto(`/servers/${targetId}`);
      const dialog = await openDeployFromWebsite(page, t, WWW, WWW);
      await dialog.getByRole('button', { name: t('deploy.submit'), exact: true }).click();
      await settle(request, dialog.getByText(t('deploy.succeeded')));
      await expect(dialog.getByText(t('locations.warnings.san_mismatch', { site: WWW }))).toBeVisible();
      expect(served(WWW), 'the certificate of the signing request is served').toBe(fingerprintHex(signed));
    });

    test('a deployment to five websites at once is followed without being throttled', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const { totpSecret } = await runWizard(page, request, lang);
      const api = await apiAs(page);
      await api.stepUp(totpSecret);
      const targetId = await prepareAndAddByApi(api, request);
      // One certificate for the five websites, first put in place through the API.
      const pair = newCert(SITES.join(','));
      const certId = await uploadByApi(api, pair, 'five-sites');
      const ids = await locationIds(api, targetId);
      const first = await json<{ deployments: { id: string }[] }>(
        await api.post(`/api/v1/certificates/${certId}/deploy`, { location_ids: SITES.map((s) => ids[s]) }),
        202,
      );
      expect(first.deployments).toHaveLength(SITES.length);
      await expect(async () => {
        await drainJobs(request);
        for (const d of first.deployments) {
          expect((await json<{ status: string }>(await api.get(`/api/v1/deployments/${d.id}`))).status).toBe('succeeded');
        }
      }).toPass({ timeout: 120_000 });
      for (const s of SITES) expect(served(s), s).toBe(fingerprintHex(pair.cert));

      // From the certificate's page: deploy it again to its five websites in one request.
      const throttled: string[] = [];
      page.on('response', (r) => {
        if (r.status() === 429) throttled.push(r.url());
      });
      await page.goto(`/certificates/${certId}`);
      await expect(page.getByRole('table', { name: t('certificates.detail.usedWhere') }).getByRole('row')).toHaveCount(SITES.length + 1);
      await page.getByRole('button', { name: t('certificates.detail.deploy'), exact: true }).click();
      const dialog = page.getByRole('dialog', { name: t('deploy.title') });
      const choices = dialog.getByRole('group', { name: t('deploy.websites') }).getByRole('checkbox');
      await expect(choices).toHaveCount(SITES.length);
      for (const box of await choices.all()) await box.check();
      await expectAccessible(page, 'deploy dialog with five websites');
      await dialog.getByRole('button', { name: t('deploy.submit'), exact: true }).click();
      const runs = dialog.getByTestId('deployment-run');
      await settle(request, dialog.getByText(t('deploy.partial', { ok: 0, total: SITES.length })));
      await expect(runs).toHaveCount(SITES.length);
      await expect(runs.filter({ hasText: t('deploy.unchanged') })).toHaveCount(SITES.length);
      await expectAccessible(page, 'deploy dialog, five websites finished');
      expect(throttled, 'no request was answered 429').toEqual([]);
      for (const s of SITES) expect(served(s), s).toBe(fingerprintHex(pair.cert));
    });

    test('roles: an Administrator sets verification, an Operator deploys, an Auditor only reads', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const { totpSecret } = await runWizard(page, request, lang);
      const api = await apiAs(page);
      await api.stepUp(totpSecret);
      const targetId = await prepareAndAddByApi(api, request);
      // A Linux server keeps its own label and its SSH key scan.
      const linux = await json<{ target: Target }>(
        await api.post('/api/v1/targets', { type: 'linux', name: 'linux-box', host: 'linux-box.invalid', port: 22, username: 'alice-svc' }),
        201,
      );
      for (const [account, role] of [
        [OPERATOR, 'operator'],
        [AUDITOR, 'auditor'],
      ] as const) {
        const res = await api.post('/api/v1/users', { username: account.username, display_name: account.fullName, email: '', role, password: account.password });
        expect(res.status(), await res.text()).toBe(201);
      }
      await page.reload();

      await page.goto(`/servers/${linux.target.id}`);
      await expect(page.getByText(t('targets.typeLabel.linux'), { exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: t('targets.discover'), exact: true })).toBeVisible();
      await expect(page.getByRole('region', { name: t('locations.title') })).toHaveCount(0);

      // Administrator: verification settings of a website.
      await page.goto(`/servers/${targetId}`);
      await expect(page.getByText(t('targets.typeLabel.nginx'), { exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: t('locations.discover'), exact: true })).toBeVisible();
      await page.getByRole('button', { name: t('locations.settingsNamed', { site: WWW }) }).click();
      const settings = page.getByRole('dialog', { name: t('locations.verify.title') });
      await field(settings, t('locations.verify.port')).fill('443');
      await field(settings, t('locations.verify.sni')).fill(WWW);
      await expectAccessible(page, 'verification settings');
      await settings.getByRole('button', { name: t('locations.verify.save') }).click();
      await answerStepUp(page, request, lang, totpSecret, settings.getByText(t('locations.verify.saved')));
      await expectAccessible(page, 'verification settings saved');
      await page.keyboard.press('Escape');
      await expect(settings).toHaveCount(0);
      await openAuditLog(page, lang);
      await expect(page.getByText(t('audit.actions.location_updated'), { exact: true }).first()).toBeVisible();
      await signOut(page);

      // Operator: deploys, and sees the verification settings without changing them.
      await firstSignIn(page, request, OPERATOR);
      await chooseLanguage(page, lang);
      const pair = newCert(WWW);
      await uploadInUI(page, t, pair, 'operator-renewal');
      await page.goto(`/servers/${targetId}`);
      await page.getByRole('button', { name: t('locations.settingsNamed', { site: WWW }) }).click();
      const readOnly = page.getByRole('dialog', { name: t('locations.verify.title') });
      await expect(readOnly.getByText(t('locations.verify.readOnly'))).toBeVisible();
      await expect(field(readOnly, t('locations.verify.port'))).toHaveValue('443');
      await expect(readOnly.getByRole('button', { name: t('locations.verify.save') })).toHaveCount(0);
      await expectAccessible(page, 'verification settings, read-only');
      await readOnly.getByRole('button', { name: t('locations.verify.close') }).last().click();
      const dialog = await openDeployFromWebsite(page, t, WWW, 'operator-renewal');
      await dialog.getByRole('button', { name: t('deploy.submit'), exact: true }).click();
      await settle(request, dialog.getByText(t('deploy.succeeded')));
      expect(served(WWW)).toBe(fingerprintHex(pair.cert));
      await closeDeployDialog(dialog, t);
      await signOut(page);

      // Auditor: reads certificates, the server, the history and a deployment; changes nothing.
      await firstSignIn(page, request, AUDITOR);
      await chooseLanguage(page, lang);
      await nav(page, t, 'nav.certificates');
      await expect(page.getByTestId('certificates-table')).toBeVisible();
      await expect(page.getByRole('button', { name: t('certificates.uploadButton') })).toHaveCount(0);
      await expect(page.getByRole('button', { name: t('certificates.createRequest') })).toHaveCount(0);
      await page.getByTestId('certificates-table').getByRole('link', { name: 'operator-renewal' }).click();
      await expect(page.getByRole('heading', { level: 1, name: 'operator-renewal' })).toBeVisible();
      await expect(page.getByRole('button', { name: t('certificates.detail.deploy'), exact: true })).toHaveCount(0);
      await page.goto(`/servers/${targetId}`);
      await expect(websiteRow(page, t, WWW)).toContainText('operator-renewal');
      await expect(page.getByRole('button', { name: t('locations.deployNamed', { site: WWW }) })).toHaveCount(0);
      await expect(page.getByRole('button', { name: t('locations.discover'), exact: true })).toHaveCount(0);
      await nav(page, t, 'nav.deployments');
      const rows = page.getByTestId('deployment-row');
      await expect(rows).toHaveCount(1);
      await openDeployment(page, t, 'operator-renewal');
      await expect(page.getByTestId('deployment-status')).toHaveText(t('enum.deploymentStatus.succeeded'));
      await expectAccessible(page, 'deployment page for an Auditor');
    });

    test('an invalid Nginx configuration keeps the websites as of the last scan and stops deploying', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const { totpSecret } = await runWizard(page, request, lang);
      const api = await apiAs(page);
      await api.stepUp(totpSecret);
      const targetId = await prepareAndAddByApi(api, request);
      await page.goto(`/servers/${targetId}`);
      await expect(websiteRow(page, t, WWW)).toBeVisible();
      configMode('broken');
      await page.getByRole('button', { name: t('locations.discover'), exact: true }).click();
      await settle(request, page.getByTestId('config-invalid'));
      const stale = page.getByTestId('stale-websites');
      await expect(stale).toContainText(t('locations.stale.title'));
      await expect(stale).toContainText(t('locations.stale.help', { time: 'TIME' }).split('TIME')[0]);
      await expect(stale).toContainText(t('locations.deployUnavailable'));
      await expect(websiteRow(page, t, WWW)).toContainText(t('locations.ready'));
      await expect(page.getByRole('button', { name: t('locations.deployNamed', { site: WWW }) })).toBeDisabled();
      await expectWide(page, 'Nginx server with an invalid configuration');
      // After a reload the facts still say so.
      await page.reload();
      await expect(page.getByTestId('config-invalid')).toBeVisible();
      await expect(page.getByRole('button', { name: t('locations.deployNamed', { site: WWW }) })).toBeDisabled();
    });

    test('a locked license holds a queued deployment, refuses new ones and keeps everything readable (L-29)', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const { totpSecret } = await runWizard(page, request, lang);
      const api = await apiAs(page);
      await api.stepUp(totpSecret);
      const targetId = await prepareAndAddByApi(api, request);
      await uploadByApi(api, newCert(WWW), 'queued');
      await uploadByApi(api, newCert(SITES[0]), 'refused');
      const before = served(WWW);
      await page.goto(`/servers/${targetId}`);
      const dialog = await openDeployFromWebsite(page, t, WWW, 'queued');
      await dialog.getByRole('button', { name: t('deploy.submit'), exact: true }).click();
      await expect(dialog.getByText(t('deploy.working'))).toBeVisible();
      await closeDeployDialog(dialog, t);

      // The evaluation ends while the deployment waits: it is held, not run.
      await advanceClock(request, 31 * DAY_SECONDS);
      await signIn(page, request, ADMIN, totpSecret);
      await expect(page.getByTestId('license-banner-evaluation_ended')).toBeVisible();
      await drainJobs(request);
      await nav(page, t, 'nav.deployments');
      const row = page.getByTestId('deployment-row');
      await expect(row).toHaveCount(1);
      await expect(row).toContainText(t('deployments.held'));
      await openDeployment(page, t, 'queued');
      await expect(page.getByText(t('deploy.held'))).toBeVisible();
      await expectAccessible(page, 'deployment page, held for the license');
      expect(served(WWW), 'a held deployment changed nothing').toBe(before);

      // Certificates and websites stay readable; uploading and deploying are refused with the license text.
      await nav(page, t, 'nav.certificates');
      await expect(page.getByTestId('certificates-table').getByRole('link', { name: 'queued' })).toBeVisible();
      await expectWide(page, 'certificates with the license locked');
      const upload = await openUpload(page, t, newCert(WWW), 'too-late');
      await upload.getByRole('button', { name: t('certificates.upload.submit') }).click();
      await expect(upload.getByRole('alert')).toContainText(t('errors.license.locked.title'));
      await upload.getByRole('button', { name: t('certificates.cancel') }).click();
      await page.goto(`/servers/${targetId}`);
      await expect(websiteRow(page, t, WWW)).toBeVisible();
      await expect(websiteRow(page, t, WWW)).toContainText(t('locations.deploying'));
      const refused = await openDeployFromWebsite(page, t, SITES[0], 'refused');
      await refused.getByRole('button', { name: t('deploy.submit'), exact: true }).click();
      await expect(refused.getByRole('alert')).toContainText(t('errors.license.locked.title'));
      await expectAccessible(page, 'deploy dialog refused by the license');
    });
  });
}
