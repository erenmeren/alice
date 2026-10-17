import type { APIRequestContext, APIResponse, Locator, Page } from '@playwright/test';
import {
  ADMIN,
  COPY,
  advanceClock,
  apiAs,
  browserLocale,
  configMode,
  drainJobs,
  drainUntil,
  expect,
  expectAccessible,
  expectWide,
  field,
  fingerprintHex,
  fingerprintOf,
  firstSignIn,
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

// A few contract strings pinned as literals in both languages: most copy is read from the locale
// files at run time (translator), which would follow an accidental change of these texts too.
const PINNED: Record<Lang, { discover: string; verified: string; rolledBack: string }> = {
  en: { discover: 'Discover', verified: 'The new certificate is live and verified.', rolledBack: 'Your server was restored to its previous certificate.' },
  tr: { discover: 'Keşfet', verified: 'Yeni sertifika yayında ve doğrulandı.', rolledBack: 'Sunucunuz önceki sertifikasına geri döndürüldü.' },
};

// TIME matches a date and time as the app shows them (Intl medium date, short time), in English
// ("Oct 4, 2026, 8:30 AM") and Turkish ("4 Eki 2026 08:30"): a year, then hours and minutes.
const TIME = String.raw`\S[^.]*?\b20\d\d\b[^.]*?\b\d{1,2}[:.]\d{2}(?!\d)(?:[\s\u202f]?[AP]M)?`;

// withTime is a locale text whose {{time}} must be an actual date and time.
function withTime(t: Translate, key: string): RegExp {
  const [before, after] = t(key, { time: '\u0000' }).split('\u0000');
  return new RegExp(`${escapeRegExp(before)}${TIME}${escapeRegExp(after.replace(/\s+$/, ''))}`);
}

// The nginx helper subcommands of the profile today (cmd/alice-helper); the script must grant each.
const NGINX_SUBCOMMANDS = ['nginx-dump', 'nginx-test', 'nginx-deploy', 'nginx-restore', 'nginx-status', 'nginx-fence'];

async function json<T>(res: APIResponse, status?: number): Promise<T> {
  const text = await res.text();
  if (status !== undefined) expect(res.status(), text).toBe(status);
  else expect(res.ok(), `${res.status()} ${text}`).toBe(true);
  return (text ? JSON.parse(text) : {}) as T;
}

// nginxSudoersLines are the nginx helper command lines the setup script installs, read from the
// script itself (the sudoers text it writes), so the check follows the product.
function nginxSudoersLines(script: string): string[] {
  const lines = [...script.matchAll(/\/usr\/local\/libexec\/alice-helper nginx-[a-z]+[^\n]*/g)].map((m) => m[0].replace(/,?\s*\\?\s*$/, '').trim());
  const subcommands = [...new Set(lines.map((l) => l.split(' ')[1]))].sort();
  expect(subcommands, 'the nginx subcommands the setup script grants').toEqual([...NGINX_SUBCOMMANDS].sort());
  return lines;
}

// expectNginxSudoers proves the target got the nginx profile: every nginx command line of the script
// (nginx-fence included) is in the target's sudoers.
function expectNginxSudoers(script: string): void {
  const installed = targetExec(['sh', '-c', 'cat /etc/sudoers.d/*']);
  for (const line of nginxSudoersLines(script)) expect(installed, `sudoers of the target grant: ${line}`).toContain(line);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function chooseLanguage(page: Page, lang: Lang): Promise<void> {
  if ((await uiLang(page)) === lang) return;
  await page.getByRole('button', { name: LANGUAGE_NAMES[lang], exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('lang', lang);
}

async function nav(page: Page, t: Translate, key: string): Promise<void> {
  await page.getByRole('link', { name: t(key), exact: true }).click();
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
}

// prepareAndAddInUI is owner steps 1–2 for an Nginx server, as a person does it: the nginx
// profile's commands from the Servers page run on the target, then Add server with the type Nginx
// server and the fingerprint compared with the one the server shows. It returns the server's id.
async function prepareAndAddInUI(page: Page, request: APIRequestContext, t: Translate): Promise<string> {
  await nav(page, t, 'nav.servers');
  await field(page, t('targets.prepare.profile')).selectOption('nginx');
  const script = (await page.getByTestId('setup-script').textContent()) ?? '';
  expect(script).toContain('nginx-fence');
  await expect(page.getByRole('button', { name: t('targets.prepare.copy') })).toBeVisible();
  targetExec(['/usr/local/sbin/alice-e2e-prepare'], script);
  expectNginxSudoers(script);
  expectHelperProtocol();

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
  expectNginxSudoers(key.profiles.nginx.script);
  expectHelperProtocol();
  const created = await json<{ target: Target }>(
    await api.post('/api/v1/targets', { type: 'nginx', name: SERVER, host: 'sshtarget', port: 22, username: 'alice-svc' }),
    201,
  );
  const id = created.target.id;
  const onServer = fingerprintOf(targetExec(['ssh-keygen', '-lf', HOST_KEY_PUB]));
  let hostKey: { id: string; fingerprint: string } | undefined;
  await drainUntil(request, async () => {
    const keys = await json<{ items: { id: string; status: string; fingerprint: string }[] }>(await api.get(`/api/v1/targets/${id}/host-keys`));
    hostKey = keys.items.find((k) => k.status === 'observed' && k.fingerprint === onServer);
    expect(hostKey).toBeDefined();
  });
  await json(await api.post(`/api/v1/targets/${id}/host-keys/${hostKey!.id}/actions/confirm`, { fingerprint: hostKey!.fingerprint }), 202);
  await drainUntil(request, async () => {
    const locs = await json<{ items: { servers: { names: string[] }[] }[] }>(await api.get(`/api/v1/targets/${id}/certificate-locations`));
    expect(locs.items.flatMap((l) => l.servers.flatMap((s) => s.names))).toEqual(expect.arrayContaining([WWW, FILES, ...SITES]));
  });
  return id;
}

// An Administrator with an email address: deployment emails go only to Administrators who have one.
const MAILED_ADMIN: Account & { email: string } = { ...ADMIN, email: 'ada@example.com' };

// DEPLOYMENT_SUBJECTS are the subjects of every deployment email template, in both languages.
const DEPLOYMENT_SUBJECTS = ['failed', 'rollback_failed', 'outcome_unknown', 'restored_unverified', 'superseded', 'needs_attention', 'pending_change_restored', 'needs_attention_unconfirmed'].flatMap(
  (k) => (['en', 'tr'] as Lang[]).map((l) => translator(l)(`email.deployment.${k}.subject`, { target_name: SERVER })),
);

// deploymentMails are the deployment emails the e2e build has sent (GET /test/mail).
async function deploymentMails(request: APIRequestContext): Promise<{ to: string; subject: string }[]> {
  const res = await request.get('/test/mail');
  expect(res.ok()).toBe(true);
  return ((await res.json()) as { messages: { to: string; subject: string }[] }).messages
    .filter((m) => DEPLOYMENT_SUBJECTS.includes(m.subject))
    .map((m) => ({ to: m.to, subject: m.subject }));
}

// servedChainLength is how many certificates Nginx sends for name (openssl s_client -showcerts on
// the target): the leaf alone is 1, leaf and CA 2.
function servedChainLength(name: string): number {
  return Number(
    targetExec(['sh', '-c', 'openssl s_client -connect 127.0.0.1:443 -servername "$1" -showcerts </dev/null 2>/dev/null | grep -c "BEGIN CERTIFICATE" || true', 'sh', name]).trim(),
  );
}

// expectHelperProtocol: the helper installed on the target is the current build, protocol 9 (Alice still opens protocol 6; HTTP-01 needs 7, Apache 8, HAProxy 9).
function expectHelperProtocol(): void {
  const v = JSON.parse(targetExec(['/usr/local/libexec/alice-helper', 'version'])) as { helper: string; protocol: number };
  expect(v.protocol, `alice-helper ${v.helper} on the target`).toBe(9);
}

// leafOf is the first certificate of a PEM chain (the website's own certificate, without the CA).
function leafOf(pem: string): string {
  const end = '-----END CERTIFICATE-----';
  return pem.slice(0, pem.indexOf(end) + end.length) + '\n';
}

// certificatesInFile counts the certificates in a file on the target.
function certificatesInFile(path: string): number {
  return Number(targetExec(['sh', '-c', `grep -c 'BEGIN CERTIFICATE' ${path} || true`]).trim());
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

      // The pinned contract strings are still what the app shows (a locale drift fails here).
      expect(t('locations.discover')).toBe(PINNED[lang].discover);
      expect(t('deploy.succeeded')).toBe(PINNED[lang].verified);
      expect(t('deploy.rolledBack')).toBe(PINNED[lang].rolledBack);

      // Discover: the websites with their state; the one with a variable path is not supported, says
      // why and offers no Deploy.
      await page.getByRole('button', { name: PINNED[lang].discover, exact: true }).click();
      await settle(request, page.getByText(t('targets.jobDone')));
      const www = websiteRow(page, t, WWW);
      await expect(www).toContainText(t('locations.ready'));
      await expect(www).toContainText(/\d+ (days|gün)/);
      const files = websiteRow(page, t, FILES);
      await expect(files).toContainText(t('locations.notSupported'));
      await expect(files).toContainText(t('locations.unsupported.variable'));
      await expect(page.getByRole('button', { name: t('locations.deployNamed', { site: FILES }) })).toHaveCount(0);
      await expect(page.getByRole('button', { name: t('locations.deployNamed', { site: WWW }) })).toBeEnabled();
      // The test target is far below Alice's discovery bounds: no chain left unresolved, no list cut.
      for (const key of ['locations.warnings.chain_unresolved', 'locations.warnings.list_truncated', 'warnings.list_truncated', 'locations.truncated']) {
        await expect(page.getByText(t(key)), key).toHaveCount(0);
      }
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
      await settle(request, dialog.getByText(PINNED[lang].verified, { exact: true }));
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
      await settle(request, reloadDialog.getByText(PINNED[lang].rolledBack, { exact: true }));
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
      await expectAccessible(page, 'deploy dialog, restored after nginx -t failed');
      expect(served(WWW), 'the previous certificate is served again').toBe(fingerprintHex(renewed.cert));
      await closeDeployDialog(testDialog, t);

      // The certificate list in its normal state, at every width (375 px included).
      await nav(page, t, 'nav.certificates');
      await expect(page.getByTestId('certificates-table').getByRole('link', { name: 'renewal-3' })).toBeVisible();
      await expectWide(page, 'certificates');

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
      await expect(recovery).toContainText(withTime(t, 'deployments.recovery.next'));
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
      // A certificate's page deploys only to the websites that already use it (by design), so the
      // five websites first get this certificate WITHOUT its chain, through the API (an incomplete
      // chain confirmed by the Administrator). Uploading it again with the full chain completes the
      // stored chain, and the batch from the UI then really writes, tests, reloads and verifies five
      // websites: their files gain the CA certificate.
      const pair = newCert(SITES.join(','));
      const certId = await uploadByApi(api, { cert: leafOf(pair.cert), key: pair.key }, 'five-sites');
      const ids = await locationIds(api, targetId);
      const first = await json<{ deployments: { id: string }[] }>(
        await api.post(`/api/v1/certificates/${certId}/deploy`, { location_ids: SITES.map((s) => ids[s]), confirm_incomplete_chain: true }),
        202,
      );
      expect(first.deployments).toHaveLength(SITES.length);
      await drainUntil(request, async () => {
        for (const d of first.deployments) {
          expect((await json<{ status: string }>(await api.get(`/api/v1/deployments/${d.id}`))).status).toBe('succeeded');
        }
      }, 120_000);
      for (const s of SITES) {
        expect(served(s), s).toBe(fingerprintHex(pair.cert));
        expect(certificatesInFile(`/etc/nginx/ssl/${s.split('.')[0]}.crt`), `${s}: the leaf alone`).toBe(1);
        expect(servedChainLength(s), `${s}: Nginx sends the leaf alone before the batch`).toBe(1);
      }

      // The same certificate uploaded again with its full chain: Alice completes the stored chain (200).
      await page.reload();
      const upload = await openUpload(page, t, pair, 'five-sites');
      await upload.getByRole('button', { name: t('certificates.upload.submit') }).click();
      await expect(upload.getByText(t('certificates.upload.chainCompleted'))).toBeVisible();
      await expect(upload.getByText(t('certificates.upload.uploaded'))).toHaveCount(0);
      await expectAccessible(page, 'upload dialog, chain completed');
      await upload.getByRole('button', { name: t('ui.close') }).last().click();
      await expect(page.getByRole('heading', { level: 1, name: 'five-sites' })).toBeVisible();
      await expect(page.getByText(t('certificates.detail.chainComplete'))).toBeVisible();

      // Every API response the browser gets from now on, with the time it arrived.
      const responses: { at: number; path: string; method: string; status: number }[] = [];
      page.on('response', (r) => {
        const url = new URL(r.url());
        if (url.pathname.startsWith('/api/')) responses.push({ at: Date.now(), path: url.pathname, method: r.request().method(), status: r.status() });
      });
      const deploymentReads = () => responses.filter((r) => r.method === 'GET' && r.path.startsWith('/api/v1/deployments/'));
      // most is the largest number of the given responses within any 60 s.
      const most = (rs: { at: number }[]) => Math.max(0, ...rs.map((r) => rs.filter((x) => x.at >= r.at && x.at < r.at + 60_000).length));

      await expect(page.getByRole('table', { name: t('certificates.detail.usedWhere') }).getByRole('row')).toHaveCount(SITES.length + 1);
      await page.getByRole('button', { name: t('certificates.detail.deploy'), exact: true }).click();
      const dialog = page.getByRole('dialog', { name: t('deploy.title') });
      const choices = dialog.getByRole('group', { name: t('deploy.websites') }).getByRole('checkbox');
      await expect(choices).toHaveCount(SITES.length);
      for (const box of await choices.all()) await box.check();
      await expectAccessible(page, 'deploy dialog with five websites');
      await dialog.getByRole('button', { name: t('deploy.submit'), exact: true }).click();
      const runs = dialog.getByTestId('deployment-run');
      await expect(runs).toHaveCount(SITES.length);
      await expect(dialog.getByText(t('deploy.working'))).toBeVisible();
      await expectAccessible(page, 'deploy dialog, deploying (working)');

      // The five runs stay queued (nothing drains): the dialog keeps polling. Before the fix it read
      // each deployment every second, 5 x 60 = 300 reads a minute, the whole session limit (300 a
      // minute, internal/api/server.go). The budget (task 22) is one loop of at most 2 reads a second
      // for any batch: at most 120 deployment reads in any minute (asserted: 125, timer slack), and
      // 150 API requests of every kind together. The wait lasts a full minute of polling.
      const pollStart = () => deploymentReads()[0]?.at ?? Date.now();
      await expect
        .poll(() => (deploymentReads().at(-1)?.at ?? 0) - pollStart(), { message: 'the dialog polls for a full minute', timeout: 100_000, intervals: [1_000] })
        .toBeGreaterThanOrEqual(61_000);
      test.info().annotations.push({
        type: 'polling budget',
        description: `${deploymentReads().length} deployment reads in ${Math.round(((deploymentReads().at(-1)?.at ?? 0) - pollStart()) / 1000)} s; most in a minute: ${most(deploymentReads())} deployment reads, ${most(responses)} API requests`,
      });
      expect(most(deploymentReads()), 'deployment reads in any minute (budget 120; before the fix 300)').toBeLessThanOrEqual(125);
      expect(most(responses), 'API requests of every kind in any minute').toBeLessThanOrEqual(150);
      expect(most(deploymentReads()), 'the dialog kept polling all minute').toBeGreaterThanOrEqual(60);
      for (const id of new Set(deploymentReads().map((r) => r.path))) {
        expect(deploymentReads().filter((r) => r.path === id).length, `${id} read during the minute`).toBeGreaterThanOrEqual(10);
      }
      expect(new Set(deploymentReads().map((r) => r.path)).size, 'every run is followed').toBe(SITES.length);
      expect(responses.filter((r) => r.status === 429), 'no request was answered 429').toEqual([]);

      // Now the jobs run: five real deployments, each verified.
      await settle(request, dialog.getByText(t('deploy.partial', { ok: SITES.length, total: SITES.length })));
      await expect(runs.filter({ hasText: PINNED[lang].verified })).toHaveCount(SITES.length);
      await expect(dialog.getByText(t('deploy.partialUnchanged', { count: SITES.length }))).toHaveCount(0);
      await expectAccessible(page, 'deploy dialog, five websites finished');
      expect(responses.filter((r) => r.status === 429), 'no request was answered 429').toEqual([]);
      for (const s of SITES) {
        expect(served(s), s).toBe(fingerprintHex(pair.cert));
        expect(certificatesInFile(`/etc/nginx/ssl/${s.split('.')[0]}.crt`), `${s}: leaf and CA written by the batch`).toBe(2);
        // The leaf is the same before and after: the chain Nginx sends proves it reloaded the new file.
        expect(servedChainLength(s), `${s}: Nginx sends leaf and CA after the batch (reloaded)`).toBe(2);
      }
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
      // Verification settings need no step-up (permission targets.manage): saved at once, never asked.
      await expect(settings.getByText(t('locations.verify.saved'))).toBeVisible();
      await expect(page.getByRole('dialog', { name: COPY[lang].stepUpHeading })).toHaveCount(0);
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
      await page.getByRole('button', { name: PINNED[lang].discover, exact: true }).click();
      await settle(request, page.getByTestId('config-invalid'));
      const stale = page.getByTestId('stale-websites');
      await expect(stale).toContainText(t('locations.stale.title'));
      await expect(stale).toContainText(withTime(t, 'locations.stale.help'));
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

    test('a deployment an administrator cancels while the license holds it ends cancelled and sends no failure email', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      // Deployment emails go to every Administrator WITH an email address.
      const { totpSecret } = await runWizard(page, request, lang, MAILED_ADMIN);
      const api = await apiAs(page);
      await api.stepUp(totpSecret);
      const targetId = await prepareAndAddByApi(api, request);
      await uploadByApi(api, newCert(WWW), 'control');
      await uploadByApi(api, newCert(WWW), 'cancel-me');

      // Positive control: a deployment that fails and is restored sends the deployment-failed email,
      // so the outbox path works before the absence of an email below counts.
      await page.goto(`/servers/${targetId}`);
      const control = await openDeployFromWebsite(page, t, WWW, 'control');
      await control.getByRole('button', { name: t('deploy.submit'), exact: true }).click();
      reloadMode('fail-once');
      await settle(request, control.getByText(PINNED[lang].rolledBack, { exact: true }));
      await closeDeployDialog(control, t);
      const failedSubject = t('email.deployment.failed.subject', { target_name: SERVER });
      await drainUntil(request, async () => {
        await runScheduled(request, 'notify.send');
        expect(await deploymentMails(request)).toEqual([{ to: MAILED_ADMIN.email, subject: failedSubject }]);
      });

      const before = served(WWW);
      const dialog = await openDeployFromWebsite(page, t, WWW, 'cancel-me');
      await dialog.getByRole('button', { name: t('deploy.submit'), exact: true }).click();
      await expect(dialog.getByText(t('deploy.working'))).toBeVisible();
      await closeDeployDialog(dialog, t);

      // The evaluation ends while the deployment waits: held, nothing sent.
      await advanceClock(request, 31 * DAY_SECONDS);
      await signIn(page, request, MAILED_ADMIN, totpSecret);
      await drainJobs(request);
      // A new license unlocks Alice; the held job still waits for an Administrator (it never starts on its own).
      const issued = await request.post('/test/license', { data: {} });
      expect(issued.ok(), await issued.text()).toBe(true);
      const admin = await apiAs(page);
      await admin.stepUp(totpSecret);
      await json(await admin.post('/api/v1/license', { license: ((await issued.json()) as { license: string }).license }));
      await page.goto('/servers');
      const panel = page.getByTestId('blocked-jobs');
      const job = t('jobs.types.certificate.deploy');
      await expect(panel.getByText(t('jobs.deploymentNotSent'))).toBeVisible();
      await expectWide(page, 'servers with a held deployment');
      await panel.getByRole('button', { name: t('jobs.discardNamed', { job }) }).click();
      await expect(panel).toHaveCount(0);

      // The sweep ends the deployment: cancelled, not a server failure; nothing was sent.
      await runScheduled(request, 'deployment.recovery_sweep');
      await drainJobs(request);
      await nav(page, t, 'nav.deployments');
      const rows = page.getByTestId('deployment-row');
      await expect(rows).toHaveCount(2);
      await expect(rows.filter({ hasText: 'cancel-me' })).toContainText(t('deployments.cancelled'));
      await openDeployment(page, t, 'cancel-me');
      await expect(page.getByTestId('deployment-status')).toHaveText(t('deployments.cancelled'));
      await expect(page.getByText(t('deploy.noChange'))).toBeVisible();
      const note = page.locator('[data-reason="deployment.cancelled"]');
      await expect(note).toContainText(t('errors.deployment.cancelled.title'));
      await expect(note).toHaveAttribute('role', 'status');
      await expectAccessible(page, 'deployment page, cancelled by an administrator');
      expect(served(WWW), 'a cancelled deployment changed nothing').toBe(before);

      // The sender runs again: the control's email is still the only deployment email.
      await runScheduled(request, 'notify.send');
      await drainJobs(request);
      expect(await deploymentMails(request), 'no email for the cancelled deployment').toEqual([{ to: MAILED_ADMIN.email, subject: failedSubject }]);
    });
  });
}
