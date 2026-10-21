import type { APIRequestContext, APIResponse, Locator, Page } from '@playwright/test';
import {
  ADMIN,
  acmeAdvertise,
  acmeCA,
  acmeClearRequests,
  acmeCounters,
  acmeCtl,
  acmeDns,
  acmeDnsProviders,
  acmeFault,
  acmeHttpTarget,
  acmeLifetime,
  acmeReset,
  acmeSyncClock,
  advanceClock,
  answerStepUp,
  apiAs,
  browserLocale,
  drainJobs,
  drainUntil,
  expect,
  expectAccessible,
  field,
  fingerprintOf,
  firstSignIn,
  nginxReset,
  resetInstall,
  runScheduled,
  runWizard,
  served,
  signIn,
  signOut,
  targetExec,
  test,
  testMode,
  translator,
  type Account,
  type AcmeCredentials,
  type Api,
  type Lang,
  type Translate,
} from './helpers';

// Phase 10 (ACME issuance and renewal) on the e2e stack: the fake certificate authority (compose service fakeacme,
// acme.test.alice, driven with "ctl" through helpers.ts; its built-in DNS hook publishes the DNS-01 records), the SSH
// target's Nginx as the website the issued certificate is deployed to (www.example.test, as in Phases 4 and 5).
// acme.schedule and acme.auto_deploy never tick by themselves in the e2e build: the journeys move Alice's clock
// (POST /test/clock) and run them with POST /test/scheduler/run. Every visible text is read from the locale files at
// run time (translator), so the Turkish journey checks the Turkish screens with the same code.
//
// The fake's external account binding key and its hook secret are typed into fields and sent in API bodies, so they
// are in the Playwright trace of a failed test. That is acceptable only because the fake generates both when it starts
// and they die with the stack: never reuse this pattern against a real certificate authority.

const HOST_KEY_PUB = '/etc/ssh/ssh_host_ed25519_key.pub';
const WWW = 'www.example.test';
const DOMAIN = 'example.test';
const WILDCARD = '*.example.test';
const SERVER = 'e2e-nginx';
const CA_NAME = 'Test CA';
const HOOK_NAME = 'Test DNS hook';
const CHALLENGE_DIR = '/var/www/alice-acme/.well-known/acme-challenge';
const DAY_SECONDS = 24 * 3600;
// The lifetime of the certificates the fake issues in the renewal journeys: Alice renews at not_after - lifetime/3
// (renew.RenewAt; the fake's ARI window starts there too), 20 minutes after issuance, which stays inside the 30-minute
// idle limit of a session (auth.SessionIdle) and above the 15-minute spacing of planner orders (renew.MinSpacing).
const SHORT_LIFETIME = '30m';
const DUE_AFTER_SECONDS = 21 * 60;
const JOURNEY_TIMEOUT = 10 * 60_000;
// The licence lock's plain title (locales/common/en.json errors.license.locked.title), pinned.
const LOCK_TITLE = 'Not available while the license is expired.';
const OPERATOR: Account = { username: 'olcay', fullName: 'Olcay Öztürk', password: 'operator-password-2026' };
const AUDITOR: Account = { username: 'deniz', fullName: 'Deniz Aksoy', password: 'auditor-password-2026' };

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function json<T>(res: APIResponse, status?: number): Promise<T> {
  const text = await res.text();
  if (status !== undefined) expect(res.status(), text).toBe(status);
  else expect(res.ok(), `${res.status()} ${text}`).toBe(true);
  return (text ? JSON.parse(text) : {}) as T;
}

const hex = (fp: string) => fp.replace(/[^0-9a-fA-F]/g, '').toLocaleLowerCase('en-US');

// --- the API views the journeys read ---

interface CurrentView {
  id: string;
  fingerprint_sha256: string;
  not_after: string;
}

interface AcmeCertView {
  id: string;
  state: string;
  failures: number;
  next_attempt_at: string | null;
  running_order_id: string | null;
  current: CurrentView | null;
  last_error: { code: string; reason: string } | null;
}

interface OrderView {
  id: string;
  kind: 'issue' | 'test';
  state: 'running' | 'succeeded' | 'failed';
  trigger: string;
  certificate_id: string | null;
  presented: number;
  cleanup_at: string | null;
  error: { code: string; reason: string } | null;
  replaces: string;
  replaces_outcome: string;
}

interface DeploymentView {
  id: string;
  status: string;
  trigger: string;
  location_id?: string;
  certificate_id?: string;
}

async function acmeCert(api: Api, id: string): Promise<AcmeCertView> {
  return json<AcmeCertView>(await api.get(`/api/v1/acme/certificates/${id}`));
}

async function acmeOrders(api: Api, id: string): Promise<OrderView[]> {
  return (await json<{ items: OrderView[] }>(await api.get(`/api/v1/acme/certificates/${id}/orders?limit=20`))).items;
}

async function deployments(api: Api): Promise<DeploymentView[]> {
  return (await json<{ items: DeploymentView[] }>(await api.get('/api/v1/deployments?limit=50'))).items;
}

async function auditActions(api: Api, totpSecret: string, prefix: string): Promise<string[]> {
  await api.stepUp(totpSecret);
  const res = await json<{ items: { action: string }[] }>(await api.get(`/api/v1/audit?limit=200&action=${encodeURIComponent(prefix)}`));
  return res.items.map((i) => i.action);
}

// --- setup through the API (what a journey is not about) ---

// prepareAndAddServer prepares the SSH target with the real nginx profile script (the HTTP-01 lines included), adds it
// as an Nginx server, confirms its host key after comparing it with the server's own, and waits for its websites.
async function prepareAndAddServer(api: Api, request: APIRequestContext): Promise<string> {
  const key = await json<{ profiles: { nginx: { script: string } } }>(await api.get('/api/v1/ssh-keys/platform-key'));
  targetExec(['/usr/local/sbin/alice-e2e-prepare'], key.profiles.nginx.script);
  const created = await json<{ target: { id: string } }>(
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
    expect(locs.items.flatMap((l) => l.servers.flatMap((s) => s.names))).toContain(WWW);
  });
  return id;
}

// wwwLocation is the id of the www.example.test certificate file on the target (an ECDSA pair, as the ACME default).
async function wwwLocation(api: Api): Promise<string> {
  const locations = await json<{ items: { id: string; server_names: string[] }[] }>(await api.get('/api/v1/certificate-locations?key_type=ecdsa&limit=50'));
  const www = locations.items.find((l) => l.server_names.includes(WWW));
  expect(www, `${WWW} is a deployable website`).toBeDefined();
  return www!.id;
}

interface Authority {
  providerId: string;
  hookId: string;
}

// addAuthorityByApi adds the fake as an authority (its CA bundle, the external account binding, example.test allowed),
// registers the account for the terms the CA shows, and adds the fake's DNS hook. The step-up must be fresh.
async function addAuthorityByApi(api: Api, creds: AcmeCredentials, opts: { wait?: number } = {}): Promise<Authority> {
  const provider = await json<{ id: string }>(
    await api.post('/api/v1/acme/providers', {
      name: CA_NAME,
      directory_url: creds.directory_url,
      preset: 'custom',
      ca_bundle_pem: acmeCA(),
      eab_kid: creds.eab_kid,
      eab_hmac: creds.eab_hmac,
      allowed_suffixes: [DOMAIN],
    }),
    201,
  );
  const preview = await json<{ terms_of_service_url: string }>(await api.post(`/api/v1/acme/providers/${provider.id}/preview`));
  await json(await api.post(`/api/v1/acme/providers/${provider.id}/account`, { tos_accepted: true, accepted_terms_url: preview.terms_of_service_url }), 201);
  const hook = await json<{ id: string }>(
    await api.post('/api/v1/acme/hooks', {
      name: HOOK_NAME,
      url: creds.hook_url,
      secret: creds.hook_secret,
      allowed_suffixes: [DOMAIN],
      propagation_wait_seconds: opts.wait ?? 0,
      poll_timeout_seconds: 10,
    }),
    201,
  );
  return { providerId: provider.id, hookId: hook.id };
}

async function createCertificateByApi(api: Api, a: Authority, names: string[], extra: Record<string, unknown> = {}): Promise<string> {
  const created = await json<{ id: string }>(
    await api.post('/api/v1/acme/certificates', { provider_id: a.providerId, names, challenge: 'dns01', hook_id: a.hookId, ...extra }),
    201,
  );
  return created.id;
}

// orderAndWait orders the certificate now (a person's order) and runs the issue job until the order ended.
async function orderAndWait(api: Api, request: APIRequestContext, id: string, path: 'order' | 'test' = 'order'): Promise<OrderView> {
  const started = await json<OrderView>(await api.post(`/api/v1/acme/certificates/${id}/${path}`), 202);
  let ended: OrderView | undefined;
  await drainUntil(request, async () => {
    ended = (await acmeOrders(api, id)).find((o) => o.id === started.id);
    expect(ended?.state).not.toBe('running');
  });
  return ended!;
}

interface Install {
  totpSecret: string;
  api: Api;
  serverId: string;
  creds: AcmeCredentials;
}

// install resets Alice, the fake CA and the target's Nginx, installs Alice in lang and adds the Nginx server.
async function install(page: Page, request: APIRequestContext, lang: Lang): Promise<Install> {
  await resetInstall(request);
  const creds = acmeReset();
  nginxReset();
  const { totpSecret } = await runWizard(page, request, lang);
  const api = await apiAs(page);
  await api.stepUp(totpSecret);
  const serverId = await prepareAndAddServer(api, request);
  await page.reload();
  return { totpSecret, api, serverId, creds };
}

// --- the screens ---

// setScheme switches the color scheme the app follows ("auto") and waits until the new colors are drawn: the scheme is
// on <html>, two frames have passed (WebKit starts the color transitions only then) and every finite animation ended,
// so axe never measures a color halfway.
async function setScheme(page: Page, scheme: 'light' | 'dark'): Promise<void> {
  await page.emulateMedia({ colorScheme: scheme });
  await expect(page.locator('html')).toHaveAttribute('data-mantine-color-scheme', scheme);
  await page.evaluate(
    () =>
      new Promise<void>((done) =>
        requestAnimationFrame(() =>
          requestAnimationFrame(() => {
            const running = document.getAnimations().filter((a) => a.effect?.getComputedTiming().iterations !== Infinity);
            void Promise.all(running.map((a) => a.finished.catch(() => undefined))).then(() => done());
          }),
        ),
      ),
  );
}

function bindingRow(page: Page): Locator {
  return page.getByTestId('acme-binding').filter({ hasText: SERVER });
}

async function openSettingsAcme(page: Page, api: Api, totpSecret: string, t: Translate): Promise<void> {
  await api.stepUp(totpSecret); // Settings reads need a fresh step-up
  await page.goto('/settings?tab=acme');
  await expect(page.getByRole('tab', { name: t('settings.tabs.acme'), selected: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: t('acme.settings.providers') })).toBeVisible();
}

async function openStatus(page: Page, id: string, name: string): Promise<void> {
  await page.goto(`/acme/${id}`);
  await expect(page.getByRole('heading', { level: 1, name })).toBeVisible();
}

// addSuffix types a domain ending into the allowed names of a dialog and adds it.
async function addSuffix(dialog: Locator, t: Translate, suffix: string): Promise<void> {
  await field(dialog, t('acme.suffix.label')).fill(suffix);
  await dialog.getByRole('button', { name: t('acme.suffix.add'), exact: true }).click();
  await expect(dialog.getByRole('list', { name: t('acme.suffix.listLabel') }).getByText(suffix, { exact: true })).toBeVisible();
}

// addAuthorityInUI is Settings → Certificate authorities as an Administrator does it: the authority (own CA, its
// bundle, the external account binding, allowed names), the account (the terms link shown before the box is ticked,
// a change of the terms between reading and accepting), and the DNS hook.
async function addAuthorityInUI(page: Page, request: APIRequestContext, lang: Lang, s: Install, t: Translate, opts: { termsChange: boolean }): Promise<void> {
  await page.getByRole('button', { name: t('acme.settings.addProvider'), exact: true }).click();
  let dialog = page.getByRole('dialog', { name: t('acme.provider.addTitle') });
  await expect(dialog).toBeVisible();
  await expectAccessible(page, `add certificate authority dialog ${lang}`, { soft: true, dialog });
  await field(dialog, t('acme.provider.preset')).selectOption('custom');
  await field(dialog, t('acme.provider.name')).fill(CA_NAME);
  await field(dialog, t('acme.provider.directory')).fill(s.creds.directory_url);
  await field(dialog, t('acme.provider.bundle')).fill(acmeCA());
  await field(dialog, t('acme.provider.eabKid')).fill(s.creds.eab_kid);
  await field(dialog, t('acme.provider.eabHmac')).fill(s.creds.eab_hmac);
  await addSuffix(dialog, t, DOMAIN);
  acmeClearRequests();
  await dialog.getByRole('button', { name: t('acme.provider.save'), exact: true }).click();
  await answerStepUp(page, request, lang, s.totpSecret, dialog.getByText(t('settings.saved'), { exact: true }));
  // Air-gap: saving an authority contacts no one.
  expect(acmeCounters().requests ?? 0, 'saving the authority contacted the CA').toBe(0);
  await dialog.getByRole('button', { name: t('ui.continue'), exact: true }).click();
  await expect(dialog).toHaveCount(0);

  const region = page.getByRole('region', { name: CA_NAME, exact: true });
  await expect(region.getByText(t('acme.settings.accountNone'), { exact: true })).toBeVisible();
  await expect(region.getByText(t('acme.settings.eabConfigured'), { exact: true })).toBeVisible();

  // Register: the terms link is on screen before the box can be ticked, and the box starts unticked.
  await region.getByRole('button', { name: t('acme.account.register'), exact: true }).click();
  dialog = page.getByRole('dialog', { name: t('acme.register.title', { name: CA_NAME }) });
  const link = dialog.getByRole('link', { name: s.creds.terms_url });
  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute('href', s.creds.terms_url);
  const box = dialog.getByRole('checkbox', { name: t('acme.register.tos') });
  await expect(box).not.toBeChecked();
  await expect(dialog.getByRole('button', { name: t('acme.register.submit'), exact: true })).toBeDisabled();
  await expectAccessible(page, `register account dialog ${lang}`, { soft: true, dialog });
  await field(dialog, t('acme.register.email')).fill('pki@example.test');
  if (opts.termsChange) {
    // The CA changes its terms after they were read: the registration is refused, the new terms are shown, and the
    // box must be ticked again for them.
    const changed = `${s.creds.base_url}/terms-2026`;
    acmeAdvertise('termsOfService', changed);
    await box.check();
    await dialog.getByRole('button', { name: t('acme.register.submit'), exact: true }).click();
    await answerStepUp(page, request, lang, s.totpSecret, dialog.getByText(t('acme.register.termsChangedTitle'), { exact: true }));
    await expect(dialog.getByRole('link', { name: changed })).toBeVisible();
    await expect(box).not.toBeChecked();
    await expect(dialog.getByRole('button', { name: t('acme.register.submit'), exact: true })).toBeDisabled();
  }
  await box.check();
  await dialog.getByRole('button', { name: t('acme.register.submit'), exact: true }).click();
  await answerStepUp(page, request, lang, s.totpSecret, dialog.getByText(t('acme.register.done'), { exact: false }));
  await dialog.getByRole('button', { name: t('ui.continue'), exact: true }).click();
  await expect(region.getByText(t('acme.settings.accountRegistered'), { exact: true })).toBeVisible();
  const account = region.getByRole('region', { name: t('acme.account.regionLabel', { name: CA_NAME }) });
  await expect(account.getByText('pki@example.test')).toBeVisible();

  // The DNS hook: the fake's own receiver, with its secret, for example.test.
  await page.getByRole('button', { name: t('acme.settings.addHook'), exact: true }).click();
  dialog = page.getByRole('dialog', { name: t('acme.hook.addTitle') });
  await expect(dialog).toBeVisible();
  await field(dialog, t('acme.hook.name')).fill(HOOK_NAME);
  await field(dialog, t('acme.hook.url')).fill(s.creds.hook_url);
  await field(dialog, t('acme.hook.secret')).fill(s.creds.hook_secret);
  await field(dialog, t('acme.hook.wait')).fill('0');
  await field(dialog, t('acme.hook.poll')).fill('10');
  await addSuffix(dialog, t, DOMAIN);
  await expectAccessible(page, `add DNS hook dialog ${lang}`, { soft: true, dialog });
  await dialog.getByRole('button', { name: t('acme.hook.save'), exact: true }).click();
  await answerStepUp(page, request, lang, s.totpSecret, dialog.getByText(t('settings.saved'), { exact: true }));
  await dialog.getByRole('button', { name: t('ui.continue'), exact: true }).click();
  await expect(page.getByRole('region', { name: HOOK_NAME, exact: true }).getByText(t('acme.settings.secretConfigured'), { exact: true })).toBeVisible();
}

// getCertificateInUI runs the Get a certificate wizard for names with the DNS hook and saves it (step-up); it stops on
// the done step and returns the dialog.
async function getCertificateInUI(page: Page, request: APIRequestContext, lang: Lang, totpSecret: string, t: Translate, names: string[], opts: { autoDeploy?: boolean; scan?: boolean } = {}): Promise<Locator> {
  await page.goto('/acme');
  await expect(page.getByRole('heading', { level: 1, name: t('acme.issued.title') })).toBeVisible();
  await page.getByRole('button', { name: t('acme.issued.getCertificate'), exact: true }).first().click();
  const dialog = page.getByRole('dialog', { name: t('acme.issued.wizard.title') });
  await expect(dialog).toBeVisible();
  const next = dialog.getByRole('button', { name: t('acme.issued.wizard.next'), exact: true });
  await dialog.getByRole('radio', { name: CA_NAME }).check();
  if (opts.scan) await expectAccessible(page, `get a certificate: authority ${lang}`, { soft: true, dialog });
  await next.click();
  await expect(dialog.getByRole('heading', { name: t('acme.issued.wizard.heading.names') })).toBeFocused();
  for (const n of names) {
    await field(dialog, t('acme.issued.wizard.name')).fill(n);
    await dialog.getByRole('button', { name: t('acme.suffix.add'), exact: true }).click();
  }
  await expect(dialog.getByRole('list', { name: t('acme.issued.wizard.namesList') }).getByRole('listitem')).toHaveCount(names.length);
  if (opts.scan) await expectAccessible(page, `get a certificate: names ${lang}`, { soft: true, dialog });
  await next.click();
  await dialog.getByRole('radio', { name: t('acme.enum.challenge.dns01') }).check();
  if (names.some((n) => n.startsWith('*.'))) await expect(dialog.getByRole('radio', { name: t('acme.enum.challenge.http01') })).toBeDisabled();
  await field(dialog, t('acme.issued.wizard.hook')).selectOption({ label: `${HOOK_NAME} (${t('acme.enum.hookKind.webhook')})` });
  if (opts.scan) await expectAccessible(page, `get a certificate: proof ${lang}`, { soft: true, dialog });
  await next.click();
  await expect(field(dialog, t('acme.issued.wizard.keyType'))).toHaveValue('ecdsa_p256');
  if (opts.autoDeploy) await dialog.getByRole('checkbox', { name: t('acme.issued.wizard.autoDeploy') }).check();
  if (opts.scan) await expectAccessible(page, `get a certificate: options ${lang}`, { soft: true, dialog });
  await next.click();
  await expect(dialog.getByRole('heading', { name: t('acme.issued.wizard.heading.review') })).toBeVisible();
  if (opts.scan) await expectAccessible(page, `get a certificate: review ${lang}`, { soft: true, dialog });
  acmeClearRequests();
  await dialog.getByRole('button', { name: t('acme.issued.wizard.save'), exact: true }).click();
  await answerStepUp(page, request, lang, totpSecret, dialog.getByText(t('acme.issued.wizard.saved'), { exact: true }));
  // Saving orders nothing.
  expect(acmeCounters().requests ?? 0, 'saving the certificate contacted the CA').toBe(0);
  return dialog;
}

// certIdFromUrl reads the ACME certificate id of the status page that is open.
function certIdFromUrl(page: Page): string {
  const m = new URL(page.url()).pathname.match(/^\/acme\/([0-9a-f-]{36})$/);
  expect(m, `a status page is open: ${page.url()}`).not.toBeNull();
  return m![1];
}

// addWebsiteInUI connects www.example.test on the status page (Add websites), with automatic deployment off.
async function addWebsiteInUI(page: Page, t: Translate): Promise<void> {
  await page.getByRole('button', { name: t('acme.issued.bindings.add'), exact: true }).click();
  const dialog = page.getByRole('dialog', { name: t('acme.issued.bindings.addTitle') });
  await dialog.getByRole('checkbox', { name: new RegExp(escapeRegExp(WWW)) }).check();
  await dialog.getByRole('button', { name: t('acme.issued.bindings.add'), exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await expect(bindingRow(page)).toBeVisible();
}

// deployNowInUI deploys the current certificate to every connected website (Deploy now) and runs the deployment until
// the target serves fingerprint.
async function deployNowInUI(page: Page, request: APIRequestContext, t: Translate, fingerprint: string): Promise<void> {
  await page.getByTestId('acme-bindings').getByRole('button', { name: t('acme.issued.deployNow'), exact: true }).click();
  const dialog = page.getByRole('dialog', { name: t('acme.issued.deployTitle') });
  await expect(dialog.getByRole('checkbox', { name: new RegExp(escapeRegExp(SERVER)) })).toBeChecked();
  await dialog.getByRole('button', { name: t('acme.issued.deployNow'), exact: true }).click();
  await expect(dialog.getByText(t('acme.issued.deployQueued', { count: 1 }), { exact: true })).toBeVisible();
  // The dialog's own Close (the header's close button has the same name).
  await dialog.getByRole('button', { name: t('ui.close'), exact: true }).last().click();
  await drainUntil(request, async () => expect(served(WWW)).toBe(fingerprint));
}

// switchSiteAutoOn switches on automatic deployment for www.example.test as an Administrator: confirmation, step-up.
async function switchSiteAutoOn(page: Page, request: APIRequestContext, lang: Lang, totpSecret: string, t: Translate, certPath: string): Promise<void> {
  const name = t('acme.issued.bindings.autoNamed', { site: `"${SERVER}" ${certPath}` });
  const sw = page.getByRole('switch', { name });
  await expect(sw).not.toBeChecked();
  await sw.click({ force: true });
  const confirm = page.getByRole('dialog', { name: t('acme.issued.bindings.autoConfirmTitle') });
  await confirm.getByRole('button', { name: t('acme.issued.bindings.autoConfirm'), exact: true }).click();
  await answerStepUp(page, request, lang, totpSecret, page.getByRole('switch', { name, checked: true }));
}

// The happy path, as a person does it, in one language: the authority, the account and the hook in Settings; the
// wizard; a Test run (the CA verifies the names, nothing is issued); the certificate; the website; automatic deployment
// (Administrator, step-up); Deploy now; the target serves the issued leaf.
async function happyPath(page: Page, request: APIRequestContext, lang: Lang): Promise<void> {
  const t = translator(lang);
  const s = await install(page, request, lang);
  await openSettingsAcme(page, s.api, s.totpSecret, t);
  await expect(page.getByText(t('acme.settings.airGapTitle'), { exact: true })).toBeVisible();
  for (const scheme of ['light', 'dark'] as const) {
    await setScheme(page, scheme);
    await expectAccessible(page, `settings ACME tab, empty, ${scheme} ${lang}`, { soft: true });
  }
  await setScheme(page, 'light');
  // No authority yet: nothing was contacted while Alice was installed and the tab was opened.
  expect(acmeCounters().requests ?? 0).toBe(0);
  await addAuthorityInUI(page, request, lang, s, t, { termsChange: lang === 'en' });
  for (const scheme of ['light', 'dark'] as const) {
    await setScheme(page, scheme);
    await expectAccessible(page, `settings ACME tab, filled, ${scheme} ${lang}`, { soft: true });
  }
  await setScheme(page, 'light');

  // The wizard; saved, nothing ordered; then a Test run from the done step.
  const dialog = await getCertificateInUI(page, request, lang, s.totpSecret, t, [WWW, DOMAIN], { scan: true });
  for (const scheme of ['light', 'dark'] as const) {
    await setScheme(page, scheme);
    await expectAccessible(page, `get a certificate: saved ${scheme} ${lang}`, { soft: true, dialog });
  }
  await setScheme(page, 'light');
  await dialog.getByRole('button', { name: t('acme.issued.wizard.testFirst'), exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: WWW })).toBeVisible();
  const id = certIdFromUrl(page);
  await expect(page.getByTestId('acme-state')).toHaveText(t('acme.enum.certificateState.pending'));
  const testResult = page.getByTestId('test-result');
  await drainUntil(request, () => expect(testResult).toContainText(t('acme.issued.test.ok'), { timeout: 3_000 }));
  // The CA verified both names through the hook and issued nothing: no finalize, no certificate.
  const afterTest = acmeCounters();
  expect(afterTest['validations-dns-01'] ?? 0, 'DNS-01 validations of the Test run').toBe(2);
  expect(afterTest['hook-present'] ?? 0).toBe(2);
  expect(afterTest.finalize ?? 0, 'a Test run never finalizes').toBe(0);
  expect(afterTest.issued ?? 0, 'a Test run issues nothing').toBe(0);
  await drainJobs(request);
  expect(Object.keys(acmeDns()), 'the Test run removed its DNS records').toEqual([]);
  expect((await acmeCert(s.api, id)).current).toBeNull();
  await expect(page.getByTestId('acme-state')).toHaveText(t('acme.enum.certificateState.pending'));
  for (const scheme of ['light', 'dark'] as const) {
    await setScheme(page, scheme);
    await expectAccessible(page, `status page before issuance ${scheme} ${lang}`, { soft: true });
  }
  await setScheme(page, 'light');

  // Get the certificate now.
  await page.getByRole('button', { name: t('acme.issued.getNow'), exact: true }).click();
  await drainUntil(request, () => expect(page.getByTestId('acme-state')).toHaveText(t('acme.enum.certificateState.active'), { timeout: 3_000 }));
  expect(acmeCounters().issued, 'the CA issued one certificate').toBe(1);
  const cert = await acmeCert(s.api, id);
  expect(cert.current).not.toBeNull();
  const fp = hex(cert.current!.fingerprint_sha256);
  await expect(page.getByRole('button', { name: t('acme.issued.orderNow'), exact: true })).toBeVisible();
  await expect(page.getByTestId('current-panel')).toContainText(fp.slice(0, 16));
  await expect(page.getByRole('table', { name: t('acme.issued.orders.title') }).getByTestId('acme-order')).toHaveCount(2);

  // The certificate is in the inventory as issued by ACME.
  await page.getByTestId('current-panel').getByRole('link', { name: t('acme.issued.current.open') }).click();
  await expect(page).toHaveURL(new RegExp(`/certificates/${cert.current!.id}$`));
  await expect(page.getByText(t('enum.certificateSource.acme')).first()).toBeVisible();
  await page.goto('/certificates?source=acme');
  await expect(page.getByTestId('certificates-table').locator('tbody tr')).toHaveCount(1);

  // The list.
  await page.goto('/acme');
  const row = page.getByTestId('acme-certificate-row');
  await expect(row).toHaveCount(1);
  await expect(row.getByRole('link', { name: WWW })).toHaveAttribute('href', `/acme/${id}`);
  await expect(row.getByText(t('acme.enum.certificateState.active'), { exact: true })).toBeVisible();
  for (const scheme of ['light', 'dark'] as const) {
    await setScheme(page, scheme);
    await expectAccessible(page, `issued certificates list ${scheme} ${lang}`, { soft: true });
  }
  await setScheme(page, 'light');

  // The website, automatic deployment, Deploy now: the target serves the issued leaf.
  await openStatus(page, id, WWW);
  await addWebsiteInUI(page, t);
  await expect(bindingRow(page)).toHaveAttribute('data-state', 'pending');
  const certPath = ((await bindingRow(page).locator('code').first().textContent()) ?? '').trim();
  expect(certPath).not.toBe('');
  await switchSiteAutoOn(page, request, lang, s.totpSecret, t, certPath);
  // Only the website's switch is on: the summary says nothing deploys by itself yet.
  await expect(page.getByTestId('auto-sites-only')).toBeVisible();
  await expect(page.getByTestId('auto-summary')).toContainText(t('acme.issued.bindings.autoSummary', { n: 0, count: 1 }));
  await deployNowInUI(page, request, t, fp);
  // The status page does not follow a deployment by itself (it polls only while an order runs): read it again.
  await page.reload();
  await expect(bindingRow(page)).toHaveAttribute('data-state', 'current');
  await expect(bindingRow(page)).toContainText(t('acme.issued.bindings.servedCurrent'));
  for (const scheme of ['light', 'dark'] as const) {
    await setScheme(page, scheme);
    await expectAccessible(page, `status page, issued and deployed, ${scheme} ${lang}`, { soft: true });
  }
  await setScheme(page, 'light');
  const deps = await deployments(s.api);
  expect(deps.filter((d) => d.status === 'succeeded'), 'one deployment succeeded').toHaveLength(1);
}

for (const lang of ['en', 'tr'] as Lang[]) {
  test.describe(`Phase 10 ACME happy path (${lang})`, () => {
    test.use({ locale: browserLocale(lang) });
    test(`authority, account, hook, wizard, test run, certificate, website and deployment (${lang})`, async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      await happyPath(page, request, lang);
    });
  });
}

test.describe('Phase 10 ACME (en)', () => {
  test.use({ locale: browserLocale('en') });
  const lang: Lang = 'en';
  const t = translator(lang);

  test('renewal by the planner, automatic deployment, and a failed deployment that is rolled back', async ({ page, request }) => {
    test.setTimeout(JOURNEY_TIMEOUT);
    const s = await install(page, request, lang);
    await addAuthorityByApi(s.api, s.creds);
    const loc = await wwwLocation(s.api);
    // Short-lived certificates in Alice's time, so the journey can make one due.
    acmeLifetime(SHORT_LIFETIME);
    await acmeSyncClock(request);

    // A wildcard variant through the wizard, with automatic deployment of new certificates on.
    const dialog = await getCertificateInUI(page, request, lang, s.totpSecret, t, [WWW, WILDCARD], { autoDeploy: true });
    await dialog.getByRole('button', { name: t('acme.issued.getNow'), exact: true }).click();
    await expect(page.getByRole('heading', { level: 1, name: WWW })).toBeVisible();
    const id = certIdFromUrl(page);
    await drainUntil(request, () => expect(page.getByTestId('acme-state')).toHaveText(t('acme.enum.certificateState.active'), { timeout: 3_000 }));
    // The wildcard and its base name share one DNS name: two TXT values side by side, both validated.
    expect(acmeCounters()['validations-dns-01']).toBe(2);
    const first = (await acmeCert(s.api, id)).current!;
    const fp1 = hex(first.fingerprint_sha256);

    // The website with its own automatic deployment on (Administrator, step-up), and the first deployment.
    await s.api.stepUp(s.totpSecret);
    await json(await s.api.put(`/api/v1/acme/certificates/${id}/bindings/${loc}`, { auto_deploy: true }));
    await json(await s.api.post(`/api/v1/acme/certificates/${id}/deploy`, { location_ids: [loc] }), 202);
    await drainUntil(request, async () => expect(served(WWW)).toBe(fp1));
    await page.reload();
    await expect(page.getByTestId('auto-summary')).toContainText(t('acme.issued.bindings.autoSummary', { n: 1, count: 1 }));

    // Not due yet: the planner orders nothing.
    acmeClearRequests();
    await runScheduled(request, 'acme.schedule');
    await drainJobs(request);
    expect(acmeCounters()['new-order'] ?? 0, 'nothing is due yet').toBe(0);

    // Due: the planner renews, and automatic deployment puts the new certificate on the website.
    await advanceClock(request, DUE_AFTER_SECONDS);
    await acmeSyncClock(request);
    // Only a person's action slides the session's idle limit (reads do not): confirm it's you, as a person would.
    await s.api.stepUp(s.totpSecret);
    await runScheduled(request, 'acme.schedule');
    let second: CurrentView | null = null;
    await drainUntil(request, async () => {
      second = (await acmeCert(s.api, id)).current;
      expect(second?.id).not.toBe(first.id);
    });
    const fp2 = hex(second!.fingerprint_sha256);
    expect(fp2).not.toBe(fp1);
    const renewalOrder = (await acmeOrders(s.api, id)).find((o) => o.certificate_id === second!.id);
    expect(renewalOrder?.trigger, 'the planner ordered it').toBe('renewal');
    expect(renewalOrder?.replaces_outcome, 'the renewal named the certificate it replaces (RFC 9773, R50)').toBe('sent');
    expect(renewalOrder?.replaces).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect((await acmeOrders(s.api, id)).find((o) => o.certificate_id === first.id)?.replaces, 'a first order names none').toBe('');
    expect(served(WWW), 'nothing is deployed before the automatic deployment planner runs').toBe(fp1);
    await runScheduled(request, 'acme.auto_deploy');
    await drainUntil(request, async () => expect(served(WWW)).toBe(fp2));
    const auto = (await deployments(s.api)).filter((d) => d.trigger === 'acme_renewal');
    expect(auto.map((d) => d.status), 'the automatic deployment of the renewal').toEqual(['succeeded']);

    // Rollback proof: the next renewal's deployment fails its configuration test after the write; Alice restores the
    // previous certificate, which the website still serves; the website needs attention; the certificate stays active.
    await advanceClock(request, DUE_AFTER_SECONDS);
    await acmeSyncClock(request);
    // Only a person's action slides the session's idle limit (reads do not): confirm it's you, as a person would.
    await s.api.stepUp(s.totpSecret);
    await runScheduled(request, 'acme.schedule');
    let third: CurrentView | null = null;
    await drainUntil(request, async () => {
      third = (await acmeCert(s.api, id)).current;
      expect(third?.id).not.toBe(second!.id);
    });
    const fp3 = hex(third!.fingerprint_sha256);
    testMode('fail-once');
    await runScheduled(request, 'acme.auto_deploy');
    await drainUntil(request, async () => {
      const rolled = (await deployments(s.api)).filter((d) => d.trigger === 'acme_renewal' && d.status !== 'succeeded');
      expect(rolled.map((d) => d.status)).toEqual(['rolled_back']);
    });
    expect(served(WWW), 'the previous certificate is still served').toBe(fp2);
    expect(served(WWW)).not.toBe(fp3);
    const audit = await auditActions(s.api, s.totpSecret, 'deployment.');
    expect(audit).toContain('deployment.rolled_back');
    // The planner's next run marks the website (it waits before it tries again: no new deployment yet).
    const before = (await deployments(s.api)).length;
    await runScheduled(request, 'acme.auto_deploy');
    await drainJobs(request);
    expect((await deployments(s.api)).length, 'a failed website is not retried at once').toBe(before);
    expect(served(WWW)).toBe(fp2);
    await page.goto(`/acme/${id}`);
    await expect(page.getByTestId('acme-state')).toHaveText(t('acme.enum.certificateState.active'));
    await expect(bindingRow(page)).toHaveAttribute('data-state', 'attention');
    await expect(bindingRow(page).getByTestId('attention')).toContainText(t('errors.deployment.config_test_failed.title'));
    await expect(bindingRow(page)).toContainText(t('acme.issued.bindings.servedOlder'));
    expect((await acmeCert(s.api, id)).state).toBe('active');
    await expectAccessible(page, 'status page, a website needs attention', { soft: true });
  });

  // Built-in DNS providers (R57): the fake CA's container answers as the Cloudflare and Route 53 APIs and mirrors their
  // records into its DNS. Their credentials are typed and sent, as the hook secret is: they are the fakes' own and die
  // with the stack.
  test('DNS providers: Cloudflare added in Settings issues a wildcard certificate, Route 53 passes a Test run', async ({ page, request }) => {
    test.setTimeout(JOURNEY_TIMEOUT);
    const s = await install(page, request, lang);
    const a = await addAuthorityByApi(s.api, s.creds);
    const dns = acmeDnsProviders();
    expect(dns.zone).toBe(DOMAIN);
    await openSettingsAcme(page, s.api, s.totpSecret, t);
    await page.getByRole('button', { name: t('acme.settings.addDnsProvider'), exact: true }).click();
    const dialog = page.getByRole('dialog', { name: t('acme.dns.addTitle') });
    await expect(dialog).toBeVisible();
    await expect(field(dialog, t('acme.dns.kind'))).toHaveValue('cloudflare');
    await field(dialog, t('acme.hook.name')).fill('Cloudflare DNS');
    await field(dialog, t('acme.dns.apiToken')).fill(dns.cloudflare.token);
    await field(dialog, t('acme.hook.wait')).fill('0');
    await addSuffix(dialog, t, DOMAIN);
    await expectAccessible(page, `add DNS provider dialog ${lang}`, { soft: true, dialog });
    await dialog.getByRole('button', { name: t('acme.dns.save'), exact: true }).click();
    await expect(dialog.getByText(t('settings.saved'), { exact: true })).toBeVisible();
    await dialog.getByRole('button', { name: t('ui.continue'), exact: true }).click();
    const region = page.getByRole('region', { name: 'Cloudflare DNS', exact: true });
    await expect(region.getByText(t('acme.settings.credentialsConfigured'), { exact: true })).toBeVisible();
    await expect(region.getByText('api.cloudflare.com', { exact: true })).toBeVisible();
    expect(await page.content()).not.toContain(dns.cloudflare.token);

    const hooks = await json<{ items: { id: string; name: string; kind: string; secret_configured: boolean }[] }>(await s.api.get('/api/v1/acme/hooks'));
    const cf = hooks.items.find((h) => h.name === 'Cloudflare DNS');
    expect(cf?.kind).toBe('cloudflare');
    expect(JSON.stringify(hooks)).not.toContain(dns.cloudflare.token);
    const id = await createCertificateByApi(s.api, { providerId: a.providerId, hookId: cf!.id }, [WWW, WILDCARD]);
    const issued = await orderAndWait(s.api, request, id);
    expect(issued.state, JSON.stringify(issued.error)).toBe('succeeded');
    expect(acmeDns(), 'the CA sees no challenge value any more').toEqual({});
    expect(acmeDnsProviders().cloudflare.records, 'Alice removed its values at Cloudflare').toEqual({});

    const r53 = await json<{ id: string }>(
      await s.api.post('/api/v1/acme/hooks', {
        kind: 'route53',
        name: 'Route 53',
        access_key_id: dns.route53.access_key_id,
        secret_access_key: dns.route53.secret_access_key,
        allowed_suffixes: [DOMAIN],
        propagation_wait_seconds: 0,
        poll_timeout_seconds: 20,
      }),
      201,
    );
    const testId = await createCertificateByApi(s.api, { providerId: a.providerId, hookId: r53.id }, ['api.example.test']);
    const tested = await orderAndWait(s.api, request, testId, 'test');
    expect(tested.state, JSON.stringify(tested.error)).toBe('succeeded');
    expect(acmeDnsProviders().route53.records, 'Alice removed its value at Route 53').toEqual({});
  });

  test('failures: the CA rate limits, the hook is down, records left by a failed order are cleaned up', async ({ page, request }) => {
    test.setTimeout(JOURNEY_TIMEOUT);
    const s = await install(page, request, lang);
    const a = await addAuthorityByApi(s.api, s.creds, { wait: 3 });

    // The CA rate limits new orders: the order fails, the page says so in plain words and when Alice tries again.
    const limited = await createCertificateByApi(s.api, a, [WWW]);
    acmeFault({ endpoint: 'new-order', kind: 'rateLimited', retryAfter: 7200 });
    await openStatus(page, limited, WWW);
    await page.getByRole('button', { name: t('acme.issued.getNow'), exact: true }).click();
    await drainUntil(request, () => expect(page.getByTestId('acme-state')).toHaveText(t('acme.enum.certificateState.failing'), { timeout: 3_000 }));
    await expect(page.getByTestId('failing')).toContainText(t('acme.issued.renewal.failingTitle'));
    // The next attempt as the page formats it (the browser's own date format and time zone, the page's language).
    const nextAt = (await acmeCert(s.api, limited)).next_attempt_at;
    expect(nextAt).not.toBeNull();
    const formatted = await page.evaluate(
      ([iso, locale]) => new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(iso)),
      [nextAt!, await page.evaluate(() => document.documentElement.lang)] as const,
    );
    await expect(page.getByTestId('next-attempt')).toHaveText(formatted);
    await expect(page.getByTestId('failing')).toContainText(t('acme.issued.renewal.failingNext', { count: 1, time: formatted }));
    const last = page.getByTestId('last-error');
    await expect(last).toContainText(t('errors.acme.ca_rate_limited.title'));
    await expect(last).toContainText(t('errors.acme.ca_rate_limited.action'));
    await expect(last).toContainText('ALC-ACM-0005');
    const view = await acmeCert(s.api, limited);
    expect(view.next_attempt_at).not.toBeNull();
    expect(Date.parse(view.next_attempt_at!) - Date.now(), 'the CA asked for two hours').toBeGreaterThan(3600_000);
    await expectAccessible(page, 'status page, rate limited', { soft: true });
    acmeFault('clear');

    // The hook is down: the order fails at once with the hook's refusal; nothing is left published.
    const hookDown = await createCertificateByApi(s.api, a, ['api.example.test']);
    acmeFault({ endpoint: 'hook', kind: 'serverInternal' });
    await openStatus(page, hookDown, 'api.example.test');
    await page.getByRole('button', { name: t('acme.issued.getNow'), exact: true }).click();
    const failedRow = page.getByTestId('acme-order').first();
    await drainUntil(request, () => expect(failedRow).toHaveAttribute('data-state', 'failed', { timeout: 3_000 }));
    await expect(failedRow).toContainText(t('errors.acme.hook_refused.title'));
    await expect(page.getByTestId('last-error')).toContainText('ALC-ACM-0008');
    expect(acmeCounters().finalize ?? 0).toBe(0);
    expect(Object.keys(acmeDns())).toEqual([]);
    acmeFault('clear');

    // The hook goes down while an order waits for its record to spread, and the CA cannot verify the name: the order
    // fails, its record cannot be removed then, and the cleanup job removes it once the hook answers again.
    const midway = await createCertificateByApi(s.api, a, ['mid.example.test']);
    await json(await s.api.post(`/api/v1/acme/certificates/${midway}/order`), 202);
    const drain = drainJobs(request, { allowCutOff: false });
    // Settled at once: a failure while the steps below run must not become an unhandled rejection; it is still
    // reported where the drain is awaited.
    const drained = drain.then(
      () => null,
      (e: unknown) => e,
    );
    await expect.poll(() => acmeCounters()['hook-present'] ?? 0, { timeout: 20_000, intervals: [100] }).toBeGreaterThanOrEqual(1);
    acmeCtl('validation-fail', 'dns-01', 'on');
    acmeFault({ endpoint: 'hook', kind: 'serverInternal' });
    expect(await drained, 'the drain of the order').toBeNull();
    let order: OrderView | undefined;
    await drainUntil(request, async () => {
      order = (await acmeOrders(s.api, midway))[0];
      expect(order.state).toBe('failed');
    });
    expect(order!.error?.reason).toBe('acme.validation_failed_dns');
    expect(Object.keys(acmeDns()), 'the record is still published while the hook is down').toContain('_acme-challenge.mid.example.test');
    acmeFault('clear');
    acmeCtl('validation-fail', 'dns-01', 'off');
    // The cleanup job's retry is due after the queue's backoff (30 s at most +20 %).
    await advanceClock(request, 60);
    await drainUntil(request, async () => expect(Object.keys(acmeDns())).toEqual([]));
    await expect.poll(async () => (await acmeOrders(s.api, midway))[0].presented).toBe(0);
    expect(await auditActions(s.api, s.totpSecret, 'acme.order.')).toContain('acme.order.cleaned_up');
    await openStatus(page, midway, 'mid.example.test');
    await expect(page.getByTestId('acme-order').first()).toContainText(t('errors.acme.validation_failed_dns.title'));
  });

  test('licence lock: Order now and Test run are refused, the planner contacts no one', async ({ page, request }) => {
    test.setTimeout(JOURNEY_TIMEOUT);
    const s = await install(page, request, lang);
    const a = await addAuthorityByApi(s.api, s.creds);
    const id = await createCertificateByApi(s.api, a, [WWW]);
    // The evaluation ends: the licence locks changes.
    await advanceClock(request, 31 * DAY_SECONDS);
    await signIn(page, request, ADMIN, s.totpSecret);
    const api = await apiAs(page);
    acmeClearRequests();
    await openStatus(page, id, WWW);
    await expect(page.getByText(t('acme.issued.lockedTitle'), { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: t('acme.issued.testRun'), exact: true })).toBeDisabled();
    await expect(page.getByRole('button', { name: t('acme.issued.getNow'), exact: true })).toBeDisabled();
    for (const path of ['order', 'test']) {
      const res = await api.post(`/api/v1/acme/certificates/${id}/${path}`);
      expect(res.status(), `${path} in lock`).toBe(403);
      const body = (await res.json()) as { error: { code: string; reason: string; message: string } };
      expect(body.error.code).toBe('ALC-LIC-0001');
      expect(body.error.reason).toBe('license.locked');
      // The plain licence text, in the account's language.
      expect(body.error.message).toContain(LOCK_TITLE);
    }
    expect(t('errors.license.locked.title')).toBe(LOCK_TITLE);
    await page.goto('/acme');
    await expect(page.getByRole('button', { name: t('acme.issued.getCertificate'), exact: true })).toBeDisabled();
    // The scheduler pauses the planners in lock (the e2e run endpoint answers with the scheduler's gate).
    for (const task of ['acme.schedule', 'acme.auto_deploy']) {
      const res = await request.post('/test/scheduler/run', { data: { task } });
      expect(res.ok(), `${task} runs in lock`).toBe(false);
      expect(await res.text()).toContain('paused while the license is expired');
    }
    await drainJobs(request);
    expect(acmeCounters().requests ?? 0, 'the CA was contacted in lock').toBe(0);
    expect(await acmeOrders(api, id)).toEqual([]);
    await expectAccessible(page, 'issued certificates list in lock', { soft: true });
  });

  test('roles: an Operator tests and deploys but cannot switch automatic deployment on; an Auditor reads', async ({ page, request }) => {
    test.setTimeout(JOURNEY_TIMEOUT);
    const s = await install(page, request, lang);
    const a = await addAuthorityByApi(s.api, s.creds);
    const id = await createCertificateByApi(s.api, a, [WWW]);
    const ordered = await orderAndWait(s.api, request, id);
    expect(ordered.state).toBe('succeeded');
    const fp = hex((await acmeCert(s.api, id)).current!.fingerprint_sha256);
    const loc = await wwwLocation(s.api);
    await json(await s.api.put(`/api/v1/acme/certificates/${id}/bindings/${loc}`, { auto_deploy: false }));
    for (const [account, role] of [
      [OPERATOR, 'operator'],
      [AUDITOR, 'auditor'],
    ] as const) {
      await s.api.stepUp(s.totpSecret);
      await json(await s.api.post('/api/v1/users', { username: account.username, display_name: account.fullName, email: '', role, password: account.password }), 201);
    }
    await page.reload(); // the step-ups rotated the session's CSRF token
    await signOut(page);

    // The Operator.
    await firstSignIn(page, request, OPERATOR);
    await page.goto('/acme');
    await expect(page.getByTestId('acme-certificate-row')).toHaveCount(1);
    await expect(page.getByRole('button', { name: t('acme.issued.getCertificate') })).toHaveCount(0);
    await openStatus(page, id, WWW);
    await expect(page.getByRole('button', { name: t('acme.issued.delete'), exact: true })).toHaveCount(0);
    await expect(page.getByRole('switch', { name: t('acme.issued.renewal.auto') })).toHaveCount(0);
    await expect(page.getByTestId('cert-auto-deploy').getByRole('switch')).toHaveCount(0);
    const siteSwitch = page.getByRole('switch', { name: t('acme.issued.bindings.autoNamed', { site: `"${SERVER}" ${await bindingPath(page)}` }) });
    await expect(siteSwitch).toBeDisabled();
    await expect(page.getByText(t('acme.issued.bindings.autoAdminOnly'))).toBeVisible();
    const opApi = await apiAs(page);
    const refused = await opApi.put(`/api/v1/acme/certificates/${id}/bindings/${loc}`, { auto_deploy: true });
    expect(refused.status(), 'an Operator switches automatic deployment on').toBe(403);
    // Test run.
    await page.getByRole('button', { name: t('acme.issued.testRun'), exact: true }).click();
    await drainUntil(request, () => expect(page.getByTestId('test-result')).toContainText(t('acme.issued.test.ok'), { timeout: 3_000 }));
    // Deploy now.
    await deployNowInUI(page, request, t, fp);
    await expectAccessible(page, 'status page as an Operator', { soft: true });
    await signOut(page);

    // The Auditor reads only.
    await firstSignIn(page, request, AUDITOR);
    await page.goto('/acme');
    await expect(page.getByTestId('acme-certificate-row')).toHaveCount(1);
    await expect(page.getByRole('button', { name: t('acme.issued.getCertificate') })).toHaveCount(0);
    await openStatus(page, id, WWW);
    await expect(page.getByText(t('acme.issued.readOnly'), { exact: true })).toBeVisible();
    for (const key of ['acme.issued.testRun', 'acme.issued.orderNow', 'acme.issued.delete', 'acme.issued.deployNow', 'acme.issued.bindings.add']) {
      await expect(page.getByRole('button', { name: t(key), exact: true }), key).toHaveCount(0);
    }
    await expect(page.getByRole('switch')).toHaveCount(0);
    const audApi = await apiAs(page);
    expect((await audApi.post(`/api/v1/acme/certificates/${id}/test`)).status(), 'an Auditor starts a Test run').toBe(403);
    await expectAccessible(page, 'status page as an Auditor', { soft: true });
  });

  test('HTTP-01: the web proof through the webroot of the Nginx server', async ({ page, request }) => {
    test.setTimeout(JOURNEY_TIMEOUT);
    const s = await install(page, request, lang);
    const a = await addAuthorityByApi(s.api, s.creds);
    // www.example.test points at the target on the e2e network (a compose alias), for Alice's own check; the fake CA
    // dials only names it was told about.
    acmeHttpTarget(WWW, `${WWW}:80`);
    const id = await createCertificateByApi(s.api, a, [WWW], { challenge: 'http01', hook_id: null, http_target_id: s.serverId });
    await openStatus(page, id, WWW);
    await expect(page.getByText(t('acme.enum.challenge.http01')).first()).toBeVisible();
    await page.getByRole('button', { name: t('acme.issued.getNow'), exact: true }).click();
    await drainUntil(request, () => expect(page.getByTestId('acme-state')).toHaveText(t('acme.enum.certificateState.active'), { timeout: 3_000 }));
    const counters = acmeCounters();
    expect(counters['validations-http-01'] ?? 0, 'the CA fetched the token from the website').toBe(1);
    expect(counters['validations-dns-01'] ?? 0).toBe(0);
    expect(targetExec(['ls', '-A', CHALLENGE_DIR]).trim(), 'the token file is removed').toBe('');
  });
});

// bindingPath reads the certificate file of the www.example.test row on the status page.
async function bindingPath(page: Page): Promise<string> {
  const path = ((await bindingRow(page).locator('code').first().textContent()) ?? '').trim();
  expect(path).not.toBe('');
  return path;
}

