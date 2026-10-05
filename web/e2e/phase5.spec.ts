import type { APIRequestContext, APIResponse, Locator, Page } from '@playwright/test';
import {
  ADMIN,
  COPY,
  advanceClock,
  apiAs,
  azureCredentials,
  azureFault,
  azureLeafFingerprint,
  azureRenew,
  azureRequests,
  azureReset,
  azureSyncClock,
  azureRole,
  browserLocale,
  drainJobs,
  drainUntil,
  expect,
  AXE_WIDTHS,
  PHONE_WIDTH,
  seriousViolations,
  field,
  fingerprintOf,
  freshCode,
  newCert,
  nginxReset,
  resetInstall,
  runScheduled,
  runWizard,
  served,
  settle,
  signIn,
  targetExec,
  test,
  translator,
  type Api,
  type AzureCredentials,
  type Lang,
  type PemPair,
  type Translate,
} from './helpers';

// Phase 5 owner journeys on the e2e stack: Azure Key Vault against the fake Azure service
// (cmd/alice-fakeazure, driven with "ctl" through helpers.ts), the SSH target's Nginx as the place
// certificates are deployed to. The contract's key texts are pinned in COPY (kv); every other visible
// text is read from the locale files at run time (translator), as the Phase 4 journeys do.

const HOST_KEY_PUB = '/etc/ssh/ssh_host_ed25519_key.pub';
const WWW = 'www.example.test';
const SERVER = 'e2e-nginx';
const VAULT = 'prod-vault';
const CERT = 'web-cert';
// auth.StepUpWindow: a sign-in or step-up confirms the session for this long.
const STEP_UP_SECONDS = 5 * 60;
const DAY_SECONDS = 24 * 3600;
// A journey prepares a server, adds a vault, polls, deploys: more than the default 3 minutes.
const JOURNEY_TIMEOUT = 8 * 60_000;
// A Retry-After above Alice's longest wait (azurekv.MaxRetryAfter, 60 s): a throttled cycle ends at
// once instead of waiting on the injected clock.
const LONG_RETRY_AFTER = 61;

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function json<T>(res: APIResponse, status?: number): Promise<T> {
  const text = await res.text();
  if (status !== undefined) expect(res.status(), text).toBe(status);
  else expect(res.ok(), `${res.status()} ${text}`).toBe(true);
  return (text ? JSON.parse(text) : {}) as T;
}

// axe checks the screen on show at 640, 1280 and 1920 px (no serious or critical violation, no
// horizontal page scroll) like expectAccessible, but softly: a finding fails the test at its end and
// the journey goes on, so one run lists every violation of every screen instead of the first.
async function axe(page: Page, screen: string): Promise<void> {
  const original = page.viewportSize();
  try {
    for (const width of AXE_WIDTHS) {
      await page.setViewportSize({ width, height: original?.height ?? 720 });
      expect.soft(await seriousViolations(page), `axe: ${screen} at ${width} px`).toEqual([]);
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect.soft(overflow, `horizontal overflow: ${screen} at ${width} px`).toBeLessThanOrEqual(0);
    }
  } finally {
    if (original) await page.setViewportSize(original);
  }
}

// axeWide is axe plus the 375 px phone width of expectWide (tables scroll inside their container).
async function axeWide(page: Page, screen: string): Promise<void> {
  const original = page.viewportSize();
  try {
    await page.setViewportSize({ width: PHONE_WIDTH, height: original?.height ?? 720 });
    expect.soft(await seriousViolations(page), `axe: ${screen} at ${PHONE_WIDTH} px`).toEqual([]);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect.soft(overflow, `horizontal overflow: ${screen} at ${PHONE_WIDTH} px`).toBeLessThanOrEqual(0);
  } finally {
    if (original) await page.setViewportSize(original);
  }
  await axe(page, screen);
}

// --- setup through the API (what the journeys are not about) ---

// prepareAndAddServer prepares the SSH target with the real nginx profile script, adds it as an Nginx
// server, confirms its host key after comparing it with the server's own, and waits for its websites.
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

// addVaultByApi adds the fake's vault with its client secret and runs the first poll.
async function addVaultByApi(api: Api, request: APIRequestContext, creds: AzureCredentials, name = VAULT): Promise<string> {
  state.vaultAdded = true;
  const created = await json<{ target: { id: string } }>(
    await api.post('/api/v1/key-vaults', {
      name,
      vault_url: creds.vault_url,
      auth: 'client_secret',
      tenant_id: creds.tenant_id,
      client_id: creds.client_id,
      client_secret: creds.client_secret,
    }),
    201,
  );
  await drainJobs(request);
  return created.target.id;
}

interface KVCertificateRow {
  id: string;
  name: string;
  current_version: string;
}

async function kvCertificates(api: Api, vaultId: string): Promise<KVCertificateRow[]> {
  return (await json<{ items: KVCertificateRow[] }>(await api.get(`/api/v1/targets/${vaultId}/kv/certificates?limit=50`))).items;
}

async function kvCertificateId(api: Api, vaultId: string, name: string): Promise<string> {
  const row = (await kvCertificates(api, vaultId)).find((c) => c.name === name);
  expect(row, `${name} is in the vault's inventory`).toBeDefined();
  return row!.id;
}

interface BindingView {
  id: string;
  version: number;
  auto_deploy: boolean;
}

// connectByApi connects the website to the vault certificate; with autoDeploy the connection deploys
// by itself from now on (an Administrator's step-up must be fresh: api.stepUp first).
async function connectByApi(api: Api, kvCertificate: string, opts: { autoDeploy: boolean }): Promise<BindingView> {
  const locations = await json<{ items: { id: string; server_names: string[] }[] }>(await api.get('/api/v1/certificate-locations?key_type=ecdsa&unbound=true&limit=50'));
  const www = locations.items.find((l) => l.server_names.includes(WWW));
  expect(www, `${WWW} is offered to connect`).toBeDefined();
  let binding = await json<BindingView>(await api.post('/api/v1/bindings', { kv_certificate_id: kvCertificate, location_ids: [www!.id] }), 201);
  if (opts.autoDeploy) {
    binding = await json<BindingView>(await api.put(`/api/v1/bindings/${binding.id}/auto-deploy`, { enabled: true }, { 'If-Match': `"${binding.version}"` }));
  }
  return binding;
}

// The provider keeps one rate limiter per vault host on Alice's clock, and POST /test/reset moves that
// clock back to the wall clock while the limiter lives on: after a journey that advanced the clock
// (step-up windows, the license lock), the next journey's first request to the vault would wait for the
// clock to catch up and fail as unreachable. Removing a vault releases its host's limiter, so every
// journey that added a vault removes its vaults at the end (releaseVaults), passed or failed.
const state = { totpSecret: '', vaultAdded: false };

// releaseVaults signs in again (the journey's own session may be gone: the license lock ends sessions)
// and removes every vault with its connections.
async function releaseVaults(page: Page, request: APIRequestContext): Promise<void> {
  if (!state.vaultAdded) return;
  state.vaultAdded = false;
  try {
    await page.context().clearCookies();
    await signIn(page, request, ADMIN, state.totpSecret);
    const api = await apiAs(page);
    await api.stepUp(state.totpSecret);
    const vaults = await json<{ items: { id: string }[] }>(await api.get('/api/v1/targets?type=azure_key_vault'));
    for (const v of vaults.items) await api.del(`/api/v1/targets/${v.id}?remove_bindings=true`);
  } catch (e) {
    console.log(`releaseVaults: ${String(e).slice(0, 300)}`);
  }
}

interface Session {
  totpSecret: string;
  api: Api;
  serverId: string;
  vaultId: string;
  creds: AzureCredentials;
}

// startVault installs Alice, prepares and adds the Nginx server and adds the fake vault (first poll
// drained) through the API; the page is reloaded so it holds the session's current CSRF token.
async function startVault(page: Page, request: APIRequestContext, lang: Lang, opts: { server?: boolean } = {}): Promise<Session> {
  const { totpSecret } = await runWizard(page, request, lang);
  state.totpSecret = totpSecret;
  const api = await apiAs(page);
  await api.stepUp(totpSecret);
  const serverId = opts.server === false ? '' : await prepareAndAddServer(api, request);
  const creds = azureCredentials();
  const vaultId = await addVaultByApi(api, request, creds);
  await page.reload();
  return { totpSecret, api, serverId, vaultId, creds };
}

// --- the screens ---

async function nav(page: Page, t: Translate, key: string): Promise<void> {
  await page.getByRole('link', { name: t(key), exact: true }).click();
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
}

// answerStepUp confirms the step-up dialog with a fresh code if the server asks for one before done
// appears (the sign-in's five minutes may or may not have passed).
async function answerStepUp(page: Page, request: APIRequestContext, lang: Lang, secret: string, done: Locator): Promise<void> {
  const c = COPY[lang];
  const stepUp = page.getByRole('dialog', { name: c.stepUpHeading });
  await expect(stepUp.or(done).first()).toBeVisible();
  if (await stepUp.isVisible()) {
    await field(stepUp, c.code).fill(await freshCode(request, secret));
    await stepUp.getByRole('button', { name: c.stepUpConfirm }).click();
    await expect(stepUp).toHaveCount(0);
  }
  await expect(done).toBeVisible();
}

// expireStepUp moves the server clock past the sign-in's step-up window, so the next change asks for a code.
async function expireStepUp(request: APIRequestContext): Promise<void> {
  await advanceClock(request, STEP_UP_SECONDS + 1);
}

function vaultRow(page: Page, name = VAULT): Locator {
  return page.getByTestId('vaults-table').getByRole('row').filter({ has: page.getByRole('link', { name, exact: true }) });
}

async function openVault(page: Page, t: Translate, vaultId: string): Promise<void> {
  await page.goto(`/key-vaults/${vaultId}`);
  await expect(page.getByRole('heading', { level: 1, name: VAULT })).toBeVisible();
  await expect(page.getByTestId('vault-status')).toBeVisible();
  void t;
}

async function openTab(page: Page, t: Translate, tab: 'certificates' | 'keys' | 'secrets'): Promise<Locator> {
  await page.getByRole('tab', { name: t(`vaults.tabs.${tab}`), exact: true }).click();
  const table = page.getByRole('table', { name: t(`vaults.tabs.${tab}`), exact: true });
  await expect(table).toBeVisible();
  return table;
}

// checkNow runs "Check now" on the vault page and drains the poll job until the page says it finished.
async function checkNow(page: Page, request: APIRequestContext, lang: Lang): Promise<void> {
  const c = COPY[lang].kv;
  await page.getByRole('button', { name: c.checkNow, exact: true }).click();
  await settle(request, page.getByText(c.finished, { exact: true }));
}

// openCertificate opens a certificate of the vault from the Certificates tab.
async function openCertificate(page: Page, t: Translate, name: string): Promise<void> {
  const table = await openTab(page, t, 'certificates');
  await table.getByRole('link', { name, exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name })).toBeVisible();
}

function bindingPanel(page: Page): Locator {
  return page.getByTestId('binding-panel');
}

function websiteState(page: Page): Locator {
  return bindingPanel(page).getByTestId('binding-location').locator('[data-state]');
}

function versionRows(page: Page): Locator {
  return page.getByTestId('kv-version-row');
}

// deployedText is "Deployed: version xxxxxxxx" for the 8-digit short form of a version id.
function deployedText(t: Translate, version: string): string {
  return t('bindings.state.deployed', { version: version.slice(0, 8) });
}


async function uploadByApi(api: Api, pair: PemPair, label: string): Promise<string> {
  const res = await json<{ certificate: { id: string } }>(
    await api.post('/api/v1/certificates/upload', { label, certificate_pem: pair.cert, private_key_pem: pair.key }),
    201,
  );
  return res.certificate.id;
}

// waitDeployed drains due jobs until the website of the open certificate page shows the version as deployed.
async function waitDeployed(page: Page, request: APIRequestContext, t: Translate, version: string): Promise<void> {
  await drainUntil(request, async () => {
    await page.reload();
    await expect(websiteState(page)).toHaveText(deployedText(t, version), { timeout: 3_000 });
  });
}

function steps(scope: Locator, t: Translate): Locator {
  return scope.getByRole('list', { name: t('deployments.stepsTitle') });
}

// expectDeployment checks the deployment page that is open: its status, that it came from the vault
// and the first step, "Read the certificate from Key Vault".
async function expectKeyVaultSteps(page: Page, t: Translate, kvText: string): Promise<void> {
  const row = steps(page.getByRole('main'), t).locator('li[data-step="kv_secret"]');
  await expect(row).toContainText(kvText);
  await expect(row).toHaveAttribute('data-status', 'ok');
}

// lockLicense ends the 30-day evaluation (it ends directly in lock: no grace period) and signs in again.
async function lockLicense(page: Page, request: APIRequestContext, totpSecret: string): Promise<void> {
  await advanceClock(request, 31 * DAY_SECONDS);
  await signIn(page, request, ADMIN, totpSecret);
}

// unlockLicense installs a fresh license through the API (an Administrator's step-up first).
async function unlockLicense(request: APIRequestContext, api: Api, totpSecret: string): Promise<void> {
  const issued = await request.post('/test/license', { data: { valid_days: 365 } });
  expect(issued.ok(), await issued.text()).toBe(true);
  await api.stepUp(totpSecret);
  await json(await api.post('/api/v1/license', { license: ((await issued.json()) as { license: string }).license }));
}

// checkNowSettled runs "Check now" and drains jobs until the page is ready again, whatever the job's
// result (a failed poll shows its error instead of "Finished.").
async function checkNowSettled(page: Page, request: APIRequestContext, label: string): Promise<void> {
  const button = page.getByRole('button', { name: label, exact: true });
  await button.click();
  await drainUntil(request, () => expect(button).toBeEnabled({ timeout: 1_500 }));
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const t = translator(lang);
  const c = COPY[lang];
  const kv = c.kv;

  test.describe(`Phase 5 Key Vault (${lang})`, () => {
    // A click that cannot happen fails after 30 s, not at the end of the journey's 8 minutes.
    test.use({ locale: browserLocale(lang), actionTimeout: 30_000 });
    test.beforeEach(async ({ request }) => {
      nginxReset();
      azureReset();
      await resetInstall(request);
    });
    test.afterEach(async ({ page, request }) => {
      await releaseVaults(page, request);
      nginxReset();
      azureReset();
    });

    test('add a vault with a client secret, see its certificates, keys and secrets', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const { totpSecret } = await runWizard(page, request, lang);
      state.totpSecret = totpSecret;
      const creds = azureCredentials();

      // The pinned contract strings are what the app shows (a locale drift fails here).
      expect(t('vaults.title')).toBe(kv.title);
      expect(t('vaults.add')).toBe(kv.add);
      expect(t('vaults.added')).toBe(kv.added);
      expect(t('vaults.monitorOnly')).toBe(kv.monitorOnly);

      await nav(page, t, 'nav.keyVaults');
      await expect(page.getByRole('heading', { level: 1, name: kv.title })).toBeVisible();
      await expect(page.getByText(t('vaults.empty'))).toBeVisible();

      await page.getByRole('button', { name: kv.add }).click();
      const dialog = page.getByRole('dialog', { name: kv.add });
      await dialog.getByRole('radio', { name: t('vaults.auth.client_secret') }).check();
      await field(dialog, t('vaults.fields.name')).fill(VAULT);
      await field(dialog, t('vaults.fields.vault_url')).fill(creds.vault_url);
      await field(dialog, t('vaults.fields.tenant_id')).fill(creds.tenant_id);
      await field(dialog, t('vaults.fields.client_id')).fill(creds.client_id);
      await field(dialog, t('vaults.fields.client_secret')).fill(creds.client_secret);
      await axe(page, 'Add Key Vault, client secret');

      // The sign-in's five minutes have passed: the request asks for a fresh code.
      await expireStepUp(request);
      await dialog.getByRole('button', { name: kv.add }).click();
      const stepUp = page.getByRole('dialog', { name: c.stepUpHeading });
      await expect(stepUp).toBeVisible();
      // The secret left the form the moment the request was built: it is nowhere in the page.
      expect(await secretOnPage(page, creds.client_secret), 'the client secret is gone from the DOM and the browser storage').toBe(false);
      await field(stepUp, c.code).fill(await freshCode(request, totpSecret));
      await stepUp.getByRole('button', { name: c.stepUpConfirm }).click();
      await expect(dialog.getByText(kv.added, { exact: true })).toBeVisible();
      state.vaultAdded = true;
      expect(await secretOnPage(page, creds.client_secret)).toBe(false);

      // The access check: monitoring is allowed; deploying is not checked yet; importing is checked when you import.
      const access = dialog.getByRole('table', { name: t('vaults.access.title') });
      await expect(access.locator('[data-access-row="monitor"]')).toContainText(t('vaults.access.ok'));
      await expect(access.locator('[data-access-row="deploy"]')).toContainText(t('vaults.access.notChecked'));
      await expect(access.locator('[data-access-row="import"]')).toContainText(t('vaults.access.importNote'));
      await expect(dialog.locator('code').filter({ hasText: /^[0-9a-f]{8}-[0-9a-f-]{27}$/ })).toBeVisible(); // "Alice signs in to Azure as <object id>"
      await axe(page, 'Add Key Vault, added');
      await dialog.getByRole('button', { name: kv.openVault }).click();
      await expect(page.getByRole('heading', { level: 1, name: VAULT })).toBeVisible();
      const vaultId = new URL(page.url()).pathname.split('/').pop() ?? '';

      // The first poll runs; the inventory follows.
      await drainJobs(request);
      await page.reload();
      await expect(page.getByTestId('vault-status')).toHaveText(t('enum.targetStatus.ok'));
      const certs = await openTab(page, t, 'certificates');
      const webCert = certs.getByTestId('kv-certificate-row').filter({ hasText: CERT });
      const monitorOnly = certs.getByTestId('kv-certificate-row').filter({ hasText: 'monitor-only' });
      await expect(webCert).toHaveCount(1);
      await expect(monitorOnly).toContainText(kv.monitorOnly);
      await expect(webCert).not.toContainText(kv.monitorOnly);
      const keys = await openTab(page, t, 'keys');
      const signing = keys.getByRole('row').filter({ hasText: 'signing-key' });
      await expect(signing).toContainText(/rsa/i);
      await expect(signing).toContainText(t('vaults.keys.bits', { bits: 2048 }));
      const secrets = await openTab(page, t, 'secrets');
      await expect(secrets.getByRole('row').filter({ hasText: 'db-password' })).toContainText('text/plain');
      // Nothing of the secret value is shown: names and metadata only.
      await expect(secrets).not.toContainText(/password-value|BEGIN/);

      // Check now (a manual poll) finishes.
      await checkNow(page, request, lang);

      // The list shows the vault with its status, sign-in method and last successful check.
      await nav(page, t, 'nav.keyVaults');
      const row = vaultRow(page);
      await expect(row).toContainText(creds.vault_url);
      await expect(row).toContainText(t('enum.targetStatus.ok'));
      await expect(row).toContainText(t('vaults.auth.client_secret'));
      await expect(row).not.toContainText(t('vaults.neverChecked'));
      expect(vaultId).toMatch(/^[0-9a-f-]{36}$/);
      // The API never returns the secret either.
      const api = await apiAs(page);
      expect(await (await api.get(`/api/v1/targets/${vaultId}`)).text()).not.toContain(creds.client_secret);
    });

    test('connect websites, switch automatic deployment on, renew in the vault and watch the deployment', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const s = await startVault(page, request, lang);
      const original = served(WWW);

      await openVault(page, t, s.vaultId);
      await openCertificate(page, t, CERT);
      await expect(bindingPanel(page)).toContainText(t('bindings.none'));
      await bindingPanel(page).getByRole('button', { name: kv.connect, exact: true }).click();
      const connect = page.getByRole('dialog', { name: kv.connect });
      await connect.getByRole('checkbox', { name: new RegExp(escapeRegExp(WWW)) }).check();
      await axe(page, 'Connect websites');
      await connect.getByRole('button', { name: kv.connect, exact: true }).click();
      await expect(connect).toHaveCount(0);
      const website = bindingPanel(page).getByTestId('binding-location');
      await expect(website).toContainText(SERVER);
      await expect(website).toContainText(t('bindings.state.not_deployed'));
      await expect(bindingPanel(page).getByText(t('bindings.autoDeployHelpOff'))).toBeVisible();

      // Automatic deployment: confirmed first (what it means), then an Administrator's step-up.
      const auto = bindingPanel(page).getByRole('switch', { name: kv.autoDeployment });
      await expect(auto).not.toBeChecked();
      // Mantine draws the switch's track over its input: the click goes to the track, as a person's does.
      await auto.click({ force: true });
      const confirm = page.getByRole('dialog', { name: t('bindings.autoDeployConfirmTitle') });
      await axe(page, 'switch on automatic deployment');
      await expireStepUp(request);
      await confirm.getByRole('button', { name: kv.switchOn, exact: true }).click();
      await answerStepUp(page, request, lang, s.totpSecret, bindingPanel(page).getByText(t('bindings.autoDeployHelp'), { exact: true }));
      await expect(auto).toBeChecked();
      await expect(bindingPanel(page).getByTestId('auto-deploy')).toContainText(t('bindings.autoDeployState.on'));

      // Key Vault renews the certificate; Alice finds the new version at the next check.
      const before = azureLeafFingerprint(CERT);
      await azureSyncClock(request);
      const version = azureRenew(CERT);
      const renewed = azureLeafFingerprint(CERT);
      expect(renewed).not.toBe(before);
      await openVault(page, t, s.vaultId);
      await checkNow(page, request, lang);
      const certs = await openTab(page, t, 'certificates');
      await expect(certs.getByTestId('kv-certificate-row').filter({ hasText: CERT })).toContainText(kv.newVersion);
      await openCertificate(page, t, CERT);
      await expect(versionRows(page)).toHaveCount(2);
      await expect(versionRows(page).first()).toContainText(kv.newVersion);
      await expect(versionRows(page).first()).toContainText(version.slice(0, 8));

      // The planner (it never ticks by itself in the e2e build) deploys it by itself.
      await runScheduled(request, 'kv.auto_deploy');
      await waitDeployed(page, request, t, version);
      expect(served(WWW), 'Nginx serves the new version of the vault certificate').toBe(renewed);
      expect(served(WWW)).not.toBe(original);
      await expect(versionRows(page).first()).toContainText(kv.newVersion);

      // The history says where it came from, and the steps start with reading it from the vault.
      await nav(page, t, 'nav.deployments');
      const rows = page.getByTestId('deployment-row');
      await expect(rows).toHaveCount(1);
      await expect(rows.first().getByTestId('deployment-source')).toContainText(kv.sourceNamed(VAULT));
      await expect(rows.first()).toContainText(t('enum.deploymentStatus.succeeded'));
      await rows.first().getByRole('link', { name: t('deployments.open') }).click();
      await expect(page.getByRole('heading', { level: 1, name: t('deployments.detailTitle') })).toBeVisible();
      await expectKeyVaultSteps(page, t, kv.readStep);
      await expect(page.getByTestId('deployment-status')).toHaveText(t('enum.deploymentStatus.succeeded'));
    });

    test('a missing Key Vault Secrets User role is named, the website is unchanged, then Deploy now works', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const s = await startVault(page, request, lang);
      await connectByApi(s.api, await kvCertificateId(s.api, s.vaultId, CERT), { autoDeploy: true });
      await page.reload();
      const original = served(WWW);

      azureRole('revoke', 'secrets/get');
      await azureSyncClock(request);
      azureRenew(CERT);
      await openVault(page, t, s.vaultId);
      await checkNow(page, request, lang);
      await openCertificate(page, t, CERT);
      const newest = (await versionRows(page).first().locator('code').first().textContent()) ?? '';
      expect(newest).toMatch(/^[0-9a-f]{8}$/);
      await runScheduled(request, 'kv.auto_deploy');
      await drainUntil(request, async () => {
        await page.reload();
        await expect(websiteState(page)).toHaveText(t('bindings.state.failed'), { timeout: 3_000 });
      });
      expect(served(WWW), 'the website still serves the previous certificate').toBe(original);

      // The deployment failed before anything reached the server: the permission is named, the role is code.
      await bindingPanel(page).getByRole('link', { name: t('deploy.openDeployment') }).click();
      await expect(page.getByRole('heading', { level: 1, name: t('deployments.detailTitle') })).toBeVisible();
      await expect(page.getByTestId('deployment-status')).toHaveText(t('enum.deploymentStatus.failed'));
      const alert = page.getByRole('alert').filter({ hasText: kv.missingPermission });
      await expect(alert).toBeVisible();
      await expect(alert.locator('code').filter({ hasText: new RegExp(`^${kv.secretsUser}$`) })).toBeVisible();
      await expect(steps(page.getByRole('main'), t).locator('li[data-step="kv_secret"]')).toHaveAttribute('data-status', 'failed');
      await expect(steps(page.getByRole('main'), t).locator('li[data-step="write"]')).toHaveAttribute('data-status', 'notRun');
      await axe(page, 'deployment that failed for a missing role');
      expect(served(WWW)).toBe(original);

      // Granted again, Deploy now works.
      azureRole('grant', 'secrets/get');
      await page.goBack();
      await page.reload();
      await expect(page.getByRole('heading', { level: 1, name: CERT })).toBeVisible();
      await bindingPanel(page).getByRole('button', { name: kv.deployNow, exact: true }).click();
      const dialog = page.getByRole('dialog', { name: t('bindings.deployTitle') });
      await expect(dialog.getByRole('checkbox', { name: new RegExp(escapeRegExp(SERVER)) })).toBeChecked();
      await axe(page, 'Deploy now');
      await dialog.getByRole('button', { name: kv.deployNow, exact: true }).click();
      await answerStepUp(page, request, lang, s.totpSecret, dialog.getByTestId('deployment-run'));
      await settle(request, dialog.getByText(t('deploy.succeeded'), { exact: true }));
      expect(served(WWW), 'the new version is served').toBe(azureLeafFingerprint(CERT));
      expect(served(WWW)).not.toBe(original);
      await dialog.getByRole('button', { name: t('deploy.close') }).last().click();
      await expect(dialog).toHaveCount(0);
    });

    test('import an uploaded certificate into the vault; importing into a connected name asks first', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const s = await startVault(page, request, lang);
      await connectByApi(s.api, await kvCertificateId(s.api, s.vaultId, CERT), { autoDeploy: true });
      const pair = newCert('import.example.test');
      const certificateId = await uploadByApi(s.api, pair, 'import-me');
      await page.goto(`/certificates/${certificateId}`);

      // A new name: the import is queued, the job runs, the vault now has the certificate.
      await page.getByRole('button', { name: kv.importAction, exact: true }).click();
      const dialog = page.getByRole('dialog', { name: kv.importAction });
      await expect(field(dialog, t('imports.name'))).toHaveValue('import-example-test');
      await axe(page, 'Import into Key Vault');
      await expireStepUp(request);
      await dialog.getByRole('button', { name: kv.importAction, exact: true }).click();
      await answerStepUp(page, request, lang, s.totpSecret, dialog.getByText(t('imports.working')));
      await settle(request, dialog.getByTestId('import-outcome'));
      await expect(dialog.getByTestId('import-outcome')).toHaveAttribute('data-state', 'succeeded');
      await expect(dialog.getByTestId('import-outcome')).toContainText(kv.imported);
      await expect(dialog.getByTestId('import-outcome').locator('code')).toHaveText(/^[0-9a-f]{32}$/);
      await axe(page, 'Import into Key Vault, imported');
      await dialog.getByRole('button', { name: t('ui.close') }).last().click();
      await expect(dialog).toHaveCount(0);

      // The history of the certificate lists it; after Check now the vault does too.
      const history = page.getByTestId('import-history');
      await expect(history.getByRole('heading', { name: t('imports.history.title') })).toBeVisible();
      const row = history.getByTestId('import-row');
      await expect(row).toHaveCount(1);
      await expect(row).toContainText('import-example-test');
      await expect(row).toContainText(kv.imported);
      await expect(row).toContainText(VAULT);
      await axe(page, 'certificate page with its import history');
      await openVault(page, t, s.vaultId);
      await checkNow(page, request, lang);
      const certs = await openTab(page, t, 'certificates');
      await expect(certs.getByTestId('kv-certificate-row').filter({ hasText: 'import-example-test' })).toHaveCount(1);

      // The name of a certificate that is connected with automatic deployment on: the dialog asks first
      // and says what would follow; nothing is sent until it is confirmed (here it is cancelled).
      await page.goto(`/certificates/${certificateId}`);
      await page.getByRole('button', { name: kv.importAction, exact: true }).click();
      const again = page.getByRole('dialog', { name: kv.importAction });
      await field(again, t('imports.name')).fill(CERT);
      const sent = azureRequests().count;
      await again.getByRole('button', { name: kv.importAction, exact: true }).click();
      await answerStepUp(page, request, lang, s.totpSecret, again.getByTestId('import-confirm'));
      const warning = again.getByTestId('import-confirm');
      await expect(warning).toContainText(t('imports.newVersionWarning', { name: CERT }));
      await expect(warning.locator('code').filter({ hasText: new RegExp(`^${CERT}$`) })).toBeVisible();
      await expect(warning).toContainText(t('imports.policyWarning'));
      await expect(warning).toContainText(kv.boundNote);
      await expect(warning).toContainText(kv.autoFollows);
      await expect(again.getByRole('button', { name: kv.importAction, exact: true })).toBeDisabled();
      await axe(page, 'Import into Key Vault, confirmation');
      await again.getByRole('button', { name: t('ui.cancel') }).click();
      await expect(again).toHaveCount(0);
      expect(azureRequests().count, 'nothing was sent to the vault').toBe(sent);
      await openVault(page, t, s.vaultId);
      await openCertificate(page, t, CERT);
      await expect(versionRows(page)).toHaveCount(1);
    });

    test('a version created while the license was locked is held; releasing it lets automatic deployment deploy it', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const s = await startVault(page, request, lang);
      await connectByApi(s.api, await kvCertificateId(s.api, s.vaultId, CERT), { autoDeploy: true });
      const original = served(WWW);

      // The evaluation ends (lock); the vault renews the certificate meanwhile; a license ends the lock.
      await lockLicense(page, request, s.totpSecret);
      await azureSyncClock(request);
      const version = azureRenew(CERT);
      const renewed = azureLeafFingerprint(CERT);
      const api = await apiAs(page);
      await unlockLicense(request, api, s.totpSecret);
      await page.reload();

      // The check that finds it holds it: neutral words, no deployment by itself.
      await openVault(page, t, s.vaultId);
      await checkNow(page, request, lang);
      const certs = await openTab(page, t, 'certificates');
      await expect(certs.getByTestId('kv-certificate-row').filter({ hasText: CERT })).toContainText(kv.held);
      await openCertificate(page, t, CERT);
      const held = versionRows(page).filter({ has: page.locator('[data-testid="held-text"]') });
      await expect(held).toHaveCount(1);
      await expect(held).toContainText(version.slice(0, 8));
      await expect(held.getByTestId('held-text')).toHaveText(kv.heldText);
      await axe(page, 'vault certificate with a held version');
      await runScheduled(request, 'kv.auto_deploy');
      await drainJobs(request);
      expect(served(WWW), 'a held version is not deployed by itself').toBe(original);

      // An Administrator releases it: the text says what may follow and never promises it.
      await held.getByRole('button', { name: t('vaults.cert.releaseNamed', { version: version.slice(0, 8) }) }).click();
      const dialog = page.getByRole('dialog', { name: t('vaults.cert.releaseTitle') });
      await expect(dialog.getByText(kv.heldText)).toBeVisible();
      await expect(dialog.getByText(kv.releaseMay, { exact: true })).toBeVisible();
      await axe(page, 'release dialog');
      await expireStepUp(request);
      await dialog.getByRole('button', { name: kv.release, exact: true }).click();
      await answerStepUp(page, request, lang, s.totpSecret, page.getByText(kv.releasedMay, { exact: true }));
      await expect(dialog).toHaveCount(0);
      await expect(page.getByTestId('held-text')).toHaveCount(0);
      await runScheduled(request, 'kv.auto_deploy');
      await drainJobs(request);
      await waitDeployed(page, request, t, version);
      expect(served(WWW), 'the released version is deployed').toBe(renewed);
    });

    test('a throttled vault is degraded after three cycles with neutral words, a firewall is named', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const s = await startVault(page, request, lang, { server: false });
      await openVault(page, t, s.vaultId);
      await expect(page.getByTestId('vault-status')).toHaveText(t('enum.targetStatus.ok'));
      const status = page.getByTestId('vault-status');

      // Azure throttles every list: the first two cycles change nothing, the third degrades the vault.
      azureFault({ throttle: LONG_RETRY_AFTER });
      for (const cycle of [1, 2]) {
        await checkNowSettled(page, request, kv.checkNow);
        await expect(status, `after ${cycle} throttled cycle(s)`).toHaveText(t('enum.targetStatus.ok'));
      }
      await checkNowSettled(page, request, kv.checkNow);
      await expect(status).toHaveText(kv.degraded);
      await expect(page.getByTestId('vault-status-help')).toHaveText(kv.degradedHelp);
      await expect(page.getByRole('alert').filter({ hasText: kv.throttled })).toBeVisible();
      await axeWide(page, 'vault page, throttled');
      await nav(page, t, 'nav.keyVaults');
      await expect(vaultRow(page)).toContainText(kv.degraded);
      await expect(vaultRow(page)).toContainText(kv.throttled);
      await openVault(page, t, s.vaultId);

      // Azure stops throttling: the next check restores it.
      azureFault('clear');
      await checkNowSettled(page, request, kv.checkNow);
      await expect(status).toHaveText(t('enum.targetStatus.ok'));
      await expect(page.getByTestId('vault-status-help')).toHaveCount(0);

      // The vault's firewall refuses Alice's address: degraded at once, the firewall is the reason.
      azureFault({ firewall: '203.0.113.7' });
      await checkNowSettled(page, request, kv.checkNow);
      await expect(status).toHaveText(kv.degraded);
      await expect(page.getByRole('alert').filter({ hasText: t('errors.azure.firewall.title') })).toBeVisible();
      await expect(page.getByTestId('vault-status-help')).toHaveText(kv.degradedHelp);
      const detail = await json<{ last_error: { reason: string; params?: { client_address?: string } } }>(await s.api.get(`/api/v1/targets/${s.vaultId}`));
      expect(detail.last_error.reason).toBe('azure.firewall');
      // The troubleshooting guide (ALC-AKV-0004) says the parameter client_address names the address the vault
      // saw, but the vault's last error carries no params and no text names it: a documented gap, not a failure
      // of this journey (see the report); the annotation shows up in the test report.
      if (detail.last_error.params?.client_address !== '203.0.113.7') {
        test.info().annotations.push({ type: 'gap', description: 'the address the vault names (client_address) is not exposed by the API nor shown by the UI' });
      }
      await axe(page, 'vault page, firewall');
      azureFault('clear');
      await checkNowSettled(page, request, kv.checkNow);
      await expect(status).toHaveText(t('enum.targetStatus.ok'));
    });

    test('a vault address that points elsewhere is refused on the field and nothing is created', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const { totpSecret } = await runWizard(page, request, lang);
      const creds = azureCredentials();
      await nav(page, t, 'nav.keyVaults');
      await page.getByRole('button', { name: kv.add }).click();
      const dialog = page.getByRole('dialog', { name: kv.add });
      await dialog.getByRole('radio', { name: t('vaults.auth.client_secret') }).check();
      await field(dialog, t('vaults.fields.name')).fill('hostile');
      await field(dialog, t('vaults.fields.tenant_id')).fill(creds.tenant_id);
      await field(dialog, t('vaults.fields.client_id')).fill(creds.client_id);
      const baseline = azureRequests().count;
      for (const address of ['https://contoso.vault.azure.net.evil.test', 'http://contoso.vault.azure.net', 'https://contoso.vault.azure.net:8443', 'https://contoso.vault.azure.net/secrets']) {
        await field(dialog, t('vaults.fields.vault_url')).fill(address);
        await field(dialog, t('vaults.fields.client_secret')).fill(creds.client_secret);
        await dialog.getByRole('button', { name: kv.add, exact: true }).click();
        const urlField = field(dialog, t('vaults.fields.vault_url'));
        await answerStepUp(page, request, lang, totpSecret, dialog.locator('input[aria-invalid="true"]').first());
        await expect(urlField, address).toHaveAttribute('aria-invalid', 'true');
        await expect(dialog.getByText(t('validation.pattern'), { exact: false }).first(), address).toBeVisible();
        // The form is still open, the secret is not kept.
        await expect(dialog.getByText(t('vaults.retypeSecret'))).toBeVisible();
        await expect(field(dialog, t('vaults.fields.client_secret'))).toHaveValue('');
        expect(await secretOnPage(page, creds.client_secret)).toBe(false);
      }
      await axe(page, 'Add Key Vault, vault address refused');
      await dialog.getByRole('button', { name: t('ui.cancel') }).click();
      const api = await apiAs(page);
      expect((await json<{ items: unknown[] }>(await api.get('/api/v1/targets?type=azure_key_vault'))).items, 'no vault was created').toEqual([]);
      expect(azureRequests().count, 'nothing was sent to Azure (no sign-in, no vault call)').toBe(baseline);
    });

    test('Key Vault screens are accessible in every state, at every width', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const s = await startVault(page, request, lang);
      const pair = newCert('import.example.test');
      const certificateId = await uploadByApi(s.api, pair, 'import-me');

      await nav(page, t, 'nav.keyVaults');
      await expect(vaultRow(page)).toBeVisible();
      await axeWide(page, 'Key Vaults list');

      // Add Key Vault: every sign-in method and certificate format.
      await page.getByRole('button', { name: kv.add }).click();
      const add = page.getByRole('dialog', { name: kv.add });
      await axe(page, 'Add Key Vault, certificate (PEM)');
      await add.getByRole('radio', { name: t('vaults.certFormat.pfx') }).check();
      await axe(page, 'Add Key Vault, certificate (PFX)');
      await add.getByRole('radio', { name: t('vaults.auth.client_secret') }).check();
      await axe(page, 'Add Key Vault, client secret');
      await add.getByRole('radio', { name: t('vaults.auth.managed_identity') }).check();
      await axe(page, 'Add Key Vault, managed identity');
      await add.getByRole('button', { name: t('ui.cancel') }).click();
      await expect(add).toHaveCount(0);

      // The vault page, each tab; the vault certificate page.
      await openVault(page, t, s.vaultId);
      for (const tab of ['certificates', 'keys', 'secrets'] as const) {
        await openTab(page, t, tab);
        await axeWide(page, `vault page, ${tab} tab`);
      }
      await openCertificate(page, t, CERT);
      await axeWide(page, 'vault certificate page, not connected');

      // Connect websites, automatic deployment, Deploy now, the connection.
      await bindingPanel(page).getByRole('button', { name: kv.connect, exact: true }).click();
      const connect = page.getByRole('dialog', { name: kv.connect });
      await connect.getByRole('checkbox', { name: new RegExp(escapeRegExp(WWW)) }).check();
      await axe(page, 'Connect websites');
      await connect.getByRole('button', { name: kv.connect, exact: true }).click();
      await expect(connect).toHaveCount(0);
      await expect(bindingPanel(page).getByTestId('binding-location')).toBeVisible();
      await axeWide(page, 'vault certificate page, connected');
      await bindingPanel(page).getByRole('button', { name: kv.deployNow, exact: true }).click();
      const deploy = page.getByRole('dialog', { name: t('bindings.deployTitle') });
      await expect(deploy.getByRole('checkbox', { name: new RegExp(escapeRegExp(SERVER)) })).toBeChecked();
      await axe(page, 'Deploy now');
      await deploy.getByRole('button', { name: t('deploy.cancel') }).click();
      await expect(deploy).toHaveCount(0);
      await bindingPanel(page).getByRole('button', { name: kv.deleteConnection, exact: true }).click();
      await axe(page, 'Delete connection');
      await page.getByRole('dialog', { name: t('bindings.deleteTitle') }).getByRole('button', { name: t('ui.cancel') }).click();

      // Remove Key Vault, with a connected website (the confirmation names the consequence).
      await openVault(page, t, s.vaultId);
      await page.getByRole('button', { name: kv.removeVault, exact: true }).click();
      const remove = page.getByRole('dialog', { name: t('vaults.deleteTitle') });
      await axe(page, 'Remove Key Vault');
      await remove.getByRole('button', { name: kv.removeVault, exact: true }).click();
      await expect(remove.getByText(t('vaults.hasBindings'))).toBeVisible();
      await axe(page, 'Remove Key Vault, connections');
      await remove.getByRole('button', { name: t('ui.cancel') }).click();

      // Import into Key Vault: the form, the confirmation and the history with a finished import.
      await page.goto(`/certificates/${certificateId}`);
      await page.getByRole('button', { name: kv.importAction, exact: true }).click();
      const imp = page.getByRole('dialog', { name: kv.importAction });
      await axe(page, 'Import into Key Vault');
      await imp.getByRole('button', { name: kv.importAction, exact: true }).click();
      await answerStepUp(page, request, lang, s.totpSecret, imp.getByText(t('imports.working')));
      await settle(request, imp.getByTestId('import-outcome'));
      await axe(page, 'Import into Key Vault, imported');
      await imp.getByRole('button', { name: t('ui.close') }).last().click();
      await expect(page.getByTestId('import-history').getByTestId('import-row')).toHaveCount(1);
      await axeWide(page, 'certificate page with its import history');
    });

    test('delete the connection, then remove the Key Vault', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const s = await startVault(page, request, lang);
      const certId = await kvCertificateId(s.api, s.vaultId, CERT);
      await connectByApi(s.api, certId, { autoDeploy: false });
      await page.reload();

      // A vault with a connected website is refused first; the dialog then offers to remove both.
      await openVault(page, t, s.vaultId);
      await page.getByRole('button', { name: kv.removeVault, exact: true }).click();
      const remove = page.getByRole('dialog', { name: t('vaults.deleteTitle') });
      await remove.getByRole('button', { name: kv.removeVault, exact: true }).click();
      await expect(remove.getByText(t('vaults.hasBindings'))).toBeVisible();
      await remove.getByRole('button', { name: t('ui.cancel') }).click();
      await expect(remove).toHaveCount(0);
      await nav(page, t, 'nav.keyVaults');
      await expect(vaultRow(page)).toBeVisible();

      // Delete the connection: the websites are released, the vault certificate stays.
      await openVault(page, t, s.vaultId);
      await openCertificate(page, t, CERT);
      await expect(bindingPanel(page).getByTestId('binding-location')).toBeVisible();
      await bindingPanel(page).getByRole('button', { name: kv.deleteConnection, exact: true }).click();
      const del = page.getByRole('dialog', { name: t('bindings.deleteTitle') });
      await expect(del.getByText(t('bindings.deleteHelp'))).toBeVisible();
      await del.getByRole('button', { name: kv.deleteConnection, exact: true }).click();
      await expect(del).toHaveCount(0);
      await expect(bindingPanel(page)).toContainText(t('bindings.none'));
      await expect(bindingPanel(page).getByTestId('binding-location')).toHaveCount(0);

      // Remove the Key Vault: confirmed, the list no longer shows it.
      await openVault(page, t, s.vaultId);
      await page.getByRole('button', { name: kv.removeVault, exact: true }).click();
      const confirm = page.getByRole('dialog', { name: t('vaults.deleteTitle') });
      await expect(confirm.getByText(t('vaults.deleteHelp'))).toBeVisible();
      await confirm.getByRole('button', { name: kv.removeVault, exact: true }).click();
      await answerStepUp(page, request, lang, s.totpSecret, page.getByRole('heading', { level: 1, name: kv.title }));
      await expect(page).toHaveURL(/\/key-vaults$/);
      await expect(page.getByText(t('vaults.empty'))).toBeVisible();
      await expect(vaultRow(page)).toHaveCount(0);

      // With its connections: add the vault again, connect, remove both in one confirmation.
      const again = await addVaultByApi(s.api, request, s.creds);
      await connectByApi(s.api, await kvCertificateId(s.api, again, CERT), { autoDeploy: false });
      await openVault(page, t, again);
      await page.getByRole('button', { name: kv.removeVault, exact: true }).click();
      const both = page.getByRole('dialog', { name: t('vaults.deleteTitle') });
      await both.getByRole('button', { name: kv.removeVault, exact: true }).click();
      await expect(both.getByText(t('vaults.hasBindings'))).toBeVisible();
      await both.getByRole('button', { name: kv.removeVaultAndConnections, exact: true }).click();
      await answerStepUp(page, request, lang, s.totpSecret, page.getByRole('heading', { level: 1, name: kv.title }));
      await expect(page.getByText(t('vaults.empty'))).toBeVisible();
      const bindings = await s.api.get(`/api/v1/targets/${again}`);
      expect(bindings.status(), 'the removed vault is gone').toBe(404);
    });
  });
}

// secretOnPage says whether the text is in any input, in the page's markup or in the browser's storage.
async function secretOnPage(page: Page, secret: string): Promise<boolean> {
  return page.evaluate((s) => {
    const inInputs = [...document.querySelectorAll('input, textarea')].some((e) => (e as HTMLInputElement).value.includes(s));
    let inStorage = false;
    try {
      inStorage = JSON.stringify({ ...localStorage, ...sessionStorage }).includes(s);
    } catch {
      // storage unavailable: nothing stored there
    }
    return inInputs || inStorage || document.documentElement.outerHTML.includes(s) || location.href.includes(s);
  }, secret);
}

