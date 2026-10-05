import type { APIRequestContext, APIResponse, Locator, Page } from '@playwright/test';
import {
  ADMIN,
  COPY,
  advanceClock,
  apiAs,
  azureAddCertificate,
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
  expectAccessible,
  expectWide,
  PHONE_WIDTH,
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
  tabTo,
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
//
// The fake's client secret is typed into fields (journeys A and G) and sent in API bodies
// (addVaultByApi), so it is in the Playwright trace of a failed test (trace: retain-on-failure; CI
// uploads the report with its traces). That is acceptable only because the fake generates the secret
// when it starts and on every reset (azureReset, before each journey) and it dies with the stack:
// never reuse this pattern in a suite that signs in to a real Azure tenant.

const HOST_KEY_PUB = '/etc/ssh/ssh_host_ed25519_key.pub';
const WWW = 'www.example.test';
const SERVER = 'e2e-nginx';
const VAULT = 'prod-vault';
const CERT = 'web-cert';
// A certificate for the website whose chain stops at the intermediate CA: Key Vault holds no root for it.
const CHAIN_CERT = 'chain-cert';
// auth.StepUpWindow: a sign-in or step-up confirms the session for this long.
const STEP_UP_SECONDS = 5 * 60;
const DAY_SECONDS = 24 * 3600;
// inventory.AutoDeployRetryAfter: a website waits this long after a failed automatic deployment.
const RETRY_AFTER_SECONDS = 3600;
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

// axe checks the screen on show like expectAccessible, softly (a finding fails the test at its end and
// the journey goes on, so one run lists every violation); with dialog, it first waits for the dialog.
async function axe(page: Page, screen: string, dialog?: Locator): Promise<void> {
  await expectAccessible(page, screen, { soft: true, dialog });
}

// axeWide is axe plus the 375 px phone width of expectWide (tables scroll inside their container).
async function axeWide(page: Page, screen: string): Promise<void> {
  await expectWide(page, screen, { soft: true });
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

interface VaultView {
  status: string;
  updated_at: string;
  last_success_at: string | null;
  last_error: { reason: string; params?: Record<string, string> } | null;
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

async function openVault(page: Page, vaultId: string): Promise<void> {
  await page.goto(`/key-vaults/${vaultId}`);
  await expect(page.getByRole('heading', { level: 1, name: VAULT })).toBeVisible();
  await expect(page.getByTestId('vault-status')).toBeVisible();
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

// deployedText is "Deployed: version xxxxxxxx" for the 8-digit short form of a version id (the pinned
// contract text, which the locale file must say too).
function deployedText(t: Translate, lang: Lang, version: string): string {
  const text = `${COPY[lang].kv.deployedVersion} ${version.slice(0, 8)}`;
  expect(t('bindings.state.deployed', { version: version.slice(0, 8) })).toBe(text);
  return text;
}

async function uploadByApi(api: Api, pair: PemPair, label: string): Promise<string> {
  const res = await json<{ certificate: { id: string } }>(
    await api.post('/api/v1/certificates/upload', { label, certificate_pem: pair.cert, private_key_pem: pair.key }),
    201,
  );
  return res.certificate.id;
}

// waitDeployed drains due jobs until the website of the open certificate page shows the version as deployed.
async function waitDeployed(page: Page, request: APIRequestContext, t: Translate, lang: Lang, version: string): Promise<void> {
  const text = deployedText(t, lang, version);
  await drainUntil(request, async () => {
    await page.reload();
    await expect(websiteState(page)).toHaveText(text, { timeout: 3_000 });
  });
}

function steps(scope: Locator, t: Translate): Locator {
  return scope.getByRole('list', { name: t('deployments.stepsTitle') });
}

// expectKeyVaultSteps checks the step "Read the certificate from Key Vault" (kv_secret) of the deployment
// page that is open: its text and that it succeeded.
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

interface ChainStart {
  s: Session;
  certificatePage: string;
  // held is the row of a version that is held (a version an Administrator deployed while it was held stays held).
  held: (version: string) => Locator;
  deployments: () => Promise<{ status: string; trigger: string; error: { reason: string } | null }[]>;
}

// startChain adds the vault and a certificate for the website whose chain is incomplete (CHAIN_CERT),
// connects the website with automatic deployment on and opens the certificate's page.
async function startChain(page: Page, request: APIRequestContext, lang: Lang): Promise<ChainStart> {
  const s = await startVault(page, request, lang);
  azureAddCertificate(CHAIN_CERT, { cn: WWW, root: false });
  await openVault(page, s.vaultId);
  await checkNow(page, request, lang);
  await s.api.stepUp(s.totpSecret);
  await connectByApi(s.api, await kvCertificateId(s.api, s.vaultId, CHAIN_CERT), { autoDeploy: true });
  await openVault(page, s.vaultId);
  await openCertificate(page, translator(lang), CHAIN_CERT);
  const deployments = async () =>
    (await json<{ items: { status: string; trigger: string; error: { reason: string } | null }[] }>(await (await apiAs(page)).get('/api/v1/deployments?limit=50'))).items;
  const held = (version: string) => versionRows(page).filter({ hasText: version.slice(0, 8) }).filter({ has: page.getByTestId('held-text') });
  return { s, certificatePage: page.url(), held, deployments };
}

// heldUntilShown runs due jobs until the certificate page shows the held version's row.
async function heldUntilShown(page: Page, request: APIRequestContext, held: Locator): Promise<void> {
  await drainUntil(request, async () => {
    await page.reload();
    await expect(held).toHaveCount(1, { timeout: 3_000 });
  });
}

// holdForChain renews CHAIN_CERT in the vault; Alice finds the version, automatic deployment reads it,
// refuses its incomplete chain and holds it. Returns the version id; the certificate page is open.
async function holdForChain(page: Page, request: APIRequestContext, t: Translate, lang: Lang, c0: ChainStart): Promise<string> {
  await azureSyncClock(request);
  const version = azureRenew(CHAIN_CERT);
  await openVault(page, c0.s.vaultId);
  await checkNow(page, request, lang);
  await openCertificate(page, t, CHAIN_CERT);
  await runScheduled(request, 'kv.auto_deploy');
  await heldUntilShown(page, request, c0.held(version));
  await expect(c0.held(version).getByTestId('held-text')).toHaveText(COPY[lang].kv.heldChain);
  return version;
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
    // No vault is removed at the end: POST /test/reset (the next journey's beforeEach) moves Alice's
    // clock back, and the vault rate limiter moves its schedule back with the clock, so nobody waits for
    // the difference.
    test.afterEach(() => {
      nginxReset();
      azureReset();
    });

    test('add a vault with a client secret, see its certificates, keys and secrets', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const { totpSecret } = await runWizard(page, request, lang);
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

      await openVault(page, s.vaultId);
      await openCertificate(page, t, CERT);
      await expect(bindingPanel(page)).toContainText(t('bindings.none'));
      await bindingPanel(page).getByRole('button', { name: kv.connect, exact: true }).click();
      const connect = page.getByRole('dialog', { name: kv.connect });
      await connect.getByRole('checkbox', { name: new RegExp(escapeRegExp(WWW)) }).check();
      await axe(page, 'Connect websites', connect);
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
      await axe(page, 'switch on automatic deployment', confirm);
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
      await openVault(page, s.vaultId);
      await checkNow(page, request, lang);
      const certs = await openTab(page, t, 'certificates');
      await expect(certs.getByTestId('kv-certificate-row').filter({ hasText: CERT })).toContainText(kv.newVersion);
      await openCertificate(page, t, CERT);
      await expect(versionRows(page)).toHaveCount(2);
      await expect(versionRows(page).first()).toContainText(kv.newVersion);
      await expect(versionRows(page).first()).toContainText(version.slice(0, 8));

      // The planner (it never ticks by itself in the e2e build) deploys it by itself.
      await runScheduled(request, 'kv.auto_deploy');
      await waitDeployed(page, request, t, lang, version);
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

      // The background job that ran it names the deployment (GET /api/v1/jobs: deployment_id).
      const deploymentId = new URL(page.url()).pathname.split('/').pop() ?? '';
      expect(deploymentId).toMatch(/^[0-9a-f-]{36}$/);
      const api = await apiAs(page);
      const jobs = await json<{ items: { type: string; status: string; deployment_id: string | null; import_id: string | null }[] }>(await api.get('/api/v1/jobs?limit=100'));
      const deployJobs = jobs.items.filter((j) => j.type === 'certificate.deploy');
      expect(deployJobs.map((j) => [j.deployment_id, j.status, j.import_id])).toEqual([[deploymentId, 'succeeded', null]]);
    });

    test('a missing Key Vault Secrets User role is named, the website is unchanged, then Deploy now works', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const s = await startVault(page, request, lang);
      await s.api.stepUp(s.totpSecret);
      await connectByApi(s.api, await kvCertificateId(s.api, s.vaultId, CERT), { autoDeploy: true });
      await page.reload();
      const original = served(WWW);

      azureRole('revoke', 'secrets/get');
      await azureSyncClock(request);
      azureRenew(CERT);
      await openVault(page, s.vaultId);
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
      await axe(page, 'Deploy now', dialog);
      await dialog.getByRole('button', { name: kv.deployNow, exact: true }).click();
      await answerStepUp(page, request, lang, s.totpSecret, dialog.getByTestId('deployment-run'));
      await settle(request, dialog.getByText(t('deploy.succeeded'), { exact: true }));
      expect(served(WWW), 'the new version is served').toBe(azureLeafFingerprint(CERT));
      expect(served(WWW)).not.toBe(original);
      await dialog.getByRole('button', { name: t('deploy.close') }).last().click();
      await expect(dialog).toHaveCount(0);
      await expect(websiteState(page), 'the website now has the version whose deployment had failed').toHaveText(deployedText(t, lang, newest));
    });

    test('import an uploaded certificate into the vault; importing into a connected name asks first', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const s = await startVault(page, request, lang);
      await s.api.stepUp(s.totpSecret);
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
      const api = await apiAs(page);
      const imports = async () =>
        (await json<{ items: { id: string; name: string; state: string }[] }>(await api.get(`/api/v1/targets/${s.vaultId}/kv/imports?certificate_id=${certificateId}`))).items;
      const [imported] = await imports();
      expect(imported).toMatchObject({ name: 'import-example-test', state: 'succeeded' });
      // The background job that sent it names the import (GET /api/v1/jobs: import_id).
      const jobs = await json<{ items: { type: string; import_id: string | null; deployment_id: string | null }[] }>(await api.get('/api/v1/jobs?limit=100'));
      expect(jobs.items.filter((j) => j.type === 'kv.import').map((j) => [j.import_id, j.deployment_id])).toEqual([[imported.id, null]]);

      // The history of the certificate lists it; after Check now the vault does too.
      const history = page.getByTestId('import-history');
      await expect(history.getByRole('heading', { name: t('imports.history.title') })).toBeVisible();
      const row = history.getByTestId('import-row');
      await expect(row).toHaveCount(1);
      await expect(row).toContainText('import-example-test');
      await expect(row).toContainText(kv.imported);
      await expect(row).toContainText(VAULT);
      await axe(page, 'certificate page with its import history');
      await openVault(page, s.vaultId);
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
      // Had an import been queued, this drain would run it: nothing reaches the vault, nothing is recorded.
      await drainJobs(request);
      expect(azureRequests().count, 'nothing was sent to the vault').toBe(sent);
      expect(await imports(), 'the import history still has the one import').toEqual([imported]);
      // A fresh check reads the vault again: web-cert still has its one version.
      await openVault(page, s.vaultId);
      await checkNow(page, request, lang);
      await openCertificate(page, t, CERT);
      await expect(versionRows(page)).toHaveCount(1);
    });

    test('a version created while the license was locked is held; releasing it lets automatic deployment deploy it', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const s = await startVault(page, request, lang);
      await s.api.stepUp(s.totpSecret);
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
      await openVault(page, s.vaultId);
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
      await axe(page, 'release dialog', dialog);
      await expireStepUp(request);
      await dialog.getByRole('button', { name: kv.release, exact: true }).click();
      await answerStepUp(page, request, lang, s.totpSecret, page.getByText(kv.releasedMay, { exact: true }));
      await expect(dialog).toHaveCount(0);
      await expect(page.getByTestId('held-text')).toHaveCount(0);
      await runScheduled(request, 'kv.auto_deploy');
      await drainJobs(request);
      await waitDeployed(page, request, t, lang, version);
      expect(served(WWW), 'the released version is deployed').toBe(renewed);
    });

    test('a version held for its incomplete chain: releasing it never deploys it, Deploy now with the chain confirmed does', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      // The pinned contract texts are what the app shows.
      expect(t('vaults.heldChain')).toBe(kv.heldChain);
      expect(t('vaults.cert.releaseHelpChain')).toBe(kv.releaseChain);
      expect(t('vaults.cert.releasedChain')).toBe(kv.releasedChain);
      expect(t('vaults.cert.releaseHelpManual')).toBe(kv.releaseManual);
      expect(t('vaults.cert.releasedManual')).toBe(kv.releasedManual);
      expect(t('deploy.confirmChain')).toBe(kv.confirmChain);

      const c0 = await startChain(page, request, lang);
      const { deployments } = c0;
      const original = served(WWW);
      const first = await holdForChain(page, request, t, lang, c0);
      expect((await deployments()).map((d) => [d.trigger, d.status, d.error?.reason])).toEqual([['kv_renewal', 'failed', 'certificate.chain_unconfirmed']]);
      expect(served(WWW), 'an incomplete chain is never deployed by itself').toBe(original);
      await axe(page, 'vault certificate with a version held for its chain');

      // Release, automatic deployment on: the text says automatic deployment never deploys the incomplete
      // chain; the Administrator confirms the chain before Release can be pressed.
      await c0.held(first).getByRole('button', { name: t('vaults.cert.releaseNamed', { version: first.slice(0, 8) }) }).click();
      const dialog = page.getByRole('dialog', { name: t('vaults.cert.releaseTitle') });
      await expect(dialog.getByText(kv.heldChain, { exact: true })).toBeVisible();
      await expect(dialog.getByText(kv.releaseChain, { exact: true })).toBeVisible();
      const confirmChain = dialog.getByRole('checkbox', { name: kv.confirmChain });
      await expect(confirmChain).not.toBeChecked();
      await expect(dialog.getByRole('button', { name: kv.release, exact: true })).toBeDisabled();
      await axe(page, 'release dialog, incomplete chain', dialog);
      await confirmChain.check();
      await expireStepUp(request);
      await dialog.getByRole('button', { name: kv.release, exact: true }).click();
      await answerStepUp(page, request, lang, c0.s.totpSecret, page.getByText(kv.releasedChain, { exact: true }));
      await expect(dialog).toHaveCount(0);
      await expect(page.getByTestId('held-text')).toHaveCount(0);

      // What follows, as the text says: nothing is deployed; at its next try (a website waits an hour after a
      // failed automatic deployment) the chain is still incomplete, so Alice holds the version again.
      await runScheduled(request, 'kv.auto_deploy');
      await drainJobs(request);
      expect(await deployments(), 'the release itself deploys nothing').toHaveLength(1);
      await advanceClock(request, RETRY_AFTER_SECONDS + 1);
      await signIn(page, request, ADMIN, c0.s.totpSecret); // the hour ended the idle session
      await runScheduled(request, 'kv.auto_deploy');
      await page.goto(c0.certificatePage);
      await heldUntilShown(page, request, c0.held(first));
      await expect(c0.held(first).getByTestId('held-text')).toHaveText(kv.heldChain);
      expect((await deployments()).map((d) => [d.status, d.error?.reason])).toEqual([
        ['failed', 'certificate.chain_unconfirmed'],
        ['failed', 'certificate.chain_unconfirmed'],
      ]);
      expect(served(WWW), 'held again, still not deployed').toBe(original);

      // Deploy now, as the text says: for a version held for its chain the dialog asks for the confirmation
      // first; with it, the version is live.
      await bindingPanel(page).getByRole('button', { name: kv.deployNow, exact: true }).click();
      const deploy = page.getByRole('dialog', { name: t('bindings.deployTitle') });
      await expect(deploy.getByRole('checkbox', { name: new RegExp(escapeRegExp(SERVER)) })).toBeChecked();
      const deployChain = deploy.getByRole('checkbox', { name: kv.confirmChain });
      await expect(deployChain).not.toBeChecked();
      await expect(deploy.getByRole('button', { name: kv.deployNow, exact: true })).toBeDisabled();
      await axe(page, 'Deploy now, chain confirmation', deploy);
      await deployChain.check();
      await deploy.getByRole('button', { name: kv.deployNow, exact: true }).click();
      await answerStepUp(page, request, lang, c0.s.totpSecret, deploy.getByTestId('deployment-run'));
      await settle(request, deploy.getByText(t('deploy.succeeded'), { exact: true }));
      expect(served(WWW), 'Deploy now with the chain confirmed deploys it').toBe(azureLeafFingerprint(CHAIN_CERT, first));
      await deploy.getByRole('button', { name: t('deploy.close') }).last().click();
      await expect(deploy).toHaveCount(0);
      await expect(websiteState(page)).toHaveText(deployedText(t, lang, first));

      // The next renewal is held for its chain again; with automatic deployment off, releasing it says
      // nothing is deployed (and still asks for the chain).
      const second = await holdForChain(page, request, t, lang, c0);
      const auto = bindingPanel(page).getByRole('switch', { name: kv.autoDeployment });
      await expect(auto).toBeChecked();
      await auto.click({ force: true });
      await answerStepUp(page, request, lang, c0.s.totpSecret, bindingPanel(page).getByText(t('bindings.autoDeployHelpOff'), { exact: true }));
      await expect(auto).not.toBeChecked();
      await c0.held(second).getByRole('button', { name: t('vaults.cert.releaseNamed', { version: second.slice(0, 8) }) }).click();
      await expect(dialog.getByText(kv.heldChain, { exact: true })).toBeVisible();
      await expect(dialog.getByText(kv.releaseManual, { exact: true })).toBeVisible();
      await expect(dialog.getByText(kv.releaseChain, { exact: true })).toHaveCount(0);
      await axe(page, 'release dialog, automatic deployment off', dialog);
      await dialog.getByRole('checkbox', { name: kv.confirmChain }).check();
      await expireStepUp(request);
      await dialog.getByRole('button', { name: kv.release, exact: true }).click();
      await answerStepUp(page, request, lang, c0.s.totpSecret, page.getByText(kv.releasedManual, { exact: true }));
      await expect(c0.held(second)).toHaveCount(0);
      await runScheduled(request, 'kv.auto_deploy');
      await drainJobs(request);
      expect(served(WWW), 'released with automatic deployment off: nothing is deployed').toBe(azureLeafFingerprint(CHAIN_CERT, first));
    });

    // After a version held for its incomplete chain is released, Alice still knows the chain is incomplete (the read
    // found it): Deploy now asks the Administrator to confirm the chain up front, as the release texts say, and a
    // release alone never confirms it.
    test('after releasing a version held for its chain, Deploy now asks the Administrator to confirm the chain', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const c0 = await startChain(page, request, lang);
      const version = await holdForChain(page, request, t, lang, c0);
      const auto = bindingPanel(page).getByRole('switch', { name: kv.autoDeployment });
      await auto.click({ force: true });
      await answerStepUp(page, request, lang, c0.s.totpSecret, bindingPanel(page).getByText(t('bindings.autoDeployHelpOff'), { exact: true }));
      await c0.held(version).getByRole('button', { name: t('vaults.cert.releaseNamed', { version: version.slice(0, 8) }) }).click();
      const dialog = page.getByRole('dialog', { name: t('vaults.cert.releaseTitle') });
      await dialog.getByRole('checkbox', { name: kv.confirmChain }).check();
      await expireStepUp(request);
      await dialog.getByRole('button', { name: kv.release, exact: true }).click();
      await answerStepUp(page, request, lang, c0.s.totpSecret, page.getByText(kv.releasedManual, { exact: true }));

      await bindingPanel(page).getByRole('button', { name: kv.deployNow, exact: true }).click();
      const deploy = page.getByRole('dialog', { name: t('bindings.deployTitle') });
      const deployChain = deploy.getByRole('checkbox', { name: kv.confirmChain });
      // Offered up front for the released version, unchecked; Deploy now waits for it.
      await expect(deployChain).toBeVisible();
      await expect(deployChain).not.toBeChecked();
      await expect(deploy.getByRole('button', { name: kv.deployNow, exact: true })).toBeDisabled();
      await axe(page, 'Deploy now of a released version with an incomplete chain', deploy);
      // The API says the chain is incomplete, and refuses a request without the confirmation before anything is
      // queued (ALC-CRT-0011).
      const api = await apiAs(page);
      const certId = await kvCertificateId(api, c0.s.vaultId, CHAIN_CERT);
      const detail = await json<{ binding: { id: string }; versions: { id: string; version: string; held: boolean; chain_incomplete: boolean }[] }>(
        await api.get(`/api/v1/targets/${c0.s.vaultId}/kv/certificates/${certId}`),
      );
      const released = detail.versions.find((v) => v.version === version);
      expect(released, 'the released version is listed').toBeDefined();
      expect([released!.held, released!.chain_incomplete]).toEqual([false, true]);
      const before = (await c0.deployments()).length;
      const refused = await api.post(`/api/v1/bindings/${detail.binding.id}/actions/deploy`, { version_id: released!.id });
      expect((await json<{ error: { code: string } }>(refused, 409)).error.code).toBe('ALC-CRT-0011');
      expect(await c0.deployments(), 'nothing was queued').toHaveLength(before);
      await expect(deploy.getByTestId('deployment-run'), 'nothing ran without the confirmation').toHaveCount(0);
      await deployChain.check();
      await deploy.getByRole('button', { name: kv.deployNow, exact: true }).click();
      await answerStepUp(page, request, lang, c0.s.totpSecret, deploy.getByTestId('deployment-run'));
      await settle(request, deploy.getByText(t('deploy.succeeded'), { exact: true }));
      expect(served(WWW)).toBe(azureLeafFingerprint(CHAIN_CERT, version));
    });

    test('a throttled vault is degraded after three cycles with neutral words, a firewall is named with the address it saw', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const s = await startVault(page, request, lang, { server: false });
      await openVault(page, s.vaultId);
      const status = page.getByTestId('vault-status');
      await expect(status).toHaveText(t('enum.targetStatus.ok'));
      const vault = async () => json<VaultView>(await s.api.get(`/api/v1/targets/${s.vaultId}`));
      const lastSuccess = (await vault()).last_success_at;
      expect(lastSuccess, 'the first poll succeeded').not.toBeNull();

      // Azure throttles every list: the first two cycles change nothing, the third degrades the vault.
      azureFault({ throttle: LONG_RETRY_AFTER });
      for (const cycle of [1, 2]) {
        const before = await vault();
        const throttled = azureRequests().throttled;
        await checkNowSettled(page, request, kv.checkNow);
        // Proof that this cycle ran and was throttled: the fake answered 429 to it, the poll stored its
        // outcome (updated_at moved) without a successful listing (last_success_at did not), and the vault
        // is still Connected without an error, also on a page loaded afresh.
        expect(azureRequests().throttled, `cycle ${cycle} ran into the throttle`).toBeGreaterThan(throttled);
        const after = await vault();
        expect(Date.parse(after.updated_at), `cycle ${cycle} stored its outcome`).toBeGreaterThan(Date.parse(before.updated_at));
        expect(after, `after ${cycle} throttled cycle(s)`).toMatchObject({ status: 'ok', last_error: null, last_success_at: lastSuccess });
        await page.reload();
        await expect(status, `after ${cycle} throttled cycle(s)`).toHaveText(t('enum.targetStatus.ok'));
        await expect(page.getByRole('alert').filter({ hasText: kv.throttled })).toHaveCount(0);
      }
      await checkNowSettled(page, request, kv.checkNow);
      await expect(status).toHaveText(kv.degraded);
      expect(await vault()).toMatchObject({ status: 'degraded', last_error: { reason: 'azure.throttled' }, last_success_at: lastSuccess });
      await expect(page.getByTestId('vault-status-help')).toHaveText(kv.degradedHelp);
      await expect(page.getByRole('alert').filter({ hasText: kv.throttled })).toBeVisible();
      await axeWide(page, 'vault page, throttled');
      await nav(page, t, 'nav.keyVaults');
      await expect(vaultRow(page)).toContainText(kv.degraded);
      await expect(vaultRow(page)).toContainText(kv.throttled);
      await openVault(page, s.vaultId);

      // Azure stops throttling: the next check restores it.
      azureFault('clear');
      await checkNowSettled(page, request, kv.checkNow);
      await expect(status).toHaveText(t('enum.targetStatus.ok'));
      await expect(page.getByTestId('vault-status-help')).toHaveCount(0);

      // The vault's firewall refuses Alice's address: degraded at once, the firewall is the reason, and the
      // page shows the address the vault saw (Azure's "Client address: ..."), as code.
      expect(t('errors.azure.firewall.title')).toBe(kv.firewall);
      expect(t('vaults.firewallAddress')).toBe(kv.firewallAddress);
      azureFault({ firewall: '203.0.113.7' });
      await checkNowSettled(page, request, kv.checkNow);
      await expect(status).toHaveText(kv.degraded);
      await expect(page.getByRole('alert').filter({ hasText: kv.firewall })).toBeVisible();
      await expect(page.getByTestId('vault-status-help')).toHaveText(kv.degradedHelp);
      const address = page.getByTestId('vault-firewall-address');
      await expect(address).toContainText(kv.firewallAddress);
      await expect(address.locator('code')).toHaveText('203.0.113.7');
      expect((await vault()).last_error).toMatchObject({ reason: 'azure.firewall', params: { client_address: '203.0.113.7' } });
      await axeWide(page, 'vault page, firewall');
      azureFault('clear');
      await checkNowSettled(page, request, kv.checkNow);
      await expect(status).toHaveText(t('enum.targetStatus.ok'));
      await expect(address).toHaveCount(0);
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
      // The five addresses of the Review Focus that are refused when typed: another host behind the vault
      // suffix, plain HTTP, another port, a path, and a sovereign cloud's vault (Alice serves the public cloud).
      for (const address of [
        'https://contoso.vault.azure.net.evil.test',
        'http://contoso.vault.azure.net',
        'https://contoso.vault.azure.net:8443',
        'https://contoso.vault.azure.net/secrets',
        'contoso.vault.usgovcloudapi.net',
      ]) {
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
      await axe(page, 'Add Key Vault, certificate (PEM)', add);
      await add.getByRole('radio', { name: t('vaults.certFormat.pfx') }).check();
      await axe(page, 'Add Key Vault, certificate (PFX)');
      await add.getByRole('radio', { name: t('vaults.auth.client_secret') }).check();
      await axe(page, 'Add Key Vault, client secret');
      await add.getByRole('radio', { name: t('vaults.auth.managed_identity') }).check();
      await axe(page, 'Add Key Vault, managed identity');
      await add.getByRole('button', { name: t('ui.cancel') }).click();
      await expect(add).toHaveCount(0);

      // The vault page, each tab; the vault certificate page.
      await openVault(page, s.vaultId);
      for (const tab of ['certificates', 'keys', 'secrets'] as const) {
        await openTab(page, t, tab);
        await axeWide(page, `vault page, ${tab} tab`);
      }

      // The scrolling part of a table is a named group the keyboard reaches, and its focus ring is drawn
      // inside it (the scroll area around it clips anything outside): checked on a phone, where it scrolls.
      const desktop = page.viewportSize()!;
      await page.setViewportSize({ width: PHONE_WIDTH, height: desktop.height });
      const keysTable = await openTab(page, t, 'keys');
      const region = page.getByRole('group', { name: t('ui.scrollRegion'), exact: true }).filter({ has: keysTable });
      await expect(region).toHaveCount(1);
      await page.getByRole('tab', { name: t('vaults.tabs.keys'), exact: true }).focus();
      await tabTo(page, region);
      const ring = await region.evaluate((el) => {
        const cs = getComputedStyle(el);
        return { focusVisible: el.matches(':focus-visible'), style: cs.outlineStyle, width: cs.outlineWidth, offset: cs.outlineOffset, scrolls: el.scrollWidth > el.clientWidth };
      });
      expect(ring).toEqual({ focusVisible: true, style: 'solid', width: '2px', offset: '-2px', scrolls: true });
      await page.setViewportSize(desktop);
      await openCertificate(page, t, CERT);
      await axeWide(page, 'vault certificate page, not connected');

      // Connect websites, automatic deployment, Deploy now, the connection.
      await bindingPanel(page).getByRole('button', { name: kv.connect, exact: true }).click();
      const connect = page.getByRole('dialog', { name: kv.connect });
      await connect.getByRole('checkbox', { name: new RegExp(escapeRegExp(WWW)) }).check();
      await axe(page, 'Connect websites', connect);
      await connect.getByRole('button', { name: kv.connect, exact: true }).click();
      await expect(connect).toHaveCount(0);
      await expect(bindingPanel(page).getByTestId('binding-location')).toBeVisible();
      await axeWide(page, 'vault certificate page, connected');
      await bindingPanel(page).getByRole('button', { name: kv.deployNow, exact: true }).click();
      const deploy = page.getByRole('dialog', { name: t('bindings.deployTitle') });
      await expect(deploy.getByRole('checkbox', { name: new RegExp(escapeRegExp(SERVER)) })).toBeChecked();
      await axe(page, 'Deploy now', deploy);
      await deploy.getByRole('button', { name: t('deploy.cancel') }).click();
      await expect(deploy).toHaveCount(0);
      await bindingPanel(page).getByRole('button', { name: kv.deleteConnection, exact: true }).click();
      const deleteConnection = page.getByRole('dialog', { name: t('bindings.deleteTitle') });
      await axe(page, 'Delete connection', deleteConnection);
      await deleteConnection.getByRole('button', { name: t('ui.cancel') }).click();
      await expect(deleteConnection).toHaveCount(0);

      // Remove Key Vault, with a connected website (the confirmation names the consequence).
      await openVault(page, s.vaultId);
      await page.getByRole('button', { name: kv.removeVault, exact: true }).click();
      const remove = page.getByRole('dialog', { name: t('vaults.deleteTitle') });
      await axe(page, 'Remove Key Vault', remove);
      await remove.getByRole('button', { name: kv.removeVault, exact: true }).click();
      await expect(remove.getByText(t('vaults.hasBindings'))).toBeVisible();
      await axe(page, 'Remove Key Vault, connections');
      await remove.getByRole('button', { name: t('ui.cancel') }).click();

      // Import into Key Vault: the form, the confirmation and the history with a finished import.
      await page.goto(`/certificates/${certificateId}`);
      await page.getByRole('button', { name: kv.importAction, exact: true }).click();
      const imp = page.getByRole('dialog', { name: kv.importAction });
      await axe(page, 'Import into Key Vault', imp);
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
      await openVault(page, s.vaultId);
      await page.getByRole('button', { name: kv.removeVault, exact: true }).click();
      const remove = page.getByRole('dialog', { name: t('vaults.deleteTitle') });
      await remove.getByRole('button', { name: kv.removeVault, exact: true }).click();
      await expect(remove.getByText(t('vaults.hasBindings'))).toBeVisible();
      await remove.getByRole('button', { name: t('ui.cancel') }).click();
      await expect(remove).toHaveCount(0);
      await nav(page, t, 'nav.keyVaults');
      await expect(vaultRow(page)).toBeVisible();

      // Delete the connection: the websites are released, the vault certificate stays.
      await openVault(page, s.vaultId);
      await openCertificate(page, t, CERT);
      await expect(bindingPanel(page).getByTestId('binding-location')).toBeVisible();
      await bindingPanel(page).getByRole('button', { name: kv.deleteConnection, exact: true }).click();
      const del = page.getByRole('dialog', { name: t('bindings.deleteTitle') });
      await expect(del.getByText(t('bindings.deleteHelp'))).toBeVisible();
      // Deleting a connection needs no step-up (docs/authz-matrix.md): even after the sign-in's step-up window
      // has passed, it goes through without asking for a code.
      await expireStepUp(request);
      await del.getByRole('button', { name: kv.deleteConnection, exact: true }).click();
      await expect(del).toHaveCount(0);
      await expect(page.getByRole('dialog', { name: COPY[lang].stepUpHeading })).toHaveCount(0);
      await expect(bindingPanel(page)).toContainText(t('bindings.none'));
      await expect(bindingPanel(page).getByTestId('binding-location')).toHaveCount(0);

      // Remove the Key Vault: confirmed, the list no longer shows it.
      await openVault(page, s.vaultId);
      await page.getByRole('button', { name: kv.removeVault, exact: true }).click();
      const confirm = page.getByRole('dialog', { name: t('vaults.deleteTitle') });
      await expect(confirm.getByText(t('vaults.deleteHelp'))).toBeVisible();
      await confirm.getByRole('button', { name: kv.removeVault, exact: true }).click();
      await answerStepUp(page, request, lang, s.totpSecret, page.getByRole('heading', { level: 1, name: kv.title }));
      await expect(page).toHaveURL(/\/key-vaults$/);
      await expect(page.getByText(t('vaults.empty'))).toBeVisible();
      await expect(vaultRow(page)).toHaveCount(0);

      // With its connections: add the vault again, connect, remove both in one confirmation. The step-up
      // dialogs above rotated the session's CSRF token: a fresh API client, confirmed again.
      const api = await apiAs(page);
      await api.stepUp(s.totpSecret);
      const again = await addVaultByApi(api, request, s.creds);
      await connectByApi(api, await kvCertificateId(api, again, CERT), { autoDeploy: false });
      await openVault(page, again);
      await page.getByRole('button', { name: kv.removeVault, exact: true }).click();
      const both = page.getByRole('dialog', { name: t('vaults.deleteTitle') });
      await both.getByRole('button', { name: kv.removeVault, exact: true }).click();
      await expect(both.getByText(t('vaults.hasBindings'))).toBeVisible();
      await both.getByRole('button', { name: kv.removeVaultAndConnections, exact: true }).click();
      await answerStepUp(page, request, lang, s.totpSecret, page.getByRole('heading', { level: 1, name: kv.title }));
      await expect(page.getByText(t('vaults.empty'))).toBeVisible();
      const gone = await (await apiAs(page)).get(`/api/v1/targets/${again}`);
      expect(gone.status(), 'the removed vault is gone').toBe(404);
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

