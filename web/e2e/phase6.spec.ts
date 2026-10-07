import type { APIRequestContext, APIResponse, Download, Locator, Page } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import {
  ADMIN,
  COPY,
  advanceClock,
  apiAs,
  browserLocale,
  drainJobs,
  drainUntil,
  expect,
  expectAccessibleAt,
  field,
  fingerprintOf,
  firstSignIn,
  freshCode,
  resetInstall,
  runScheduled,
  runWizard,
  serverNow,
  setOverlapMinutes,
  settle,
  signIn,
  signOut,
  tabTo,
  targetExec,
  test,
  translator,
  uiLang,
  type Account,
  type Api,
  type Lang,
  type Translate,
} from './helpers';

// Phase 6 owner journeys on the e2e stack: SSH keys Alice generates, deploys with a verified login,
// hands out as a file, and rotates on the e2e SSH target (accounts deploy and root; alice-svc is the
// account Alice connects with). The contract's key texts are pinned in COPY (ssh); every other visible
// text is read from the locale files at run time (translator).
//
// No secret in artefacts: private keys cross the browser (Download) and the API (the test downloads a
// key to prove a real login), passphrases and step-up codes are typed. Tracing, screenshots and video
// are off for every test of this file (test.use below), so neither the HTML report nor a trace holds
// them; assertions on secret material are booleans with a message (a failed expect never prints the
// value); key files are read into memory from the download stream and the download is deleted at once;
// the private key reaches the SSH target only on standard input (mktemp, umask 077, removed after use).

const HOST_KEY_PUB = '/etc/ssh/ssh_host_ed25519_key.pub';
const SERVER = 'e2e-target';
const DEPLOY_USER = 'deploy';
const DEPLOY_KEYS = '/home/deploy/.ssh/authorized_keys';
const ROOT_KEYS = '/root/.ssh/authorized_keys';
// The connection account's second AuthorizedKeysFile entry (sshd's default list); a symbolic link there is a file
// the helper cannot read safely, so the account's key files are not known completely.
const SVC_KEYS2 = '/var/lib/alice-svc/.ssh/authorized_keys2';
const SVC_KEYS = '/var/lib/alice-svc/.ssh/authorized_keys';
const KEY_LABEL = 'ci-deploy';
const OPENSSH_HEADER = '-----BEGIN OPENSSH PRIVATE KEY-----';
// auth.StepUpWindow: a sign-in or step-up confirms the session for this long.
const STEP_UP_SECONDS = 5 * 60;
const DAY_SECONDS = 24 * 3600;
const JOURNEY_TIMEOUT = 10 * 60_000;
// The widths the Phase 6 screens are checked at: a phone, a tablet, the desktop widths of §26.1 item 9.
const WIDTHS = [375, 768, 1280, 1920] as const;

const OPERATOR: Account = { username: 'olcay', fullName: 'Olcay Öztürk', password: 'operator-password-2026' };
// Rotation emails go to Administrators with an email address.
const MAILED_ADMIN: Account & { email: string } = { ...ADMIN, email: 'ada@example.com' };
const LANGUAGE_NAMES: Record<Lang, string> = { en: 'English', tr: 'Türkçe' };

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// withDate matches a text with a {{date}} parameter, whatever the date (it is formatted in the reader's time zone).
function withDate(t: Translate, key: string): RegExp {
  const [before, after] = t(key, { date: '\u0000' }).split('\u0000');
  return new RegExp(`^${escapeRegExp(before)}.+${escapeRegExp(after)}$`);
}

async function json<T>(res: APIResponse, status?: number): Promise<T> {
  const text = await res.text();
  if (status !== undefined) expect(res.status(), text).toBe(status);
  else expect(res.ok(), `${res.status()} ${text}`).toBe(true);
  return (text ? JSON.parse(text) : {}) as T;
}

// axe checks the screen at every Phase 6 width, softly (a finding fails the test at its end and the journey goes on).
async function axe(page: Page, screen: string, dialog?: Locator): Promise<void> {
  await expectAccessibleAt(page, screen, WIDTHS, { soft: true, dialog });
}

// axeIn checks only the dialog (at every width), for a dialog over a key page that shows a rotation policy that is
// off: that page is checked whole by its own test below ('the SSH key page with a rotation policy that is off').
async function axeIn(page: Page, screen: string, dialog: Locator): Promise<void> {
  await expectAccessibleAt(page, screen, WIDTHS, { soft: true, dialog, only: dialog });
}

// --- the SSH target: fixture files back to their start state, logins, file facts ---

// restoreTarget puts the fixture key files back as the image built them (only the fixture lines, owner and mode) and
// removes what a journey added for the connection account. POST /test/reset resets only Alice.
function restoreTarget(): void {
  targetExec([
    'sh',
    '-c',
    `set -e
keep() { grep -E " ($2)\\$" "$1" > /tmp/.alice-e2e-keep || true; cat /tmp/.alice-e2e-keep > "$1"; rm -f /tmp/.alice-e2e-keep; }
keep ${DEPLOY_KEYS} 'deploy@laptop|ci@build'
keep ${ROOT_KEYS} 'root@bastion'
chown deploy:deploy ${DEPLOY_KEYS}; chmod 0600 ${DEPLOY_KEYS} ${ROOT_KEYS}
rm -f ${SVC_KEYS2}`,
  ]);
}

// keyLine is "type base64" of an OpenSSH public key line (no options, no comment).
function keyLine(publicKey: string): string {
  const [type, b64] = publicKey.trim().split(/\s+/);
  return `${type} ${b64}`;
}

function fileText(path: string): string {
  return targetExec(['cat', path]);
}

// sshLogin signs in to the SSH target as user with the private key (given on standard input, written to a mktemp file
// that only root reads, removed after) and returns what "id -un" printed, or null when the login was refused.
function sshLogin(user: string, privateKey: string): string | null {
  try {
    return targetExec(
      [
        'sh',
        '-c',
        'umask 077; f=$(mktemp); cat > "$f"; ssh -F /dev/null -i "$f" -o IdentitiesOnly=yes -o BatchMode=yes -o PasswordAuthentication=no ' +
          '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 "$1"@127.0.0.1 id -un; s=$?; rm -f "$f"; exit $s',
        'sh',
        user,
      ],
      privateKey,
    ).trim();
  } catch {
    return null;
  }
}

// publicHalf derives the public key of a private key file on the SSH target (ssh-keygen -y), with the passphrase when
// given; null when ssh-keygen refuses (a wrong or missing passphrase). Both travel on standard input.
function publicHalf(privateKey: string, passphrase = ''): string | null {
  try {
    return targetExec(
      ['sh', '-c', 'umask 077; f=$(mktemp); IFS= read -r p; cat > "$f"; ssh-keygen -y -P "$p" -f "$f"; s=$?; rm -f "$f"; exit $s'],
      `${passphrase}\n${privateKey}`,
    ).trim();
  } catch {
    return null;
  }
}

// fileFacts is "owner mode mtime" of a file on the target.
function fileFacts(path: string): { owner: string; mode: string; mtime: string } {
  const [owner, mode, mtime] = targetExec(['stat', '-c', '%U %a %Y', path]).trim().split(' ');
  return { owner, mode, mtime };
}

// --- setup through the API (what the journeys are not about) ---

interface Setup {
  totpSecret: string;
  api: Api;
  serverId: string;
}

// addServer prepares the SSH target with the linux profile script, adds it, confirms its host key after comparing it
// with the server's own and waits for the first scan of its keys (key files listed).
async function addServer(api: Api, request: APIRequestContext): Promise<string> {
  const key = await json<{ profiles: { linux: { script: string } } }>(await api.get('/api/v1/ssh-keys/platform-key'));
  targetExec(['/usr/local/sbin/alice-e2e-prepare'], key.profiles.linux.script);
  return addPreparedServer(api, request);
}

async function addPreparedServer(api: Api, request: APIRequestContext): Promise<string> {
  const created = await json<{ target: { id: string } }>(
    await api.post('/api/v1/targets', { type: 'linux', name: SERVER, host: 'sshtarget', port: 22, username: 'alice-svc' }),
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
  await scanned(api, request, id);
  return id;
}

// scanned drains jobs until the server's last scan has listed its key files.
async function scanned(api: Api, request: APIRequestContext, serverId: string, after = ''): Promise<void> {
  await drainUntil(request, async () => {
    const files = await json<{ scanned_at: string | null }>(await api.get(`/api/v1/targets/${serverId}/key-files`));
    expect(files.scanned_at).not.toBeNull();
    expect(files.scanned_at! > after).toBe(true);
  });
}

// rescan asks for a new scan of the server and waits for it.
async function rescan(api: Api, request: APIRequestContext, serverId: string): Promise<void> {
  const before = (await json<{ scanned_at: string | null }>(await api.get(`/api/v1/targets/${serverId}/key-files`))).scanned_at ?? '';
  await json(await api.post(`/api/v1/targets/${serverId}/actions/discover`), 202);
  await scanned(api, request, serverId, before);
}

// start installs Alice (the Administrator has an email address: rotation emails go to Administrators with one), adds
// the SSH target through the API and reloads the page so it holds the session's current CSRF token.
async function start(page: Page, request: APIRequestContext, lang: Lang, opts: { beforeAdd?: () => void } = {}): Promise<Setup> {
  const { totpSecret } = await runWizard(page, request, lang, MAILED_ADMIN);
  const api = await apiAs(page);
  await api.stepUp(totpSecret);
  let serverId: string;
  if (opts.beforeAdd) {
    const key = await json<{ profiles: { linux: { script: string } } }>(await api.get('/api/v1/ssh-keys/platform-key'));
    targetExec(['/usr/local/sbin/alice-e2e-prepare'], key.profiles.linux.script);
    opts.beforeAdd();
    serverId = await addPreparedServer(api, request);
  } else {
    serverId = await addServer(api, request);
  }
  await page.reload();
  return { totpSecret, api, serverId };
}

interface KeyView {
  id: string;
  fingerprint: string;
  public_key: string;
  managed_key: { label: string; comment: string; policy_id: string | null; open_rotation_id: string | null; download_count: number; retired_at: string | null } | null;
}

async function getKey(api: Api, id: string): Promise<KeyView> {
  return json<KeyView>(await api.get(`/api/v1/ssh-keys/${id}`));
}

async function generateByApi(api: Api, label = KEY_LABEL): Promise<KeyView> {
  const created = await json<{ id: string }>(await api.post('/api/v1/ssh-keys/generate', { label, key_type: 'ed25519' }), 201);
  return getKey(api, created.id);
}

interface JobView {
  status: string;
  result: Record<string, unknown>;
}

// deployByApi deploys a key to a user's file and runs the job; returns the job's outcome (result.result).
async function deployByApi(
  api: Api,
  request: APIRequestContext,
  keyId: string,
  serverId: string,
  user: string,
  file: string,
  opts: { from?: string } = {},
): Promise<string> {
  const accepted = await json<{ job_id: string }>(
    await api.post(`/api/v1/ssh-keys/${keyId}/actions/deploy`, { target_id: serverId, os_user: user, file_path: file, ...(opts.from && { from: opts.from }) }),
    202,
  );
  let job: JobView | undefined;
  await drainUntil(request, async () => {
    job = await json<JobView>(await api.get(`/api/v1/jobs/${accepted.job_id}`));
    expect(['succeeded', 'failed']).toContain(job.status);
  });
  return String(job!.result.result ?? '');
}

// downloadByApi downloads a private key without a passphrase (an Administrator's fresh step-up first: api.stepUp).
async function downloadByApi(api: Api, keyId: string): Promise<string> {
  const res = await api.post(`/api/v1/ssh-keys/${keyId}/actions/download-private-key`, { reason: 'Proof of a real login in the e2e journey' });
  expect(res.status(), 'download of the private key').toBe(200);
  const text = (await res.body()).toString('utf8');
  expect(text.startsWith(OPENSSH_HEADER), 'the file starts like an OpenSSH private key').toBe(true);
  return text;
}

interface PolicyView {
  id: string;
  version: number;
  enabled: boolean;
  overlap_minutes: number;
  open_rotation_id: string | null;
  next_run_at: string | null;
}

interface RunView {
  id: string;
  status: string;
  trigger: string;
  new_ssh_key_id: string | null;
  paused_license: boolean;
  actions_allowed: string[];
  kept_count: number;
  overlap_until: string | null;
  planned_for: string;
  location_counts: Record<string, number>;
  locations: { id: string; os_user: string; file_path: string; state: string; skip_reason: string; error: { reason: string } | null }[];
  notice_state?: { reason: string } | null;
}

async function getRun(api: Api, id: string): Promise<RunView> {
  return json<RunView>(await api.get(`/api/v1/rotation/runs/${id}`));
}

async function createPolicyByApi(api: Api, keyId: string, overrides: Record<string, unknown> = {}): Promise<PolicyView> {
  return json<PolicyView>(
    await api.post('/api/v1/rotation/policies', { ssh_key_id: keyId, name: 'ci-deploy rotation', interval_days: 90, overlap_days: 7, notify_before_hours: 24, new_key_type: 'same', ...overrides }),
    201,
  );
}

async function mails(request: APIRequestContext): Promise<{ to: string; subject: string }[]> {
  const res = await request.get('/test/mail');
  expect(res.ok()).toBe(true);
  return ((await res.json()) as { messages: { to: string; subject: string }[] }).messages;
}

// --- the screens ---

async function nav(page: Page, t: Translate, key: string): Promise<void> {
  await page.getByRole('link', { name: t(key), exact: true }).click();
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
}

// chooseLanguage switches the signed-in user's UI language with the header switcher (saved on the account).
async function chooseLanguage(page: Page, lang: Lang): Promise<void> {
  if ((await uiLang(page)) === lang) return;
  // The choice is saved on the account (PUT /auth/locale) once the page is translated. A full page load before the
  // answer cancels the request, and the next load applies the account's old language (AuthProvider).
  const saved = page.waitForResponse((r) => r.request().method() === 'PUT' && new URL(r.url()).pathname === '/api/v1/auth/locale');
  await page.getByText(LANGUAGE_NAMES[lang], { exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('lang', lang);
  expect((await saved).ok(), 'the language is saved on the account').toBe(true);
}

// answerStepUp confirms the step-up dialog with a fresh code if the server asks for one before done appears.
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

// expectStepUp waits for the step-up dialog (the server asked for a code) and confirms it.
async function expectStepUp(page: Page, request: APIRequestContext, lang: Lang, secret: string): Promise<void> {
  const c = COPY[lang];
  const stepUp = page.getByRole('dialog', { name: c.stepUpHeading });
  await expect(stepUp).toBeVisible();
  await field(stepUp, c.code).fill(await freshCode(request, secret));
  await stepUp.getByRole('button', { name: c.stepUpConfirm }).click();
  await expect(stepUp).toHaveCount(0);
}

async function expireStepUp(request: APIRequestContext): Promise<void> {
  await advanceClock(request, STEP_UP_SECONDS + 1);
}

async function openKey(page: Page, t: Translate, keyId: string): Promise<void> {
  await page.goto(`/ssh-keys/${keyId}`);
  await expect(page.getByRole('heading', { level: 1, name: t('sshKeys.detailTitle') })).toBeVisible();
}

function panel(page: Page): Locator {
  return page.getByTestId('rotation-panel');
}

function runStatus(page: Page): Locator {
  return page.locator('[role="status"][aria-live="polite"]').filter({ has: page.locator('.mantine-Badge-root') });
}

// waitRun drains due jobs until the run page that is open shows the status (its own polling shows it).
async function waitRun(page: Page, request: APIRequestContext, t: Translate, status: string): Promise<void> {
  await drainUntil(request, () => expect(runStatus(page)).toHaveText(t(`rotation.status.${status}`), { timeout: 4_000 }));
}

async function openRun(page: Page, t: Translate, runId: string): Promise<void> {
  await page.goto(`/rotation/runs/${runId}`);
  await expect(page.getByRole('heading', { level: 1, name: t('rotation.runTitle') })).toBeVisible();
}

function runPlace(page: Page, user: string): Locator {
  return page.getByTestId('run-location').filter({ has: page.getByRole('cell', { name: user, exact: true }) });
}

// runNowInUI starts the policy's run from the key page: Run now, the preview on screen, Start rotation, a fresh code;
// returns the run's id from the run page that opens.
async function runNowInUI(page: Page, request: APIRequestContext, lang: Lang, t: Translate, secret: string, keyId: string): Promise<string> {
  const s = COPY[lang].ssh;
  await openKey(page, t, keyId);
  await panel(page).getByRole('button', { name: s.runNow, exact: true }).click();
  const preview = page.getByRole('dialog', { name: t('rotation.previewTitle') });
  await expect(preview.getByRole('table', { name: t('rotation.previewTitle') })).toBeVisible();
  await preview.getByRole('button', { name: s.runNow, exact: true }).click();
  const confirm = page.getByRole('dialog', { name: t('rotation.runConfirmTitle') });
  await expireStepUp(request);
  await confirm.getByRole('button', { name: s.runConfirm, exact: true }).click();
  await expectStepUp(page, request, lang, secret);
  await expect(page.getByRole('heading', { level: 1, name: t('rotation.runTitle') })).toBeVisible();
  const runId = new URL(page.url()).pathname.split('/').pop() ?? '';
  expect(runId).toMatch(/^[0-9a-f-]{36}$/);
  return runId;
}

// expectFocusTrapped presses Tab and Shift+Tab more often than the dialog has controls: the focus never leaves it.
async function expectFocusTrapped(page: Page, dialog: Locator): Promise<void> {
  const count = await dialog.locator('button, input, select, textarea, [tabindex]:not([tabindex="-1"])').count();
  for (const key of ['Tab', 'Shift+Tab']) {
    for (let i = 0; i < count + 2; i++) {
      await page.keyboard.press(key);
      expect(await dialog.evaluate((el) => el.contains(document.activeElement)), `${key} ${i + 1}: the focus stays in the dialog`).toBe(true);
    }
  }
}

// selectByKeyboard picks an option of the focused native select with the arrow keys only.
async function selectByKeyboard(page: Page, select: Locator, value: string): Promise<void> {
  await expect(select).toBeFocused();
  const options = await select.locator('option').evaluateAll((els) => els.map((e) => (e as HTMLOptionElement).value));
  const target = options.indexOf(value);
  expect(target, `${value} is offered`).toBeGreaterThanOrEqual(0);
  for (let i = 0; i < options.length && (await select.inputValue()) !== value; i++) {
    const current = options.indexOf(await select.inputValue());
    await page.keyboard.press(current < target ? 'ArrowDown' : 'ArrowUp');
  }
  await expect(select).toHaveValue(value);
}

function readDownload(download: Download): Promise<string> {
  return (async () => {
    const stream = await download.createReadStream();
    const chunks: Buffer[] = [];
    for await (const chunk of stream) chunks.push(chunk as Buffer);
    return Buffer.concat(chunks).toString('utf8');
  })();
}

// newPassphrase is a fresh random passphrase for one download (never committed, never printed).
function newPassphrase(): string {
  return `e2e-${randomBytes(18).toString('base64url')}`;
}

// A private key, a passphrase or a step-up code crosses the browser or the API in these journeys: no trace, screenshot
// or video is kept for any test of this file, so none can carry it (the HTML report has only the error texts).
// Playwright's error context (an accessibility snapshot of the page, with the values of its fields, attached to a
// failed test) is switched off while this file runs, so a typed passphrase or code cannot land there either.
test.use({ trace: 'off', video: 'off', screenshot: 'off' });
let copyPrompt: string | undefined;
test.beforeAll(() => {
  copyPrompt = process.env.PLAYWRIGHT_NO_COPY_PROMPT;
  process.env.PLAYWRIGHT_NO_COPY_PROMPT = '1';
});
test.afterAll(() => {
  if (copyPrompt === undefined) delete process.env.PLAYWRIGHT_NO_COPY_PROMPT;
  else process.env.PLAYWRIGHT_NO_COPY_PROMPT = copyPrompt;
});

for (const lang of ['en', 'tr'] as Lang[]) {
  const t = translator(lang);
  const c = COPY[lang];
  const s = c.ssh;

  test.describe(`Phase 6 SSH key lifecycle and rotation (${lang})`, () => {
    test.use({ locale: browserLocale(lang), actionTimeout: 30_000 });
    test.beforeEach(async ({ request }) => {
      restoreTarget();
      await resetInstall(request);
    });
    test.afterEach(() => {
      restoreTarget();
    });

    test('§26.8 Phase 6: an Operator generates a key and deploys it with a verified login; the key logs in for real', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      // The pinned contract strings are what the app shows (a locale drift fails here).
      expect(t('sshKeys.generate')).toBe(s.generate);
      expect(t('sshKeys.managedBadge')).toBe(s.managedBadge);
      expect(t('sshKeys.deployResult.verified')).toBe(s.verified);
      expect(t('sshKeys.types.ed25519')).toBe(s.ed25519);

      const setup = await start(page, request, lang);
      const created = await setup.api.post('/api/v1/users', { username: OPERATOR.username, display_name: OPERATOR.fullName, email: '', role: 'operator', password: OPERATOR.password });
      expect(created.status(), await created.text()).toBe(201);
      await page.reload();
      await signOut(page);
      await firstSignIn(page, request, OPERATOR);
      await chooseLanguage(page, lang);

      // Generate: Ed25519 is preselected.
      await nav(page, t, 'nav.sshKeys');
      await page.getByRole('button', { name: s.generate, exact: true }).click();
      const generate = page.getByRole('dialog', { name: t('sshKeys.generateTitle') });
      await expect(generate.getByRole('radio', { name: s.ed25519 })).toBeChecked();
      await field(generate, t('sshKeys.label')).fill(KEY_LABEL);
      await axe(page, 'Generate key', generate);
      await generate.getByRole('button', { name: t('sshKeys.generateSubmit'), exact: true }).click();
      await expect(generate).toHaveCount(0);
      await expect(page.getByRole('heading', { level: 1, name: t('sshKeys.detailTitle') })).toBeVisible();
      const keyId = new URL(page.url()).pathname.split('/').pop() ?? '';
      expect(keyId).toMatch(/^[0-9a-f-]{36}$/);
      const managed = page.getByTestId('managed-key');
      await expect(managed.getByText(s.managedBadge, { exact: true })).toBeVisible();
      await expect(managed).toContainText(KEY_LABEL);
      // An Operator does not see the download of the private key.
      await expect(page.getByRole('button', { name: s.download })).toHaveCount(0);
      const generated = await getKey(await apiAs(page), keyId);
      const publicKey = keyLine(generated.public_key);
      expect(publicKey).toMatch(/^ssh-ed25519 [A-Za-z0-9+/=]+$/);
      await expect(page.getByRole('main')).toContainText(publicKey);
      await expect(page.getByRole('main')).toContainText(generated.fingerprint);

      // The list shows it with the badge.
      await nav(page, t, 'nav.sshKeys');
      const fingerprint = generated.fingerprint;
      const row = page.getByTestId('ssh-keys-table').getByRole('row').filter({ hasText: fingerprint });
      await expect(row).toHaveCount(1);
      await expect(row.getByText(s.managedBadge, { exact: true })).toBeVisible();

      // Deploy: only the deploy account's own files are offered, never the connection account's; the options are from=
      // and restrict only.
      await openKey(page, t, keyId);
      await page.getByRole('button', { name: s.deploy, exact: true }).click();
      const deploy = page.getByRole('dialog', { name: t('sshKeys.deployTitle') });
      const userSelect = field(deploy, t('sshKeys.deployUser'));
      const fileSelect = field(deploy, t('sshKeys.deployFile'));
      await expect(field(deploy, t('sshKeys.deployServer'))).toHaveValue(setup.serverId);
      await expect(userSelect.locator('option')).not.toHaveCount(0);
      const users = await userSelect.locator('option').allTextContents();
      expect(users).toContain(DEPLOY_USER);
      expect(users, 'the connection account is never offered').not.toContain('alice-svc');
      for (const u of users) {
        await userSelect.selectOption(u);
        const files = await fileSelect.locator('option').allTextContents();
        expect(files.some((f) => f === SVC_KEYS || f.startsWith('/var/lib/alice-svc/')), `no file of the connection account is offered for ${u}`).toBe(false);
      }
      await userSelect.selectOption(DEPLOY_USER);
      await fileSelect.selectOption(DEPLOY_KEYS);
      await expect(deploy.getByRole('textbox')).toHaveCount(1);
      await expect(deploy.getByRole('textbox')).toHaveAccessibleName(new RegExp(`^${escapeRegExp(t('sshKeys.deployFrom'))}`));
      await expect(deploy.getByRole('checkbox')).toHaveCount(1);
      await expect(deploy.getByRole('checkbox')).toHaveAccessibleName(t('sshKeys.deployRestrict'));
      await axe(page, 'Deploy key', deploy);
      await deploy.getByRole('button', { name: t('sshKeys.deploySubmit'), exact: true }).click();
      await settle(request, deploy.getByText(s.verified, { exact: true }));
      await axe(page, 'Deploy key, verified', deploy);
      await deploy.getByRole('button', { name: t('ui.close') }).last().click();
      await expect(deploy).toHaveCount(0);

      // On the server: the key is in deploy's file, which stays deploy's own with mode 0600.
      expect(fileText(DEPLOY_KEYS)).toContain(publicKey);
      expect(fileFacts(DEPLOY_KEYS)).toMatchObject({ owner: DEPLOY_USER, mode: '600' });
      await expect(page.getByTestId('key-locations')).toContainText(DEPLOY_KEYS);

      // A real login as deploy with that key: an Administrator downloads it (the API), the target's own ssh client logs in.
      await signOut(page);
      await signIn(page, request, MAILED_ADMIN, setup.totpSecret);
      const admin = await apiAs(page);
      await admin.stepUp(setup.totpSecret);
      expect(sshLogin(DEPLOY_USER, await downloadByApi(admin, keyId)), 'ssh -i <the key> deploy@sshtarget id -un').toBe(DEPLOY_USER);
    });

    test('§26.8 Phase 6: rotation with a one-minute overlap adds, verifies, overlaps, removes and completes', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const setup = await start(page, request, lang);
      const key = await generateByApi(setup.api);
      expect(await deployByApi(setup.api, request, key.id, setup.serverId, DEPLOY_USER, DEPLOY_KEYS)).toBe('verified');
      const oldPrivate = await downloadByApi(setup.api, key.id);
      // A place the planner skips: the key twice in root's file.
      targetExec(['sh', '-c', `printf '%s rotation-dup\\n%s rotation-dup\\n' "$1" "$1" >> ${ROOT_KEYS}`, 'sh', keyLine(key.public_key)]);
      await rescan(setup.api, request, setup.serverId);

      // Create the policy: 90 / 7 / 24; it is off.
      await openKey(page, t, key.id);
      await expect(panel(page)).toContainText(t('rotation.none'));
      await panel(page).getByRole('button', { name: s.createPolicy, exact: true }).click();
      const create = page.getByRole('dialog', { name: t('rotation.createTitle') });
      await field(create, t('rotation.name')).fill('ci-deploy rotation');
      await expect(field(create, t('rotation.intervalDays'))).toHaveValue('90');
      await expect(field(create, t('rotation.overlapDays'))).toHaveValue('7');
      await expect(field(create, t('rotation.notifyHours'))).toHaveValue('24');
      await axe(page, 'Create rotation policy', create);
      await create.getByRole('button', { name: t('rotation.save'), exact: true }).click();
      await expect(create).toHaveCount(0);
      const sw = panel(page).getByRole('switch', { name: t('rotation.switch') });
      await expect(sw).not.toBeChecked();
      await expect(panel(page).getByText(s.offHelp, { exact: true })).toBeVisible();
      const policyId = (await getKey(setup.api, key.id)).managed_key!.policy_id!;

      // Preview: the change and the skipped place with its reason; an email goes to the Administrators.
      await panel(page).getByRole('button', { name: s.preview, exact: true }).click();
      const preview = page.getByRole('dialog', { name: t('rotation.previewTitle') });
      const table = preview.getByRole('table', { name: t('rotation.previewTitle') });
      const deployRow = table.getByRole('row').filter({ has: page.getByRole('cell', { name: DEPLOY_USER, exact: true }) });
      const rootRow = table.getByRole('row').filter({ has: page.getByRole('cell', { name: 'root', exact: true }) });
      await expect(deployRow).toContainText(SERVER);
      await expect(deployRow).toContainText(DEPLOY_KEYS);
      await expect(deployRow).toContainText(s.willChange);
      await expect(rootRow).toContainText(t('rotation.skipped'));
      await expect(rootRow).toContainText(t('rotation.skip.duplicate_lines'));
      await expect(preview.getByText(t('rotation.changes', { count: 1 }))).toBeVisible();
      await expect(preview.getByText(t('rotation.skips', { count: 1 }))).toBeVisible();
      await axeIn(page, 'Rotation preview', preview);
      await preview.getByRole('button', { name: t('ui.close') }).last().click();
      await expect(preview).toHaveCount(0);
      await advanceClock(request, 1); // the email sender runs after a clock move
      expect((await mails(request)).map((m) => m.subject)).toContain(t('email.rotation.preview.subject', { key_label: KEY_LABEL }));

      // Switch it on: an Administrator's fresh code.
      await expireStepUp(request);
      await sw.click({ force: true });
      await expectStepUp(page, request, lang, setup.totpSecret);
      await expect(sw).toBeChecked();
      await expect(panel(page).getByText(s.offHelp, { exact: true })).toHaveCount(0);

      // The overlap is one minute (the e2e endpoint); the panel shows it in minutes.
      await setOverlapMinutes(request, policyId, 1);
      await page.reload();
      await expect(panel(page)).toContainText(t('rotation.overlap', { duration: t('rotation.duration.minutes', { count: 1 }) }));

      // Run now from the preview on screen: confirm, a fresh code, the run page.
      await panel(page).getByRole('button', { name: s.runNow, exact: true }).click();
      await expect(preview.getByText(t('rotation.changes', { count: 1 }))).toBeVisible();
      await preview.getByRole('button', { name: s.runNow, exact: true }).click();
      const confirm = page.getByRole('dialog', { name: t('rotation.runConfirmTitle') });
      await axeIn(page, 'Start rotation', confirm);
      await expireStepUp(request);
      await confirm.getByRole('button', { name: s.runConfirm, exact: true }).click();
      await expectStepUp(page, request, lang, setup.totpSecret);
      await expect(page.getByRole('heading', { level: 1, name: t('rotation.runTitle') })).toBeVisible();
      const runId = new URL(page.url()).pathname.split('/').pop() ?? '';
      await expect(page.getByText(t('rotation.trigger.manual'), { exact: true })).toBeVisible();

      // Adding → verifying → overlap: both keys are in the file.
      await waitRun(page, request, t, 'overlap');
      const run = await getRun(setup.api, runId);
      const newKey = await getKey(setup.api, run.new_ssh_key_id!);
      expect(fileText(DEPLOY_KEYS)).toContain(keyLine(key.public_key));
      expect(fileText(DEPLOY_KEYS)).toContain(keyLine(newKey.public_key));
      await expect(runPlace(page, DEPLOY_USER)).toContainText(t('rotation.loc.verified'));
      await expect(runPlace(page, 'root')).toContainText(t('rotation.loc.skipped'));
      await expect(page.getByTestId('run-counts')).toContainText(t('rotation.countLine', { label: t('rotation.counts.total'), count: 2 }));
      await axe(page, 'Rotation run, overlap');

      // The overlap is not over after 30 s: still both keys.
      await advanceClock(request, 30);
      await runScheduled(request, 'rotation.sweep');
      await drainJobs(request);
      await page.reload();
      await expect(runStatus(page)).toHaveText(t('rotation.status.overlap'));
      expect(fileText(DEPLOY_KEYS)).toContain(keyLine(key.public_key));

      // After the minute: removing, then completed with its counts.
      await advanceClock(request, 31);
      await runScheduled(request, 'rotation.sweep');
      await waitRun(page, request, t, 'completed');
      expect(fileText(DEPLOY_KEYS)).not.toContain(keyLine(key.public_key));
      expect(fileText(DEPLOY_KEYS)).toContain(keyLine(newKey.public_key));
      expect(fileFacts(DEPLOY_KEYS)).toMatchObject({ owner: DEPLOY_USER, mode: '600' });
      await expect(runPlace(page, DEPLOY_USER)).toContainText(t('rotation.loc.removed'));
      await expect(page.getByTestId('run-counts')).toContainText(t('rotation.countLine', { label: t('rotation.counts.removed'), count: 1 }));
      await expect(page.getByTestId('run-counts')).toContainText(t('rotation.countLine', { label: t('rotation.counts.skipped'), count: 1 }));
      await axe(page, 'Rotation run, completed');

      // The new key logs in; the old one no longer does. (The step-up dialogs rotated the CSRF token: a fresh client.)
      const api = await apiAs(page);
      await api.stepUp(setup.totpSecret);
      expect(sshLogin(DEPLOY_USER, await downloadByApi(api, newKey.id)), 'the new key logs in').toBe(DEPLOY_USER);
      expect(sshLogin(DEPLOY_USER, oldPrivate), 'the old key no longer logs in').toBeNull();

      // The policy is the new key's now; its panel shows the last run's outcome.
      await page.getByRole('link', { name: t('rotation.backToKey') }).click();
      await expect(page).toHaveURL(new RegExp(`/ssh-keys/${newKey.id}$`));
      await expect(panel(page)).toContainText(t('rotation.lastRun', { status: t('rotation.status.completed') }));
      await expect(panel(page).getByRole('link', { name: t('rotation.openLastRun') })).toBeVisible();
      // The old key still works in root's file, which the run skipped: the run says so, and so does its email.
      const subjects = (await mails(request)).map((m) => m.subject);
      for (const k of ['overlap_started', 'completed_partial']) expect(subjects, k).toContain(t(`email.rotation.${k}.subject`, { key_label: KEY_LABEL }));
      expect(subjects).not.toContain(t('email.rotation.completed.subject', { key_label: KEY_LABEL }));
      await page.goBack();
      await expect(page.getByText(t('rotation.keptCount', { count: 1 }), { exact: true })).toBeVisible();
      await expect(page.getByText(t('rotation.keptHelp'), { exact: true })).toBeVisible();

      // The old key's page: it is no longer the policy's key (no policy, the rotation's new key has it).
      await openKey(page, t, key.id);
      await expect(panel(page)).toContainText(t('rotation.none'));
      expect((await getKey(api, key.id)).managed_key!.policy_id).toBeNull();
      expect((await getKey(api, newKey.id)).managed_key!.policy_id).toBe(policyId);

      // The audit log lists the run's state changes.
      await page.getByRole('link', { name: c.navAudit, exact: true }).click();
      await expect(page.getByRole('heading', { name: c.auditHeading })).toBeVisible();
      await expect(page.getByRole('row').filter({ hasText: t('audit.actions.rotation_status_changed') }).first()).toBeVisible();
    });

    test('§26.8 owner step 2, S-09: an Administrator downloads the private key with a step-up, a reason and an optional passphrase; the audit log shows it', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      expect(t('sshKeys.download')).toBe(s.download);
      const setup = await start(page, request, lang);
      const key = await generateByApi(setup.api);
      expect(await deployByApi(setup.api, request, key.id, setup.serverId, DEPLOY_USER, DEPLOY_KEYS)).toBe('verified');
      await openKey(page, t, key.id);
      await expect(page.getByText(t('sshKeys.downloadCount', { count: 0 }), { exact: true })).toBeVisible();

      const dialog = page.getByRole('dialog', { name: t('sshKeys.downloadTitle') });
      const reason = field(dialog, t('sshKeys.downloadReason'));
      const protect = dialog.getByRole('checkbox', { name: t('sshKeys.downloadProtect') });
      const passphrases = dialog.locator('input[type="password"]');
      // allEmpty: every passphrase field on the page is empty (a boolean: a failure never prints a value).
      const allEmpty = () => page.locator('input[type="password"]').evaluateAll((els) => els.every((e) => (e as HTMLInputElement).value === ''));
      const pass = newPassphrase();

      // Cancel drops what was typed.
      await page.getByRole('button', { name: s.download, exact: true }).click();
      await expect(dialog.getByText(t('sshKeys.downloadWarning'), { exact: true })).toBeVisible();
      await expect(protect).toBeChecked();
      await reason.fill('Hand-over for the e2e journey');
      await field(dialog, t('sshKeys.downloadPassphrase')).fill(pass);
      await field(dialog, t('sshKeys.downloadPassphraseRepeat')).fill(pass);
      await axe(page, 'Download private key', dialog);
      await dialog.getByRole('button', { name: t('ui.cancel'), exact: true }).click();
      await expect(dialog).toHaveCount(0);
      expect(await allEmpty(), 'the passphrase fields are empty after Cancel').toBe(true);
      await page.getByRole('button', { name: s.download, exact: true }).click();
      await expect(reason).toHaveValue('');
      await expect(passphrases).toHaveCount(2);
      expect(await allEmpty(), 'the passphrase fields are empty when the dialog opens again').toBe(true);

      // With a passphrase: the server asks for a fresh code; the passphrase fields are empty while it asks.
      await reason.fill('Hand-over for the e2e journey');
      await field(dialog, t('sshKeys.downloadPassphrase')).fill(pass);
      await field(dialog, t('sshKeys.downloadPassphraseRepeat')).fill(pass);
      await expireStepUp(request);
      const answered = page.waitForResponse((r) => r.url().endsWith(`/api/v1/ssh-keys/${key.id}/actions/download-private-key`) && r.status() === 200);
      const downloaded = page.waitForEvent('download');
      await dialog.getByRole('button', { name: t('sshKeys.downloadSubmit'), exact: true }).click();
      await expect(page.getByRole('dialog', { name: c.stepUpHeading })).toBeVisible();
      expect(await allEmpty(), 'the passphrase fields are empty while the code is asked for').toBe(true);
      await expectStepUp(page, request, lang, setup.totpSecret);
      const res = await answered;
      // The real handler answers with the file itself, never JSON, and the browser does not keep it.
      expect(res.headers()['content-type']).toBe('application/octet-stream');
      expect(res.headers()['cache-control']).toContain('no-store');
      expect(res.headers()['x-content-type-options']).toBe('nosniff');
      expect(res.headers()['content-disposition']).toMatch(/^attachment; filename="?alice-ci-deploy[a-z0-9._-]*\.key"?$/);
      const download = await downloaded;
      expect(download.suggestedFilename()).toBe('alice-ci-deploy.key');
      const file = await readDownload(download).finally(() => download.delete());
      expect(file.startsWith(OPENSSH_HEADER), 'the file starts like an OpenSSH private key').toBe(true);
      expect(publicHalf(file), 'without the passphrase the file does not open').toBeNull();
      expect(publicHalf(file, pass)?.startsWith(keyLine(key.public_key)), 'with the passphrase it is the private half of the key on the page').toBe(true);
      await expect(dialog.getByText(t('sshKeys.downloadDone'), { exact: true })).toBeVisible();
      expect(await allEmpty(), 'no passphrase is left on the page after the download').toBe(true);
      await axe(page, 'Download private key, done', dialog);
      await dialog.getByRole('button', { name: t('ui.close') }).last().click();
      await expect(dialog).toHaveCount(0);
      await expect(page.getByText(t('sshKeys.downloadCount', { count: 1 }), { exact: true })).toBeVisible();

      // Without a passphrase (the step-up is still fresh: no code is asked): the file is the key, and it logs in.
      await page.getByRole('button', { name: s.download, exact: true }).click();
      await reason.fill('Second hand-over, unprotected');
      await protect.uncheck();
      await expect(passphrases).toHaveCount(0);
      const plain = page.waitForEvent('download');
      await dialog.getByRole('button', { name: t('sshKeys.downloadSubmit'), exact: true }).click();
      const second = await plain;
      const plainFile = await readDownload(second).finally(() => second.delete());
      await expect(page.getByRole('dialog', { name: c.stepUpHeading })).toHaveCount(0);
      expect(plainFile.startsWith(OPENSSH_HEADER), 'the file starts like an OpenSSH private key').toBe(true);
      expect(publicHalf(plainFile)?.startsWith(keyLine(key.public_key)), 'the unprotected file is the private half of the key on the page').toBe(true);
      expect(sshLogin(DEPLOY_USER, plainFile), 'the downloaded key logs in as deploy').toBe(DEPLOY_USER);
      await dialog.getByRole('button', { name: t('ui.close') }).last().click();
      await expect(page.getByText(t('sshKeys.downloadCount', { count: 2 }), { exact: true })).toBeVisible();

      // The audit log lists both downloads with their reasons.
      await page.getByRole('link', { name: c.navAudit, exact: true }).click();
      await expect(page.getByRole('heading', { name: c.auditHeading })).toBeVisible();
      const rows = page.getByRole('row').filter({ hasText: t('audit.actions.sshkey_private_key_downloaded') });
      await expect(rows).toHaveCount(2);
      for (const [i, text] of [
        [0, 'Second hand-over, unprotected'],
        [1, 'Hand-over for the e2e journey'],
      ] as const) {
        await rows.nth(i).locator('button[aria-expanded]').click();
        await expect(rows.nth(i)).toContainText(text);
      }
    });

    test('§26.8 a place that cannot be tested: an Administrator is offered Keep old and Stop and undo, an Operator nothing; Keep old completes keeping the old key there', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const setup = await start(page, request, lang);
      const created = await setup.api.post('/api/v1/users', { username: OPERATOR.username, display_name: OPERATOR.fullName, email: '', role: 'operator', password: OPERATOR.password });
      expect(created.status(), await created.text()).toBe(201);
      const key = await generateByApi(setup.api);
      expect(await deployByApi(setup.api, request, key.id, setup.serverId, DEPLOY_USER, DEPLOY_KEYS)).toBe('verified');
      // A place limited to a source address: Alice cannot test a login there.
      expect(await deployByApi(setup.api, request, key.id, setup.serverId, 'root', ROOT_KEYS, { from: '10.0.0.0/8' })).toBe('unverified');
      await rescan(setup.api, request, setup.serverId);
      const policy = await createPolicyByApi(setup.api, key.id);
      await setOverlapMinutes(request, policy.id, 1);

      const runId = await runNowInUI(page, request, lang, t, setup.totpSecret, key.id);
      await waitRun(page, request, t, 'verifying_new');
      await expect(runPlace(page, DEPLOY_USER)).toContainText(t('rotation.loc.verified'));
      await expect(runPlace(page, 'root')).toContainText(t('rotation.loc.unverifiable'));
      await expect(runPlace(page, 'root')).toContainText(t('rotation.note.from_option'));
      // Exactly the decisions the API allows: Keep old and Stop and undo.
      const allowed = (await getRun(await apiAs(page), runId)).actions_allowed;
      expect([...allowed].sort()).toEqual(['abort', 'keep_old']);
      await expect(page.getByRole('button', { name: s.keepOld, exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: s.abort, exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: s.continueRun, exact: true })).toHaveCount(0);
      await expect(page.getByRole('button', { name: s.finishNow, exact: true })).toHaveCount(0);
      await expect(page.getByText(withDate(t, 'rotation.decisionDue'))).toBeVisible();
      await axe(page, 'Rotation run waiting for a decision');

      // An Operator reads the same run and is offered nothing.
      await signOut(page);
      await firstSignIn(page, request, OPERATOR);
      await chooseLanguage(page, lang);
      await openRun(page, t, runId);
      await expect(runStatus(page)).toHaveText(t('rotation.status.verifying_new'));
      for (const name of [s.keepOld, s.abort, s.continueRun, s.finishNow]) await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0);
      await axe(page, 'Rotation run waiting for a decision, Operator');
      await signOut(page);
      await signIn(page, request, MAILED_ADMIN, setup.totpSecret);

      // Keep old: its help text; the untested place is ticked; an Administrator's fresh code.
      await openRun(page, t, runId);
      await page.getByRole('button', { name: s.keepOld, exact: true }).click();
      const keep = page.getByRole('dialog', { name: s.keepOld });
      await expect(keep.getByText(t('rotation.keepOldHelp'), { exact: true })).toBeVisible();
      const place = keep.getByRole('checkbox', { name: `${SERVER}, root, ${ROOT_KEYS}` });
      await expect(keep.getByRole('button', { name: s.keepOld, exact: true })).toBeDisabled();
      await place.check();
      await axe(page, 'Keep the old key', keep);
      await expireStepUp(request);
      await keep.getByRole('button', { name: s.keepOld, exact: true }).click();
      await expectStepUp(page, request, lang, setup.totpSecret);
      await expect(keep).toHaveCount(0);
      await waitRun(page, request, t, 'overlap');
      await expect(runPlace(page, 'root')).toContainText(t('rotation.loc.kept_old'));

      // After the minute the old key is removed where the new key works and kept in root's file.
      await advanceClock(request, 61);
      await runScheduled(request, 'rotation.sweep');
      await waitRun(page, request, t, 'completed');
      const newKey = await getKey(await apiAs(page), (await getRun(await apiAs(page), runId)).new_ssh_key_id!);
      await expect(runPlace(page, DEPLOY_USER)).toContainText(t('rotation.loc.removed'));
      await expect(runPlace(page, 'root')).toContainText(t('rotation.loc.kept_old'));
      await expect(page.getByText(t('rotation.keptCount', { count: 1 }), { exact: true })).toBeVisible();
      expect(fileText(DEPLOY_KEYS)).not.toContain(keyLine(key.public_key));
      expect(fileText(DEPLOY_KEYS)).toContain(keyLine(newKey.public_key));
      expect(fileText(ROOT_KEYS), 'the old key stays where it was kept').toContain(keyLine(key.public_key));
      await axe(page, 'Rotation run, completed with a kept place');
    });

    test('§26.8 Stop and undo needs no code and undoes every place; a planned run starts with Run now; editing a policy that is on switches it off', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const setup = await start(page, request, lang);
      const key = await generateByApi(setup.api);
      expect(await deployByApi(setup.api, request, key.id, setup.serverId, DEPLOY_USER, DEPLOY_KEYS)).toBe('verified');
      expect(await deployByApi(setup.api, request, key.id, setup.serverId, 'root', ROOT_KEYS, { from: '10.0.0.0/8' })).toBe('unverified');
      await rescan(setup.api, request, setup.serverId);
      // A policy that is on: every day, a notice one hour before; the planner plans the run when the notice is due.
      let policy = await createPolicyByApi(setup.api, key.id, { interval_days: 1, notify_before_hours: 1 });
      await json(await setup.api.post(`/api/v1/rotation/policies/${policy.id}/actions/enable`, undefined, { 'If-Match': `"${policy.version}"` }));
      policy = await json<PolicyView>(await setup.api.get(`/api/v1/rotation/policies/${policy.id}`));
      expect(policy.enabled).toBe(true);
      await setOverlapMinutes(request, policy.id, 1);
      const nextRun = Date.parse(policy.next_run_at!);
      await advanceClock(request, Math.ceil((nextRun - (await serverNow(request))) / 1000) - 3600 + 60);
      await runScheduled(request, 'rotation.plan');
      await signIn(page, request, MAILED_ADMIN, setup.totpSecret); // the hours passed ended the idle session
      expect((await mails(request)).map((m) => m.subject)).toContain(t('email.rotation.preview.subject', { key_label: KEY_LABEL }));

      // The planned run: the panel links it and Run now starts it (it stays a scheduled run).
      await openKey(page, t, key.id);
      await expect(panel(page).getByRole('link', { name: t('rotation.openRun') })).toBeVisible();
      const runNow = panel(page).getByRole('button', { name: s.runNow, exact: true });
      await expect(runNow).toBeEnabled();
      const planned = (await json<{ open_rotation_id: string }>(await (await apiAs(page)).get(`/api/v1/rotation/policies/${policy.id}`))).open_rotation_id;
      expect((await getRun(await apiAs(page), planned)).status).toBe('dry_run_notified');
      const runId = await runNowInUI(page, request, lang, t, setup.totpSecret, key.id);
      expect(runId).toBe(planned);
      await expect(page.getByText(t('rotation.trigger.scheduled'), { exact: true })).toBeVisible();
      await waitRun(page, request, t, 'verifying_new');

      // Stop and undo: a confirmation, then no code is asked although the step-up window has passed.
      await expireStepUp(request);
      await page.getByRole('button', { name: s.abort, exact: true }).click();
      const stop = page.getByRole('dialog', { name: s.abort });
      await expect(stop.getByText(t('rotation.abortConfirm'), { exact: true })).toBeVisible();
      await axe(page, 'Stop and undo', stop);
      await stop.getByRole('button', { name: s.abort, exact: true }).click();
      await expect(stop).toHaveCount(0);
      await expect(page.getByRole('dialog', { name: c.stepUpHeading })).toHaveCount(0);
      await waitRun(page, request, t, 'aborted');
      await expect(page.getByRole('dialog', { name: c.stepUpHeading })).toHaveCount(0);
      const run = await getRun(await apiAs(page), runId);
      const newKey = await getKey(await apiAs(page), run.new_ssh_key_id!);
      await expect(runPlace(page, DEPLOY_USER)).toContainText(t('rotation.loc.undone'));
      await expect(runPlace(page, 'root')).toContainText(t('rotation.loc.undone'));
      await expect(page.getByText(t('errors.rotation.stopped.title'), { exact: true })).toBeVisible();
      expect(fileText(DEPLOY_KEYS)).toContain(keyLine(key.public_key));
      expect(fileText(DEPLOY_KEYS)).not.toContain(keyLine(newKey.public_key));
      expect(fileText(ROOT_KEYS)).toContain(keyLine(key.public_key));
      expect(fileText(ROOT_KEYS)).not.toContain(keyLine(newKey.public_key));
      await axe(page, 'Rotation run, undone');

      // Edit the policy that is on: the dialog warns before saving; afterwards the policy is off and its overlap of one
      // minute (set by the e2e endpoint, under a day) is still shown in minutes.
      await openKey(page, t, key.id);
      const sw = panel(page).getByRole('switch', { name: t('rotation.switch') });
      await expect(sw).toBeChecked();
      await panel(page).getByRole('button', { name: t('rotation.edit'), exact: true }).click();
      const edit = page.getByRole('dialog', { name: t('rotation.editTitle') });
      await expect(edit.getByText(t('rotation.editSwitchesOff'), { exact: true })).toBeVisible();
      await axeIn(page, 'Edit rotation policy', edit);
      await field(edit, t('rotation.intervalDays')).fill('2');
      await edit.getByRole('button', { name: t('rotation.save'), exact: true }).click();
      await expect(edit).toHaveCount(0);
      await expect(sw).not.toBeChecked();
      await expect(panel(page).getByText(s.offHelp, { exact: true })).toBeVisible();
      await expect(panel(page)).toContainText(t('rotation.every', { count: 2 }));
      await expect(panel(page)).toContainText(t('rotation.overlap', { duration: t('rotation.duration.minutes', { count: 1 }) }));
      const after = await json<PolicyView>(await (await apiAs(page)).get(`/api/v1/rotation/policies/${policy.id}`));
      expect([after.enabled, after.overlap_minutes]).toEqual([false, 1]);
    });

    test('§26.8 L-83, L-84: a scheduled run starts by itself; a lock pauses its overlap and nothing reaches the server; after the renewal Continue and Finish now complete it', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const setup = await start(page, request, lang);
      const key = await generateByApi(setup.api);
      expect(await deployByApi(setup.api, request, key.id, setup.serverId, DEPLOY_USER, DEPLOY_KEYS)).toBe('verified');
      let policy = await createPolicyByApi(setup.api, key.id, { interval_days: 1, notify_before_hours: 1 });
      await json(await setup.api.post(`/api/v1/rotation/policies/${policy.id}/actions/enable`, undefined, { 'If-Match': `"${policy.version}"` }));
      policy = await json<PolicyView>(await setup.api.get(`/api/v1/rotation/policies/${policy.id}`));
      // An overlap of 60 days: the lock (the evaluation ends 30 days after the installation) falls inside it.
      await setOverlapMinutes(request, policy.id, 60 * 24 * 60);

      // The planner plans the run when its notice is due; the notice is delivered; at the planned time the sweep
      // starts it by itself.
      await advanceClock(request, Math.ceil((Date.parse(policy.next_run_at!) - (await serverNow(request))) / 1000) - 3600 + 60);
      await runScheduled(request, 'rotation.plan');
      await advanceClock(request, 1); // the email sender delivers the notice (before the planned start: S1)
      expect((await mails(request)).map((m) => m.subject)).toContain(t('email.rotation.preview.subject', { key_label: KEY_LABEL }));
      await advanceClock(request, 3600);
      await runScheduled(request, 'rotation.sweep');
      await signIn(page, request, MAILED_ADMIN, setup.totpSecret);
      const runId = (await json<PolicyView>(await (await apiAs(page)).get(`/api/v1/rotation/policies/${policy.id}`))).open_rotation_id!;
      await openRun(page, t, runId);
      await expect(page.getByText(t('rotation.trigger.scheduled'), { exact: true })).toBeVisible();
      await waitRun(page, request, t, 'overlap');
      const newKeyId = (await getRun(await apiAs(page), runId)).new_ssh_key_id!;
      const newKey = await getKey(await apiAs(page), newKeyId);
      await expect(page.getByText(withDate(t, 'rotation.overlapUntil'))).toBeVisible();

      // The new key of a live rotation cannot be deployed elsewhere: the dialog says why.
      await openKey(page, t, newKeyId);
      await page.getByRole('button', { name: s.deploy, exact: true }).click();
      const deploy = page.getByRole('dialog', { name: t('sshKeys.deployTitle') });
      await field(deploy, t('sshKeys.deployUser')).selectOption('root');
      await deploy.getByRole('button', { name: t('sshKeys.deploySubmit'), exact: true }).click();
      await expect(deploy.getByRole('alert').filter({ hasText: t('errors.sshkey.in_rotation.title') })).toBeVisible();
      await deploy.getByRole('button', { name: t('ui.cancel'), exact: true }).click();
      expect(fileText(ROOT_KEYS)).not.toContain(keyLine(newKey.public_key));

      // The evaluation ends: the license is locked. The sweep pauses the overlap; nothing reaches the server.
      const before = { text: fileText(DEPLOY_KEYS), facts: fileFacts(DEPLOY_KEYS) };
      await advanceClock(request, 31 * DAY_SECONDS);
      await runScheduled(request, 'rotation.sweep');
      await drainJobs(request);
      await signIn(page, request, MAILED_ADMIN, setup.totpSecret);
      await openRun(page, t, runId);
      await expect(page.getByRole('alert').filter({ hasText: t('rotation.pausedBanner') })).toBeVisible();
      await expect(page.getByText(t('rotation.licensePaused'), { exact: true })).toBeVisible();
      await expect(page.getByText(t('rotation.overlapOnHold'), { exact: true })).toBeVisible();
      // One message, no countdown to the overlap's end.
      await expect(page.getByText(withDate(t, 'rotation.overlapUntil'))).toHaveCount(0);
      await expect(page.getByText(t('errors.rotation.paused_license.title'), { exact: true })).toHaveCount(0);
      // Only Stop and undo is offered.
      await expect(page.getByRole('button', { name: s.abort, exact: true })).toBeVisible();
      for (const name of [s.keepOld, s.continueRun, s.finishNow]) await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0);
      expect((await getRun(await apiAs(page), runId)).actions_allowed).toEqual(['abort']);
      // Its accessibility is checked by the test 'the run page paused by the license' below.
      await runScheduled(request, 'rotation.sweep');
      await drainJobs(request);
      expect({ text: fileText(DEPLOY_KEYS), facts: fileFacts(DEPLOY_KEYS) }, 'nothing reached the server in lock').toEqual(before);
      expect((await mails(request)).map((m) => m.subject)).toContain(t('email.rotation.paused_license.subject', { key_label: KEY_LABEL }));

      // A license again: until the sweep has queued the renewal notice, Continue is not offered and the page says why.
      const issued = await request.post('/test/license', { data: { valid_days: 365 } });
      expect(issued.ok(), await issued.text()).toBe(true);
      const api = await apiAs(page);
      await api.stepUp(setup.totpSecret);
      await json(await api.post('/api/v1/license', { license: ((await issued.json()) as { license: string }).license }));
      await page.reload();
      await expect(page.getByText(t('errors.rotation.notice_pending.title'), { exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: s.continueRun, exact: true })).toHaveCount(0);
      await runScheduled(request, 'rotation.sweep');
      await page.reload();
      await expect(page.getByText(t('errors.rotation.notice_pending.title'), { exact: true })).toHaveCount(0);
      await expect(page.getByText(t('rotation.continueHelp'), { exact: true })).toBeVisible();
      expect({ text: fileText(DEPLOY_KEYS), facts: fileFacts(DEPLOY_KEYS) }, 'still nothing sent before Continue').toEqual(before);
      await advanceClock(request, 1);
      expect((await mails(request)).map((m) => m.subject)).toContain(t('email.rotation.preview_after_license.subject', { key_label: KEY_LABEL }));

      // Continue (a fresh code): the overlap goes on; Finish now ends it and the old key is removed.
      await expireStepUp(request);
      await page.getByRole('button', { name: s.continueRun, exact: true }).click();
      await expectStepUp(page, request, lang, setup.totpSecret);
      await expect(page.getByRole('alert').filter({ hasText: t('rotation.pausedBanner') })).toHaveCount(0);
      await expect(runStatus(page)).toHaveText(t('rotation.status.overlap'));
      await page.getByRole('button', { name: s.finishNow, exact: true }).click();
      const finish = page.getByRole('dialog', { name: s.finishNow });
      await expect(finish.getByText(t('rotation.finishNowHelp'), { exact: true })).toBeVisible();
      await axe(page, 'Finish now', finish);
      await finish.getByRole('button', { name: s.finishNow, exact: true }).click();
      await answerStepUp(page, request, lang, setup.totpSecret, runStatus(page));
      await waitRun(page, request, t, 'completed');
      expect(fileText(DEPLOY_KEYS)).not.toContain(keyLine(key.public_key));
      expect(fileText(DEPLOY_KEYS)).toContain(keyLine(newKey.public_key));
      await expect(runPlace(page, DEPLOY_USER)).toContainText(t('rotation.loc.removed'));
    });

    test('§26.8 refusals are shown truthfully: unknown key files of the connection account, a plan that changed before Run now', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      // The connection account's key files are not known completely: its second AuthorizedKeysFile is a link.
      const setup = await start(page, request, lang, { beforeAdd: () => targetExec(['ln', '-sfn', '/dev/null', SVC_KEYS2]) });
      const key = await generateByApi(setup.api);
      await openKey(page, t, key.id);
      await page.getByRole('button', { name: s.deploy, exact: true }).click();
      const deploy = page.getByRole('dialog', { name: t('sshKeys.deployTitle') });
      const refusal = deploy.getByRole('status').filter({ hasText: t('errors.sshkey.connection_files_unknown.title') });
      await expect(refusal).toBeVisible();
      await expect(refusal).toContainText(t('errors.sshkey.connection_files_unknown.action'));
      await expect(deploy.getByText(t('sshKeys.deployNoFiles'), { exact: true })).toHaveCount(0);
      await expect(field(deploy, t('sshKeys.deployUser')).locator('option')).toHaveCount(0);
      await expect(deploy.getByRole('button', { name: t('sshKeys.deploySubmit'), exact: true })).toBeDisabled();
      await axe(page, 'Deploy key, key files not known', deploy);
      const refused = await setup.api.post(`/api/v1/ssh-keys/${key.id}/actions/deploy`, { target_id: setup.serverId, os_user: DEPLOY_USER, file_path: DEPLOY_KEYS });
      expect((await json<{ error: { code: string } }>(refused, 409)).error.code).toBe('ALC-KEY-0014');
      await deploy.getByRole('button', { name: t('ui.cancel'), exact: true }).click();

      // As the text says: after a new scan of the repaired server the files are offered again.
      targetExec(['rm', '-f', SVC_KEYS2]);
      await rescan(setup.api, request, setup.serverId);
      await page.reload();
      await page.getByRole('button', { name: s.deploy, exact: true }).click();
      await expect(field(deploy, t('sshKeys.deployUser')).locator('option', { hasText: DEPLOY_USER })).toHaveCount(1);
      await expect(deploy.getByText(t('errors.sshkey.connection_files_unknown.title'))).toHaveCount(0);
      await deploy.getByRole('button', { name: t('ui.cancel'), exact: true }).click();
      expect(await deployByApi(setup.api, request, key.id, setup.serverId, DEPLOY_USER, DEPLOY_KEYS)).toBe('verified');

      // Run now with a preview whose plan changed meanwhile (the overlap is part of the plan): 409, nothing starts, the
      // dialog shows the new preview and asks to look at it.
      const policy = await createPolicyByApi(setup.api, key.id);
      await openKey(page, t, key.id);
      await panel(page).getByRole('button', { name: s.runNow, exact: true }).click();
      const preview = page.getByRole('dialog', { name: t('rotation.previewTitle') });
      await expect(preview.getByText(t('rotation.changes', { count: 1 }))).toBeVisible();
      await setOverlapMinutes(request, policy.id, 1);
      await preview.getByRole('button', { name: s.runNow, exact: true }).click();
      const confirm = page.getByRole('dialog', { name: t('rotation.runConfirmTitle') });
      await expireStepUp(request);
      const refusedRun = page.waitForResponse((r) => r.url().endsWith(`/api/v1/rotation/policies/${policy.id}/actions/run`) && r.status() === 409);
      await confirm.getByRole('button', { name: s.runConfirm, exact: true }).click();
      await expectStepUp(page, request, lang, setup.totpSecret);
      expect(((await (await refusedRun).json()) as { error: { code: string } }).error.code).toBe('ALC-ROT-0003');
      await expect(confirm).toHaveCount(0);
      await expect(preview.getByRole('alert').filter({ hasText: t('rotation.previewRefreshed') })).toBeVisible();
      await expect(preview.getByText(t('rotation.changes', { count: 1 }))).toBeVisible();
      await axeIn(page, 'Rotation preview after a changed plan', preview);
      expect(page.url()).toMatch(new RegExp(`/ssh-keys/${key.id}$`));
      const runs = await json<{ items: { status: string }[] }>(await (await apiAs(page)).get(`/api/v1/rotation/runs?policy_id=${policy.id}`));
      expect(runs.items.filter((r) => !['cancelled'].includes(r.status)), 'nothing started').toEqual([]);
    });

    test('§26.1 keyboard: Generate, Deploy and Download by keyboard only; dialogs keep and give back the focus; the run page announces its state politely', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const setup = await start(page, request, lang);
      await nav(page, t, 'nav.sshKeys');
      await axe(page, 'SSH keys');

      // Generate: the button, the name, Enter; the new key's page opens.
      const generateButton = page.getByRole('button', { name: s.generate, exact: true });
      await tabTo(page, generateButton, 60);
      await page.keyboard.press('Enter');
      const generate = page.getByRole('dialog', { name: t('sshKeys.generateTitle') });
      const label = field(generate, t('sshKeys.label'));
      await expect(label).toBeFocused();
      await expectFocusTrapped(page, generate);
      await page.keyboard.press('Escape');
      await expect(generate).toHaveCount(0);
      await expect(generateButton, 'the focus is back on Generate key').toBeFocused();
      await page.keyboard.press('Enter');
      await expect(label).toBeFocused();
      await page.keyboard.type(KEY_LABEL);
      await page.keyboard.press('Enter');
      await expect(page.getByRole('heading', { level: 1, name: t('sshKeys.detailTitle') })).toBeVisible();
      await axe(page, 'SSH key, generated');

      // Deploy: the server select has the focus; the user and the file by keyboard; Deploy with Enter.
      const deployButton = page.getByRole('button', { name: s.deploy, exact: true });
      await tabTo(page, deployButton, 80);
      await page.keyboard.press('Enter');
      const deploy = page.getByRole('dialog', { name: t('sshKeys.deployTitle') });
      await expect(field(deploy, t('sshKeys.deployServer'))).toBeFocused();
      await expect(field(deploy, t('sshKeys.deployUser')).locator('option', { hasText: DEPLOY_USER })).toHaveCount(1);
      await expectFocusTrapped(page, deploy);
      await page.keyboard.press('Escape');
      await expect(deploy).toHaveCount(0);
      await expect(deployButton, 'the focus is back on Deploy').toBeFocused();
      await page.keyboard.press('Enter');
      const userSelect = field(deploy, t('sshKeys.deployUser'));
      await tabTo(page, userSelect);
      await selectByKeyboard(page, userSelect, DEPLOY_USER);
      await tabTo(page, field(deploy, t('sshKeys.deployFile')));
      await selectByKeyboard(page, field(deploy, t('sshKeys.deployFile')), DEPLOY_KEYS);
      const submit = deploy.getByRole('button', { name: t('sshKeys.deploySubmit'), exact: true });
      await tabTo(page, submit);
      await page.keyboard.press('Enter');
      await settle(request, deploy.getByText(s.verified, { exact: true }));
      const close = deploy.getByRole('button', { name: t('ui.close') }).last();
      await tabTo(page, close);
      await page.keyboard.press('Enter');
      await expect(deploy).toHaveCount(0);
      await expect(deployButton, 'the focus is back on Deploy').toBeFocused();

      // Download: reason, no passphrase, Download with Enter; the code with the keyboard too.
      const downloadButton = page.getByRole('button', { name: s.download, exact: true });
      await tabTo(page, downloadButton);
      await page.keyboard.press('Enter');
      const download = page.getByRole('dialog', { name: t('sshKeys.downloadTitle') });
      await expect(field(download, t('sshKeys.downloadReason'))).toBeFocused();
      await expectFocusTrapped(page, download);
      await field(download, t('sshKeys.downloadReason')).focus();
      await page.keyboard.type('Keyboard-only hand-over');
      await tabTo(page, download.getByRole('checkbox', { name: t('sshKeys.downloadProtect') }));
      await page.keyboard.press('Space');
      await expect(download.getByRole('checkbox', { name: t('sshKeys.downloadProtect') })).not.toBeChecked();
      await tabTo(page, download.getByRole('button', { name: t('sshKeys.downloadSubmit'), exact: true }));
      await expireStepUp(request);
      const saved = page.waitForEvent('download');
      await page.keyboard.press('Enter');
      const stepUp = page.getByRole('dialog', { name: c.stepUpHeading });
      await expect(field(stepUp, c.code)).toBeFocused();
      await page.keyboard.type(await freshCode(request, setup.totpSecret));
      await page.keyboard.press('Enter');
      const file = await saved;
      try {
        expect((await readDownload(file)).startsWith(OPENSSH_HEADER), 'the file starts like an OpenSSH private key').toBe(true);
      } finally {
        await file.delete();
      }
      await expect(download.getByText(t('sshKeys.downloadDone'), { exact: true })).toBeVisible();
      await page.keyboard.press('Escape');
      await expect(download).toHaveCount(0);
      await expect(downloadButton, 'the focus is back on Download').toBeFocused();

      // The run page's state is a polite live region whose text follows the run.
      const keyId = new URL(page.url()).pathname.split('/').pop() ?? '';
      const policy = await createPolicyByApi(await apiAs(page), keyId);
      await setOverlapMinutes(request, policy.id, 1);
      const runId = await runNowInUI(page, request, lang, t, setup.totpSecret, keyId);
      const live = page.locator('[role="status"][aria-live="polite"]').filter({ has: page.locator('.mantine-Badge-root') });
      await expect(live).toHaveCount(1);
      await waitRun(page, request, t, 'overlap');
      await expect(live).toHaveText(t('rotation.status.overlap'));
      await axe(page, 'Rotation run, overlap');
      await advanceClock(request, 61);
      await runScheduled(request, 'rotation.sweep');
      await waitRun(page, request, t, 'completed');
      await expect(live).toHaveText(t('rotation.status.completed'));
      expect(new URL(page.url()).pathname).toBe(`/rotation/runs/${runId}`);
    });

    test('§26.1 accessibility: the SSH key page with a rotation policy that is off', async ({ page, request }) => {
      const setup = await start(page, request, lang);
      const key = await generateByApi(setup.api);
      await createPolicyByApi(setup.api, key.id);
      await openKey(page, t, key.id);
      await expect(panel(page).getByRole('switch', { name: t('rotation.switch') })).not.toBeChecked();
      await expectAccessibleAt(page, 'SSH key with a rotation policy that is off', WIDTHS);
    });

    test('§26.1 accessibility: the run page paused by the license', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const setup = await start(page, request, lang);
      const key = await generateByApi(setup.api);
      expect(await deployByApi(setup.api, request, key.id, setup.serverId, DEPLOY_USER, DEPLOY_KEYS)).toBe('verified');
      const policy = await createPolicyByApi(setup.api, key.id);
      await setOverlapMinutes(request, policy.id, 60 * 24 * 60);
      const runId = await runNowInUI(page, request, lang, t, setup.totpSecret, key.id);
      await waitRun(page, request, t, 'overlap');
      await advanceClock(request, 31 * DAY_SECONDS);
      await runScheduled(request, 'rotation.sweep');
      await signIn(page, request, MAILED_ADMIN, setup.totpSecret);
      await openRun(page, t, runId);
      await expect(page.getByRole('alert').filter({ hasText: t('rotation.pausedBanner') })).toBeVisible();
      await expectAccessibleAt(page, 'Rotation run paused by the license', WIDTHS);
    });
  });
}
