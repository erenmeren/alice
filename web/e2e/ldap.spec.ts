import type { APIRequestContext, APIResponse, Page } from '@playwright/test';
import {
  ADMIN,
  COPY,
  advanceClock,
  answerStepUp,
  apiAs,
  browserLocale,
  either,
  enrollTotp,
  expect,
  expectSignedInAs,
  field,
  freshCode,
  ldapCA,
  ldapCtl,
  ldapRunning,
  ldapService,
  resetInstall,
  runWizard,
  signIn,
  signOut,
  test,
  translator,
} from './helpers';

// Directory (LDAP) sign-in on the e2e stack, against the fake directory (compose service fakeldap: the OpenLDAP image of
// the integration tests, test/images/openldap). Alice reaches it as ldaps://ldap.alice-e2e.test:636 with a certificate
// issued by a CA generated when the container started, which the Administrator pastes into the directory's CA field.
//
// Journey 1: the Administrator adds the directory with the OpenLDAP preset, tests the connection and a sign-in (groups and
// role shown, the password field cleared), maps alice-ops to Operator and switches sign-in on. A person in no mapped
// group and a wrong password get the same generic text; Ada (in alice-ops) enrols her authenticator at the first sign-in,
// signs in again with the code and confirms with the directory password and the code. Three failures of one name lock it
// ('Too many requests'). Removing Ada from alice-ops in the directory refuses her next sign-in and ends her open session.
// The audit log (read through the API) has the ldap.* and auth.ldap.denied entries and no password, nor the typed name
// that matched nobody.
// Journey 2 (break-glass): with the directory switched off, and then with the directory unreachable, the local
// Administrator still signs in.
//
// Preset: the journey uses the OpenLDAP preset (uid, entryUUID, (member={dn})). OpenLDAP has neither AD's binary
// objectGUID nor the in-chain rule 1.2.840.113556.1.4.1941, so the Active Directory preset is covered only by unit
// tests of its values (web/src/api/ldap.test.ts, DirectoriesSettings.test.tsx); it was not run against a real AD.
//
// Clock: the directory checks no time, the certificate is checked against the real time, Alice's sign-in limits and TOTP
// codes run on the e2e clock (advanced in small steps only; POST /test/reset puts it back and clears the lockout). Every
// refused directory sign-in takes at least 1.5 s (Alice's minimum delay on refusals).
//
// No secret in artefacts: tracing, video and screenshots are off for this file (passwords are typed).

const DIRECTORY = 'Example LDAP';
const ADDRESS = 'ldaps://ldap.alice-e2e.test:636';
const SERVICE_DN = 'cn=alice-svc,ou=services,dc=example,dc=test';
// Throw-away passwords of the test directory (test/images/openldap/bootstrap.ldif, internal/testutil/fakeldap).
const SERVICE_PASSWORD = 'svc-Pa55-0f-the-service';
const ADA = { login: 'ada', password: 'ada-Analytical-1843', name: 'Ada Lovelace' };
const GRACE = { login: 'grace', password: 'grace-COBOL-1959' };
const WRONG_PASSWORD = 'not-Ada-s-password-77';
// A name the directory does not know: Alice must never store it (people type passwords into the name field).
const GHOST = { login: 'e2e-ghost-nobody', password: 'ghost-Guess-0001' };
const SECRETS = [SERVICE_PASSWORD, ADA.password, GRACE.password, WRONG_PASSWORD, GHOST.password];
const JOURNEY_TIMEOUT = 10 * 60_000;
// auth.StepUpWindow: a sign-in or a confirmation opens the window for this long.
const STEP_UP_SECONDS = 5 * 60;

test.use({ trace: 'off', video: 'off', screenshot: 'off', ignoreHTTPSErrors: true });

const lang = 'en';
const t = translator(lang);
const c = COPY[lang];

// directoryBody is the directory the journeys set up: the OpenLDAP preset's attributes and filters (web/src/api/ldap.ts)
// with the test tree's base DNs and service account.
function directoryBody(enabled: boolean): Record<string, unknown> {
  return {
    name: DIRECTORY,
    addresses: [ADDRESS],
    user_base_dn: 'ou=people,dc=example,dc=test',
    user_filter: '(&(objectClass=inetOrgPerson)(uid={login}))',
    login_attribute: 'uid',
    unique_id_attribute: 'entryUUID',
    display_name_attribute: 'cn',
    email_attribute: 'mail',
    bind_dn: SERVICE_DN,
    bind_password: SERVICE_PASSWORD,
    group_base_dn: 'ou=groups,dc=example,dc=test',
    group_filter: '(member={dn})',
    group_name_attribute: 'cn',
    ca_pem: ldapCA(),
    mfa_required: true,
    enabled,
  };
}

// directorySignIn signs in through the directory on the sign-in page and returns the HTTP status of its login request.
async function directorySignIn(page: Page, login: string, password: string): Promise<number> {
  await page.goto('/login');
  await expect(page.getByRole('heading', { name: either('loginHeading') })).toBeVisible();
  await field(page, t('login.signInTo')).selectOption({ label: DIRECTORY });
  await field(page, c.username).fill(login);
  await field(page, c.password).fill(password);
  const [res] = await Promise.all([
    page.waitForResponse((r) => /\/api\/v1\/auth\/ldap\/[0-9a-f-]{36}\/login$/.test(r.url()) && r.request().method() === 'POST'),
    page.getByRole('button', { name: c.signIn, exact: true }).click(),
  ]);
  return res.status();
}

// expectNoSecretOnPage checks that no password typed in this journey is anywhere in the page: not in the DOM, not in a
// field's value (React state), not in the address.
async function expectNoSecretOnPage(page: Page): Promise<void> {
  const html = await page.content();
  const values = await page.locator('input, textarea').evaluateAll((els) => els.map((e) => (e as HTMLInputElement).value));
  for (const s of SECRETS) {
    expect(html, 'no password in the page').not.toContain(s);
    expect(values, 'no password in a form field').not.toContain(s);
    expect(page.url()).not.toContain(encodeURIComponent(s));
  }
}

// expectRefused checks the one generic refusal text of a directory sign-in (title and action only, no code, no reason).
async function expectRefused(page: Page): Promise<string> {
  const alert = page.getByTestId('directory-error');
  await expect(alert).toContainText(t('errors.ldap.signin_refused.title'));
  await expect(alert).toContainText(t('errors.ldap.signin_refused.action'));
  await expect(alert).not.toContainText('ALC-');
  return (await alert.textContent()) ?? '';
}

interface Session {
  csrf: string;
}

// adminApi returns the session's CSRF token after a fresh step-up (the directory routes need one).
async function adminApi(page: Page, totpSecret: string): Promise<Session> {
  const api = await apiAs(page);
  await api.stepUp(totpSecret);
  const s = await page.request.get('/api/v1/auth/session');
  expect(s.ok()).toBe(true);
  return { csrf: ((await s.json()) as { csrf_token: string }).csrf_token };
}

async function ok<T>(res: APIResponse): Promise<T> {
  expect(res.ok(), `${res.status()} ${await res.text()}`).toBe(true);
  return (await res.json()) as T;
}

interface AuditEntry {
  action: string;
  result: string;
  details?: Record<string, unknown>;
}

// auditExport reads the whole audit log through the API (the JSON export, as an Auditor or Administrator).
async function auditExport(request: APIRequestContext): Promise<{ text: string; entries: AuditEntry[] }> {
  const res = await request.get('/api/v1/audit/export?format=json');
  expect(res.ok(), await res.text()).toBe(true);
  const text = await res.text();
  return { text, entries: (JSON.parse(text) as { entries: AuditEntry[] }).entries };
}

test.describe('Directory sign-in (LDAP)', () => {
  test.use({ locale: browserLocale(lang), actionTimeout: 30_000 });
  test.beforeEach(async ({ request }) => {
    // A journey that failed while the directory was stopped, or after Ada left alice-ops, leaves it so: put it back.
    if (!ldapRunning()) await ldapService('start');
    ldapCtl('member', 'add', 'ada', 'alice-ops');
    await resetInstall(request);
  });
  test.afterEach(async () => {
    if (!ldapRunning()) await ldapService('start');
    ldapCtl('member', 'add', 'ada', 'alice-ops');
  });

  test('an Administrator adds a directory; directory users sign in with MFA, are refused alike, locked out after three failures, and lose access when the directory removes them', async ({ page, request, browser }) => {
    test.setTimeout(JOURNEY_TIMEOUT);
    const { totpSecret } = await runWizard(page, request, lang, ADMIN);

    // Settings, Directories: add the directory with the OpenLDAP preset (MFA on and sign-in off by default).
    const add = page.getByRole('button', { name: t('directories.add'), exact: true });
    await page.goto('/settings?tab=directories');
    await answerStepUp(page, request, lang, totpSecret, add);
    await expect(page.getByText(t('directories.none'), { exact: true })).toBeVisible();
    await add.click();
    const dlg = page.getByRole('dialog', { name: t('directories.add') });
    await field(dlg, t('directories.fields.name')).fill(DIRECTORY);
    await dlg.getByRole('button', { name: t('directories.presets.openldap'), exact: true }).click();
    await expect(field(dlg, t('directories.fields.userFilter'))).toHaveValue('(&(objectClass=inetOrgPerson)(uid={login}))');
    await expect(field(dlg, t('directories.fields.uniqueIdAttribute'))).toHaveValue('entryUUID');
    await expect(field(dlg, t('directories.fields.groupFilter'))).toHaveValue('(member={dn})');
    await field(dlg, t('directories.fields.addresses')).fill(ADDRESS);
    await field(dlg, t('directories.fields.userBaseDn')).fill('ou=people,dc=example,dc=test');
    await field(dlg, t('directories.fields.bindDn')).fill(SERVICE_DN);
    await field(dlg, t('directories.fields.bindPassword')).fill(SERVICE_PASSWORD);
    await field(dlg, t('directories.fields.groupBaseDn')).fill('ou=groups,dc=example,dc=test');
    await field(dlg, t('directories.fields.caPem')).fill(ldapCA());
    await expect(dlg.getByRole('switch', { name: t('directories.fields.mfaRequired') })).toBeChecked();
    await expect(dlg.getByRole('switch', { name: t('directories.fields.enabled') })).not.toBeChecked();
    await dlg.getByRole('button', { name: t('directories.save'), exact: true }).click();
    await expect(dlg).toHaveCount(0);
    await expectNoSecretOnPage(page);
    const table = page.getByRole('table', { name: t('directories.table') });
    const row = table.getByRole('row').filter({ hasText: DIRECTORY });
    await expect(row).toContainText(ADDRESS);
    await expect(row).toContainText(t('directories.mfa.on'));
    await expect(row).toContainText(t('directories.status.disabled'));
    const region = page.getByRole('region', { name: DIRECTORY });

    // Test connection: the service account binds and searches the user base DN.
    await region.getByRole('button', { name: t('directories.testConnectionNamed', { name: DIRECTORY }) }).click();
    await expect(region.getByRole('status')).toHaveText(t('directories.connectionOk'));

    // Test sign-in, before any mapping: the groups the directory returns, no role; the password field is cleared.
    const testSignIn = async (expectRole: string) => {
      await region.getByRole('button', { name: t('directories.testSignInNamed', { name: DIRECTORY }) }).click();
      const td = page.getByRole('dialog', { name: t('directories.testSignInTitle', { name: DIRECTORY }) });
      await field(td, t('directories.testUsername')).fill(ADA.login);
      await field(td, t('directories.testPassword')).fill(ADA.password);
      await td.getByRole('button', { name: t('directories.runTest'), exact: true }).click();
      const result = td.getByRole('status');
      await expect(result).toContainText(t('directories.result.title'));
      await expect(result.locator('code').filter({ hasText: /^alice-ops$/ })).toBeVisible();
      await expect(result).toContainText(ADA.name);
      await expect(result).toContainText('ada@example.test');
      await expect(result).toContainText(expectRole);
      await expect(field(td, t('directories.testPassword'))).toHaveValue('');
      await expectNoSecretOnPage(page);
      await td.getByRole('button', { name: t('ui.cancel'), exact: true }).click();
      await expect(td).toHaveCount(0);
    };
    await testSignIn(t('directories.result.noRole'));

    // Map alice-ops to Operator (the value exactly as Test sign-in listed it); the test now gives Operator.
    await field(region, t('directories.group')).fill('alice-ops');
    await field(region, t('directories.role')).selectOption('operator');
    await region.getByRole('button', { name: t('directories.addMapping'), exact: true }).click();
    await expect(region.getByRole('row').filter({ has: page.getByText('alice-ops', { exact: true }) })).toContainText(t('enum.role.operator'));
    await testSignIn(t('enum.role.operator'));

    // Switch sign-in on (only the switch changes: no service account password needed again).
    await page.getByRole('button', { name: t('directories.edit', { name: DIRECTORY }) }).click();
    const edit = page.getByRole('dialog', { name: t('directories.editTitle') });
    await expect(field(edit, t('directories.fields.bindPassword'))).toHaveValue('');
    await edit.getByRole('switch', { name: t('directories.fields.enabled') }).click();
    await edit.getByRole('button', { name: t('directories.save'), exact: true }).click();
    await expect(edit).toHaveCount(0);
    await expect(row).toContainText(t('directories.status.enabled'));

    // The sign-in page offers the directory under "Sign in to"; Local stays the default.
    await signOut(page);
    const signInTo = field(page, t('login.signInTo'));
    await expect(signInTo).toBeVisible();
    await expect(signInTo.locator('option:checked')).toHaveText(t('login.local'));
    await expect(signInTo.locator('option')).toHaveText([t('login.local'), DIRECTORY]);

    // Refused alike: a person in no mapped group (Grace) and a wrong password; nobody is signed in, no password stays.
    expect(await directorySignIn(page, GRACE.login, GRACE.password)).toBe(401);
    const noAccessText = await expectRefused(page);
    await expect(field(page, c.password)).toHaveValue('');
    await expectNoSecretOnPage(page);
    expect(await directorySignIn(page, ADA.login, WRONG_PASSWORD)).toBe(401);
    expect(await expectRefused(page)).toBe(noAccessText);
    await expectNoSecretOnPage(page);
    await expect(page.getByRole('button', { name: c.signOut })).toHaveCount(0);

    // Ada's first sign-in: the directory accepts the password, Alice asks her to set up the authenticator (with recovery
    // codes), then she is in as Ada Lovelace, an Operator.
    expect(await directorySignIn(page, ADA.login, ADA.password)).toBe(200);
    await expectNoSecretOnPage(page);
    const { totpSecret: adaSecret } = await enrollTotp(page, request, c);
    await expectSignedInAs(page, ADA.name);
    const navigation = page.getByRole('navigation', { name: t('nav.label') });
    await expect(navigation.getByRole('link', { name: t('nav.certificates'), exact: true })).toBeVisible();
    await expect(navigation.getByRole('link', { name: t('nav.settings'), exact: true })).toHaveCount(0);
    const session = await ok<{ user: { auth_source: string; role: string; username: string } }>(await page.request.get('/api/v1/auth/session'));
    expect(session.user).toMatchObject({ auth_source: 'ldap', role: 'operator', username: 'ada' });

    // The second sign-in asks for the authenticator code.
    await signOut(page);
    expect(await directorySignIn(page, ADA.login, ADA.password)).toBe(200);
    await expect(page.getByRole('heading', { name: c.mfaHeading })).toBeVisible();
    await field(page, c.code).fill(await freshCode(request, adaSecret));
    await page.getByRole('button', { name: c.verify }).click();
    await expectSignedInAs(page, ADA.name);

    // "Confirm it's you" for a directory user: the directory password again and the authenticator code.
    await advanceClock(request, STEP_UP_SECONDS + 1);
    await page.goto('/account');
    await page.getByRole('button', { name: t('account.recovery.create'), exact: true }).click();
    const stepUp = page.getByRole('dialog', { name: c.stepUpHeading });
    await expect(stepUp).toBeVisible();
    await expect(stepUp).toContainText(t('stepUp.directoryHelp'));
    await field(stepUp, t('stepUp.directoryPassword')).fill(ADA.password);
    await field(stepUp, c.code).fill(await freshCode(request, adaSecret));
    const [confirmed] = await Promise.all([
      page.waitForResponse((r) => r.url().endsWith('/api/v1/auth/ldap/stepup') && r.request().method() === 'POST'),
      stepUp.getByRole('button', { name: c.stepUpConfirm }).click(),
    ]);
    expect(confirmed.status()).toBe(200);
    await expect(stepUp).toHaveCount(0);
    await expect(page.getByTestId('recovery-codes')).toBeVisible();
    await expectNoSecretOnPage(page);

    // Three failed sign-ins of one name lock it in Alice: the fourth attempt is answered "Too many requests" at once, even
    // for a name the directory does not know (the per-address limit is reset first by moving the e2e clock a minute on).
    const other = await browser.newContext({ baseURL: test.info().project.use.baseURL, ignoreHTTPSErrors: true, locale: browserLocale(lang) });
    try {
      const page2 = await other.newPage();
      await advanceClock(request, 61);
      for (let i = 0; i < 3; i++) {
        expect(await directorySignIn(page2, GHOST.login, GHOST.password)).toBe(401);
        await expectRefused(page2);
      }
      expect(await directorySignIn(page2, GHOST.login, GHOST.password)).toBe(429);
      await expect(page2.getByRole('alert').filter({ hasText: t('errors.rate.limited.title') })).toBeVisible();
      await expectNoSecretOnPage(page2);

      // The directory removes Ada from alice-ops: her next sign-in is refused with the same text, and her open session
      // (the first browser) ends.
      ldapCtl('member', 'remove', 'ada', 'alice-ops');
      await advanceClock(request, 61);
      expect(await directorySignIn(page2, ADA.login, ADA.password)).toBe(401);
      expect(await expectRefused(page2)).toBe(noAccessText);
    } finally {
      await other.close();
    }
    expect((await page.request.get('/api/v1/auth/session')).status()).toBe(401);
    await page.goto('/');
    await expect(page).toHaveURL(/\/login/);
    await expect(page.getByRole('heading', { name: either('loginHeading') })).toBeVisible();

    // The local Administrator: Ada is listed as a directory user (badge, Operator); the audit log has the story.
    await signIn(page, request, ADMIN, totpSecret);
    await page.getByRole('link', { name: c.navUsers, exact: true }).click();
    const adaRow = page.getByRole('row').filter({ hasText: ADA.name });
    await expect(adaRow.getByText(t('users.directory'), { exact: true })).toBeVisible();
    await expect(adaRow).toContainText(t('enum.role.operator'));
    await expect(page.getByRole('row').filter({ hasText: 'grace' })).toHaveCount(0);

    const { text, entries } = await auditExport(page.request);
    const actions = entries.map((e) => e.action);
    expect(actions).toEqual(
      expect.arrayContaining([
        'ldap.directory_created',
        'ldap.directory_tested',
        'ldap.signin_tested',
        'ldap.mapping_created',
        'ldap.directory_changed',
        'auth.ldap.denied',
        'user.provisioned',
        'auth.stepup',
        'user.sessions_ended',
      ]),
    );
    const denied = entries.filter((e) => e.action === 'auth.ldap.denied');
    expect(denied.map((e) => e.details?.reason)).toEqual(expect.arrayContaining(['no_access', 'bad_credentials']));
    expect(denied.every((e) => e.result === 'failure')).toBe(true);
    expect(entries.some((e) => e.action === 'auth.stepup' && e.result === 'success' && e.details?.method === 'ldap')).toBe(true);
    for (const s of SECRETS) expect(text, 'no password in the audit log').not.toContain(s);
    expect(text, 'a name the directory did not resolve is not recorded').not.toContain(GHOST.login);
  });

  test('break-glass: the local Administrator signs in while the directory is switched off and while it is unreachable', async ({ page, request }) => {
    test.setTimeout(JOURNEY_TIMEOUT);
    const { totpSecret } = await runWizard(page, request, lang, ADMIN);
    const { csrf } = await adminApi(page, totpSecret);
    const headers = { 'X-CSRF-Token': csrf };
    const dir = await ok<{ id: string; version: number }>(await page.request.post('/api/v1/ldap/directories', { headers, data: directoryBody(true) }));
    await ok(await page.request.post('/api/v1/ldap/group-mappings', { headers, data: { directory_id: dir.id, group: 'alice-ops', role: 'operator' } }));
    const off = await ok<{ version: number }>(
      await page.request.patch(`/api/v1/ldap/directories/${dir.id}`, { headers: { ...headers, 'If-Match': `"${dir.version}"` }, data: { enabled: false } }),
    );

    // Switched off: the sign-in page offers no directory; the local Administrator signs in. (The API step-up rotated the
    // session and its CSRF token: the page is loaded again before the UI is used.)
    await page.reload();
    await signOut(page);
    await expect(page.getByRole('button', { name: c.signIn, exact: true })).toBeVisible();
    await expect(field(page, t('login.signInTo'))).toHaveCount(0);
    await signIn(page, request, ADMIN, totpSecret);
    await expectSignedInAs(page, ADMIN.fullName);

    // Switched on again but unreachable (the directory container is stopped): a directory sign-in says the directory
    // cannot be used; the local Administrator signs in.
    const again = await adminApi(page, totpSecret);
    await ok(await page.request.patch(`/api/v1/ldap/directories/${dir.id}`, { headers: { 'X-CSRF-Token': again.csrf, 'If-Match': `"${off.version}"` }, data: { enabled: true } }));
    await page.reload();
    await signOut(page);
    await ldapService('stop');
    try {
      expect(await directorySignIn(page, ADA.login, ADA.password)).toBe(503);
      const alert = page.getByTestId('directory-error');
      await expect(alert).toContainText(t('errors.ldap.directory_unavailable.title'));
      await expect(alert).toContainText(t('errors.ldap.directory_unavailable.action'));
      await expectNoSecretOnPage(page);
      await signIn(page, request, ADMIN, totpSecret);
      await expectSignedInAs(page, ADMIN.fullName);
    } finally {
      await ldapService('start');
    }

    // The refusal is recorded as directory_unreachable, without the password.
    const { text, entries } = await auditExport(page.request);
    expect(entries.some((e) => e.action === 'auth.ldap.denied' && e.details?.reason === 'directory_unreachable')).toBe(true);
    for (const s of SECRETS) expect(text, 'no password in the audit log').not.toContain(s);
  });
});
