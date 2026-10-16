import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { createI18n } from '../../i18n';
import { DIRECTORY_PRESETS } from '../../api/ldap';
import { adminSession, DIRECTORY_ID, directoryFixture, errorResponse, sessionFor, sessionHandlers } from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

// The form has many fields: typed character by character they take long under coverage on a busy machine.
vi.setConfig({ testTimeout: 30_000 });

const steppedUp = { ...adminSession, stepup_until: '2099-01-01T00:00:00Z' };
const CANARY = 'canary-bind-password-7Q';
const TEST_CANARY = 'canary-user-password-9Z';
const dirURL = `/api/v1/ldap/directories/${DIRECTORY_ID}`;

function base(extra: Parameters<typeof server.use> = [] as never) {
  // msw takes the first matching handler: a test's own handlers come first.
  server.use(
    ...extra,
    ...sessionHandlers(steppedUp),
    http.get('/api/v1/ldap/directories', () => HttpResponse.json({ items: [directoryFixture()] })),
    http.get('/api/v1/ldap/group-mappings', () => HttpResponse.json({ items: [] })),
  );
}

// fillNew types the required fields of a new directory (everything a preset does not fill).
async function fillNew(dialog: HTMLElement, password = CANARY) {
  const put = async (label: RegExp, value: string) => {
    await userEvent.click(within(dialog).getByLabelText(label));
    await userEvent.paste(value);
  };
  await put(/^Name shown/, 'Corp LDAP');
  await put(/^Addresses/, 'ldaps://ldap1.corp.example\nldaps://ldap2.corp.example:636');
  await put(/^User base DN/, 'ou=people,dc=corp,dc=example');
  await put(/^Service account DN/, 'cn=svc,dc=corp,dc=example');
  if (password) await put(/^Service account password/, password);
  await put(/^Group base DN/, 'ou=groups,dc=corp,dc=example');
}

const save = (dialog: HTMLElement) => userEvent.click(within(dialog).getByRole('button', { name: 'Save directory' }));

describe('Directories settings', () => {
  it('lists the directories as a table with name, addresses, MFA, sign-in and version', async () => {
    base([
      http.get('/api/v1/ldap/directories', () =>
        HttpResponse.json({ items: [directoryFixture(), directoryFixture({ id: 'd2', name: 'Lab LDAP', addresses: ['ldaps://lab.example'], mfa_required: false, enabled: false, version: 1 })] }),
      ),
    ]);
    await renderRoute('/settings?tab=directories');
    const table = await screen.findByRole('table', { name: 'Directories' });
    const corp = within(table).getByText('Corp AD').closest('tr') as HTMLElement;
    expect(within(corp).getByText('ldaps://dc1.corp.example:636').tagName).toBe('CODE');
    expect(within(corp).getByText('ldaps://dc2.corp.example')).toBeInTheDocument();
    expect(within(corp).getByText('Code asked')).toBeInTheDocument();
    expect(within(corp).getByText('On')).toBeInTheDocument();
    expect(within(corp).getByRole('cell', { name: '3' })).toBeInTheDocument();
    const lab = within(table).getByText('Lab LDAP').closest('tr') as HTMLElement;
    expect(within(lab).getByText('Password only')).toBeInTheDocument();
    expect(within(lab).getByText('Off')).toBeInTheDocument();
    // Each directory has its own group mappings section, and the Admin switch of the SSO tab is named.
    expect(screen.getByRole('region', { name: 'Corp AD' })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Lab LDAP' })).toBeInTheDocument();
    expect(screen.getByText(/applies to directory users too/)).toBeInTheDocument();
    expect(screen.getByText('Keep a local recovery administrator')).toBeInTheDocument();
  });

  it('says so when no directory is set up', async () => {
    base([http.get('/api/v1/ldap/directories', () => HttpResponse.json({ items: [] }))]);
    await renderRoute('/settings?tab=directories');
    expect(await screen.findByText('No directory is set up yet.')).toBeInTheDocument();
    expect(screen.queryByRole('table', { name: 'Directories' })).not.toBeInTheDocument();
  });

  it('adds a directory with the defaults (MFA on, sign-in off), sends the password once and never shows it again', async () => {
    let body: Record<string, unknown> | undefined;
    base([
      http.post('/api/v1/ldap/directories', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(directoryFixture({ id: 'd2', name: 'Corp LDAP', enabled: false }), { status: 201 });
      }),
    ]);
    await renderRoute('/settings?tab=directories');
    await userEvent.click(await screen.findByRole('button', { name: 'Add directory' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add directory' });
    expect(within(dialog).getByRole('switch', { name: "Ask for Alice's authenticator code after the directory password" })).toBeChecked();
    expect(within(dialog).getByRole('switch', { name: 'Allow sign-in with this directory' })).not.toBeChecked();
    expect(within(dialog).getByLabelText(/^Group filter/)).toHaveValue('(member={dn})');
    expect(within(dialog).queryByText('A password is stored. Leave the field empty to keep it.')).not.toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'OpenLDAP' }));
    await fillNew(dialog);
    await save(dialog);
    await waitFor(() => expect(body).toBeDefined());
    expect(body).toEqual({
      name: 'Corp LDAP',
      addresses: ['ldaps://ldap1.corp.example', 'ldaps://ldap2.corp.example:636'],
      user_base_dn: 'ou=people,dc=corp,dc=example',
      bind_dn: 'cn=svc,dc=corp,dc=example',
      bind_password: CANARY,
      group_base_dn: 'ou=groups,dc=corp,dc=example',
      ca_pem: '',
      mfa_required: true,
      enabled: false,
      ...DIRECTORY_PRESETS.openldap,
    });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(document.body.innerHTML).not.toContain(CANARY);
  });

  it('fills only the attribute and filter fields from a preset, keeping what was typed', async () => {
    base();
    await renderRoute('/settings?tab=directories');
    await userEvent.click(await screen.findByRole('button', { name: 'Add directory' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add directory' });
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'Corp AD');
    await userEvent.type(within(dialog).getByLabelText(/^Service account password/), CANARY);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Active Directory' }));
    expect(within(dialog).getByLabelText(/^Sign-in name attribute/)).toHaveValue('sAMAccountName');
    expect(within(dialog).getByLabelText(/^Unique ID attribute/)).toHaveValue('objectGUID');
    expect(within(dialog).getByLabelText(/^Display name attribute/)).toHaveValue('displayName');
    expect(within(dialog).getByLabelText(/^E-mail attribute/)).toHaveValue('mail');
    expect(within(dialog).getByLabelText(/^User filter/)).toHaveValue('(&(objectClass=user)(sAMAccountName={login}))');
    expect(within(dialog).getByLabelText(/^Group filter/)).toHaveValue('(member:1.2.840.113556.1.4.1941:={dn})');
    expect(within(dialog).getByLabelText(/^Group name attribute/)).toHaveValue('cn');
    expect(within(dialog).getByLabelText(/^Name shown/)).toHaveValue('Corp AD');
    expect(within(dialog).getByLabelText(/^Service account password/)).toHaveValue(CANARY);
    await userEvent.click(within(dialog).getByRole('button', { name: 'OpenLDAP' }));
    expect(within(dialog).getByLabelText(/^Sign-in name attribute/)).toHaveValue('uid');
    expect(within(dialog).getByLabelText(/^Unique ID attribute/)).toHaveValue('entryUUID');
    expect(within(dialog).getByLabelText(/^User filter/)).toHaveValue('(&(objectClass=inetOrgPerson)(uid={login}))');
    expect(within(dialog).getByLabelText(/^Group filter/)).toHaveValue('(member={dn})');
    // Nothing was sent: a preset is not a save (msw fails the test on an unhandled POST).
    // Closing the form forgets the typed password.
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(document.body.innerHTML).not.toContain(CANARY);
    await userEvent.click(screen.getByRole('button', { name: 'Add directory' }));
    expect(within(await screen.findByRole('dialog')).getByLabelText(/^Service account password/)).toHaveValue('');
  });

  it('shows the template rules next to the filter fields', async () => {
    base();
    await renderRoute('/settings?tab=directories');
    await userEvent.click(await screen.findByRole('button', { name: 'Add directory' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/\{login\} and \{dn\} stand only in a value position/)).toBeInTheDocument();
    expect(within(dialog).getByText(/\\7b or \\7d/)).toBeInTheDocument();
    expect(within(dialog).getByLabelText(/^User filter/)).toHaveAccessibleDescription(/Holds \{login\} once/);
  });

  it('sends nothing while a required field is empty', async () => {
    let posts = 0;
    base([
      http.post('/api/v1/ldap/directories', () => {
        posts++;
        return HttpResponse.json(directoryFixture(), { status: 201 });
      }),
    ]);
    await renderRoute('/settings?tab=directories');
    await userEvent.click(await screen.findByRole('button', { name: 'Add directory' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Active Directory' }));
    await save(dialog);
    expect(within(dialog).getByLabelText(/^Name shown/)).toBeRequired();
    expect(within(dialog).getByLabelText(/^Service account password/)).toBeRequired();
    expect(posts).toBe(0);
  });

  it('shows the field errors under their fields and clears the password after a refused save', async () => {
    base([
      http.post('/api/v1/ldap/directories', () =>
        errorResponse(422, 'ALC-SYS-0006', 'validation.failed', {
          details: [
            { field: 'addresses', code: 'validation.pattern' },
            { field: 'user_filter', code: 'validation.pattern' },
          ],
        }),
      ),
    ]);
    await renderRoute('/settings?tab=directories');
    await userEvent.click(await screen.findByRole('button', { name: 'Add directory' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Active Directory' }));
    await fillNew(dialog);
    await save(dialog);
    await waitFor(() => expect(within(dialog).getByLabelText(/^Addresses/)).toHaveAttribute('aria-invalid', 'true'));
    expect(within(dialog).getByLabelText(/^User filter/)).toHaveAttribute('aria-invalid', 'true');
    expect(within(dialog).getByLabelText(/^Service account password/)).toHaveValue('');
    expect(document.body.innerHTML).not.toContain(CANARY);
    // The rest of the form stays as typed.
    expect(within(dialog).getByLabelText(/^Name shown/)).toHaveValue('Corp LDAP');
  });

  it('says at most 3 directories when the server refuses a fourth (ALC-LDAP-0005)', async () => {
    base([http.post('/api/v1/ldap/directories', () => errorResponse(409, 'ALC-LDAP-0005', 'ldap.too_many_directories', { params: { max: '3' } }))]);
    await renderRoute('/settings?tab=directories');
    await userEvent.click(await screen.findByRole('button', { name: 'Add directory' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Active Directory' }));
    await fillNew(dialog);
    await save(dialog);
    expect(await within(dialog).findByText('No more directories can be added.')).toBeInTheDocument();
  });

  it('edits a directory with If-Match, sends only the changed keys and keeps the stored password when the field is empty', async () => {
    let patch: { body: unknown; ifMatch: string | null } | undefined;
    base([
      http.patch(dirURL, async ({ request }) => {
        patch = { body: await request.json(), ifMatch: request.headers.get('If-Match') };
        return HttpResponse.json(directoryFixture({ version: 4, name: 'Renamed' }));
      }),
    ]);
    await renderRoute('/settings?tab=directories');
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Corp AD' }));
    const dialog = await screen.findByRole('dialog', { name: 'Edit directory' });
    const password = within(dialog).getByLabelText(/^Service account password/);
    expect(password).toHaveValue('');
    expect(password).not.toBeRequired();
    expect(password).toHaveAccessibleDescription('A password is stored. Leave the field empty to keep it.');
    expect(within(dialog).getByLabelText(/^Addresses/)).toHaveValue('ldaps://dc1.corp.example:636\nldaps://dc2.corp.example');
    await userEvent.clear(within(dialog).getByLabelText(/^Name shown/));
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'Renamed');
    await userEvent.click(within(dialog).getByRole('switch', { name: 'Allow sign-in with this directory' }));
    await save(dialog);
    await waitFor(() => expect(patch).toBeDefined());
    expect(patch).toEqual({ body: { name: 'Renamed', enabled: false }, ifMatch: '"3"' });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('asks for the password again when a protected field changes, and shows the server\'s field error on it', async () => {
    let patch: Record<string, unknown> | undefined;
    base([
      http.patch(dirURL, async ({ request }) => {
        patch = (await request.json()) as Record<string, unknown>;
        return errorResponse(422, 'ALC-SYS-0006', 'validation.failed', { details: [{ field: 'bind_password', code: 'validation.too_long', params: { max: '1024' } }] });
      }),
    ]);
    await renderRoute('/settings?tab=directories');
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Corp AD' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).queryByText(/enter the service account password again/)).not.toBeInTheDocument();
    await userEvent.clear(within(dialog).getByLabelText(/^Service account DN/));
    await userEvent.type(within(dialog).getByLabelText(/^Service account DN/), 'cn=other,dc=corp,dc=example');
    const password = within(dialog).getByLabelText(/^Service account password/);
    expect(password).toHaveAccessibleDescription(/enter the service account password again/);
    expect(password).toBeRequired();
    // Without the password nothing is sent, even when the browser's own check is bypassed.
    password.removeAttribute('required');
    await save(dialog);
    expect(patch).toBeUndefined();
    // With it, the server has the last word and its field error lands on the field.
    await userEvent.type(password, CANARY);
    await save(dialog);
    await waitFor(() => expect(patch).toBeDefined());
    // Mantine marks a PasswordInput's error with data-invalid (a TextInput uses aria-invalid).
    await waitFor(() => expect(password).toHaveAttribute('data-invalid', 'true'));
    expect(patch).toEqual({ bind_dn: 'cn=other,dc=corp,dc=example', bind_password: CANARY });
    expect(password).toHaveValue('');
    expect(document.body.innerHTML).not.toContain(CANARY);
  });

  it('keeps the typed password when the form stops before sending (a required field is empty)', async () => {
    base();
    await renderRoute('/settings?tab=directories');
    await userEvent.click(await screen.findByRole('button', { name: 'Add directory' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/^Service account password/), CANARY);
    for (const el of dialog.querySelectorAll('[required]')) el.removeAttribute('required');
    await save(dialog);
    expect(within(dialog).getByLabelText(/^Service account password/)).toHaveValue(CANARY);
  });

  it('reads the directory again after a 412 and saves the same change against the newer version', async () => {
    const ifMatch: (string | null)[] = [];
    let listed = 0;
    base([
      http.get('/api/v1/ldap/directories', () => HttpResponse.json({ items: [directoryFixture(++listed > 1 ? { version: 5 } : {})] })),
      http.patch(dirURL, ({ request }) => {
        ifMatch.push(request.headers.get('If-Match'));
        return ifMatch.length === 1 ? errorResponse(412, 'ALC-SYS-0008', 'system.precondition_failed') : HttpResponse.json(directoryFixture({ version: 6, name: 'Renamed' }));
      }),
    ]);
    await renderRoute('/settings?tab=directories');
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Corp AD' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.clear(within(dialog).getByLabelText(/^Name shown/));
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'Renamed');
    await save(dialog);
    expect(await within(dialog).findByText('Someone changed this item while you were editing it.')).toBeInTheDocument();
    expect(within(dialog).getByLabelText(/^Name shown/)).toHaveValue('Renamed');
    await save(dialog);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(ifMatch).toEqual(['"3"', '"5"']);
  });

  it('deletes with the newer version after a 412', async () => {
    const ifMatch: (string | null)[] = [];
    let listed = 0;
    base([
      http.get('/api/v1/ldap/directories', () => HttpResponse.json({ items: [directoryFixture(++listed > 1 ? { version: 7 } : {})] })),
      http.delete(dirURL, ({ request }) => {
        ifMatch.push(request.headers.get('If-Match'));
        return ifMatch.length === 1 ? errorResponse(412, 'ALC-SYS-0008', 'system.precondition_failed') : new HttpResponse(null, { status: 204 });
      }),
    ]);
    await renderRoute('/settings?tab=directories');
    await userEvent.click(await screen.findByRole('button', { name: 'Delete Corp AD' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete directory' }));
    expect(await within(dialog).findByText('Someone changed this item while you were editing it.')).toBeInTheDocument();
    await waitFor(() => expect(listed).toBeGreaterThan(1));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete directory' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(ifMatch).toEqual(['"3"', '"7"']);
  });

  it('marks the other protected fields too: addresses, unique ID attribute and certificate authority', async () => {
    base();
    await renderRoute('/settings?tab=directories');
    for (const [label, value] of [[/^Addresses/, '{enter}ldaps://dc3.corp.example'], [/^Unique ID attribute/, 'X'], [/^Certificate authority/, 'x']] as const) {
      await userEvent.click(await screen.findByRole('button', { name: 'Edit Corp AD' }));
      const dialog = await screen.findByRole('dialog');
      await userEvent.type(within(dialog).getByLabelText(label), value);
      expect(within(dialog).getByLabelText(/^Service account password/)).toHaveAccessibleDescription(/enter the service account password again/);
      await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    }
  });

  it('tests the connection of a directory and shows the result or the closed reason', async () => {
    let calls = 0;
    base([
      http.post(`${dirURL}/actions/test-connection`, () =>
        ++calls === 1 ? HttpResponse.json({ result: 'ok' }) : errorResponse(422, 'ALC-LDAP-0004', 'ldap.connection_test_failed', { params: { reason: 'tls', detail: 'dial' } }),
      ),
    ]);
    await renderRoute('/settings?tab=directories');
    const section = await screen.findByRole('region', { name: 'Corp AD' });
    await userEvent.click(within(section).getByRole('button', { name: 'Test the connection of Corp AD' }));
    expect(await within(section).findByText(/The connection works/)).toBeInTheDocument();
    await userEvent.click(within(section).getByRole('button', { name: 'Test the connection of Corp AD' }));
    expect(await within(section).findByText('The connection test failed.')).toBeInTheDocument();
    expect(within(section).getByText(/reason: tls, step: dial/)).toBeInTheDocument();
    expect(within(section).queryByText(/The connection works/)).not.toBeInTheDocument();
  });

  it('runs a test sign-in: shows the groups and the role, and clears the password after the call', async () => {
    let body: unknown;
    base([
      http.post(`${dirURL}/actions/test-signin`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ login: 'deniz', display_name: 'Deniz Kaya', email: 'deniz@corp.example', unique_id: 'ab12', groups: ['CN=Alice Ops,OU=Groups,DC=corp', 'alice-auditors'], role: 'operator' });
      }),
    ]);
    await renderRoute('/settings?tab=directories');
    const section = await screen.findByRole('region', { name: 'Corp AD' });
    await userEvent.click(within(section).getByRole('button', { name: 'Test a sign-in with Corp AD' }));
    const dialog = await screen.findByRole('dialog', { name: 'Test a sign-in with Corp AD' });
    await userEvent.type(within(dialog).getByLabelText(/^Sign-in name/), 'deniz');
    await userEvent.type(within(dialog).getByLabelText(/^Password/), TEST_CANARY);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Run test' }));
    expect(await within(dialog).findByText('The directory accepted the sign-in.')).toBeInTheDocument();
    expect(body).toEqual({ username: 'deniz', password: TEST_CANARY });
    expect(within(dialog).getByText('CN=Alice Ops,OU=Groups,DC=corp').tagName).toBe('CODE');
    expect(within(dialog).getByText('alice-auditors')).toBeInTheDocument();
    expect(within(dialog).getByText('Operator')).toBeInTheDocument();
    expect(within(dialog).getByText('Deniz Kaya')).toBeInTheDocument();
    expect(within(dialog).getByLabelText(/^Password/)).toHaveValue('');
    expect(document.body.innerHTML).not.toContain(TEST_CANARY);
  });

  it('says when no group gives a role, shows a refused test sign-in, and forgets the password on close', async () => {
    let calls = 0;
    base([
      http.post(`${dirURL}/actions/test-signin`, () =>
        ++calls === 1
          ? HttpResponse.json({ login: 'deniz', display_name: '', email: '', unique_id: 'ab12', groups: [], role: null })
          : errorResponse(422, 'ALC-LDAP-0006', 'ldap.signin_test_failed', { params: { reason: 'bad_credentials', detail: 'bind' } }),
      ),
    ]);
    await renderRoute('/settings?tab=directories');
    await userEvent.click(await screen.findByRole('button', { name: 'Test a sign-in with Corp AD' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/^Sign-in name/), 'deniz');
    await userEvent.type(within(dialog).getByLabelText(/^Password/), TEST_CANARY);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Run test' }));
    expect(await within(dialog).findByText('No group was found.')).toBeInTheDocument();
    expect(within(dialog).getByText(/None: no group is mapped/)).toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText(/^Password/), TEST_CANARY);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Run test' }));
    expect(await within(dialog).findByText('The sign-in test failed.')).toBeInTheDocument();
    expect(within(dialog).getByText(/reason: bad_credentials, step: bind/)).toBeInTheDocument();
    expect(within(dialog).queryByText('No group was found.')).not.toBeInTheDocument();
    expect(within(dialog).getByLabelText(/^Password/)).toHaveValue('');
    await userEvent.type(within(dialog).getByLabelText(/^Password/), TEST_CANARY);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(document.body.innerHTML).not.toContain(TEST_CANARY);
  });

  it('deletes a directory after confirmation and explains switching it off while it has users (ALC-LDAP-0003)', async () => {
    let calls = 0;
    base([
      http.delete(dirURL, ({ request }) => {
        calls++;
        expect(request.headers.get('If-Match')).toBe('"3"');
        return calls === 1 ? errorResponse(409, 'ALC-LDAP-0003', 'ldap.directory_in_use') : new HttpResponse(null, { status: 204 });
      }),
    ]);
    await renderRoute('/settings?tab=directories');
    await userEvent.click(await screen.findByRole('button', { name: 'Delete Corp AD' }));
    const dialog = await screen.findByRole('dialog', { name: 'Delete Corp AD?' });
    expect(dialog).toHaveTextContent('switch sign-in through it off instead');
    expect(calls).toBe(0);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete directory' }));
    expect(await within(dialog).findByText('This directory has users.')).toBeInTheDocument();
    expect(within(dialog).getByText('Switch sign-in through the directory off instead.')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete directory' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('adds a group mapping, refuses Administrator while SSO users may not be Admin, and removes one after confirmation', async () => {
    let created: unknown;
    let deleted = '';
    let listed = 0;
    base([
      http.get('/api/v1/ldap/group-mappings', ({ request }) => {
        expect(new URL(request.url).searchParams.get('directory_id')).toBe(DIRECTORY_ID);
        return HttpResponse.json({
          items: ++listed > 1 ? [{ id: 'm9', directory_id: DIRECTORY_ID, group: 'CN=Ops,DC=corp', role: 'operator', created_at: '2026-10-15T09:00:00Z' }] : [],
        });
      }),
      http.post('/api/v1/ldap/group-mappings', async ({ request }) => {
        const b = (await request.json()) as { role: string };
        if (b.role === 'admin') return errorResponse(409, 'ALC-SSO-0002', 'sso.admin_mapping_disabled');
        created = b;
        return HttpResponse.json({ id: 'm9', directory_id: DIRECTORY_ID, group: 'CN=Ops,DC=corp', role: 'operator', created_at: '2026-10-15T09:00:00Z' }, { status: 201 });
      }),
      http.delete('/api/v1/ldap/group-mappings/:id', ({ params, request }) => {
        deleted = `${String(params.id)}?${new URL(request.url).searchParams.toString()}`;
        return new HttpResponse(null, { status: 204 });
      }),
    ]);
    await renderRoute('/settings?tab=directories');
    const section = await screen.findByRole('region', { name: 'Corp AD' });
    expect(await within(section).findByText(/Without a mapping nobody can sign in through this directory/)).toBeInTheDocument();
    await userEvent.type(within(section).getByLabelText('Group'), 'CN=Admins,DC=corp');
    await userEvent.selectOptions(within(section).getByLabelText('Role in Alice'), 'admin');
    await userEvent.click(within(section).getByRole('button', { name: 'Map group' }));
    expect(await within(section).findByText('A group cannot be mapped to Administrator.')).toBeInTheDocument();
    await userEvent.clear(within(section).getByLabelText('Group'));
    await userEvent.type(within(section).getByLabelText('Group'), 'CN=Ops,DC=corp');
    await userEvent.selectOptions(within(section).getByLabelText('Role in Alice'), 'operator');
    await userEvent.click(within(section).getByRole('button', { name: 'Map group' }));
    await waitFor(() => expect(created).toEqual({ directory_id: DIRECTORY_ID, group: 'CN=Ops,DC=corp', role: 'operator' }));
    const table = await within(section).findByRole('table', { name: 'Group mappings' });
    expect(within(table).getByText('CN=Ops,DC=corp').tagName).toBe('CODE');
    await userEvent.click(within(section).getByRole('button', { name: 'Remove mapping for CN=Ops,DC=corp' }));
    expect(deleted).toBe('');
    await userEvent.click(within(await screen.findByRole('dialog', { name: 'Remove the mapping for CN=Ops,DC=corp?' })).getByRole('button', { name: 'Remove mapping' }));
    await waitFor(() => expect(deleted).toBe(`m9?directory_id=${DIRECTORY_ID}`));
  });

  it('asks for a fresh verification before a write and repeats it', async () => {
    let calls = 0;
    base([
      http.post(`${dirURL}/actions/test-connection`, () => (++calls === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json({ result: 'ok' }))),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(steppedUp)),
    ]);
    await renderRoute('/settings?tab=directories');
    await userEvent.click(await screen.findByRole('button', { name: 'Test the connection of Corp AD' }));
    const stepUp = await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.type(within(stepUp).getByLabelText('6-digit code'), '123456');
    await userEvent.click(within(stepUp).getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText(/The connection works/)).toBeInTheDocument();
    expect(calls).toBe(2);
  });

  it('says at most 3 once three directories exist, switches MFA off with a PATCH, and keeps a mapping when its removal is cancelled', async () => {
    let patch: unknown;
    base([
      http.get('/api/v1/ldap/directories', () =>
        HttpResponse.json({ items: [directoryFixture(), directoryFixture({ id: 'd2', name: 'B' }), directoryFixture({ id: 'd3', name: 'C' })] }),
      ),
      http.get('/api/v1/ldap/group-mappings', ({ request }) =>
        HttpResponse.json({
          items: new URL(request.url).searchParams.get('directory_id') === DIRECTORY_ID ? [{ id: 'm1', directory_id: DIRECTORY_ID, group: 'ops', role: 'auditor', created_at: '2026-10-15T09:00:00Z' }] : [],
        }),
      ),
      http.patch(dirURL, async ({ request }) => {
        patch = await request.json();
        return HttpResponse.json(directoryFixture({ mfa_required: false, version: 4 }));
      }),
    ]);
    await renderRoute('/settings?tab=directories');
    expect(await screen.findByText('Alice works with at most 3 directories.')).toBeInTheDocument();
    const section = screen.getByRole('region', { name: 'Corp AD' });
    await userEvent.click(await within(section).findByRole('button', { name: 'Remove mapping for ops' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(within(section).getByText('ops')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Edit Corp AD' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('switch', { name: "Ask for Alice's authenticator code after the directory password" }));
    await save(dialog);
    await waitFor(() => expect(patch).toEqual({ mfa_required: false }));
  });

  it('sends no test sign-in without a name and a password', async () => {
    base();
    await renderRoute('/settings?tab=directories');
    await userEvent.click(await screen.findByRole('button', { name: 'Test a sign-in with Corp AD' }));
    const dialog = await screen.findByRole('dialog');
    for (const el of dialog.querySelectorAll('[required]')) el.removeAttribute('required');
    await userEvent.type(within(dialog).getByLabelText(/^Password/), TEST_CANARY);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Run test' }));
    // msw would fail the test on the unhandled request; the typed password stays for the person to complete the form.
    expect(within(dialog).getByLabelText(/^Password/)).toHaveValue(TEST_CANARY);
    expect(within(dialog).queryByRole('status')).not.toBeInTheDocument();
  });

  it('is fully translated in Turkish', async () => {
    base([...sessionHandlers({ ...sessionFor('admin', 'tr'), stepup_until: '2099-01-01T00:00:00Z' })]);
    await renderRoute('/settings?tab=directories', { languages: ['tr-TR'] });
    expect(await screen.findByRole('table', { name: 'Dizinler' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Dizin ekle' }));
    expect(await screen.findByRole('dialog', { name: 'Dizin ekle' })).toBeInTheDocument();
    expectNoRawKeys();
  });

  it.each(['en-US', 'tr-TR'])('names the confirmations apart from the close button (%s)', async (lang) => {
    const i18n = await createI18n([lang]);
    for (const key of ['directories.removeMappingConfirm', 'directories.deleteConfirm']) {
      expect(i18n.t(key), key).not.toBe(i18n.t('ui.close'));
      expect(i18n.t(key), key).not.toBe(i18n.t('ui.cancel'));
    }
  });
});
