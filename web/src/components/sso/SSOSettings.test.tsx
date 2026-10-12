import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { createI18n } from '../../i18n';
import { adminSession, errorResponse, providerFixture, sessionHandlers } from '../../test/fixtures';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';
import ui from '../ui/ui.module.css';
import classes from '../settings/settings.module.css';

const steppedUp = { ...adminSession, stepup_until: '2099-01-01T00:00:00Z' };
const settings = (allow = false, version = 0) => HttpResponse.json({ allow_admin_role: allow, version }, { headers: { ETag: `"${version}"` } });

function base(extra: Parameters<typeof server.use> = [] as never) {
  // msw takes the first matching handler: a test's own handlers come first.
  server.use(
    ...extra,
    ...sessionHandlers(steppedUp),
    http.get('/api/v1/sso/settings', () => settings()),
    http.get('/api/v1/sso/providers', () => HttpResponse.json({ items: [providerFixture()] })),
    http.get('/api/v1/sso/group-mappings', () => HttpResponse.json({ items: [] })),
  );
}

describe('SSOSettings', () => {
  it('refuses an Admin mapping while SSO users may not be Admin (owner step 5)', async () => {
    base([http.post('/api/v1/sso/group-mappings', () => errorResponse(409, 'ALC-SSO-0002', 'sso.admin_mapping_disabled'))]);
    await renderRoute('/settings?tab=sso');
    await userEvent.type(await screen.findByLabelText('Group'), 'alice-admins');
    await userEvent.selectOptions(screen.getByLabelText('Role in Alice'), 'admin');
    await userEvent.click(screen.getByRole('button', { name: 'Map group' }));
    expect(await screen.findByText('A group cannot be mapped to Administrator.')).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: 'SSO users may be Admin' })).not.toBeChecked();
  });

  it('lists the providers with the issuer as code, and the groups mapped to roles', async () => {
    base([
      http.get('/api/v1/sso/group-mappings', ({ request }) => {
        expect(new URL(request.url).searchParams.get('provider_id')).toBe('p1');
        return HttpResponse.json({ items: [{ id: 'm1', provider_id: 'p1', group: 'alice-ops', role: 'operator', created_at: '2026-10-07T09:00:00Z' }] });
      }),
    ]);
    await renderRoute('/settings?tab=sso');
    const section = await screen.findByRole('region', { name: 'Corp IdP' });
    expect(within(section).getByText('https://idp.example.com').tagName).toBe('CODE');
    expect(await within(section).findByText('alice-ops')).toHaveProperty('tagName', 'CODE');
    expect(within(section).getByRole('cell', { name: 'Operator' })).toBeInTheDocument();
    expect(screen.getByText(/confirm their identity at the identity provider/)).toBeInTheDocument();
  });

  it('draws a provider as a panel with the design\'s head, the mappings in a resource table and the switch in a row', async () => {
    base([
      http.get('/api/v1/sso/providers', () => HttpResponse.json({ items: [providerFixture(), providerFixture({ id: 'p2', name: 'Old IdP', enabled: false })] })),
      http.get('/api/v1/sso/group-mappings', () =>
        HttpResponse.json({ items: [{ id: 'm1', provider_id: 'p1', group: 'alice-ops', role: 'operator', created_at: '2026-10-07T09:00:00Z' }] }),
      ),
    ]);
    await renderRoute('/settings?tab=sso');
    const section = await screen.findByRole('region', { name: 'Corp IdP' });
    expect(section).toHaveClass(ui.panel);
    const head = within(section).getByRole('heading', { level: 4, name: 'Corp IdP' }).closest(`.${classes.providerHead}`) as HTMLElement;
    expect(within(head).getByText('On').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'success');
    expect(within(head).getByText('https://idp.example.com').tagName).toBe('CODE');
    expect(within(head).getByRole('button', { name: 'Edit Corp IdP' })).toBeInTheDocument();
    const old = screen.getByRole('region', { name: 'Old IdP' });
    expect(within(old).getByText('Off').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'neutral');
    const table = await within(section).findByRole('table', { name: 'Group mappings' });
    expect(table.closest(`.${ui.tablePanel}`)).not.toBeNull();
    expect(screen.getByRole('heading', { level: 3, name: 'Identity providers' })).toBeInTheDocument();
    const allow = screen.getByRole('switch', { name: 'SSO users may be Admin' });
    expect(allow.closest(`.${ui.switchRow}`)).not.toBeNull();
    expect(allow).toHaveAccessibleDescription(/Off by default/);
  });

  it('adds a mapping and removes one, sending the provider with the delete', async () => {
    let created: unknown;
    let deleted = '';
    let listed = 0;
    base([
      http.get('/api/v1/sso/group-mappings', () =>
        HttpResponse.json({ items: ++listed > 1 ? [{ id: 'm9', provider_id: 'p1', group: 'g1', role: 'auditor', created_at: '2026-10-07T09:00:00Z' }] : [] }),
      ),
      http.post('/api/v1/sso/group-mappings', async ({ request }) => {
        created = await request.json();
        return HttpResponse.json({ id: 'm9', provider_id: 'p1', group: 'g1', role: 'auditor', created_at: '2026-10-07T09:00:00Z' }, { status: 201 });
      }),
      http.delete('/api/v1/sso/group-mappings/:id', ({ params, request }) => {
        deleted = `${String(params.id)}?${new URL(request.url).searchParams.toString()}`;
        return new HttpResponse(null, { status: 204 });
      }),
    ]);
    await renderRoute('/settings?tab=sso');
    await userEvent.type(await screen.findByLabelText('Group'), 'g1');
    await userEvent.selectOptions(screen.getByLabelText('Role in Alice'), 'auditor');
    await userEvent.click(screen.getByRole('button', { name: 'Map group' }));
    await waitFor(() => expect(created).toEqual({ provider_id: 'p1', group: 'g1', role: 'auditor' }));
    expect(screen.getByLabelText('Group')).toHaveValue('');
    await userEvent.click(await screen.findByRole('button', { name: 'Remove mapping for g1' }));
    expect(deleted).toBe(''); // nothing is sent before the confirmation
    await userEvent.click(within(await screen.findByRole('dialog', { name: 'Remove the mapping for g1?' })).getByRole('button', { name: 'Remove mapping' }));
    await waitFor(() => expect(deleted).toBe('m9?provider_id=p1'));
  });

  it('switches SSO users may be Admin on with the version, and shows the refusal to switch it off', async () => {
    const puts: { body: unknown; ifMatch: string | null }[] = [];
    let stored = settings(false, 0);
    base([
      http.get('/api/v1/sso/settings', () => stored.clone()),
      http.put('/api/v1/sso/settings', async ({ request }) => {
        const body = (await request.json()) as { allow_admin_role: boolean };
        expect(typeof body.allow_admin_role).toBe('boolean'); // always sent: missing is 422, null is 400
        puts.push({ body, ifMatch: request.headers.get('If-Match') });
        if (body.allow_admin_role) stored = settings(true, 1);
        return body.allow_admin_role ? settings(true, 1) : errorResponse(409, 'ALC-SSO-0003', 'sso.admin_mappings_exist');
      }),
    ]);
    await renderRoute('/settings?tab=sso');
    const sw = await screen.findByRole('switch', { name: 'SSO users may be Admin' });
    await userEvent.click(sw);
    await waitFor(() => expect(screen.getByRole('switch', { name: 'SSO users may be Admin' })).toBeChecked());
    expect(puts[0]).toEqual({ body: { allow_admin_role: true }, ifMatch: '"0"' });
    await userEvent.click(screen.getByRole('switch', { name: 'SSO users may be Admin' }));
    const confirm = await screen.findByRole('dialog', { name: 'Switch off SSO users may be Admin?' });
    expect(confirm).toHaveTextContent('becomes an Auditor and is signed out'); // DemoteSSOAdmins makes them Auditors (R42 row 24)
    expect(puts).toHaveLength(1);
    await userEvent.click(within(confirm).getByRole('button', { name: 'Switch off' }));
    expect(await screen.findByText('SSO users may be Admin cannot be switched off yet.')).toBeInTheDocument();
    expect(puts[1].ifMatch).toBe('"1"');
    expect(screen.getByRole('switch', { name: 'SSO users may be Admin' })).toBeChecked();
  });

  it('adds a provider, keeps its client secret out of the page and shows the address to register', async () => {
    let body: Record<string, unknown> | undefined;
    base([
      http.post('/api/v1/sso/providers', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(providerFixture({ id: 'p2', name: 'Second', redirect_uri: 'https://alice.example.com/api/v1/auth/oidc/p2/callback' }), { status: 201 });
      }),
    ]);
    await renderRoute('/settings?tab=sso');
    await userEvent.click(await screen.findByRole('button', { name: 'Add identity provider' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add identity provider' });
    expect(within(dialog).getByLabelText('Groups claim')).toHaveValue('groups');
    expect(within(dialog).getByRole('switch', { name: 'Allow sign-in with this provider' })).not.toBeChecked();
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'Second');
    await userEvent.type(within(dialog).getByLabelText(/^Issuer address/), 'https://idp2.example.com');
    await userEvent.type(within(dialog).getByLabelText(/^Client ID/), 'cid');
    await userEvent.type(within(dialog).getByLabelText(/^Client secret/), 'canary-secret-value');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save identity provider' }));
    await waitFor(() => expect(body).toMatchObject({ name: 'Second', issuer_url: 'https://idp2.example.com', client_id: 'cid', client_secret: 'canary-secret-value', groups_claim: 'groups', ca_pem: '', enabled: false }));
    expect(await within(dialog).findByText('https://alice.example.com/api/v1/auth/oidc/p2/callback')).toHaveProperty('tagName', 'CODE');
    expect(within(dialog).getByRole('button', { name: 'Copy' })).toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain('canary-secret-value');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('shows why a provider could not be read (ALC-SSO-0001, with its cause) inside the form', async () => {
    base([http.post('/api/v1/sso/providers', () => errorResponse(502, 'ALC-SSO-0001', 'sso.discovery_failed', { params: { cause: 'jwks_fetch' } }))]);
    await renderRoute('/settings?tab=sso');
    await userEvent.click(await screen.findByRole('button', { name: 'Add identity provider' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'X');
    await userEvent.type(within(dialog).getByLabelText(/^Issuer address/), 'https://idp.example.com');
    await userEvent.type(within(dialog).getByLabelText(/^Client ID/), 'c');
    await userEvent.type(within(dialog).getByLabelText(/^Client secret/), 's');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save identity provider' }));
    expect(await within(dialog).findByText("Alice could not read the identity provider's settings.")).toBeInTheDocument();
    expect(within(dialog).getByText(/reason: jwks_fetch/)).toBeInTheDocument();
  });

  it('edits a provider without sending the secret unless typed, and reads its settings again', async () => {
    let patch: { body: unknown; ifMatch: string | null } | undefined;
    let refreshed: string | null = null;
    base([
      http.patch('/api/v1/sso/providers/p1', async ({ request }) => {
        patch = { body: await request.json(), ifMatch: request.headers.get('If-Match') };
        return HttpResponse.json(providerFixture({ version: 2 }));
      }),
      http.post('/api/v1/sso/providers/p1/actions/refresh', ({ request }) => {
        refreshed = request.headers.get('If-Match');
        return HttpResponse.json(providerFixture({ version: 3 }));
      }),
    ]);
    await renderRoute('/settings?tab=sso');
    await userEvent.click(await screen.findByRole('button', { name: "Read the provider's settings again" }));
    await waitFor(() => expect(refreshed).toBe('"1"'));
    await userEvent.click(screen.getByRole('button', { name: 'Edit Corp IdP' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByLabelText(/^Client secret/)).toHaveValue('');
    await userEvent.clear(within(dialog).getByLabelText(/^Name shown/));
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'Renamed');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save identity provider' }));
    await waitFor(() => expect(patch).toBeDefined());
    expect(patch?.ifMatch).toBe('"3"');
    expect(patch?.body).toMatchObject({ name: 'Renamed' });
    expect(patch?.body).not.toHaveProperty('client_secret');
  });

  it('deletes a provider after confirmation and shows ALC-SSO-0005 when it still has users', async () => {
    let calls = 0;
    base([
      http.delete('/api/v1/sso/providers/p1', ({ request }) => {
        calls++;
        expect(request.headers.get('If-Match')).toBe('"1"');
        return calls === 1 ? errorResponse(409, 'ALC-SSO-0005', 'sso.provider_in_use') : new HttpResponse(null, { status: 204 });
      }),
    ]);
    await renderRoute('/settings?tab=sso');
    await userEvent.click(await screen.findByRole('button', { name: 'Delete Corp IdP' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete identity provider' }));
    expect(await within(dialog).findByText('This identity provider still has users.')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete identity provider' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('shows the missing public address (ALC-SSO-0004) next to the form', async () => {
    base([http.post('/api/v1/sso/providers', () => errorResponse(409, 'ALC-SSO-0004', 'sso.public_url_missing'))]);
    await renderRoute('/settings?tab=sso');
    await userEvent.click(await screen.findByRole('button', { name: 'Add identity provider' }));
    const dialog = await screen.findByRole('dialog');
    for (const [label, value] of [[/^Name shown/, 'X'], [/^Issuer address/, 'https://i.example.com'], [/^Client ID/, 'c'], [/^Client secret/, 's']] as const)
      await userEvent.type(within(dialog).getByLabelText(label), value);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save identity provider' }));
    expect(await within(dialog).findByText("Alice's address is not set.")).toBeInTheDocument();
  });

  it('says so when no provider is configured', async () => {
    base([http.get('/api/v1/sso/providers', () => HttpResponse.json({ items: [] }))]);
    await renderRoute('/settings?tab=sso');
    expect(await screen.findByText('No identity provider is set up yet.')).toBeInTheDocument();
  });

  it('sends nothing when the switch-off is cancelled', async () => {
    let puts = 0;
    base([
      http.get('/api/v1/sso/settings', () => settings(true, 2)),
      http.put('/api/v1/sso/settings', () => {
        puts++;
        return settings(false, 3);
      }),
    ]);
    await renderRoute('/settings?tab=sso');
    await userEvent.click(await screen.findByRole('switch', { name: 'SSO users may be Admin' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(puts).toBe(0);
    expect(screen.getByRole('switch', { name: 'SSO users may be Admin' })).toBeChecked();
  });

  it('shows a hint, a link and no Copy button when the redirect address is empty', async () => {
    base([http.post('/api/v1/sso/providers', () => HttpResponse.json(providerFixture({ id: 'p3', redirect_uri: '' }), { status: 201 }))]);
    await renderRoute('/settings?tab=sso');
    await userEvent.click(await screen.findByRole('button', { name: 'Add identity provider' }));
    const dialog = await screen.findByRole('dialog');
    for (const [label, value] of [[/^Name shown/, 'X'], [/^Issuer address/, 'https://i.example.com'], [/^Client ID/, 'c'], [/^Client secret/, 's']] as const)
      await userEvent.type(within(dialog).getByLabelText(label), value);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save identity provider' }));
    expect(await within(dialog).findByText(/the redirect address appears here afterwards/)).toBeInTheDocument();
    expect(within(dialog).getByRole('link', { name: 'Open the general settings' })).toHaveAttribute('href', '/settings?tab=general');
    expect(within(dialog).queryByRole('button', { name: 'Copy' })).not.toBeInTheDocument();
    expect(dialog.querySelector('code')).toBeNull();
  });

  // Switching off demotes SSO Administrators to Auditor (DemoteSSOAdmins, R42 row 24): the confirmation names that role
  // in both languages, never Operator.
  it.each(['en-US', 'tr-TR'])('says the switch-off makes SSO Administrators Auditors (%s)', async (lang) => {
    const i18n = await createI18n([lang]);
    const text = i18n.t('sso.switchOffText');
    expect(text).toContain(i18n.t('enum.role.auditor', { ns: 'common' }));
    expect(text).not.toContain(i18n.t('enum.role.operator', { ns: 'common' }));
  });

  // A confirm dialog has the modal's own close button too: a button with the same name but the opposite effect would be
  // ambiguous for a screen reader user (found by the Phase 7 e2e journey in Turkish: "Kapat" twice).
  it.each(['en-US', 'tr-TR'])('names the switch-off and mapping confirmations apart from the close button (%s)', async (lang) => {
    const i18n = await createI18n([lang]);
    for (const key of ['sso.switchOffConfirm', 'sso.removeMappingConfirm', 'sso.deleteConfirm']) {
      expect(i18n.t(key), key).not.toBe(i18n.t('ui.close'));
      expect(i18n.t(key), key).not.toBe(i18n.t('ui.cancel'));
    }
  });
});
