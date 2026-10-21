import { readFileSync } from 'node:fs';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { QueryClient } from '@tanstack/react-query';
import {
  ACME_ACCOUNT_ID,
  ACME_HOOK_ID,
  ACME_PROVIDER_ID,
  acmeAccountFixture,
  acmeCertificateFixture,
  acmeHookFixture,
  acmeProviderFixture,
  adminSession,
  emptyDNSSettings,
  errorResponse,
  sessionFor,
  sessionHandlers,
} from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute, renderWithStepUp } from '../../test/render';
import { server } from '../../test/server';
import type { ACMEHook, ACMEProvider } from '../../api/acme';
import { AcmeSettings } from './AcmeSettings';

const steppedUp = { ...adminSession, stepup_until: '2099-01-01T00:00:00Z' };
const PROVIDERS = '/api/v1/acme/providers';
const HOOKS = '/api/v1/acme/hooks';

type Extra = Parameters<typeof server.use>;

// base answers the lists (msw takes the first matching handler: a test's own handlers come first).
function base(opts: { providers?: ACMEProvider[]; hooks?: ACMEHook[]; extra?: Extra; session?: ReturnType<typeof sessionFor> } = {}) {
  const providers = opts.providers ?? [acmeProviderFixture()];
  server.use(
    ...(opts.extra ?? ([] as unknown as Extra)),
    ...sessionHandlers(opts.session ?? steppedUp),
    http.get(PROVIDERS, () => HttpResponse.json({ items: providers })),
    http.get(`${PROVIDERS}/:id`, ({ params }) => {
      const p = providers.find((x) => x.id === params.id) ?? providers[0];
      return HttpResponse.json({ ...p, accounts: p.active_account_id ? [acmeAccountFixture({ id: p.active_account_id, state: p.pending_rollover ? 'pending_rollover' : 'active' })] : [] });
    }),
    http.get(HOOKS, () => HttpResponse.json({ items: opts.hooks ?? [acmeHookFixture()] })),
    http.post(`${PROVIDERS}/:id/preview`, () => HttpResponse.json(preview())),
  );
}

const TERMS = 'https://letsencrypt.org/documents/LE-SA-v1.5.pdf';
const preview = (o: Record<string, unknown> = {}) => ({
  terms_of_service_url: TERMS,
  terms_url_unsafe: false,
  external_account_required: false,
  key_change_supported: true,
  renewal_info_supported: true,
  website: 'https://letsencrypt.org',
  ...o,
});

// cached is everything the query and mutation caches hold, as text: a secret must never be in it.
function cached(client: QueryClient): string {
  return JSON.stringify([
    client.getQueryCache().getAll().map((q) => [q.queryKey, q.state.data]),
    client.getMutationCache().getAll().map((m) => m.state.variables),
  ]);
}

const open = () => renderRoute('/settings?tab=acme');

describe('Certificate authorities settings', () => {
  it('explains an empty installation: no authority, no hook, nothing contacted', async () => {
    base({ providers: [], hooks: [] });
    await open();
    expect(await screen.findByText('No certificate authorities yet')).toBeInTheDocument();
    expect(screen.getByText(/A certificate authority \(CA\) issues certificates/)).toBeInTheDocument();
    expect(await screen.findByText('No DNS provider or hook yet')).toBeInTheDocument();
    expect(screen.getByText('Nothing is contacted yet').closest('[role="note"]')).not.toBeNull();
    expect(screen.getByRole('tab', { name: 'Certificate authorities', selected: true })).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByRole('heading', { level: 2, name: 'Certificate authorities' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3, name: 'Authorities and accounts' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3, name: 'DNS publishing' })).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('lists an authority with its host, preset, account, external account key and allowed names, and its account', async () => {
    base({ providers: [acmeProviderFixture({ eab_configured: true, eab_kid: 'kid-1', allowed_suffixes: ['example.com', '.corp.example.org'] })] });
    await open();
    const section = await screen.findByRole('region', { name: 'LE staging' });
    expect(within(section).getByRole('heading', { level: 4, name: 'LE staging' })).toBeInTheDocument();
    expect(within(section).getByText('acme-staging-v02.api.letsencrypt.org').tagName).toBe('CODE');
    expect(within(section).getByText("Let's Encrypt (staging, for tests)")).toBeInTheDocument();
    expect(within(section).getByText('Account registered').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'success');
    expect(within(section).getByText('External account key stored')).toBeInTheDocument();
    const names = within(section).getByRole('list', { name: 'Allowed names:' });
    expect(within(names).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['example.com', '.corp.example.org']);
    const account = await within(section).findByRole('region', { name: 'Account with LE staging' });
    expect(await within(account).findByText('ops@example.com')).toBeInTheDocument();
    expect(within(account).getByText('Active').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'success');
    const terms = within(account).getByRole('link', { name: /Open the terms/ });
    expect(terms).toHaveAttribute('href', 'https://letsencrypt.org/documents/LE-SA-v1.5.pdf');
    expect(terms).toHaveAttribute('target', '_blank');
    expect(terms).toHaveAttribute('rel', 'noopener noreferrer');
    expect(within(account).getByRole('button', { name: 'Rotate account key' })).toBeInTheDocument();
    expect(within(account).getByRole('button', { name: 'Deactivate account' })).toBeInTheDocument();
    expect(within(account).queryByRole('button', { name: 'Register account' })).not.toBeInTheDocument();
    expect(within(section).getByRole('button', { name: 'Edit LE staging' })).toBeInTheDocument();
    expect(within(section).getByRole('button', { name: 'Remove LE staging' })).toBeInTheDocument();
  });

  it('warns about an authority and a hook without allowed names, and an account without terms or contact', async () => {
    base({
      providers: [acmeProviderFixture({ allowed_suffixes: [], preset: 'custom', name: 'Corp CA', directory_url: 'https://ca.corp.example/acme' })],
      hooks: [acmeHookFixture({ allowed_suffixes: [], secret_configured: false })],
      extra: [http.get(`${PROVIDERS}/:id`, () => HttpResponse.json({ ...acmeProviderFixture(), accounts: [acmeAccountFixture({ tos_url: '', tos_accepted_at: null, contact_email: '' })] }))],
    });
    await open();
    const section = await screen.findByRole('region', { name: 'Corp CA' });
    expect(within(section).getByText('No names allowed').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'warning');
    expect(within(section).getByText(/No certificate can be ordered from this authority/)).toBeInTheDocument();
    expect(within(section).getByText('My own CA')).toBeInTheDocument();
    expect(await within(section).findByText('This authority publishes no terms of service.')).toBeInTheDocument();
    expect(within(section).getByText('Not needed')).toBeInTheDocument();
    expect(within(section).getByText('None')).toBeInTheDocument();
    const hook = await screen.findByRole('region', { name: 'Internal DNS' });
    expect(within(hook).getByText(/This hook adds no record/)).toBeInTheDocument();
    expect(within(hook).getByText('No secret stored').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'warning');
  });

  it('shows a terms address that is not https as text, not as a link', async () => {
    base({ extra: [http.get(`${PROVIDERS}/:id`, () => HttpResponse.json({ ...acmeProviderFixture(), accounts: [acmeAccountFixture({ tos_url: 'javascript:alert(1)' })] }))] });
    await open();
    expect(await screen.findByText('javascript:alert(1)')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Open the terms/ })).not.toBeInTheDocument();
  });

  it('shows the loading state, then the error of a list that could not be read', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    base({
      extra: [
        http.get(PROVIDERS, async () => {
          await gate;
          return errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected');
        }),
      ],
    });
    await open();
    expect((await screen.findAllByRole('status', { name: 'Loading…' })).length).toBeGreaterThan(0);
    release();
    expect(await screen.findByRole('alert')).toHaveTextContent('ALC-SYS-0003');
  });

  it('adds an authority from a preset: the address is filled in, the secret key leaves no trace, and nothing is contacted', async () => {
    let body: Record<string, unknown> | undefined;
    let creates = 0;
    base({
      providers: [],
      extra: [
        http.post(PROVIDERS, async ({ request }) => {
          creates++;
          if (creates === 1) return errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required');
          body = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(acmeProviderFixture({ id: 'p9', name: 'ZeroSSL', eab_configured: true }), { status: 201 });
        }),
        http.post('/api/v1/auth/stepup', () => HttpResponse.json(steppedUp)),
      ],
    });
    const { client } = await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add certificate authority' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add certificate authority' });
    const directory = within(dialog).getByLabelText(/^Directory address/);
    expect(directory).toHaveValue('https://acme-v02.api.letsencrypt.org/directory');
    expect(within(dialog).getByText(/Nothing is contacted until you register the account/)).toBeInTheDocument();
    await userEvent.selectOptions(within(dialog).getByLabelText('Certificate authority'), 'letsencrypt_staging');
    expect(directory).toHaveValue('https://acme-staging-v02.api.letsencrypt.org/directory');
    await userEvent.selectOptions(within(dialog).getByLabelText('Certificate authority'), 'custom');
    expect(directory).toHaveValue('');
    await userEvent.selectOptions(within(dialog).getByLabelText('Certificate authority'), 'zerossl');
    expect(directory).toHaveValue('https://acme.zerossl.com/v2/DV90');
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'ZeroSSL');
    await userEvent.type(within(dialog).getByLabelText(/^Key ID/), 'kid-1');
    await userEvent.type(within(dialog).getByLabelText(/^Secret key/), 'canary-eab-hmac');
    expect(within(dialog).getByText('No names are allowed yet')).toBeInTheDocument();
    const suffix = within(dialog).getByLabelText(/^Allowed names/);
    await userEvent.type(suffix, 'com{Enter}');
    expect(within(dialog).getByText(/Use at least two parts/)).toBeInTheDocument();
    await userEvent.clear(suffix);
    await userEvent.type(suffix, 'example.com{Enter}');
    expect(within(dialog).getByRole('list', { name: 'Allowed names' })).toHaveTextContent('example.com');
    await userEvent.type(suffix, 'example.com');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Add' }));
    expect(within(dialog).getByText('This domain ending is already in the list.')).toBeInTheDocument();
    await userEvent.clear(suffix);
    await userEvent.type(suffix, '.corp.example.org');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save certificate authority' }));
    // The step-up asks for the code; the request is sent again with it.
    const stepUp = await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.type(within(stepUp).getByLabelText('6-digit code'), '123456');
    await userEvent.click(within(stepUp).getByRole('button', { name: 'Confirm' }));
    expect(await within(dialog).findByText(/Register an account with this authority next/)).toBeInTheDocument();
    expect(body).toEqual({
      name: 'ZeroSSL',
      directory_url: 'https://acme.zerossl.com/v2/DV90',
      preset: 'zerossl',
      ca_bundle_pem: '',
      allowed_suffixes: ['example.com', '.corp.example.org'],
      eab_kid: 'kid-1',
      eab_hmac: 'canary-eab-hmac',
    });
    expect(creates).toBe(2);
    expect(document.body.innerHTML).not.toContain('canary-eab-hmac');
    expect(cached(client)).not.toContain('canary-eab-hmac');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('asks for both parts of an external account binding before anything is sent, and clears the secret key', async () => {
    let creates = 0;
    base({ providers: [], extra: [http.post(PROVIDERS, () => (creates++, HttpResponse.json(acmeProviderFixture(), { status: 201 })))] });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add certificate authority' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'LE');
    await userEvent.type(within(dialog).getByLabelText(/^Secret key/), 'canary-hmac-only');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save certificate authority' }));
    expect(await within(dialog).findByText(/Enter both the key ID and the secret key, or neither/)).toBeInTheDocument();
    expect(within(dialog).getByLabelText(/^Secret key/)).toHaveValue('canary-hmac-only'); // a local problem keeps it
    await userEvent.clear(within(dialog).getByLabelText(/^Secret key/));
    await userEvent.type(within(dialog).getByLabelText(/^Key ID/), 'kid-only');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save certificate authority' }));
    expect(await within(dialog).findByText(/Enter both the key ID and the secret key, or neither/)).toBeInTheDocument();
    // An invalid entry still typed in the names field stops the save too.
    await userEvent.clear(within(dialog).getByLabelText(/^Key ID/));
    await userEvent.type(within(dialog).getByLabelText(/^Allowed names/), '-bad.example');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save certificate authority' }));
    expect(await within(dialog).findByText(/Use only letters, digits, hyphens and dots/)).toBeInTheDocument();
    expect(creates).toBe(0);
    // A valid typed entry is added by the save itself.
    await userEvent.clear(within(dialog).getByLabelText(/^Allowed names/));
    await userEvent.type(within(dialog).getByLabelText(/^Allowed names/), 'example.net');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save certificate authority' }));
    await waitFor(() => expect(creates).toBe(1));
  });

  it('shows the field problems and the name refusal the server answers', async () => {
    base({
      providers: [],
      extra: [
        http.post(PROVIDERS, () =>
          errorResponse(422, 'ALC-SYS-0006', 'validation.failed', { details: [{ field: 'directory_url', code: 'validation.pattern' }, { field: 'ca_bundle_pem', code: 'validation.pattern' }] }),
        ),
      ],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add certificate authority' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'X');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save certificate authority' }));
    await waitFor(() => expect(within(dialog).getByLabelText(/^Directory address/)).toHaveAttribute('aria-invalid', 'true'));
    expect(within(dialog).getByLabelText(/^Root certificate of your CA/)).toHaveAttribute('aria-invalid', 'true');
  });

  it.each([
    ['ALC-ACM-0020', 'acme.name_taken', 409, 'This name is already used.'],
    ['ALC-LIC-0001', 'license.locked', 403, ''],
  ])('shows the refusal %s of a save', async (code, reason, status, text) => {
    base({ providers: [], extra: [http.post(PROVIDERS, () => errorResponse(status, code, reason))] });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add certificate authority' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'X');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save certificate authority' }));
    const alert = await within(dialog).findByRole('alert');
    if (text) expect(alert).toHaveTextContent(text);
    expect(alert).toHaveTextContent(code);
  });

  it('changes only what was changed, asks to retire the account for a new address, and keeps the secret key unless typed', async () => {
    const patches: Record<string, unknown>[] = [];
    base({
      providers: [acmeProviderFixture({ eab_configured: true, eab_kid: 'kid-1' })],
      extra: [
        http.patch(`${PROVIDERS}/:id`, async ({ request }) => {
          const body = (await request.json()) as Record<string, unknown>;
          patches.push(body);
          return patches.length === 1 ? errorResponse(409, 'ALC-ACM-0022', 'acme.directory_change_unconfirmed') : HttpResponse.json(acmeProviderFixture());
        }),
      ],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Edit LE staging' }));
    const dialog = await screen.findByRole('dialog', { name: 'Edit LE staging' });
    expect(within(dialog).getByLabelText('Certificate authority')).toHaveValue('letsencrypt_staging');
    expect(within(dialog).getByText('A secret key is stored. Leave this empty to keep it.')).toBeInTheDocument();
    expect(within(dialog).getByLabelText(/^Secret key/)).toHaveValue('');
    expect(within(dialog).queryByRole('checkbox', { name: /Retire the current account/ })).not.toBeInTheDocument();
    const directory = within(dialog).getByLabelText(/^Directory address/);
    await userEvent.clear(directory);
    await userEvent.type(directory, 'https://ca.example.com/acme');
    await userEvent.selectOptions(within(dialog).getByLabelText('Certificate authority'), 'custom');
    expect(directory).toHaveValue('https://ca.example.com/acme'); // an address of the person's own is kept
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save certificate authority' }));
    expect(await within(dialog).findByText('Changing the address needs your confirmation.')).toBeInTheDocument();
    expect(patches[0]).toEqual({ directory_url: 'https://ca.example.com/acme', preset: 'custom' });
    await userEvent.click(within(dialog).getByRole('checkbox', { name: /Retire the current account/ }));
    await userEvent.click(within(dialog).getByRole('checkbox', { name: 'Remove the stored external account binding' }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save certificate authority' }));
    expect(await within(dialog).findByText('Saved.')).toBeInTheDocument();
    expect(patches[1]).toEqual({ directory_url: 'https://ca.example.com/acme', preset: 'custom', remove_eab: true, confirm_directory_change: true });
  });

  it('sends a new key ID with its secret key, and names and the CA bundle when changed', async () => {
    let patch: Record<string, unknown> | undefined;
    base({
      providers: [acmeProviderFixture({ eab_configured: true, eab_kid: 'kid-1', allowed_suffixes: ['example.com'] })],
      extra: [http.patch(`${PROVIDERS}/:id`, async ({ request }) => ((patch = (await request.json()) as Record<string, unknown>), HttpResponse.json(acmeProviderFixture())))],
    });
    const { client } = await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Edit LE staging' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.clear(within(dialog).getByLabelText(/^Key ID/));
    await userEvent.type(within(dialog).getByLabelText(/^Key ID/), 'kid-2');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save certificate authority' }));
    expect(await within(dialog).findByText(/A new key ID needs its secret key/)).toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText(/^Secret key/), 'canary-new-hmac');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove "example.com"' }));
    await userEvent.type(within(dialog).getByLabelText(/^Root certificate of your CA/), 'PEM');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save certificate authority' }));
    await waitFor(() => expect(patch).toEqual({ eab_kid: 'kid-2', eab_hmac: 'canary-new-hmac', ca_bundle_pem: 'PEM', allowed_suffixes: [] }));
    expect(cached(client)).not.toContain('canary-new-hmac');
    expect(document.body.innerHTML).not.toContain('canary-new-hmac');
  });

  it('removes an authority after confirmation, and explains why one in use cannot go', async () => {
    let calls = 0;
    base({ extra: [http.delete(`${PROVIDERS}/:id`, () => (++calls === 1 ? errorResponse(409, 'ALC-ACM-0012', 'acme.provider_in_use') : new HttpResponse(null, { status: 204 })))] });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Remove LE staging' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove LE staging?' });
    expect(dialog).toHaveTextContent('its account is deactivated');
    expect(calls).toBe(0);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove certificate authority' }));
    expect(await within(dialog).findByText('The authority is still in use.')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove certificate authority' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('shows the terms as a link before the box can be ticked, and registers for exactly those terms', async () => {
    const bodies: unknown[] = [];
    let previews = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let providers = [acmeProviderFixture({ active_account_id: null })];
    base({
      providers,
      extra: [
        http.get(PROVIDERS, () => HttpResponse.json({ items: providers })),
        http.post(`${PROVIDERS}/:id/preview`, async ({ params }) => {
          expect(params.id).toBe(ACME_PROVIDER_ID);
          previews++;
          await gate;
          return HttpResponse.json(preview());
        }),
        http.post(`${PROVIDERS}/:id/account`, async ({ request, params }) => {
          expect(params.id).toBe(ACME_PROVIDER_ID);
          bodies.push(await request.json());
          providers = [acmeProviderFixture()];
          return HttpResponse.json(acmeAccountFixture(), { status: 201 });
        }),
      ],
    });
    await open();
    const section = await screen.findByRole('region', { name: 'LE staging' });
    expect(within(section).getByText('No account').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'neutral');
    expect(await within(section).findByText(/No account is registered yet/)).toBeInTheDocument();
    expect(within(section).queryByRole('button', { name: 'Rotate account key' })).not.toBeInTheDocument();
    expect(previews).toBe(0); // nothing is contacted before the form opens
    await userEvent.click(within(section).getByRole('button', { name: 'Register account' }));
    const dialog = await screen.findByRole('dialog', { name: 'Register an account with LE staging' });
    expect(dialog).toHaveTextContent('This is the first time Alice contacts the authority.');
    // While the directory is read: the host is named, the box and the registration are disabled.
    expect(await within(dialog).findByText(/to read its terms of service/)).toHaveTextContent('Contacting acme-staging-v02.api.letsencrypt.org to read its terms of service…');
    expect(within(dialog).getByText('acme-staging-v02.api.letsencrypt.org')).toHaveAttribute('translate', 'no');
    const box = within(dialog).getByRole('checkbox', { name: 'I have read and accept the terms at this address' });
    expect(box).toBeDisabled();
    expect(within(dialog).getByRole('button', { name: 'Register account' })).toBeDisabled();
    expect(within(dialog).queryByRole('link')).not.toBeInTheDocument();
    release();
    const link = await within(dialog).findByRole('link', { name: new RegExp(TERMS.replace(/\./g, '\\.')) });
    expect(link).toHaveAttribute('href', TERMS);
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    expect(link).toHaveAttribute('translate', 'no');
    // The link comes before the box in the dialog, and the box is only now enabled; Register waits for the tick.
    expect(link.compareDocumentPosition(box) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(box).toBeEnabled();
    expect(within(dialog).getByRole('button', { name: 'Register account' })).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/^Contact e-mail/), 'ops@example.com');
    await userEvent.click(box);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Register account' }));
    expect(await within(dialog).findByText(/The account is registered/)).toBeInTheDocument();
    expect(bodies).toEqual([{ contact_email: 'ops@example.com', tos_accepted: true, accepted_terms_url: TERMS }]);
    expect(previews).toBe(1); // read once, not again by the refresh of the providers
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue' }));
    expect(await within(section).findByText('Account registered')).toBeInTheDocument();
  });

  it('registers at an authority without terms: no box, and no terms are sent', async () => {
    let body: unknown;
    base({
      providers: [acmeProviderFixture({ active_account_id: null })],
      extra: [
        http.post(`${PROVIDERS}/:id/preview`, () => HttpResponse.json(preview({ terms_of_service_url: '' }))),
        http.post(`${PROVIDERS}/:id/account`, async ({ request }) => ((body = await request.json()), HttpResponse.json(acmeAccountFixture({ tos_url: '' }), { status: 201 }))),
      ],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Register account' }));
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText(/This authority publishes no terms of service/)).toBeInTheDocument();
    expect(within(dialog).queryByRole('checkbox')).not.toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Register account' }));
    expect(await within(dialog).findByText(/The account is registered/)).toBeInTheDocument();
    expect(body).toEqual({ tos_accepted: false });
  });

  it.each([
    ['the server flags the terms address as unsafe', preview({ terms_of_service_url: '', terms_url_unsafe: true })],
    ['the terms address is not https', preview({ terms_of_service_url: 'http://ca.example/terms' })],
  ])('refuses the registration when %s', async (_why, answer) => {
    let registers = 0;
    base({
      providers: [acmeProviderFixture({ active_account_id: null })],
      extra: [http.post(`${PROVIDERS}/:id/preview`, () => HttpResponse.json(answer)), http.post(`${PROVIDERS}/:id/account`, () => (registers++, HttpResponse.json(acmeAccountFixture())))],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Register account' }));
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText('The terms cannot be shown safely')).toBeInTheDocument();
    expect(within(dialog).queryByRole('link')).not.toBeInTheDocument();
    expect(within(dialog).queryByRole('checkbox')).not.toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Register account' })).toBeDisabled();
    if (answer.terms_of_service_url) expect(within(dialog).getByText(String(answer.terms_of_service_url))).toHaveAttribute('translate', 'no');
    fireEvent.submit(within(dialog).getByRole('button', { name: 'Register account' }).closest('form') as HTMLFormElement);
    expect(registers).toBe(0);
  });

  it('blocks the registration while the terms cannot be read, and tries again', async () => {
    let previews = 0;
    base({
      providers: [acmeProviderFixture({ active_account_id: null })],
      extra: [http.post(`${PROVIDERS}/:id/preview`, () => (++previews === 1 ? errorResponse(502, 'ALC-ACM-0001', 'acme.provider_unreachable') : HttpResponse.json(preview())))],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Register account' }));
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText('The certificate authority could not be reached.')).toBeInTheDocument();
    expect(within(dialog).getByText(/could not read the terms/)).toBeInTheDocument();
    expect(within(dialog).getByRole('checkbox')).toBeDisabled();
    expect(within(dialog).getByRole('button', { name: 'Register account' })).toBeDisabled();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Try again' }));
    expect(await within(dialog).findByRole('link', { name: /LE-SA-v1\.5\.pdf/ })).toBeInTheDocument();
    expect(within(dialog).queryByText('The certificate authority could not be reached.')).not.toBeInTheDocument();
    expect(previews).toBe(2);
  });

  it('reads the terms again and asks again when the authority changed them before the registration (ALC-ACM-0003)', async () => {
    const NEW = 'https://letsencrypt.org/documents/LE-SA-v1.6.pdf';
    const bodies: { accepted_terms_url?: string }[] = [];
    let previews = 0;
    base({
      providers: [acmeProviderFixture({ active_account_id: null })],
      extra: [
        http.post(`${PROVIDERS}/:id/preview`, () => HttpResponse.json(preview({ terms_of_service_url: ++previews === 1 ? TERMS : NEW }))),
        http.post(`${PROVIDERS}/:id/account`, async ({ request }) => {
          const body = (await request.json()) as { accepted_terms_url?: string };
          bodies.push(body);
          return body.accepted_terms_url === NEW ? HttpResponse.json(acmeAccountFixture({ tos_url: NEW }), { status: 201 }) : errorResponse(422, 'ALC-ACM-0003', 'acme.terms_not_accepted');
        }),
      ],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Register account' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(await within(dialog).findByRole('checkbox', { name: 'I have read and accept the terms at this address' }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Register account' }));
    expect(await within(dialog).findByText('The terms of service changed')).toBeInTheDocument();
    expect(within(dialog).queryByText('The terms of service have not been accepted.')).not.toBeInTheDocument();
    expect(await within(dialog).findByRole('link', { name: /LE-SA-v1\.6\.pdf/ })).toHaveAttribute('href', NEW);
    expect(within(dialog).getByRole('checkbox')).not.toBeChecked();
    expect(within(dialog).getByRole('button', { name: 'Register account' })).toBeDisabled();
    await userEvent.click(within(dialog).getByRole('checkbox'));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Register account' }));
    expect(await within(dialog).findByText(/The account is registered/)).toBeInTheDocument();
    expect(bodies.map((b) => b.accepted_terms_url)).toEqual([TERMS, NEW]);
    expect(previews).toBe(2);
  });

  it.each([
    [false, true],
    [true, false],
  ])('warns before the registration when the authority needs an external account binding (stored: %s)', async (stored, warned) => {
    base({
      providers: [acmeProviderFixture({ active_account_id: null, eab_configured: stored })],
      extra: [http.post(`${PROVIDERS}/:id/preview`, () => HttpResponse.json(preview({ external_account_required: true })))],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Register account' }));
    const dialog = await screen.findByRole('dialog');
    await within(dialog).findByRole('link');
    expect(within(dialog).queryByText('This authority needs an external account binding') !== null).toBe(warned);
  });

  it.each([
    ['ALC-ACM-0001', 'acme.provider_unreachable', 502, 'The certificate authority could not be reached.'],
    ['ALC-ACM-0002', 'acme.directory_invalid', 502, 'The address is not a certificate authority.'],
    ['ALC-ACM-0004', 'acme.account_rejected', 422, 'The authority rejected the account.'],
    ['ALC-ACM-0005', 'acme.ca_rate_limited', 503, 'The authority is limiting requests.'],
    ['ALC-ACM-0013', 'acme.tls_trust_failed', 502, "The authority's connection is not trusted."],
    ['ALC-ACM-0021', 'acme.account_exists', 409, 'This authority already has an account.'],
    ['ALC-ACM-0025', 'acme.secret_unreadable', 409, 'A stored secret cannot be read.'],
  ])('shows the registration refusal %s in plain words', async (code, reason, status, text) => {
    base({
      providers: [acmeProviderFixture({ active_account_id: null })],
      extra: [http.post(`${PROVIDERS}/:id/account`, () => errorResponse(status, code, reason)), http.post(`${PROVIDERS}/:id/account`, () => errorResponse(status, code, reason))],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Register account' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(await within(dialog).findByRole('checkbox', { name: 'I have read and accept the terms at this address' }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Register account' }));
    expect(await within(dialog).findByText(text)).toBeInTheDocument();
    expect(within(dialog).getByText(code)).toBeInTheDocument();
  });

  it('rotates the account key and, when the answer did not arrive (ALC-ACM-0024), checks the key change', async () => {
    let rollovers = 0;
    let recovered = '';
    base({
      extra: [
        http.post('/api/v1/acme/accounts/:id/rollover', () => (++rollovers === 1 ? errorResponse(409, 'ALC-ACM-0024', 'acme.rollover_pending', { retryable: true }) : HttpResponse.json(acmeAccountFixture({ id: 'new' })))),
        http.post('/api/v1/acme/accounts/:id/rollover/recover', ({ params }) => ((recovered = String(params.id)), HttpResponse.json(acmeAccountFixture()))),
      ],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Rotate account key' }));
    const dialog = await screen.findByRole('dialog', { name: 'Rotate the account key for LE staging?' });
    expect(dialog).toHaveTextContent('The account and its certificates stay the same.');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Rotate account key' }));
    expect(await within(dialog).findByText('The account key change is not finished.')).toBeInTheDocument();
    expect(within(dialog).getByText(/use "Check key change"/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Check key change' }));
    expect(await within(dialog).findByText('The key change is settled.')).toBeInTheDocument();
    expect(within(dialog).queryByText('The account key change is not finished.')).not.toBeInTheDocument();
    expect(within(dialog).queryByRole('alert')).not.toBeInTheDocument();
    expect(recovered).toBe(ACME_ACCOUNT_ID);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Rotate account key' }));
    expect(await within(dialog).findByText('The account key was replaced.')).toBeInTheDocument();
    expect(rollovers).toBe(2);
  });

  it('says so when the authority cannot change account keys (ALC-ACM-0014)', async () => {
    base({ extra: [http.post('/api/v1/acme/accounts/:id/rollover', () => errorResponse(422, 'ALC-ACM-0014', 'acme.rollover_unsupported'))] });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Rotate account key' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Rotate account key' }));
    expect(await within(dialog).findByText('The authority cannot change the account key.')).toBeInTheDocument();
    expect(within(dialog).queryByRole('button', { name: 'Check key change' })).not.toBeInTheDocument();
  });

  it('shows an unsettled key change on the authority with Check key change, and no other account action', async () => {
    let recovered = '';
    base({
      providers: [acmeProviderFixture({ pending_rollover: true })],
      extra: [http.post('/api/v1/acme/accounts/:id/rollover/recover', ({ params }) => ((recovered = String(params.id)), errorResponse(409, 'ALC-ACM-0024', 'acme.rollover_pending')))],
    });
    await open();
    const section = await screen.findByRole('region', { name: 'LE staging' });
    expect(within(section).getAllByText('Key change not settled')[0].closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'warning');
    expect(await within(section).findByText(/does not know the result yet/)).toBeInTheDocument();
    expect(within(section).queryByRole('button', { name: 'Rotate account key' })).not.toBeInTheDocument();
    expect(within(section).queryByRole('button', { name: 'Deactivate account' })).not.toBeInTheDocument();
    await userEvent.click(within(section).getByRole('button', { name: 'Check key change' }));
    expect(await within(section).findByRole('alert')).toHaveTextContent('ALC-ACM-0024');
    expect(recovered).toBe(ACME_ACCOUNT_ID);
  });

  it.each([
    [3, null, '3 certificates use this authority.'],
    [1, null, '1 certificate uses this authority.'],
    [200, 'next', 'More than 200 certificates use this authority.'],
  ])('warns that %i certificates stop renewing before the account is deactivated', async (count, cursor, text) => {
    let query = '';
    let deactivated = '';
    let reads = 0;
    base({
      extra: [
        http.get('/api/v1/acme/certificates', ({ request }) => {
          reads++;
          query = new URL(request.url).search;
          return HttpResponse.json({ items: Array.from({ length: count }, (_, i) => acmeCertificateFixture({ id: `c${i}` })), next_cursor: cursor });
        }),
        http.post('/api/v1/acme/accounts/:id/deactivate', ({ params }) => ((deactivated = String(params.id)), HttpResponse.json(acmeAccountFixture({ state: 'deactivated' })))),
      ],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Deactivate account' }));
    const dialog = await screen.findByRole('dialog', { name: 'Deactivate the account with LE staging?' });
    expect(await within(dialog).findByText(text)).toBeInTheDocument();
    expect(within(dialog).getByText(/They are not renewed until a new account is registered/)).toBeInTheDocument();
    expect(query).toBe(`?provider_id=${ACME_PROVIDER_ID}&limit=200`);
    expect(deactivated).toBe('');
    const before = reads;
    await userEvent.click(within(dialog).getByRole('button', { name: 'Deactivate account' }));
    expect(await within(dialog).findByText('The account is deactivated.')).toBeInTheDocument();
    expect(deactivated).toBe(ACME_ACCOUNT_ID);
    await waitFor(() => expect(reads).toBeGreaterThan(before)); // the ACME certificates are read again
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue' }));
  });

  it('says that no certificate is affected, and shows a deactivation refusal', async () => {
    base({
      extra: [
        http.get('/api/v1/acme/certificates', () => HttpResponse.json({ items: [], next_cursor: null })),
        http.post('/api/v1/acme/accounts/:id/deactivate', () => errorResponse(409, 'ALC-ACM-0023', 'acme.account_state')),
      ],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Deactivate account' }));
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText('0 certificates use this authority.')).toBeInTheDocument();
    expect(within(dialog).queryByText(/They are not renewed/)).not.toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Deactivate account' }));
    expect(await within(dialog).findByText('The account cannot do this now.')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('keeps the deactivation possible when the affected certificates cannot be counted', async () => {
    base({ extra: [http.get('/api/v1/acme/certificates', () => errorResponse(503, 'ALC-SYS-0002', 'system.unavailable'))] });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Deactivate account' }));
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('ALC-SYS-0002');
    expect(within(dialog).getByRole('button', { name: 'Deactivate account' })).toBeEnabled();
  });

  it('shows the account of a retired or deactivated authority and offers to register again', async () => {
    base({
      providers: [acmeProviderFixture({ active_account_id: null })],
      extra: [http.get(`${PROVIDERS}/:id`, () => HttpResponse.json({ ...acmeProviderFixture({ active_account_id: null }), accounts: [acmeAccountFixture({ state: 'deactivated' }), acmeAccountFixture({ id: 'old', state: 'retired' })] }))],
    });
    await open();
    const section = await screen.findByRole('region', { name: 'LE staging' });
    expect(await within(section).findByText('Deactivated')).toBeInTheDocument();
    expect(within(section).getByRole('button', { name: 'Register account' })).toBeInTheDocument();
  });
});

describe('DNS hooks', () => {
  it('lists a hook with its host, stored secret, names and waits', async () => {
    base();
    await open();
    const hook = await screen.findByRole('region', { name: 'Internal DNS' });
    expect(within(hook).getByText('dns-hook.example.com').tagName).toBe('CODE');
    expect(within(hook).getByText('Secret stored').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'info');
    expect(within(hook).getByText('Waits 5 s after adding a record, then waits up to 60 s for it to be visible.')).toBeInTheDocument();
    expect(within(hook).getByRole('button', { name: 'Edit Internal DNS' })).toBeInTheDocument();
  });

  it('keeps the wire contract for hook authors in a native disclosure, closed until opened', async () => {
    base();
    await open();
    const summary = await screen.findByText('How does the hook work?');
    const details = summary.closest('details') as HTMLDetailsElement;
    expect(summary.tagName).toBe('SUMMARY'); // a native disclosure: browsers open it with Enter and Space
    expect(details.open).toBe(false);
    await userEvent.click(summary);
    await waitFor(() => expect(details.open).toBe(true));
    expect(within(details).getByText(/"action": "present"/)).toBeVisible();
    expect(within(details).getByText(/X-Alice-Signature/)).toBeVisible();
    expect(within(details).getByText(/at most 100 seconds, 120 seconds in all/)).toBeVisible();
  });

  it('adds a hook: checks the secret and the waits first, sends it once, and leaves no trace of the secret', async () => {
    let body: Record<string, unknown> | undefined;
    base({
      hooks: [],
      extra: [http.post(HOOKS, async ({ request }) => ((body = (await request.json()) as Record<string, unknown>), HttpResponse.json(acmeHookFixture(), { status: 201 })))],
    });
    const { client } = await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add DNS hook' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add DNS hook' });
    expect(dialog).toHaveTextContent('A DNS hook is a small service of yours');
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'Internal DNS');
    await userEvent.type(within(dialog).getByLabelText(/^Address of the hook/), 'https://dns-hook.example.com/acme');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS hook' }));
    expect(await within(dialog).findByText('Enter the secret that the hook expects.')).toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText(/^Secret/), 'short');
    const wait = within(dialog).getByLabelText(/^Wait after adding/);
    await userEvent.clear(wait);
    await userEvent.type(wait, '90');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS hook' }));
    expect(await within(dialog).findByText('The secret needs 16 to 256 characters.')).toBeInTheDocument();
    expect(within(dialog).getByText('Both times together can be at most 120 seconds.')).toBeInTheDocument();
    expect(within(dialog).getByLabelText(/^Secret/)).toHaveValue('short'); // a local problem keeps it
    await userEvent.clear(within(dialog).getByLabelText(/^Secret/));
    const poll = within(dialog).getByLabelText(/^Time to wait for the record/);
    await userEvent.clear(poll);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS hook' }));
    expect(await within(dialog).findByText('Enter a whole number from 1 to 100.')).toBeInTheDocument();
    await userEvent.type(poll, '30');
    await userEvent.type(within(dialog).getByLabelText(/^Secret/), 'canary-hook-secret-0123456789');
    await userEvent.type(within(dialog).getByLabelText(/^Allowed names/), 'example.com');
    expect(body).toBeUndefined();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS hook' }));
    expect(await within(dialog).findByText('Saved.')).toBeInTheDocument();
    expect(body).toEqual({
      name: 'Internal DNS',
      url: 'https://dns-hook.example.com/acme',
      secret: 'canary-hook-secret-0123456789',
      ca_bundle_pem: '',
      allowed_suffixes: ['example.com'],
      propagation_wait_seconds: 90,
      poll_timeout_seconds: 30,
    });
    expect(document.body.innerHTML).not.toContain('canary-hook-secret');
    expect(cached(client)).not.toContain('canary-hook-secret');
  });

  it('refuses a wait out of range before sending', async () => {
    base({ hooks: [] });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add DNS hook' }));
    const dialog = await screen.findByRole('dialog');
    const wait = within(dialog).getByLabelText(/^Wait after adding/);
    await userEvent.clear(wait);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS hook' }));
    expect(await within(dialog).findByText('Enter a whole number from 0 to 120.')).toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText(/^Secret/), 'x'.repeat(16));
    await userEvent.type(wait, '5');
    await userEvent.type(within(dialog).getByLabelText(/^Allowed names/), 'com');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS hook' }));
    expect(await within(dialog).findByText(/Use at least two parts/)).toBeInTheDocument();
  });

  it('changes a hook without sending the secret unless typed, and shows the server field problems', async () => {
    const patches: Record<string, unknown>[] = [];
    base({
      extra: [
        http.patch(`${HOOKS}/:id`, async ({ request, params }) => {
          expect(params.id).toBe(ACME_HOOK_ID);
          patches.push((await request.json()) as Record<string, unknown>);
          return patches.length === 1 ? errorResponse(422, 'ALC-SYS-0006', 'validation.failed', { details: [{ field: 'url', code: 'validation.pattern' }] }) : HttpResponse.json(acmeHookFixture());
        }),
      ],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Internal DNS' }));
    const dialog = await screen.findByRole('dialog', { name: 'Edit Internal DNS' });
    expect(within(dialog).getByText('A secret is stored. Leave this empty to keep it.')).toBeInTheDocument();
    const url = within(dialog).getByLabelText(/^Address of the hook/);
    await userEvent.clear(url);
    await userEvent.type(url, 'https://other.example.com/hook');
    const wait = within(dialog).getByLabelText(/^Wait after adding/);
    await userEvent.clear(wait);
    await userEvent.type(wait, '10');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS hook' }));
    await waitFor(() => expect(url).toHaveAttribute('aria-invalid', 'true'));
    expect(patches[0]).toEqual({ url: 'https://other.example.com/hook', propagation_wait_seconds: 10 });
    await userEvent.clear(within(dialog).getByLabelText(/^Name shown/));
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'DNS 2');
    await userEvent.type(within(dialog).getByLabelText(/^Secret/), 'n'.repeat(20));
    await userEvent.type(within(dialog).getByLabelText(/^Root certificate of the hook/), 'PEM');
    const poll = within(dialog).getByLabelText(/^Time to wait for the record/);
    await userEvent.clear(poll);
    await userEvent.type(poll, '50');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove "example.com"' }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS hook' }));
    expect(await within(dialog).findByText('Saved.')).toBeInTheDocument();
    expect(patches[1]).toEqual({ secret: 'n'.repeat(20), name: 'DNS 2', url: 'https://other.example.com/hook', ca_bundle_pem: 'PEM', allowed_suffixes: [], propagation_wait_seconds: 10, poll_timeout_seconds: 50 });
  });

  it('removes a hook after confirmation, and explains why one in use cannot go (ALC-ACM-0019)', async () => {
    let calls = 0;
    base({ extra: [http.delete(`${HOOKS}/:id`, () => (++calls === 1 ? errorResponse(409, 'ALC-ACM-0019', 'acme.hook_in_use') : new HttpResponse(null, { status: 204 })))] });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Remove Internal DNS' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove the DNS hook Internal DNS?' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove DNS hook' }));
    expect(await within(dialog).findByText('The DNS hook is still in use.')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove DNS hook' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(calls).toBe(2);
  });
});

describe('typed secrets and repeated saves', () => {
  it('keeps the typed secret key when the step-up is cancelled, and sends one request for a double Enter', async () => {
    let creates = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    base({
      providers: [],
      extra: [
        http.post(PROVIDERS, async () => {
          creates++;
          if (creates === 1) return errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required');
          await gate;
          return HttpResponse.json(acmeProviderFixture(), { status: 201 });
        }),
      ],
    });
    const { client } = await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add certificate authority' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add certificate authority' });
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'ZeroSSL');
    await userEvent.type(within(dialog).getByLabelText(/^Key ID/), 'kid-1');
    await userEvent.type(within(dialog).getByLabelText(/^Secret key/), 'canary-kept-hmac');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save certificate authority' }));
    const stepUp = await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.click(within(stepUp).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: "Confirm it's you" })).not.toBeInTheDocument());
    expect(within(dialog).getByLabelText(/^Secret key/)).toHaveValue('canary-kept-hmac');
    expect(cached(client)).not.toContain('canary-kept-hmac');
    // Save again, then Enter while the request runs: one request only.
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save certificate authority' }));
    await waitFor(() => expect(creates).toBe(2));
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), '{Enter}');
    release();
    expect(await within(dialog).findByText('Saved.')).toBeInTheDocument();
    expect(creates).toBe(2);
    expect(document.body.innerHTML).not.toContain('canary-kept-hmac');
    expect(cached(client)).not.toContain('canary-kept-hmac');
  });

  it('keeps the hook secret after a refusal, and sends one request for a double Enter', async () => {
    let creates = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    base({
      hooks: [],
      extra: [
        http.post(HOOKS, async () => {
          creates++;
          if (creates === 1) return errorResponse(409, 'ALC-ACM-0020', 'acme.name_taken');
          await gate;
          return HttpResponse.json(acmeHookFixture(), { status: 201 });
        }),
      ],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add DNS hook' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'DNS');
    await userEvent.type(within(dialog).getByLabelText(/^Address of the hook/), 'https://h.example.com');
    await userEvent.type(within(dialog).getByLabelText(/^Secret/), 'canary-hook-kept-0123');
    await userEvent.type(within(dialog).getByLabelText(/^Allowed names/), 'example.com');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS hook' }));
    expect(await within(dialog).findByText('This name is already used.')).toBeInTheDocument();
    expect(within(dialog).getByLabelText(/^Secret/)).toHaveValue('canary-hook-kept-0123');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS hook' }));
    await waitFor(() => expect(creates).toBe(2));
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), '{Enter}');
    release();
    expect(await within(dialog).findByText('Saved.')).toBeInTheDocument();
    expect(creates).toBe(2);
  });

  it('refuses a CA bundle over 64 KiB before sending, in both dialogs', async () => {
    let sent = 0;
    base({ providers: [], hooks: [], extra: [http.post(PROVIDERS, () => (sent++, HttpResponse.json(acmeProviderFixture()))), http.post(HOOKS, () => (sent++, HttpResponse.json(acmeHookFixture())))] });
    await open();
    const big = 'x'.repeat(64 * 1024 + 1);
    await userEvent.click(await screen.findByRole('button', { name: 'Add certificate authority' }));
    let dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'X');
    fireEvent.change(within(dialog).getByLabelText(/^Root certificate of your CA/), { target: { value: big } });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save certificate authority' }));
    expect(await within(dialog).findByText(/can be at most 64 KiB/)).toBeInTheDocument();
    expect(within(dialog).getByLabelText(/^Root certificate of your CA/)).toHaveAttribute('aria-invalid', 'true');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: 'Add DNS hook' }));
    dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/^Secret/), 'x'.repeat(16));
    fireEvent.change(within(dialog).getByLabelText(/^Root certificate of the hook/), { target: { value: big } });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS hook' }));
    expect(await within(dialog).findByText(/can be at most 64 KiB/)).toBeInTheDocument();
    expect(sent).toBe(0);
  });

  it('does not send a preset for an authority stored without one when nothing else changed', async () => {
    let patch: unknown;
    base({
      providers: [acmeProviderFixture({ preset: '' })],
      extra: [http.patch(`${PROVIDERS}/:id`, async ({ request }) => ((patch = await request.json()), HttpResponse.json(acmeProviderFixture())))],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Edit LE staging' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByLabelText('Certificate authority')).toHaveValue('custom');
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), ' 2');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save certificate authority' }));
    await waitFor(() => expect(patch).toEqual({ name: 'LE staging 2' }));
  });

  it("keeps Mantine's description and error on the allowed-names field, and names the chips list", async () => {
    base({ providers: [] });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add certificate authority' }));
    const dialog = await screen.findByRole('dialog');
    const input = within(dialog).getByLabelText(/^Allowed names/);
    const described = () => (input.getAttribute('aria-describedby') ?? '').split(' ').map((id) => document.getElementById(id)?.textContent ?? `missing ${id}`);
    expect(described()).toEqual([expect.stringContaining('Type a domain ending')]);
    await userEvent.type(input, 'com{Enter}');
    expect(described()).toEqual([expect.stringContaining('Use at least two parts'), expect.stringContaining('Type a domain ending')]);
    expect(input).toHaveAttribute('aria-invalid', 'true');
    await userEvent.clear(input);
    await userEvent.type(input, 'example.com{Enter}');
    expect(described()).toEqual([expect.stringContaining('Type a domain ending')]);
    expect(within(dialog).getByRole('list', { name: 'Allowed names' })).toHaveTextContent('example.com');
  });
});

describe('roles', () => {
  it.each(['operator', 'auditor'] as const)('shows the %s the lists without a single change button', async (role) => {
    base({ session: sessionFor(role) });
    await renderWithStepUp(<AcmeSettings />);
    const section = await screen.findByRole('region', { name: 'LE staging' });
    expect(await within(section).findByText('ops@example.com')).toBeInTheDocument();
    expect(await screen.findByRole('region', { name: 'Internal DNS' })).toBeInTheDocument();
    expect(screen.getByText('You can look, not change')).toBeInTheDocument();
    expect(screen.queryAllByRole('button')).toEqual([]);
  });

  it.each(['operator', 'auditor'] as const)('keeps the %s out of the Settings page', async (role) => {
    base({ session: sessionFor(role) });
    await renderRoute('/settings?tab=acme');
    expect(await screen.findByText('You do not have access to this page.')).toBeInTheDocument();
  });

  it('shows the Administrator every change button and no read-only note', async () => {
    base();
    await open();
    await screen.findByRole('region', { name: 'LE staging' });
    expect(screen.queryByText('You can look, not change')).not.toBeInTheDocument();
    for (const name of ['Add certificate authority', 'Add DNS hook', 'Add DNS provider', 'Edit LE staging', 'Remove LE staging', 'Edit Internal DNS', 'Remove Internal DNS'])
      expect(screen.getByRole('button', { name })).toBeInTheDocument();
  });
});

describe('DNS providers (R57)', () => {
  const cfHook = () =>
    acmeHookFixture({ id: 'cf1', kind: 'cloudflare', name: 'Cloudflare', url: '', allowed_suffixes: ['example.com'] });
  const azHook = () =>
    acmeHookFixture({
      id: 'az1',
      kind: 'azure_dns',
      name: 'Azure',
      url: '',
      settings: {
        ...emptyDNSSettings,
        auth: 'certificate',
        tenant_id: '11111111-2222-3333-4444-555555555555',
        client_id: '66666666-7777-8888-9999-000000000000',
        subscription_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        resource_group: 'dns-rg',
        cert_thumbprint: 'ab'.repeat(20),
        cert_not_after: '2027-01-01T00:00:00Z',
      },
    });
  const r53Hook = () =>
    acmeHookFixture({
      id: 'r1',
      kind: 'route53',
      name: 'Route 53',
      url: '',
      settings: { ...emptyDNSSettings, access_key_id: 'TESTACCESSKEYID0001', role_arn: 'arn:aws:iam::123456789012:role/dns' },
    });

  it('lists each provider with its kind, its API host and where it publishes', async () => {
    base({ hooks: [acmeHookFixture(), cfHook(), azHook(), r53Hook()] });
    await open();
    const cf = await screen.findByRole('region', { name: 'Cloudflare' });
    expect(within(cf).getByText('api.cloudflare.com')).toBeInTheDocument();
    expect(within(cf).getAllByText('Cloudflare').length).toBeGreaterThan(1);
    expect(within(cf).getByText('Credentials stored')).toBeInTheDocument();
    const az = screen.getByRole('region', { name: 'Azure' });
    expect(within(az).getByText('Subscription aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee, resource group dns-rg')).toBeInTheDocument();
    const r53 = screen.getByRole('region', { name: 'Route 53' });
    expect(within(r53).getByText(/Access key TESTACCESSKEYID0001 · assumes arn:aws:iam::123456789012:role\/dns/)).toBeInTheDocument();
    const hook = screen.getByRole('region', { name: 'Internal DNS' });
    expect(within(hook).getByText('DNS hook')).toBeInTheDocument();
    expect(within(hook).getByText('Secret stored')).toBeInTheDocument();
  });

  it('adds a Cloudflare provider: checks the token first, sends it once and keeps it out of every cache', async () => {
    let body: Record<string, unknown> | undefined;
    base({
      hooks: [],
      extra: [http.post(HOOKS, async ({ request }) => ((body = (await request.json()) as Record<string, unknown>), HttpResponse.json(cfHook(), { status: 201 })))],
    });
    const { client } = await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add DNS provider' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add DNS provider' });
    expect(within(dialog).getByText(/Zone → DNS → Edit/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findAllByText('This field is required.')).toHaveLength(2);
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'Cloudflare');
    await userEvent.type(within(dialog).getByLabelText(/^API token/), 'short');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText('The token needs 20 to 256 characters without spaces.')).toBeInTheDocument();
    await userEvent.clear(within(dialog).getByLabelText(/^API token/));
    await userEvent.type(within(dialog).getByLabelText(/^API token/), 'canary-cloudflare-token-0123456789');
    await userEvent.type(within(dialog).getByLabelText(/^Allowed names/), 'example.com');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText('Saved.')).toBeInTheDocument();
    expect(body).toEqual({
      kind: 'cloudflare',
      name: 'Cloudflare',
      allowed_suffixes: ['example.com'],
      propagation_wait_seconds: 5,
      poll_timeout_seconds: 60,
      api_token: 'canary-cloudflare-token-0123456789',
    });
    expect(document.body.innerHTML).not.toContain('canary-cloudflare-token');
    expect(cached(client)).not.toContain('canary-cloudflare-token');
  });

  it('adds an Azure DNS provider with a client secret and checks its IDs first', async () => {
    const bodies: Record<string, unknown>[] = [];
    base({
      hooks: [],
      extra: [http.post(HOOKS, async ({ request }) => (bodies.push((await request.json()) as Record<string, unknown>), HttpResponse.json(azHook(), { status: 201 })))],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add DNS provider' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add DNS provider' });
    await userEvent.selectOptions(within(dialog).getByLabelText('DNS provider'), 'azure_dns');
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'Azure');
    await userEvent.type(within(dialog).getByLabelText(/^Directory \(tenant\) ID/), 'not-a-guid');
    await userEvent.type(within(dialog).getByLabelText(/^Resource group/), 'bad/group');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findAllByText('Enter an ID in the form 00000000-0000-0000-0000-000000000000.')).toHaveLength(3);
    expect(within(dialog).getByText(/Use up to 90 letters/)).toBeInTheDocument();
    await userEvent.clear(within(dialog).getByLabelText(/^Directory \(tenant\) ID/));
    await userEvent.type(within(dialog).getByLabelText(/^Directory \(tenant\) ID/), '11111111-2222-3333-4444-555555555555');
    await userEvent.type(within(dialog).getByLabelText(/^Application \(client\) ID/), '66666666-7777-8888-9999-000000000000');
    await userEvent.type(within(dialog).getByLabelText(/^Subscription ID/), 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    await userEvent.clear(within(dialog).getByLabelText(/^Resource group/));
    await userEvent.type(within(dialog).getByLabelText(/^Resource group/), 'dns-rg');
    await userEvent.type(within(dialog).getByLabelText(/^Client secret/), 'canary-azure-secret');
    await userEvent.type(within(dialog).getByLabelText(/^Allowed names/), 'example.com');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText('Saved.')).toBeInTheDocument();
    expect(bodies[0]).toMatchObject({
      kind: 'azure_dns',
      auth: 'client_secret',
      tenant_id: '11111111-2222-3333-4444-555555555555',
      client_id: '66666666-7777-8888-9999-000000000000',
      subscription_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      resource_group: 'dns-rg',
      client_secret: 'canary-azure-secret',
    });
  });

  it('adds an Azure DNS provider with a certificate, which needs its key', async () => {
    const bodies: Record<string, unknown>[] = [];
    base({
      hooks: [],
      extra: [http.post(HOOKS, async ({ request }) => (bodies.push((await request.json()) as Record<string, unknown>), HttpResponse.json(azHook(), { status: 201 })))],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add DNS provider' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add DNS provider' });
    await userEvent.selectOptions(within(dialog).getByLabelText('DNS provider'), 'azure_dns');
    await userEvent.selectOptions(within(dialog).getByLabelText('Sign-in method'), 'certificate');
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'Azure cert');
    await userEvent.type(within(dialog).getByLabelText(/^Directory \(tenant\) ID/), '11111111-2222-3333-4444-555555555555');
    await userEvent.type(within(dialog).getByLabelText(/^Application \(client\) ID/), '66666666-7777-8888-9999-000000000000');
    await userEvent.type(within(dialog).getByLabelText(/^Subscription ID/), 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    await userEvent.type(within(dialog).getByLabelText(/^Resource group/), 'dns-rg');
    fireEvent.change(within(dialog).getByLabelText(/^Certificate registered/), { target: { value: '-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----' } });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText('Paste the private key that belongs to this certificate.')).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText(/^Private key of the certificate/), { target: { value: '-----BEGIN PRIVATE KEY-----\nBB\n-----END PRIVATE KEY-----' } });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText('Saved.')).toBeInTheDocument();
    expect(bodies[0]).toMatchObject({ auth: 'certificate', certificate_pem: expect.stringContaining('BEGIN CERTIFICATE'), private_key_pem: expect.stringContaining('PRIVATE KEY') });
    expect(bodies[0]).not.toHaveProperty('client_secret');
  });

  it('adds an Azure DNS provider with the managed identity: no tenant, no secret', async () => {
    const bodies: Record<string, unknown>[] = [];
    base({
      hooks: [],
      extra: [http.post(HOOKS, async ({ request }) => (bodies.push((await request.json()) as Record<string, unknown>), HttpResponse.json(azHook(), { status: 201 })))],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add DNS provider' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add DNS provider' });
    await userEvent.selectOptions(within(dialog).getByLabelText('DNS provider'), 'azure_dns');
    await userEvent.selectOptions(within(dialog).getByLabelText('Sign-in method'), 'managed_identity');
    expect(within(dialog).queryByLabelText(/^Directory \(tenant\) ID/)).not.toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'Azure MI');
    await userEvent.type(within(dialog).getByLabelText(/^Subscription ID/), 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    await userEvent.type(within(dialog).getByLabelText(/^Resource group/), 'dns-rg');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText('Saved.')).toBeInTheDocument();
    expect(bodies[0]).toMatchObject({ kind: 'azure_dns', auth: 'managed_identity', tenant_id: '', client_id: '' });
  });

  it('adds a Route 53 provider with a role, and refuses a malformed key ID and role first', async () => {
    let body: Record<string, unknown> | undefined;
    base({
      hooks: [],
      extra: [http.post(HOOKS, async ({ request }) => ((body = (await request.json()) as Record<string, unknown>), HttpResponse.json(r53Hook(), { status: 201 })))],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add DNS provider' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add DNS provider' });
    await userEvent.selectOptions(within(dialog).getByLabelText('DNS provider'), 'route53');
    expect(within(dialog).getByText(/route53:ChangeResourceRecordSets/)).toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'Route 53');
    await userEvent.type(within(dialog).getByLabelText(/^Access key ID/), 'lower-case');
    await userEvent.type(within(dialog).getByLabelText(/^Secret access key/), 'short');
    await userEvent.type(within(dialog).getByLabelText(/^Role to assume/), 'arn:aws:iam::1:user/x');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText(/16 to 128 capital letters and digits/)).toBeInTheDocument();
    expect(within(dialog).getByText('The secret access key needs 16 to 128 characters without spaces.')).toBeInTheDocument();
    expect(within(dialog).getByText(/Enter a role ARN like/)).toBeInTheDocument();
    await userEvent.clear(within(dialog).getByLabelText(/^Access key ID/));
    await userEvent.type(within(dialog).getByLabelText(/^Access key ID/), 'TESTACCESSKEYID0001');
    await userEvent.clear(within(dialog).getByLabelText(/^Secret access key/));
    await userEvent.type(within(dialog).getByLabelText(/^Secret access key/), 'aaaa-bbbb-cccc-dddd-eeee');
    await userEvent.clear(within(dialog).getByLabelText(/^Role to assume/));
    await userEvent.type(within(dialog).getByLabelText(/^Role to assume/), 'arn:aws:iam::123456789012:role/dns');
    await userEvent.type(within(dialog).getByLabelText(/^External ID/), 'ext-1');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText('Saved.')).toBeInTheDocument();
    expect(body).toMatchObject({
      kind: 'route53',
      access_key_id: 'TESTACCESSKEYID0001',
      role_arn: 'arn:aws:iam::123456789012:role/dns',
      external_id: 'ext-1',
      secret_access_key: 'aaaa-bbbb-cccc-dddd-eeee',
    });
  });

  it('changes a provider: the kind is fixed, stored credentials stay unless typed, and the settings go as a whole', async () => {
    const patches: Record<string, unknown>[] = [];
    base({
      hooks: [azHook(), r53Hook(), cfHook()],
      extra: [
        http.patch(`${HOOKS}/:id`, async ({ request }) => {
          patches.push((await request.json()) as Record<string, unknown>);
          return patches.length === 1
            ? errorResponse(422, 'ALC-SYS-0006', 'validation.failed', { details: [{ field: 'resource_group', code: 'validation.pattern' }] })
            : HttpResponse.json(azHook());
        }),
      ],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Azure' }));
    let dialog = await screen.findByRole('dialog', { name: 'Edit Azure' });
    expect(within(dialog).queryByLabelText('DNS provider')).not.toBeInTheDocument();
    expect(within(dialog).getByText(/Stored certificate: thumbprint abab/)).toBeInTheDocument();
    await userEvent.clear(within(dialog).getByLabelText(/^Resource group/));
    await userEvent.type(within(dialog).getByLabelText(/^Resource group/), 'other-rg');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText('This value contains characters that are not allowed.')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText('Saved.')).toBeInTheDocument();
    expect(patches[1]).toEqual({
      auth: 'certificate',
      tenant_id: '11111111-2222-3333-4444-555555555555',
      client_id: '66666666-7777-8888-9999-000000000000',
      subscription_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      resource_group: 'other-rg',
    });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue' }));

    // Another sign-in method needs its credential before anything is sent.
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Azure' }));
    dialog = await screen.findByRole('dialog', { name: 'Edit Azure' });
    await userEvent.selectOptions(within(dialog).getByLabelText('Sign-in method'), 'client_secret');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText('This field is required.')).toBeInTheDocument();
    expect(patches).toHaveLength(2);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));

    // A new AWS key ID needs its secret; the name alone changes nothing else.
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Route 53' }));
    dialog = await screen.findByRole('dialog', { name: 'Edit Route 53' });
    expect(within(dialog).getByText('Credentials are stored. Leave this empty to keep them.')).toBeInTheDocument();
    await userEvent.clear(within(dialog).getByLabelText(/^Access key ID/));
    await userEvent.type(within(dialog).getByLabelText(/^Access key ID/), 'TESTACCESSKEYID0002');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText('This field is required.')).toBeInTheDocument();
    await userEvent.clear(within(dialog).getByLabelText(/^Access key ID/));
    await userEvent.type(within(dialog).getByLabelText(/^Access key ID/), 'TESTACCESSKEYID0001');
    await userEvent.clear(within(dialog).getByLabelText(/^Name shown/));
    await userEvent.type(within(dialog).getByLabelText(/^Name shown/), 'AWS');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText('Saved.')).toBeInTheDocument();
    expect(patches[2]).toEqual({ name: 'AWS' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue' }));

    // A new Cloudflare token is checked and sent; an empty one keeps the stored token.
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Cloudflare' }));
    dialog = await screen.findByRole('dialog', { name: 'Edit Cloudflare' });
    await userEvent.type(within(dialog).getByLabelText(/^API token/), 'with space in it but long enough');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText('The token needs 20 to 256 characters without spaces.')).toBeInTheDocument();
    await userEvent.clear(within(dialog).getByLabelText(/^API token/));
    await userEvent.type(within(dialog).getByLabelText(/^API token/), 'a-new-cloudflare-token-0123456789');
    const wait = within(dialog).getByLabelText(/^Wait after adding/);
    await userEvent.clear(wait);
    await userEvent.type(wait, '30');
    const poll = within(dialog).getByLabelText(/^Time to wait for the record/);
    await userEvent.clear(poll);
    await userEvent.type(poll, '100');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText('Both times together can be at most 120 seconds.')).toBeInTheDocument();
    await userEvent.clear(poll);
    await userEvent.type(poll, '90');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save DNS provider' }));
    expect(await within(dialog).findByText('Saved.')).toBeInTheDocument();
    expect(patches[3]).toEqual({ api_token: 'a-new-cloudflare-token-0123456789', propagation_wait_seconds: 30, poll_timeout_seconds: 90 });
  });

  it('words the provider dialog in Turkish', async () => {
    base({ session: { ...sessionFor('admin', 'tr'), stepup_until: '2099-01-01T00:00:00Z' }, hooks: [cfHook()] });
    await renderRoute('/settings?tab=acme', { languages: ['tr-TR'] });
    await userEvent.click(await screen.findByRole('button', { name: 'DNS sağlayıcısı ekle' }));
    const dialog = await screen.findByRole('dialog', { name: 'DNS sağlayıcısı ekle' });
    await userEvent.selectOptions(within(dialog).getByLabelText('DNS sağlayıcısı'), 'route53');
    expect(within(dialog).getByLabelText(/^Gizli erişim anahtarı/)).toBeInTheDocument();
    expectNoRawKeys();
  });
});

describe('Turkish', () => {
  it('words the section, the dialogs and the glossed terms in Turkish', async () => {
    base({ session: { ...sessionFor('admin', 'tr'), stepup_until: '2099-01-01T00:00:00Z' } });
    await renderRoute('/settings?tab=acme', { languages: ['tr-TR'] });
    expect(await screen.findByRole('tab', { name: 'Sertifika yetkilileri', selected: true })).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Hesap anahtarını yenile' })).toBeInTheDocument();
    expect(screen.getByText(/sizin küçük bir hizmetiniz olan bir DNS kancası/)).toBeInTheDocument();
    expectNoRawKeys();
    await userEvent.click(screen.getByRole('button', { name: 'Sertifika yetkilisi ekle' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/CA'nızın verdiği bir anahtar kimliği ve gizli anahtardır/)).toBeInTheDocument();
    expectNoRawKeys();
  });
});

it('keeps the ACME styles on the tokens', () => {
  const css = readFileSync('src/components/acme/acme.module.css', 'utf8');
  expect(css).not.toMatch(/#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(/i);
  expect(/\.help > summary:focus-visible\s*\{([^}]*)\}/.exec(css)?.[1]).toMatch(/outline:\s*3px solid var\(--alice-focus\)/);
});
