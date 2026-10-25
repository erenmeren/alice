import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { changedPolicyKeys, type ServicePolicy } from '../../api/services';
import { ACME_PROVIDER_ID, acmeProviderFixture, errorResponse, globalSession, SERVICE_ID, serviceFixture, servicePolicyFixture, sessionHandlers, scopedSession } from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';
import type { SessionInfo } from '../../api/types';
import { canaryOf, documentOf, splitDomains } from './PolicyPanel';

const steppedUp = (s: SessionInfo): SessionInfo => ({ ...s, stepup_until: '2099-01-01T00:00:00Z' });
const WEBSITE_ID = '0192c000-0000-7000-8000-00000000c001';
const seenLocationQueries: string[] = [];

const v2: ServicePolicy = servicePolicyFixture({
  version: 2,
  body: { schema: 1, domains: ['*.pay.example.com'], deployment: { auto_deploy: 'forbidden' } },
  created_by_name: 'Ada Admin',
  created_at: '2026-10-21T09:00:00Z',
});

function policyWorld(session: SessionInfo, put?: (body: unknown) => Response) {
  const seen: unknown[] = [];
  server.use(
    ...sessionHandlers(steppedUp(session)),
    http.get(`/api/v1/services/${SERVICE_ID}`, () => HttpResponse.json(serviceFixture())),
    http.get(`/api/v1/services/${SERVICE_ID}/policy`, () => HttpResponse.json(v2)),
    http.get(`/api/v1/services/${SERVICE_ID}/policy/versions`, () => HttpResponse.json({ items: [v2, servicePolicyFixture()] })),
    http.get('/api/v1/acme/providers', () => HttpResponse.json({ items: [acmeProviderFixture()] })),
    http.get('/api/v1/certificate-locations', ({ request }) => {
      seenLocationQueries.push(new URL(request.url).searchParams.get('service_id') ?? '');
      return HttpResponse.json({
        items: [{ id: WEBSITE_ID, target_id: 't1', target_name: 'web-01', cert_path: '/etc/nginx/ssl/www.crt', key_path: '/etc/nginx/ssl/www.key', key_type: '', server_names: [], binding_id: null }],
        next_cursor: null,
      });
    }),
    http.put(`/api/v1/services/${SERVICE_ID}/policy`, async ({ request }) => {
      const body = await request.json();
      seen.push(body);
      return put ? put(body) : HttpResponse.json({ ...v2, version: 3 });
    }),
  );
  return seen;
}

describe('PolicyPanel', () => {
  it('lets a global Administrator change every field and save the whole document with the version read', async () => {
    const seen = policyWorld(globalSession('admin'));
    await renderRoute(`/services/${SERVICE_ID}?tab=policy`);
    const domains = await screen.findByTestId('policy-domains');
    expect(domains).toHaveValue('*.pay.example.com');
    expect(screen.getByTestId('policy-auto-deploy')).toHaveValue('forbidden');
    await userEvent.type(domains, '{enter}10.20.0.0/16');
    await userEvent.click(screen.getByRole('checkbox', { name: 'ACME certificates' }));
    await userEvent.click(screen.getByRole('checkbox', { name: 'LE staging' }));
    await userEvent.selectOptions(screen.getByTestId('policy-auto-deploy'), 'allowed');
    await userEvent.click(screen.getByTestId('policy-save'));
    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]).toEqual({
      version: 2,
      body: { schema: 1, domains: ['*.pay.example.com', '10.20.0.0/16'], certificate_sources: ['acme'], acme: { providers: [ACME_PROVIDER_ID] } },
    });
  });

  it('lists every version with what it changed and who saved it', async () => {
    policyWorld(globalSession('admin'));
    await renderRoute(`/services/${SERVICE_ID}?tab=policy`);
    const history = await screen.findByTestId('policy-history');
    const rows = within(history).getAllByRole('row');
    expect(rows).toHaveLength(3);
    expect(within(rows[1]).getByText('Domains, Automatic deployment')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Ada Admin')).toBeInTheDocument();
    expect(within(rows[2]).getByText('The first version (no rules)')).toBeInTheDocument();
  });

  it('keeps the domains read-only for an Administrator of the service alone', async () => {
    const seen = policyWorld(scopedSession(['admin']));
    await renderRoute(`/services/${SERVICE_ID}?tab=policy`);
    const domains = await screen.findByTestId('policy-domains');
    expect(domains).toHaveAttribute('readonly');
    expect(screen.getByText('Only an Administrator of all services changes the domains.')).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText('Revocation in a key-compromise incident'), 'now');
    await userEvent.click(screen.getByTestId('policy-save'));
    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]).toEqual({ version: 2, body: { ...v2.body, incident: { revoke_mode: 'now' } } });
  });

  it('shows the refusal of a stale version', async () => {
    policyWorld(globalSession('admin'), () => errorResponse(409, 'ALC-SVC-0010', 'service.version_conflict'));
    await renderRoute(`/services/${SERVICE_ID}?tab=policy`);
    await userEvent.click(await screen.findByTestId('policy-save'));
    expect(await screen.findByText('The policy or the owners changed since you opened them.')).toBeInTheDocument();
  });

  it('edits the ACME rules and the e-mail addresses, keeps a removed authority and says which version it saved', async () => {
    let current: ServicePolicy = servicePolicyFixture({
      version: 4,
      body: { schema: 1, acme: { providers: ['gone-provider'] }, notifications: { addresses: [{ email: 'old@example.com', locale: 'en' }, { email: 'drop@example.com', locale: 'en' }] } },
    });
    const seen = policyWorld(globalSession('admin'), (body) => {
      current = servicePolicyFixture({ version: 5, body: (body as { body: ServicePolicy['body'] }).body });
      return HttpResponse.json(current);
    });
    server.use(http.get(`/api/v1/services/${SERVICE_ID}/policy`, () => HttpResponse.json(current)));
    await renderRoute(`/services/${SERVICE_ID}?tab=policy`);
    // The policy names an authority that no longer exists: it stays listed (and ticked) so it can be unticked.
    expect(await screen.findByRole('checkbox', { name: 'A removed certificate authority' })).toBeChecked();
    await userEvent.click(screen.getByRole('checkbox', { name: 'Web proof (file on the web server)' }));
    await userEvent.click(screen.getByRole('checkbox', { name: 'ECDSA P-384' }));
    await userEvent.type(screen.getByLabelText('Renew before expiry (days)'), '21');
    await userEvent.click(screen.getByRole('checkbox', { name: "Administrators of all services receive this service's e-mails" }));
    const addresses = screen.getAllByLabelText('Extra address');
    await userEvent.clear(addresses[0]);
    await userEvent.type(addresses[0], 'team@example.com');
    await userEvent.selectOptions(screen.getAllByLabelText('Language')[0], 'tr');
    await userEvent.click(screen.getAllByRole('button', { name: 'Remove this address' })[1]);
    expect(screen.getAllByLabelText('Extra address')).toHaveLength(1);
    await userEvent.click(screen.getByRole('button', { name: 'Add an address' }));
    await userEvent.type(screen.getAllByLabelText('Extra address')[1], 'ops@example.com');
    await userEvent.click(screen.getByTestId('policy-save'));
    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]).toEqual({
      version: 4,
      body: {
        schema: 1,
        acme: { providers: ['gone-provider'], challenges: ['http01'], key_types: ['ecdsa_p384'], renew_before_days: 21 },
        notifications: {
          administrators: false,
          addresses: [
            { email: 'team@example.com', locale: 'tr' },
            { email: 'ops@example.com', locale: 'en' },
          ],
        },
      },
    });
    expect(await screen.findByTestId('policy-saved')).toHaveTextContent('Saved as version 5.');
  });

  it('marks the field the server refuses, below its path', async () => {
    policyWorld(globalSession('admin'), () => errorResponse(422, 'ALC-SYS-0006', 'validation.failed', { details: [{ field: 'body.domains.0', code: 'validation.pattern' }] }));
    await renderRoute(`/services/${SERVICE_ID}?tab=policy`);
    await userEvent.click(await screen.findByTestId('policy-save'));
    await waitFor(() => expect(screen.getByTestId('policy-domains')).toHaveAttribute('aria-invalid', 'true'));
    expect(screen.getByTestId('policy-auto-deploy')).not.toHaveAttribute('aria-invalid', 'true');
  });

  it('says when no certificate authority is set up and when there are no versions', async () => {
    policyWorld(globalSession('admin'));
    server.use(
      http.get('/api/v1/acme/providers', () => HttpResponse.json({ items: [] })),
      http.get(`/api/v1/services/${SERVICE_ID}/policy/versions`, () => HttpResponse.json({ items: [] })),
    );
    await renderRoute(`/services/${SERVICE_ID}?tab=policy`);
    expect(await screen.findByText('No certificate authority is set up yet.')).toBeInTheDocument();
    expect(await screen.findByText('No versions yet.')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-history')).not.toBeInTheDocument();
  });

  it('gives an Operator the policy to read only, in Turkish too', async () => {
    policyWorld(scopedSession(['operator'], 'tr'));
    await renderRoute(`/services/${SERVICE_ID}?tab=policy`);
    expect(await screen.findByTestId('policy-domains')).toHaveAttribute('readonly');
    expect(screen.queryByTestId('policy-save')).not.toBeInTheDocument();
    expect(screen.getByTestId('policy-auto-deploy')).toBeDisabled();
    expect(await screen.findByText('Sürümler')).toBeInTheDocument();
    expectNoRawKeys(document.body);
  });
});

describe('the canary section (R65)', () => {
  const withCanary = (canary: ServicePolicy['body']['canary']): ServicePolicy => servicePolicyFixture({ version: 2, body: { schema: 1, canary } });

  it('renders a stored canary policy', async () => {
    policyWorld(globalSession('admin'));
    server.use(
      http.get(`/api/v1/services/${SERVICE_ID}/policy`, () =>
        HttpResponse.json(withCanary({ enabled: true, subset: { count: 3 }, hold: '20m', check: { path: '/healthz', timeout: '3s' }, first: [WEBSITE_ID] })),
      ),
    );
    await renderRoute(`/services/${SERVICE_ID}?tab=policy`);
    const section = await screen.findByTestId('policy-canary');
    expect(within(section).getByTestId('canary-enabled')).toBeChecked();
    expect(within(section).getByTestId('canary-count')).toHaveValue('3');
    expect(within(section).getByTestId('canary-hold')).toHaveValue('20m');
    expect(within(section).getByTestId('canary-path')).toHaveValue('/healthz');
    expect(within(section).getByTestId('canary-timeout')).toHaveValue('3s');
    expect(await within(section).findByText('web-01 /etc/nginx/ssl/www.crt')).toBeInTheDocument();
    expect(seenLocationQueries).toContain(SERVICE_ID);
    expect(within(section).queryByTestId('canary-time-only')).not.toBeInTheDocument();
  });

  it('switches it on and sends only what is set', async () => {
    const seen = policyWorld(globalSession('admin'));
    server.use(http.get(`/api/v1/services/${SERVICE_ID}/policy`, () => HttpResponse.json(servicePolicyFixture({ version: 2, body: { schema: 1 } }))));
    await renderRoute(`/services/${SERVICE_ID}?tab=policy`);
    await userEvent.click(await screen.findByTestId('canary-enabled'));
    expect(screen.getByTestId('canary-time-only')).toHaveTextContent('observed by time only');
    await userEvent.click(screen.getByTestId('policy-save'));
    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]).toEqual({ version: 2, body: { schema: 1, canary: { enabled: true } } });
  });

  it('sends a percentage instead of a count', async () => {
    const seen = policyWorld(globalSession('admin'));
    server.use(http.get(`/api/v1/services/${SERVICE_ID}/policy`, () => HttpResponse.json(withCanary({ enabled: true, subset: { count: 2 } }))));
    await renderRoute(`/services/${SERVICE_ID}?tab=policy`);
    await userEvent.click(await screen.findByRole('radio', { name: 'Percentage' }));
    await userEvent.type(screen.getByTestId('canary-percent'), '20');
    await userEvent.click(screen.getByTestId('policy-save'));
    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]).toEqual({ version: 2, body: { schema: 1, canary: { enabled: true, subset: { percent: 20 } } } });
  });

  it('marks the field the server refuses and a duration Alice cannot read', async () => {
    policyWorld(globalSession('admin'), () =>
      errorResponse(422, 'ALC-SYS-0006', 'validation.failed', { details: [{ field: 'body.canary.check.timeout', code: 'validation.out_of_range', params: { min: '1s', max: '14s' } }] }),
    );
    server.use(http.get(`/api/v1/services/${SERVICE_ID}/policy`, () => HttpResponse.json(withCanary({ enabled: true, check: { path: '/' } }))));
    await renderRoute(`/services/${SERVICE_ID}?tab=policy`);
    await userEvent.type(await screen.findByTestId('canary-hold'), '1h30m');
    expect(screen.getByTestId('canary-hold')).toHaveAttribute('aria-invalid', 'true');
    await userEvent.click(screen.getByTestId('policy-save'));
    await waitFor(() => expect(screen.getByTestId('canary-timeout')).toHaveAttribute('aria-invalid', 'true'));
  });

  it('is read-only without the right to change the policy, in Turkish too', async () => {
    policyWorld(scopedSession(['operator'], 'tr'));
    server.use(http.get(`/api/v1/services/${SERVICE_ID}/policy`, () => HttpResponse.json(withCanary({ enabled: true, hold: '5m' }))));
    await renderRoute(`/services/${SERVICE_ID}?tab=policy`);
    expect(await screen.findByTestId('canary-enabled')).toBeDisabled();
    expect(screen.getByTestId('canary-hold')).toHaveAttribute('readonly');
    expect(screen.getByText('Kanarya dağıtımı')).toBeInTheDocument();
    expectNoRawKeys(document.body);
  });
});

describe('the policy document', () => {
  it('leaves out every rule not set and splits the domains', () => {
    expect(splitDomains(' a.example.com,\n\n*.b.example.com  10.0.0.0/8 ')).toEqual(['a.example.com', '*.b.example.com', '10.0.0.0/8']);
    expect(
      documentOf({ domains: '', sources: [], providers: [], challenges: [], keyTypes: [], renewDays: '', autoDeploy: '', revokeMode: '', administrators: true, addresses: [{ email: ' ', locale: 'en' }] }),
    ).toEqual({ schema: 1 });
    expect(
      documentOf({
        domains: 'x.example.com',
        sources: ['csr'],
        providers: [],
        challenges: ['dns01'],
        keyTypes: ['rsa_3072'],
        renewDays: 14,
        autoDeploy: 'forbidden',
        revokeMode: 'after_verified',
        administrators: false,
        addresses: [{ email: 'team@example.com ', locale: 'tr' }],
      }),
    ).toEqual({
      schema: 1,
      domains: ['x.example.com'],
      certificate_sources: ['csr'],
      acme: { challenges: ['dns01'], key_types: ['rsa_3072'], renew_before_days: 14 },
      deployment: { auto_deploy: 'forbidden' },
      incident: { revoke_mode: 'after_verified' },
      notifications: { administrators: false, addresses: [{ email: 'team@example.com', locale: 'tr' }] },
    });
  });

  it('builds the canary key from what is set only', () => {
    const base = { enabled: false, mode: 'count' as const, count: '', percent: '', first: [], hold: '', interval: '', failures: '', check: false, path: '', host: '', port: '', statuses: '', timeout: '', forbidOverride: false };
    expect(canaryOf(base)).toBeUndefined();
    expect(canaryOf({ ...base, hold: ' 1h ' })).toEqual({ enabled: false, hold: '1h' });
    expect(
      canaryOf({ ...base, enabled: true, count: 2, first: ['a'], interval: '15s', failures: 3, check: true, path: ' /h ', host: 'app.example', port: 8443, statuses: '200, 204', timeout: '2s', forbidOverride: true }),
    ).toEqual({ enabled: true, subset: { count: 2 }, first: ['a'], interval: '15s', failures: 3, check: { path: '/h', host: 'app.example', port: 8443, expect_status: [200, 204], timeout: '2s' }, override: 'forbidden' });
    expect(changedPolicyKeys({ schema: 1 }, { schema: 1, canary: { enabled: true } })).toEqual(['canary']);
  });

  it('names the keys a version changed', () => {
    expect(changedPolicyKeys(undefined, { schema: 1, domains: ['a'] })).toEqual(['domains']);
    expect(changedPolicyKeys({ schema: 1, acme: { challenges: ['dns01'] } }, { schema: 1, acme: { challenges: ['dns01'] } })).toEqual([]);
  });
});
