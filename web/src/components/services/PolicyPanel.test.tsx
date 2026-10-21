import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { changedPolicyKeys, type ServicePolicy } from '../../api/services';
import { ACME_PROVIDER_ID, acmeProviderFixture, errorResponse, globalSession, SERVICE_ID, serviceFixture, servicePolicyFixture, sessionHandlers, scopedSession } from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';
import type { SessionInfo } from '../../api/types';
import { documentOf, splitDomains } from './PolicyPanel';

const steppedUp = (s: SessionInfo): SessionInfo => ({ ...s, stepup_until: '2099-01-01T00:00:00Z' });

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

  it('gives an Operator the policy to read only, in Turkish too', async () => {
    policyWorld(scopedSession(['operator'], 'tr'));
    await renderRoute(`/services/${SERVICE_ID}?tab=policy`);
    expect(await screen.findByTestId('policy-domains')).toHaveAttribute('readonly');
    expect(screen.queryByTestId('policy-save')).not.toBeInTheDocument();
    expect(screen.getByTestId('policy-auto-deploy')).toBeDisabled();
    expect(screen.getByText('Sürümler')).toBeInTheDocument();
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

  it('names the keys a version changed', () => {
    expect(changedPolicyKeys(undefined, { schema: 1, domains: ['a'] })).toEqual(['domains']);
    expect(changedPolicyKeys({ schema: 1, acme: { challenges: ['dns01'] } }, { schema: 1, acme: { challenges: ['dns01'] } })).toEqual([]);
  });
});
