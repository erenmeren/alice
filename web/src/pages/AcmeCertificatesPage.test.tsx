import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { ACMECertificate, ACMEProvider } from '../api/acme';
import type { SessionInfo } from '../api/types';
import { ACME_PROVIDER_ID, acmeCertificateFixture, acmeProviderFixture, errorResponse, sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const CERTS = '/api/v1/acme/certificates';

function base(opts: { session?: SessionInfo; items?: ACMECertificate[]; providers?: ACMEProvider[]; next?: string | null; onList?: (u: URL) => void } = {}) {
  server.use(
    ...sessionHandlers(opts.session ?? sessionFor('admin')),
    http.get(CERTS, ({ request }) => {
      const u = new URL(request.url);
      opts.onList?.(u);
      return HttpResponse.json({ items: opts.items ?? [], next_cursor: u.searchParams.get('cursor') ? null : (opts.next ?? null) });
    }),
    http.get('/api/v1/acme/providers', () => HttpResponse.json({ items: opts.providers ?? [acmeProviderFixture()] })),
  );
}

const issued = (o: Partial<ACMECertificate> = {}) =>
  acmeCertificateFixture({
    current: { id: '0192c000-0000-7000-8000-0000000000c9', fingerprint_sha256: 'ab'.repeat(32), not_before: '2026-10-01T00:00:00Z', not_after: '2099-12-30T00:00:00Z', chain_complete: true },
    ...o,
  });

describe('Issued certificates list', () => {
  it('explains an empty installation to an Administrator, with the way to add an authority first', async () => {
    base({ providers: [] });
    await renderRoute('/acme');
    expect(await screen.findByText('No certificates from a certificate authority yet')).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1, name: 'Issued certificates' })).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByText(/First add a certificate authority/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Settings → Certificate authorities' })).toHaveAttribute('href', '/settings?tab=acme');
    // One button, in the empty state.
    expect(screen.getAllByRole('button', { name: 'Get a certificate' })).toHaveLength(1);
    expect(screen.getByRole('link', { name: 'Issued certificates' })).toHaveAttribute('aria-current', 'page');
    expectNoRawKeys();
  });

  it('opens the wizard from the empty state', async () => {
    base();
    await renderRoute('/acme');
    await userEvent.click(await screen.findByRole('button', { name: 'Get a certificate' }));
    expect(await screen.findByRole('dialog', { name: 'Get a certificate' })).toBeInTheDocument();
  });

  it.each(['operator', 'auditor'] as const)('shows no Get a certificate button to an %s, and says who sets them up', async (role) => {
    base({ session: sessionFor(role) });
    await renderRoute('/acme');
    expect(await screen.findByText('An administrator sets them up.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Get a certificate' })).not.toBeInTheDocument();
    expect(screen.queryByText(/First add a certificate authority/)).not.toBeInTheDocument();
    if (role === 'auditor') expect(screen.getByText(/You can look, not change/)).toBeInTheDocument();
    else expect(screen.queryByText(/You can look, not change/)).not.toBeInTheDocument();
  });

  it('lists certificates with names, authority, status, proof, expiry, renewal and automation', async () => {
    base({
      session: sessionFor('auditor'),
      items: [
        issued({ names: ['www.example.com', 'example.com', 'api.example.com'], auto_deploy: true }),
        acmeCertificateFixture({ id: 'c2', names: ['*.corp.example.com'], state: 'pending', auto_renew: false }),
        issued({ id: 'c3', names: ['fail.example.com'], state: 'failing', next_attempt_at: '2026-10-14T10:00:00Z' }),
        issued({ id: 'c4', names: ['stop.example.com'], state: 'stopped', stopped_reason: 'renewal_failures' }),
        acmeCertificateFixture({ id: 'c5', names: ['new.example.com'], state: 'pending' }),
      ],
    });
    await renderRoute('/acme');
    const table = await screen.findByRole('table', { name: 'Issued certificates' });
    const rows = within(table).getAllByTestId('acme-certificate-row');
    expect(rows).toHaveLength(5);
    const [first, second, third, fourth, fifth] = rows;
    expect(within(first).getByRole('link', { name: 'www.example.com' })).toHaveAttribute('href', `/acme/${acmeCertificateFixture().id}`);
    expect(within(first).getByText('and 2 more names')).toBeInTheDocument();
    expect(within(first).getByText('LE staging')).toBeInTheDocument();
    expect(within(first).getByText('Active').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'success');
    expect(within(first).getByText('Active').closest('.mantine-Badge-root')?.querySelector('svg')).not.toBeNull();
    expect(within(first).getByText('DNS proof (DNS hook)')).toBeInTheDocument();
    expect(within(first).getByText('Renews 30 days before it expires')).toBeInTheDocument();
    expect(within(first).getByText('Renews automatically')).toBeInTheDocument();
    expect(within(first).getByText('Deploys automatically')).toBeInTheDocument();
    expect(within(second).getByText('Not issued yet', { selector: 'span:not(.mantine-Badge-label)' })).toBeInTheDocument();
    expect(within(second).getByText('No automatic renewal')).toBeInTheDocument();
    expect(within(second).getByText('Off')).toBeInTheDocument();
    expect(within(third).getByText('Renewal failing').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'warning');
    expect(within(third).getByText(/^Next attempt /)).toBeInTheDocument();
    expect(within(fourth).getByText('Renewal stopped').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'danger');
    expect(within(fourth).getByText('Stopped')).toBeInTheDocument();
    expect(within(fifth).getByText('After the first certificate is issued')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Get a certificate' })).not.toBeInTheDocument();
    expectNoRawKeys();
  });

  it('shows the renewal date the authority suggests when it is earlier (ARI)', async () => {
    base({ items: [issued({ ari_window: { start: '2099-10-01T00:00:00Z', end: '2099-10-03T00:00:00Z' } })] });
    await renderRoute('/acme');
    expect(await screen.findByText('As suggested by the authority')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Get a certificate' })).toHaveLength(1);
  });

  it('filters by status and authority in the address, ignores an unknown status and clears the filters', async () => {
    const seen: string[] = [];
    base({ items: [issued()], providers: [acmeProviderFixture(), acmeProviderFixture({ id: '0192f000-0000-7000-8000-0000000000b1', name: 'Corp CA' })], onList: (u) => seen.push(u.search) });
    const { router } = await renderRoute('/acme?state=bogus');
    await screen.findByRole('table', { name: 'Issued certificates' });
    expect(seen.at(-1)).toBe('');
    expect(screen.getByLabelText('Status')).toHaveValue('');
    await userEvent.selectOptions(screen.getByLabelText('Status'), 'failing');
    await waitFor(() => expect(seen.at(-1)).toBe('?state=failing'));
    await screen.findByRole('option', { name: 'Corp CA' });
    await userEvent.selectOptions(screen.getByLabelText('Certificate authority'), ACME_PROVIDER_ID);
    await waitFor(() => expect(seen.at(-1)).toBe(`?state=failing&provider_id=${ACME_PROVIDER_ID}`));
    expect(router.state.location.search).toContain('state=failing');
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    await waitFor(() => expect(router.state.location.search).toBe(''));
  });

  it('says when no certificate matches the filters', async () => {
    base({ items: [] });
    await renderRoute('/acme?state=stopped');
    expect(await screen.findByText('No certificate matches these filters')).toBeInTheDocument();
    expect(screen.queryByText('No certificates from a certificate authority yet')).not.toBeInTheDocument();
  });

  it('loads more certificates with the cursor', async () => {
    const cursors: (string | null)[] = [];
    base({ items: [issued()], next: 'next-1', onList: (u) => cursors.push(u.searchParams.get('cursor')) });
    await renderRoute('/acme');
    await userEvent.click(await screen.findByRole('button', { name: 'Load more certificates' }));
    await waitFor(() => expect(cursors).toEqual([null, 'next-1']));
  });

  it('shows the loading state, then the error of a list that could not be read', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    base();
    server.use(
      http.get(CERTS, async () => {
        await gate;
        return errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected');
      }),
    );
    await renderRoute('/acme');
    expect(await screen.findByRole('status', { name: /Loading/i })).toBeInTheDocument();
    release();
    expect(await screen.findByRole('alert')).toBeInTheDocument();
  });

  it('disables Get a certificate with an explanation while the license refuses changes', async () => {
    base({ items: [issued()] });
    server.use(http.get('/api/v1/license/status', () => HttpResponse.json({ expired: true, phase: 'locked', banners: [] })));
    await renderRoute('/acme');
    expect(await screen.findByText('The license does not allow changes now')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Get a certificate' })).toBeDisabled());
  });

  it('renders in Turkish with the e-mail label', async () => {
    base({ session: sessionFor('admin', 'tr'), items: [issued()] });
    await renderRoute('/acme', { languages: ['tr'] });
    expect(await screen.findByRole('heading', { level: 1, name: 'Verilen sertifikalar' })).toBeInTheDocument();
    expect(await screen.findByText('Kendiliğinden yenilenir')).toBeInTheDocument();
    expectNoRawKeys();
  });
});
