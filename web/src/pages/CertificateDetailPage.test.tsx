import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import {
  adminSession,
  auditorSession,
  certificateDetailFixture,
  deploymentFixture,
  errorResponse,
  locationFixture,
  operatorSession,
  sessionFor,
  sessionHandlers,
} from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const ID = '0192c000-0000-7000-8000-0000000000c1';

function certServer(detail = certificateDetailFixture({ id: ID }), deployments = [deploymentFixture()], role = operatorSession) {
  let deploymentQuery = '';
  server.use(
    ...sessionHandlers(role),
    // The import history asks which vaults exist.
    http.get('/api/v1/targets', () => HttpResponse.json({ items: [], next_cursor: null })),
    http.get(`/api/v1/certificates/${ID}`, () => HttpResponse.json(detail)),
    http.get('/api/v1/deployments', ({ request }) => {
      deploymentQuery = new URL(request.url).search;
      return HttpResponse.json({ items: deployments, next_cursor: null });
    }),
  );
  return () => deploymentQuery;
}

describe('CertificateDetailPage', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-03T12:00:00Z'));
  });
  afterEach(() => vi.useRealTimers());

  it('shows the certificate, its chain state and where it is used', async () => {
    const query = certServer();
    await renderRoute(`/certificates/${ID}`);
    expect(await screen.findByRole('heading', { name: 'www.example.test', level: 1 })).toBeInTheDocument();
    const facts = screen.getByLabelText('Certificate details');
    expect(within(facts).getByText('CN=www.example.test')).toBeInTheDocument();
    expect(within(facts).getByText('CN=Example Test CA')).toBeInTheDocument();
    expect(within(facts).getByText('0a1b2c')).toBeInTheDocument();
    expect(within(facts).getByText('ECDSA, 256 bit')).toBeInTheDocument();
    expect(within(facts).getByText('ab12'.repeat(16))).toBeInTheDocument();
    expect(within(facts).getByText('Uploaded')).toBeInTheDocument();
    expect(within(facts).getByText('In Alice')).toBeInTheDocument();
    expect(within(facts).getByText('example.test')).toBeInTheDocument();
    expect(screen.getByText('The certificate chain is complete.')).toBeInTheDocument();
    const table = screen.getByRole('table', { name: 'Where this certificate is used' });
    const row = within(table).getAllByRole('row')[1];
    expect(within(row).getByRole('link', { name: 'web-01' })).toHaveAttribute('href', '/servers/0192b000-0000-7000-8000-0000000000a1');
    expect(within(row).getByText('www.example.test')).toBeInTheDocument();
    expect(within(row).getByText('/etc/nginx/ssl/www.crt')).toBeInTheDocument();
    expect(query()).toBe(`?certificate_id=${ID}&limit=5`);
  });

  it('shows the design header: back link, resource tile, the label as the only h1 and the source line', async () => {
    certServer(certificateDetailFixture({ id: ID, label: 'Shop', self_signed: true }));
    await renderRoute(`/certificates/${ID}`);
    const h1 = await screen.findByRole('heading', { level: 1 });
    expect(h1).toHaveTextContent('Shop');
    expect(h1.querySelector('code')).toHaveTextContent('Shop');
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(h1).toHaveAttribute('data-detail');
    expect(screen.getByRole('link', { name: 'Back to certificates' })).toHaveAttribute('href', '/certificates');
    expect(screen.getByText('Uploaded · First seen Oct 1, 2026')).toBeInTheDocument();
    expect(screen.getByText('Self-signed certificate')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy fingerprint' })).toBeInTheDocument();
  });

  it('shows the validity panel: days left, a progress bar and the valid from/until dates', async () => {
    certServer();
    await renderRoute(`/certificates/${ID}`);
    const panel = (await screen.findByRole('heading', { name: 'Validity' })).closest('section') as HTMLElement;
    expect(within(panel).getByText('Time remaining')).toBeInTheDocument();
    expect(within(panel).getByText('332 days')).toHaveAttribute('data-tone', 'success');
    expect(within(panel).getByRole('progressbar', { name: 'Time remaining' })).toBeInTheDocument();
    expect(within(panel).getByText('Valid from')).toBeInTheDocument();
    expect(within(panel).getByText('Valid until')).toBeInTheDocument();
    // Far from expiry: the brand notice says what validity does not prove.
    expect(screen.getByText('Certificate is within its validity period')).toBeInTheDocument();
    expect(screen.getByText('Certificate validity alone does not verify the remote endpoint.')).toBeInTheDocument();
  });

  it('warns when the certificate expires within seven days', async () => {
    certServer(certificateDetailFixture({ id: ID, not_after: '2026-10-08T12:00:00Z' }));
    await renderRoute(`/certificates/${ID}`);
    expect(await screen.findByText('Renewal due in 5 days')).toBeInTheDocument();
    expect(screen.getByText('5 days', { selector: '[data-tone]' })).toHaveAttribute('data-tone', 'warning');
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeEnabled();
  });

  it('shows an expired certificate with a danger notice and no Deploy', async () => {
    certServer(certificateDetailFixture({ id: ID, not_after: '2026-09-01T00:00:00Z' }));
    await renderRoute(`/certificates/${ID}`);
    const notice = (await screen.findByText('This certificate has expired and cannot be deployed.')).closest('[role="note"]') as HTMLElement;
    expect(notice).not.toBeNull();
    expect(within(notice).getByText('Upload a valid replacement before deployment.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Deploy' })).not.toBeInTheDocument();
    const validity = screen.getByRole('heading', { name: 'Validity' }).closest('section') as HTMLElement;
    expect(within(validity).getByText('Expired')).toHaveAttribute('data-tone', 'danger');
  });

  it('shows where the certificate is used from its locations, and says when more exist', async () => {
    certServer(
      certificateDetailFixture({
        id: ID,
        locations_truncated: true,
        locations: [locationFixture({ id: 'l1', target_id: 't-9', target_name: 'edge-9' })],
      }),
    );
    await renderRoute(`/certificates/${ID}`);
    expect(await screen.findByRole('heading', { name: 'Where this certificate is used' })).toBeInTheDocument();
    const node = within(screen.getByRole('list', { name: 'Deployed locations' })).getByRole('link');
    expect(node).toHaveAttribute('href', '/servers/t-9');
    expect(node).toHaveTextContent('www.example.test:443');
    expect(screen.getByText('More locations exist than are shown here.')).toBeInTheDocument();
    expect(screen.getByText('Some websites are not shown.')).toBeInTheDocument();
    // The used-where table keeps its name and one row per website (plus the header row).
    expect(within(screen.getByRole('table', { name: 'Where this certificate is used' })).getAllByRole('row')).toHaveLength(2);
  });

  it('shows the chain as a status in the facts and keeps the private key out of the page', async () => {
    certServer(certificateDetailFixture({ id: ID, chain_complete: false }));
    await renderRoute(`/certificates/${ID}`);
    const facts = await screen.findByLabelText('Certificate details');
    expect(within(facts).getByText('Incomplete').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'warning');
    expect(within(facts).getByTestId('chain-hint')).toBeInTheDocument();
    expect(within(facts).getByText('In Alice').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'success');
    // "In Alice" appears once on the page (the e2e reads it by its exact text).
    expect(screen.getAllByText('In Alice')).toHaveLength(1);
    expect(screen.getByRole('heading', { name: 'Private keys stay private' })).toBeInTheDocument();
    expect(screen.getByText(/TLS private keys are never returned to the browser/)).toBeInTheDocument();
  });

  it('tells an Auditor the access is read-only in the next action panel', async () => {
    certServer(undefined, [], auditorSession);
    await renderRoute(`/certificates/${ID}`);
    const panel = (await screen.findByRole('heading', { name: 'Next action' })).closest('section') as HTMLElement;
    expect(within(panel).getByText('Read-only access')).toBeInTheDocument();
  });

  it('says when the chain is incomplete or the certificate is self-signed', async () => {
    certServer(certificateDetailFixture({ id: ID, chain_complete: false, self_signed: true }));
    await renderRoute(`/certificates/${ID}`);
    expect(await screen.findByText('The certificate chain is incomplete: some browsers may not trust this certificate.')).toBeInTheDocument();
    expect(screen.getByText('Self-signed certificate')).toBeInTheDocument();
    // An uploaded certificate is completed by uploading it again with its full chain.
    expect(screen.getByTestId('chain-hint')).toHaveTextContent('To complete the chain, upload this certificate again with its full chain and its private key.');
  });

  it('does not offer completing the chain by a new upload for a certificate from a signing request', async () => {
    certServer(certificateDetailFixture({ id: ID, chain_complete: false, source: 'csr' }));
    await renderRoute(`/certificates/${ID}`);
    expect(await screen.findByText('The certificate chain is incomplete: some browsers may not trust this certificate.')).toBeInTheDocument();
    expect(screen.queryByTestId('chain-hint')).not.toBeInTheDocument();
  });

  it('does not show the chain hint to an Auditor, who cannot upload', async () => {
    certServer(certificateDetailFixture({ id: ID, chain_complete: false }), undefined, auditorSession);
    await renderRoute(`/certificates/${ID}`);
    expect(await screen.findByText('The certificate chain is incomplete: some browsers may not trust this certificate.')).toBeInTheDocument();
    expect(screen.queryByTestId('chain-hint')).not.toBeInTheDocument();
  });

  it('calls a deployment an administrator cancelled Cancelled in the latest deployments', async () => {
    certServer(undefined, [deploymentFixture({ id: 'd1', status: 'failed', error: { code: 'ALC-DEP-0022', reason: 'deployment.cancelled' } })]);
    await renderRoute(`/certificates/${ID}`);
    const table = await screen.findByRole('table', { name: 'Deployments' });
    expect(within(table).getByRole('link', { name: 'Cancelled' })).toBeInTheDocument();
  });

  it('lists the latest deployments with their result', async () => {
    certServer(undefined, [deploymentFixture({ id: 'd1', status: 'rolled_back' }), deploymentFixture({ id: 'd2', status: 'succeeded' })]);
    await renderRoute(`/certificates/${ID}`);
    const table = await screen.findByRole('table', { name: 'Deployments' });
    expect(within(table).getByText('Failed, restored')).toBeInTheDocument();
    expect(within(table).getByText('Succeeded')).toBeInTheDocument();
    expect(within(table).getAllByText('web-01')).toHaveLength(2);
  });

  it('shows a neutral label for a deployment status the server did not recognise', async () => {
    certServer(undefined, [deploymentFixture({ id: 'd1', status: '' })]);
    await renderRoute(`/certificates/${ID}`);
    const table = await screen.findByRole('table', { name: 'Deployments' });
    expect(within(table).getByText('Unknown')).toBeInTheDocument();
  });

  it('says so when it was never deployed and when no server uses it', async () => {
    certServer(certificateDetailFixture({ id: ID, locations: [], location_count: 0 }), []);
    await renderRoute(`/certificates/${ID}`);
    expect(await screen.findByText('This certificate has not been deployed yet.')).toBeInTheDocument();
    expect(screen.getByText('This certificate is not used on any server that Alice knows.')).toBeInTheDocument();
    expect(screen.queryByRole('table', { name: 'Where this certificate is used' })).not.toBeInTheDocument();
  });

  it('says some websites are not shown when the list was cut', async () => {
    certServer(certificateDetailFixture({ id: ID, locations_truncated: true }));
    await renderRoute(`/certificates/${ID}`);
    expect(await screen.findByText('Some websites are not shown.')).toBeInTheDocument();
  });

  it('uses the first server name of a location, and a placeholder for one without a name', async () => {
    certServer(
      certificateDetailFixture({
        id: ID,
        locations: [locationFixture({ id: 'l1', servers: [] }), locationFixture({ id: 'l2', servers: [{ names: ['shop.example.test', 'x.example.test'], listens: [], file: 'f', line: 1 }] })],
      }),
    );
    await renderRoute(`/certificates/${ID}`);
    const table = await screen.findByRole('table', { name: 'Where this certificate is used' });
    const rows = within(table).getAllByRole('row');
    expect(within(rows[1]).getByText('(none)')).toBeInTheDocument();
    expect(within(rows[2]).getByText('shop.example.test')).toBeInTheDocument();
    expect(within(rows[2]).queryByText('x.example.test')).not.toBeInTheDocument();
  });

  describe('Deploy', () => {
    it.each(['operator', 'admin'] as const)('opens the deploy dialog for %s when the certificate can be deployed', async (role) => {
      certServer(undefined, [], sessionFor(role));
      await renderRoute(`/certificates/${ID}`);
      await userEvent.click(await screen.findByRole('button', { name: 'Deploy' }));
      const dialog = await screen.findByRole('dialog', { name: 'Deploy a certificate' });
      expect(await within(dialog).findByRole('checkbox', { name: /www\.example\.test/ })).toBeInTheDocument();
      expect(within(dialog).getByRole('button', { name: 'Deploy' })).toBeDisabled();
    });

    it('is not shown to Auditors', async () => {
      certServer(undefined, [], auditorSession);
      await renderRoute(`/certificates/${ID}`);
      await screen.findByRole('heading', { level: 1 });
      expect(screen.queryByRole('button', { name: 'Deploy' })).not.toBeInTheDocument();
    });

    it('is replaced by a notice when Alice has no private key', async () => {
      certServer(certificateDetailFixture({ id: ID, has_private_key: false, source: 'discovered' }));
      await renderRoute(`/certificates/${ID}`);
      expect(await screen.findByText('Alice does not have the private key of this certificate, so it cannot deploy it.')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Deploy' })).not.toBeInTheDocument();
      expect(screen.getByText('Not in Alice')).toBeInTheDocument();
    });

    it('is replaced by a notice when the certificate expired', async () => {
      certServer(certificateDetailFixture({ id: ID, not_after: '2026-09-01T00:00:00Z' }));
      await renderRoute(`/certificates/${ID}`);
      expect(await screen.findByText('This certificate has expired and cannot be deployed.')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Deploy' })).not.toBeInTheDocument();
    });

    it('is not shown when no server uses the certificate yet; a hint says how to deploy it instead', async () => {
      certServer(certificateDetailFixture({ id: ID, locations: [] }));
      await renderRoute(`/certificates/${ID}`);
      await screen.findByRole('heading', { level: 1 });
      expect(screen.queryByRole('button', { name: 'Deploy' })).not.toBeInTheDocument();
      const hint = screen.getByTestId('deploy-hint');
      expect(hint).toHaveTextContent('open the server of the website, choose Deploy certificate there and pick this certificate');
      expect(within(hint).getByRole('link', { name: 'Open the servers' })).toHaveAttribute('href', '/servers');
    });

    it('draws the hint link underlined in the notice color, readable on the tint in both schemes (axe color-contrast)', async () => {
      certServer(certificateDetailFixture({ id: ID, locations: [] }));
      await renderRoute(`/certificates/${ID}`);
      const link = within(await screen.findByTestId('deploy-hint')).getByRole('link', { name: 'Open the servers' });
      expect(link).toHaveAttribute('data-underline', 'always');
      expect(link.style.getPropertyValue('color')).toBe('inherit');
    });

    it('shows no hint to Auditors, for a certificate without a key or one that is already used', async () => {
      certServer(certificateDetailFixture({ id: ID, locations: [] }), [], auditorSession);
      const view = await renderRoute(`/certificates/${ID}`);
      await screen.findByRole('heading', { level: 1 });
      expect(screen.queryByTestId('deploy-hint')).not.toBeInTheDocument();
      view.unmount();
      certServer(certificateDetailFixture({ id: ID, locations: [], has_private_key: false }));
      const second = await renderRoute(`/certificates/${ID}`);
      await screen.findByRole('heading', { level: 1 });
      expect(screen.queryByTestId('deploy-hint')).not.toBeInTheDocument();
      second.unmount();
      certServer();
      await renderRoute(`/certificates/${ID}`);
      await screen.findByRole('heading', { level: 1 });
      expect(screen.queryByTestId('deploy-hint')).not.toBeInTheDocument();
    });

    it('says that Deploy sends this certificate to the websites listed', async () => {
      certServer();
      await renderRoute(`/certificates/${ID}`);
      expect(await screen.findByText('Deploy sends this certificate to the websites listed below.')).toBeInTheDocument();
    });
  });

  it('shows the server text and a way back when the certificate does not exist', async () => {
    server.use(...sessionHandlers(operatorSession), http.get(`/api/v1/certificates/${ID}`, () => errorResponse(404, 'ALC-SYS-0001', 'system.not_found')));
    await renderRoute(`/certificates/${ID}`);
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to certificates' })).toHaveAttribute('href', '/certificates');
  });

  it('never offers the private key', async () => {
    certServer();
    await renderRoute(`/certificates/${ID}`);
    await screen.findByRole('heading', { level: 1 });
    expect(screen.queryByRole('button', { name: /download|export/i })).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/PRIVATE KEY/);
  });
});

describe('CertificateDetailPage import into Key Vault', () => {
  it('offers Import into Key Vault to an Administrator for a certificate whose key Alice holds, and opens the dialog', async () => {
    certServer(certificateDetailFixture({ id: ID, has_private_key: true, not_after: '2030-01-01T00:00:00Z' }), [], adminSession);
    await renderRoute(`/certificates/${ID}`);
    const button = await screen.findByRole('button', { name: 'Import into Key Vault' });
    expect(button).toBeEnabled();
    await userEvent.click(button);
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
  });

  it('shows an Operator the action disabled with the reason, and nothing for a certificate without a key', async () => {
    certServer(certificateDetailFixture({ id: ID, has_private_key: true, not_after: '2030-01-01T00:00:00Z' }), [], operatorSession);
    const view = await renderRoute(`/certificates/${ID}`);
    expect(await screen.findByRole('button', { name: 'Import into Key Vault' })).toBeDisabled();
    expect(screen.getByText('Only an administrator can import a certificate into a Key Vault.')).toBeInTheDocument();
    view.unmount();
    certServer(certificateDetailFixture({ id: ID, has_private_key: false }), [], adminSession);
    await renderRoute(`/certificates/${ID}`);
    await screen.findByRole('heading', { level: 1 });
    expect(screen.queryByRole('button', { name: 'Import into Key Vault' })).not.toBeInTheDocument();
  });

  it('offers it to nobody who only reads', async () => {
    certServer(certificateDetailFixture({ id: ID, has_private_key: true, not_after: '2030-01-01T00:00:00Z' }), [], auditorSession);
    await renderRoute(`/certificates/${ID}`);
    await screen.findByRole('heading', { level: 1 });
    expect(screen.queryByRole('button', { name: 'Import into Key Vault' })).not.toBeInTheDocument();
  });
});

