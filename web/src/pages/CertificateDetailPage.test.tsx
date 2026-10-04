import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import {
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
    const facts = screen.getByRole('list', { name: 'Certificate details' });
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

  it('says when the chain is incomplete or the certificate is self-signed', async () => {
    certServer(certificateDetailFixture({ id: ID, chain_complete: false, self_signed: true }));
    await renderRoute(`/certificates/${ID}`);
    expect(await screen.findByText('The certificate chain is incomplete: some browsers may not trust this certificate.')).toBeInTheDocument();
    expect(screen.getByText('Self-signed certificate')).toBeInTheDocument();
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

    it('draws the hint link black and underlined, readable on the blue tint (axe color-contrast)', async () => {
      certServer(certificateDetailFixture({ id: ID, locations: [] }));
      await renderRoute(`/certificates/${ID}`);
      const link = within(await screen.findByTestId('deploy-hint')).getByRole('link', { name: 'Open the servers' });
      expect(link).toHaveAttribute('data-underline', 'always');
      expect(link.style.getPropertyValue('color')).toBe('var(--mantine-color-black)');
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
