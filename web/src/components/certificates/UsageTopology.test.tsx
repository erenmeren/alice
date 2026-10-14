import { screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import type { CertificateDetail } from '../../api/types';
import { certificateDetailFixture, locationFixture } from '../../test/fixtures';
import { renderApp } from '../../test/render';
import { UsageTopology, sourceIcon } from './UsageTopology';

const show = (certificate: CertificateDetail) =>
  renderApp(
    <MemoryRouter>
      <UsageTopology certificate={certificate} />
    </MemoryRouter>,
  );

const site = (name: string, port = 443) => ({ names: [name], listens: [{ addr: '*', port, default_server: false }], file: '/etc/nginx/conf.d/x.conf', line: 1 });

describe('UsageTopology', () => {
  it('groups the locations by server: one usage-node link per target with its site names', async () => {
    const cert = certificateDetailFixture({
      locations: [
        locationFixture({ id: 'l1', target_id: 't1', target_name: 'web-01', servers: [site('www.example.test')] }),
        locationFixture({ id: 'l2', target_id: 't1', target_name: 'web-01', servers: [site('shop.example.test', 8443)] }),
        locationFixture({ id: 'l3', target_id: 't2', target_name: 'web-02', servers: [site('www.example.test')] }),
      ],
    });
    await show(cert);
    expect(screen.getByRole('heading', { name: 'Where this certificate is used' })).toBeInTheDocument();
    expect(screen.getByText('Follow the source to the exact server and website.')).toBeInTheDocument();
    const list = screen.getByRole('list', { name: 'Deployed locations' });
    const links = within(list).getAllByRole('link');
    expect(links).toHaveLength(2);
    expect(links[0]).toHaveAttribute('href', '/servers/t1');
    expect(links[0]).toHaveTextContent('web-01');
    expect(links[0]).toHaveTextContent('www.example.test:443, shop.example.test:8443');
    expect(links[0]).toHaveAttribute('data-node', 'usage');
    expect(links[1]).toHaveAttribute('href', '/servers/t2');
    expect(screen.getByText('Connections are the locations Alice discovered or deployed to.')).toBeInTheDocument();
    expect(screen.queryByText('More locations exist than are shown here.')).not.toBeInTheDocument();
  });

  it('shows the port of the TLS listen (443) when the server block also listens on 80 first', async () => {
    const both = { names: ['www.example.test'], listens: [{ addr: '*', port: 80, default_server: false }, { addr: '*', port: 443, default_server: false }], file: '/etc/nginx/conf.d/x.conf', line: 1 };
    const other = { names: ['alt.example.test'], listens: [{ addr: '*', port: 80, default_server: false }, { addr: '*', port: 8443, default_server: false }], file: '/etc/nginx/conf.d/y.conf', line: 1 };
    await show(certificateDetailFixture({ locations: [locationFixture({ id: 'l1', target_id: 't1', target_name: 'web-01', servers: [both, other] })] }));
    const link = within(screen.getByRole('list', { name: 'Deployed locations' })).getByRole('link');
    expect(link).toHaveTextContent('www.example.test:443');
    expect(link).toHaveTextContent('alt.example.test:8443');
    expect(link).not.toHaveTextContent(':80');
  });

  it('links by target id, never by name: two servers with the same name stay two links', async () => {
    const cert = certificateDetailFixture({
      locations: [
        locationFixture({ id: 'l1', target_id: 'a1', target_name: 'same', servers: [] }),
        locationFixture({ id: 'l2', target_id: 'b2', target_name: 'same', servers: [], cert_path: '/srv/b.crt' }),
      ],
    });
    await show(cert);
    const links = within(screen.getByRole('list', { name: 'Deployed locations' })).getAllByRole('link');
    expect(links.map((l) => l.getAttribute('href'))).toEqual(['/servers/a1', '/servers/b2']);
    // A location without a site name shows its certificate file instead.
    expect(links[1]).toHaveTextContent('/srv/b.crt');
  });

  it.each([
    ['azure_kv', 'Azure Key Vault', 'Cloud'],
    ['discovered', 'Found on servers', 'Server'],
    ['uploaded', 'Uploaded', 'FileKey2'],
  ] as const)('names the source (%s) in the source node', async (source, label, icon) => {
    await show(certificateDetailFixture({ source, label: 'Shop' }));
    const node = screen.getByTestId('usage-source');
    expect(node).toHaveTextContent(label);
    expect(node).toHaveTextContent('Shop');
    expect(node.querySelector('[data-icon]')).toHaveAttribute('data-icon', icon);
  });

  it('says when no server uses the certificate and when the list was cut', async () => {
    await show(certificateDetailFixture({ locations: [], locations_truncated: true }));
    expect(screen.getByText('This certificate is not used on any server that Alice knows.')).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Deployed locations' })).not.toBeInTheDocument();
    expect(screen.getByText('More locations exist than are shown here.')).toBeInTheDocument();
  });

  it('draws the source tile of each certificate source with its own icon; one ordered from a CA is not a file', () => {
    expect(sourceIcon('azure_kv')).toBe('Cloud');
    expect(sourceIcon('discovered')).toBe('Server');
    expect(sourceIcon('acme')).toBe('ShieldCheck');
    expect(sourceIcon('uploaded')).toBe('FileKey2');
    expect(sourceIcon('csr')).toBe('FileKey2');
  });
});
