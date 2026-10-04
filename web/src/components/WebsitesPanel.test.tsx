import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { CertificateLocation, Target } from '../api/types';
import {
  certificateFixture,
  errorResponse,
  jobFixture,
  keyLocationFixture,
  locationFixture,
  nginxFacts,
  nginxTargetFixture,
  nginxTargetWith,
  sessionFor,
  sessionHandlers,
} from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const T = nginxTargetFixture.id;
const path = `/servers/${T}`;
const CERT = { id: '0192c000-0000-7000-8000-0000000000c1', subject_cn: 'www.example.test', label: '', fingerprint: 'ab12'.repeat(16), not_after: '2027-09-01T00:00:00Z' };

function onNginx(role: 'admin' | 'operator' | 'auditor', locations: CertificateLocation[], target: Target = nginxTargetFixture, truncated = false, lang = 'en') {
  const queries: string[] = [];
  server.use(
    ...sessionHandlers(sessionFor(role, lang)),
    http.get('/api/v1/targets/:id', () => HttpResponse.json(target)),
    http.get('/api/v1/targets/:id/host-keys', () => HttpResponse.json({ items: [] })),
    http.get('/api/v1/targets/:id/ssh-keys', () => HttpResponse.json({ items: [keyLocationFixture()] })),
    http.get('/api/v1/targets/:id/certificate-locations', ({ request }) => {
      queries.push(new URL(request.url).search);
      return HttpResponse.json({ items: locations, truncated });
    }),
  );
  return queries;
}

describe('WebsitesPanel on an Nginx server', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-04T12:00:00Z'));
  });
  afterEach(() => vi.useRealTimers());

  it('lists each website with its names, ports, file, certificate, expiry and state', async () => {
    onNginx('operator', [
      locationFixture({
        certificate: CERT,
        servers: [
          { names: ['www.example.test', 'example.test'], listens: [{ addr: '*', port: 443, default_server: false }, { addr: '[::]', port: 443, default_server: false }], file: '/etc/nginx/conf.d/www.conf', line: 4 },
        ],
      }),
      locationFixture({ id: 'l2', cert_path: '/etc/nginx/ssl/default.crt', servers: [{ names: ['_'], listens: [{ addr: '*', port: 8443, default_server: true }], file: '/etc/nginx/conf.d/default.conf', line: 1 }] }),
    ]);
    await renderRoute(path);
    expect(await screen.findByRole('heading', { name: 'Websites on this server', level: 2 })).toBeInTheDocument();
    const table = await screen.findByRole('table', { name: 'Websites on this server' });
    const rows = within(table).getAllByTestId('location-row');
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getAllByText('www.example.test')).toHaveLength(2); // the name and the certificate link
    expect(within(rows[0]).getByText('example.test')).toBeInTheDocument();
    expect(within(rows[0]).getByText('*:443')).toBeInTheDocument();
    expect(within(rows[0]).getByText('[::]:443')).toBeInTheDocument();
    expect(within(rows[0]).getByText('/etc/nginx/ssl/www.crt')).toBeInTheDocument();
    expect(rows[0]).toHaveTextContent('Defined in: /etc/nginx/conf.d/www.conf');
    expect(within(rows[0]).getByText('/etc/nginx/conf.d/www.conf').closest('code')).toHaveAttribute('translate', 'no');
    expect(within(rows[0]).getByText('Line: 4')).toBeInTheDocument();
    expect(within(rows[0]).getByRole('link', { name: 'www.example.test' })).toHaveAttribute('href', `/certificates/${CERT.id}`);
    expect(within(rows[0]).getByText('Ready')).toBeInTheDocument();
    expect(within(rows[0]).getByText(/Sep 1, 2027/)).toBeInTheDocument();
    expect(within(rows[0]).getByText('331 days')).toBeInTheDocument();
    expect(within(rows[1]).getByText('(default server)')).toBeInTheDocument();
    expect(within(rows[1]).getByText('No readable certificate')).toBeInTheDocument();
    // The table scrolls inside its own container (D36).
    expect(table.closest('.mantine-ScrollArea-root, [class*="ScrollArea"], [class*="scrollContainer"], [class*="ScrollContainer"]')).not.toBeNull();
    expectNoRawKeys();
  });

  it('says why a place is not supported, including the file problem, and offers no Deploy there', async () => {
    onNginx('admin', [
      locationFixture({ id: 'a', supported: false, unsupported_reason: 'variable' }),
      locationFixture({ id: 'b', supported: false, unsupported_reason: 'file_problem', problem: 'not_root_controlled', key_problem: 'hard_linked' }),
      locationFixture({ id: 'c', supported: false, unsupported_reason: 'a_newer_reason' }),
    ]);
    await renderRoute(path);
    const rows = await screen.findAllByTestId('location-row');
    expect(within(rows[0]).getByText('Not supported')).toBeInTheDocument();
    expect(within(rows[0]).getByText('The path uses a variable, so Alice cannot know which file is used.')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Alice cannot use the files at this place.')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Certificate file: A folder or link on the path can be changed by users other than root.')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Key file: The file has more than one name (hard link).')).toBeInTheDocument();
    expect(within(rows[2]).getByText('Alice cannot use this place for a reason this version does not know.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Deploy certificate/ })).not.toBeInTheDocument();
  });

  it('shows location warnings in words with their parameters', async () => {
    onNginx('operator', [
      locationFixture({ warnings: ['symlinked', 'custom_location', 'key_mode_open', 'key_group_open', 'certificate_block_dropped', 'certificate_expired', 'san_mismatch', 'list_truncated', 'made_up'], key_mode: '0644' }),
    ]);
    await renderRoute(path);
    const row = (await screen.findAllByTestId('location-row'))[0];
    expect(within(row).getByText('This file is a link. Another tool (for example certbot) may replace it.')).toBeInTheDocument();
    expect(within(row).getByText('Custom location: outside the usual certificate folders.')).toBeInTheDocument();
    expect(within(row).getByText('The private key file can be read by more users than needed: 0644')).toBeInTheDocument();
    expect(within(row).getByText(/belongs to a user other than root/)).toBeInTheDocument();
    expect(within(row).getByText(/contains a block that is not a certificate/)).toBeInTheDocument();
    expect(within(row).getByText('The certificate has expired.')).toBeInTheDocument();
    expect(row).toHaveTextContent('The certificate does not name this website: www.example.test');
    expect(within(row).getByText(/Some long lists of this website were cut/)).toBeInTheDocument();
    expect(within(row).getByText('Alice reported a note about this website that this version cannot describe.')).toBeInTheDocument();
    expect(screen.queryByText(/\{\{/)).not.toBeInTheDocument();
  });

  it('shows when a website is no longer found and when its certificate changed outside Alice', async () => {
    onNginx('operator', [
      locationFixture({ id: 'gone', missing_since: '2026-10-01T08:00:00Z' }),
      locationFixture({ id: 'moved', changed_outside_at: '2026-10-02T09:30:00Z' }),
    ]);
    await renderRoute(path);
    const rows = await screen.findAllByTestId('location-row');
    expect(within(rows[0]).getByText('No longer found')).toBeInTheDocument();
    expect(within(rows[0]).getByText(/No longer found since .*2026/)).toBeInTheDocument();
    expect(within(rows[1]).getByText('The certificate changed outside Alice.')).toBeInTheDocument();
    expect(within(rows[1]).getByText(/Changed outside Alice: .*2026/)).toBeInTheDocument();
    // Nothing to deploy to a website that is not there.
    expect(within(rows[0]).queryByRole('button', { name: /Deploy certificate/ })).not.toBeInTheDocument();
  });

  it('marks a website with a deployment in progress and offers no Deploy for it', async () => {
    onNginx('operator', [locationFixture({ active_deployment_id: '0192c000-0000-7000-8000-0000000000d1' })]);
    await renderRoute(path);
    const row = (await screen.findAllByTestId('location-row'))[0];
    expect(within(row).getByText('Deployment in progress')).toBeInTheDocument();
    expect(within(row).queryByRole('button', { name: /Deploy certificate/ })).not.toBeInTheDocument();
  });

  it('adds ?missing=true when asked to show websites that are no longer found', async () => {
    const queries = onNginx('operator', [locationFixture()]);
    await renderRoute(path);
    await screen.findAllByTestId('location-row');
    expect(queries[0]).toBe('');
    await userEvent.click(screen.getByRole('switch', { name: 'Show websites that are no longer found' }));
    await waitFor(() => expect(queries).toContain('?missing=true'));
  });

  it('says when the list is incomplete', async () => {
    onNginx('operator', [locationFixture({ missing_since: '2026-10-01T08:00:00Z' })], nginxTargetFixture, true);
    await renderRoute(path);
    expect(await screen.findByText('This list is incomplete: only the first 1000 websites that are no longer found are shown.')).toBeInTheDocument();
  });

  it('says when Alice has found nothing yet and points at Discover', async () => {
    onNginx('operator', []);
    await renderRoute(path);
    expect(await screen.findByText('Alice has not found any certificates on this server yet. Choose Discover.')).toBeInTheDocument();
  });

  describe('permissions', () => {
    it.each(['admin', 'operator'] as const)('%s deploys on supported rows only, with the website in the button name', async (role) => {
      onNginx(role, [locationFixture(), locationFixture({ id: 'x', supported: false, unsupported_reason: 'stream' })]);
      await renderRoute(path);
      expect(await screen.findAllByRole('button', { name: 'Deploy certificate: www.example.test' })).toHaveLength(1);
      expect(screen.getAllByRole('button', { name: /^Deploy certificate/ })).toHaveLength(1);
    });

    it('lets an auditor read but not deploy', async () => {
      onNginx('auditor', [locationFixture()]);
      await renderRoute(path);
      await screen.findAllByTestId('location-row');
      expect(screen.queryByRole('button', { name: /Deploy certificate/ })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Discover' })).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Verification settings: www.example.test' })).toBeInTheDocument();
    });

    it('lets only an administrator change verification settings; others see them read-only', async () => {
      onNginx('operator', [locationFixture({ verify_port: 8443 })]);
      const op = await renderRoute(path);
      await userEvent.click(await screen.findByRole('button', { name: 'Verification settings: www.example.test' }));
      const dialog = await screen.findByRole('dialog', { name: 'Verification settings' });
      expect(within(dialog).getByText('Only an administrator can change these settings.')).toBeInTheDocument();
      expect(within(dialog).queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
      op.unmount();

      onNginx('admin', [locationFixture({ verify_port: 8443 })]);
      await renderRoute(path);
      await userEvent.click(await screen.findByRole('button', { name: 'Verification settings: www.example.test' }));
      const adminDialog = await screen.findByRole('dialog', { name: 'Verification settings' });
      expect(within(adminDialog).getByRole('button', { name: 'Save' })).toBeInTheDocument();
    });

    it('handles a 403 of the server for the list', async () => {
      onNginx('operator', []);
      server.use(http.get('/api/v1/targets/:id/certificate-locations', () => errorResponse(403, 'ALC-AUTH-0002', 'auth.forbidden')));
      await renderRoute(path);
      expect(await screen.findByRole('alert')).toHaveTextContent('You do not have permission to do this.');
    });
  });

  describe('stale facts and a server that cannot be deployed to', () => {
    it('marks the websites stale with the time Alice last read them when the Nginx permissions are missing', async () => {
      // last_discovery_at moves when only the SSH keys were scanned, so it must not be shown.
      const target = nginxTargetWith({ last_discovery_at: '2026-09-30T08:00:00Z' }, { warnings: [{ code: 'nginx_profile_missing', params: {} }] });
      onNginx('admin', [locationFixture({ last_seen_at: '2026-09-20T10:00:00Z' }), locationFixture({ id: 'older', last_seen_at: '2026-09-10T10:00:00Z' })], target);
      await renderRoute(path);
      const stale = await screen.findByTestId('stale-websites');
      expect(stale).toHaveTextContent('These websites may be out of date');
      expect(stale).toHaveTextContent(/as it last read them, on .*Sep 20, 2026/);
      expect(stale).not.toHaveTextContent('Sep 30, 2026');
      expect(stale).toHaveTextContent('Deploying is unavailable for now.');
      expect(stale).toHaveTextContent('The Nginx permissions are not installed on this server.');
      const buttons = screen.getAllByRole('button', { name: 'Deploy certificate: www.example.test' });
      for (const b of buttons) expect(b).toBeDisabled();
      expect(screen.getByText(/Alice last read websites from this server on .*Sep 20, 2026/)).toBeInTheDocument();
    });

    it('uses the same time for an invalid configuration', async () => {
      const target = nginxTargetWith({ last_discovery_at: '2026-09-30T08:00:00Z' }, { nginx: nginxFacts({ config_valid: false, config_error: 'syntax' }) });
      onNginx('operator', [locationFixture({ last_seen_at: '2026-09-22T10:00:00Z' })], target);
      await renderRoute(path);
      expect(await screen.findByTestId('stale-websites')).toHaveTextContent(/as it last read them, on .*Sep 22, 2026/);
    });

    it('gives no time when Alice has not read any website from the server yet', async () => {
      const target = nginxTargetWith({ last_discovery_at: '2026-09-30T08:00:00Z' }, { warnings: [{ code: 'nginx_profile_missing', params: {} }] });
      onNginx('operator', [], target);
      await renderRoute(path);
      const stale = await screen.findByTestId('stale-websites');
      expect(stale).toHaveTextContent('Alice has not read any website from this server yet.');
      expect(stale).not.toHaveTextContent('2026');
      expect(screen.queryByText(/Alice last read websites from this server/)).not.toBeInTheDocument();
    });

    it('shows the invalid configuration with its class, reason and file, and disables Deploy', async () => {
      const target = nginxTargetWith({}, { nginx: nginxFacts({ config_valid: false, config_error: 'untrusted', config_error_reason: 'not_root_controlled', config_error_file: '/etc/nginx/conf.d/x.conf' }) });
      onNginx('operator', [locationFixture()], target);
      await renderRoute(path);
      const alert = await screen.findByTestId('config-invalid');
      expect(alert).toHaveTextContent("Nginx's configuration on this server has an error. Alice will not deploy until it is fixed.");
      expect(alert).toHaveTextContent("Alice cannot trust Nginx's output for this configuration.");
      expect(alert).toHaveTextContent('A file or folder of the configuration can be changed by users other than root.');
      expect(within(alert).getByText('/etc/nginx/conf.d/x.conf')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Deploy certificate: www.example.test' })).toBeDisabled();
      expect(screen.getByTestId('stale-websites')).toHaveTextContent("Nginx's configuration has an error.");
    });

    it('says that Nginx was not found without calling the configuration invalid', async () => {
      const target = nginxTargetWith({}, { nginx: nginxFacts({ version: '', found: false, config_valid: false }), warnings: [{ code: 'nginx_not_found', params: {} }] });
      onNginx('operator', [locationFixture()], target);
      await renderRoute(path);
      expect(await screen.findByTestId('stale-websites')).toHaveTextContent('Nginx was not found on this server.');
      expect(screen.queryByTestId('config-invalid')).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Deploy certificate: www.example.test' })).toBeDisabled();
    });

    it('disables Deploy when the server cannot be reached', async () => {
      const target = nginxTargetWith({ status: 'unreachable', last_error: { code: 'ALC-SSH-0001', reason: 'ssh.unreachable' } });
      onNginx('operator', [locationFixture()], target);
      await renderRoute(path);
      expect(await screen.findByTestId('stale-websites')).toHaveTextContent('The server is not connected right now');
      expect(screen.getByRole('button', { name: 'Deploy certificate: www.example.test' })).toBeDisabled();
    });

    it('shows no stale notice for a healthy server', async () => {
      onNginx('operator', [locationFixture()]);
      await renderRoute(path);
      await screen.findAllByTestId('location-row');
      expect(screen.queryByTestId('stale-websites')).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Deploy certificate: www.example.test' })).toBeEnabled();
    });
  });

  it('opens the deploy dialog for a website and offers the certificates that fit it', async () => {
    onNginx('operator', [locationFixture({ key_type: 'ecdsa' })]);
    server.use(http.get('/api/v1/certificates', () => HttpResponse.json({ items: [certificateFixture({ id: 'c9', subject_cn: 'fit.example.test' })], next_cursor: null })));
    await renderRoute(path);
    await userEvent.click(await screen.findByRole('button', { name: 'Deploy certificate: www.example.test' }));
    const dialog = await screen.findByRole('dialog', { name: 'Deploy a certificate' });
    expect(await within(dialog).findByLabelText('Certificate')).toBeInTheDocument();
  });

  it('is shown in Turkish', async () => {
    onNginx('admin', [locationFixture({ supported: false, unsupported_reason: 'variable' })], nginxTargetFixture, false, 'tr');
    await renderRoute(path, { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'Bu sunucudaki web siteleri' })).toBeInTheDocument();
    expect(screen.getByText('Desteklenmiyor')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Keşfet' })).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('runs Discover from the server page and waits for the scan', async () => {
    onNginx('operator', [locationFixture()]);
    let posted = 0;
    server.use(
      http.post('/api/v1/targets/:id/actions/discover', () => ((posted += 1), HttpResponse.json({ job_id: 'job-d', status_url: '/api/v1/jobs/job-d' }, { status: 202 }))),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-d' }))),
    );
    await renderRoute(path);
    await userEvent.click(await screen.findByRole('button', { name: 'Discover' }));
    expect(await screen.findByText('Finished.')).toBeInTheDocument();
    expect(posted).toBe(1);
  });
});
