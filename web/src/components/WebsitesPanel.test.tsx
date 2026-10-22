import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { CertificateLocation, Target } from '../api/types';
import {
  certificateFixture,
  driftedObservationFixture,
  errorResponse,
  jobFixture,
  keyLocationFixture,
  locationFixture,
  webServerFacts,
  apacheTargetFixture,
  nginxTargetFixture,
  nginxTargetWith,
  sessionFor,
  sessionHandlers,
  windowsBindingFixture,
  windowsTargetFixture,
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

  // A key-only problem (no certificate problem) on a Linux web server is still worded as a key file (W1 review).
  it('words a key-only file problem as the key file', async () => {
    onNginx('admin', [locationFixture({ id: 'k', supported: false, unsupported_reason: 'file_problem', problem: '', key_problem: 'hard_linked' })]);
    await renderRoute(path);
    const row = (await screen.findAllByTestId('location-row'))[0];
    expect(within(row).getByText('Alice cannot use the files at this place.')).toBeInTheDocument();
    expect(within(row).getByText('Key file: The file has more than one name (hard link).')).toBeInTheDocument();
    expect(within(row).queryByText(/^Certificate file:/)).not.toBeInTheDocument();
    expect(within(row).queryByText(/^Private key:/)).not.toBeInTheDocument();
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

  it('shows Deploy and Settings disabled with the note when the server cannot deploy', async () => {
    const target = nginxTargetWith({ capabilities: ['test_connection', 'discover_ssh_keys', 'authorized_keys', 'discover_certificates', 'key_login'] });
    onNginx('operator', [locationFixture({ certificate: CERT })], target);
    const { router } = await renderRoute(path);
    const row = (await screen.findAllByTestId('location-row'))[0];
    const note = 'Not available for Nginx servers yet';
    const deploy = within(row).getByRole('button', { name: 'Deploy certificate: www.example.test' });
    const settings = within(row).getByRole('button', { name: 'Verification settings: www.example.test' });
    expect(deploy).toHaveAttribute('aria-disabled', 'true');
    expect(deploy).toHaveAccessibleDescription(note);
    expect(settings).toHaveAttribute('aria-disabled', 'true');
    expect(settings).toHaveAccessibleDescription(note);
    await userEvent.click(within(row).getByRole('link', { name: 'www.example.test' }));
    await waitFor(() => expect(router.state.location.pathname).toBe(`/certificates/${CERT.id}`));
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
      const target = nginxTargetWith({ last_discovery_at: '2026-09-30T08:00:00Z' }, { warnings: [{ code: 'web_server_profile_missing', params: {} }] });
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
      const target = nginxTargetWith({ last_discovery_at: '2026-09-30T08:00:00Z' }, { web_server: webServerFacts({ config_valid: false, config_error: 'syntax' }) });
      onNginx('operator', [locationFixture({ last_seen_at: '2026-09-22T10:00:00Z' })], target);
      await renderRoute(path);
      expect(await screen.findByTestId('stale-websites')).toHaveTextContent(/as it last read them, on .*Sep 22, 2026/);
    });

    it('gives no time when Alice has not read any website from the server yet', async () => {
      const target = nginxTargetWith({ last_discovery_at: '2026-09-30T08:00:00Z' }, { warnings: [{ code: 'web_server_profile_missing', params: {} }] });
      onNginx('operator', [], target);
      await renderRoute(path);
      const stale = await screen.findByTestId('stale-websites');
      expect(stale).toHaveTextContent('Alice has not read any website from this server yet.');
      expect(stale).not.toHaveTextContent('2026');
      expect(screen.queryByText(/Alice last read websites from this server/)).not.toBeInTheDocument();
    });

    it('shows the invalid configuration with its class, reason and file, and disables Deploy', async () => {
      const target = nginxTargetWith({}, { web_server: webServerFacts({ config_valid: false, config_error: 'untrusted', config_error_reason: 'not_root_controlled', config_error_file: '/etc/nginx/conf.d/x.conf' }) });
      onNginx('operator', [locationFixture()], target);
      await renderRoute(path);
      const alert = await screen.findByTestId('config-invalid');
      expect(alert).toHaveTextContent("Nginx's configuration on this server has an error. Alice will not deploy until it is fixed.");
      expect(alert).toHaveTextContent('Alice cannot trust what the web server reported for this configuration.');
      expect(alert).toHaveTextContent('A file or folder of the configuration can be changed by users other than root.');
      expect(within(alert).getByText('/etc/nginx/conf.d/x.conf')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Deploy certificate: www.example.test' })).toBeDisabled();
      expect(screen.getByTestId('stale-websites')).toHaveTextContent("Nginx's configuration has an error.");
    });

    it('says that Nginx was not found without calling the configuration invalid', async () => {
      const target = nginxTargetWith({}, { web_server: webServerFacts({ version: '', found: false, config_valid: false }), warnings: [{ code: 'web_server_not_found', params: {} }] });
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

describe('WebsitesPanel in the design', () => {
  it('is a named panel region with the design subtitle and status badges with tone and text', async () => {
    onNginx('operator', [locationFixture({ certificate: CERT }), locationFixture({ id: 'l2', active_deployment_id: '0192c000-0000-7000-8000-0000000000d1' })]);
    await renderRoute(path);
    const region = await screen.findByRole('region', { name: 'Websites on this server' });
    expect(region.tagName).toBe('SECTION');
    expect(within(region).getByText(/Alice never changes the Nginx configuration/)).toBeInTheDocument();
    const rows = await within(region).findAllByTestId('location-row');
    expect(within(rows[0]).getByText('Ready').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'success');
    expect(within(rows[1]).getByText('Deployment in progress').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'info');
  });
});

describe('WebsitesPanel on an Apache server (discovery only)', () => {
  const untrusted = (reason: string): Target => ({
    ...apacheTargetFixture,
    facts: { ...apacheTargetFixture.facts, web_server: webServerFacts({ software: 'apache', config_valid: false, config_error: 'untrusted', config_error_reason: reason }) },
  });
  const rows = [
    locationFixture({ certificate: CERT, inherited: true, target_type: 'apache', deployable: false }),
    locationFixture({ id: 'k', cert_path: '/etc/apache2/ssl/dsa.crt', supported: false, unsupported_reason: 'unsupported_key', target_type: 'apache', deployable: false, warnings: ['key_group_open'] }),
  ];

  it.each(['no_conf_path', 'unexpected_text'])('names Apache, never Nginx or its http block, for an untrusted configuration (%s) and an inherited pair', async (reason) => {
    onNginx('operator', rows, untrusted(reason));
    await renderRoute(`/servers/${apacheTargetFixture.id}`);
    const alert = await screen.findByTestId('config-invalid');
    expect(alert).toHaveTextContent('Alice cannot trust what the web server reported for this configuration.');
    expect(alert).toHaveTextContent(reason === 'no_conf_path' ? 'Apache did not report where its configuration is.' : 'A file of the configuration, or what Apache reported about it, contains unexpected text.');
    await screen.findAllByTestId('location-row');
    expect(screen.getByText(/^Inherited: the certificate is set once/)).toBeInTheDocument();
    const page = document.body.textContent ?? '';
    expect(page).not.toMatch(/Nginx/);
    expect(page).not.toMatch(/http block/);
  });

  it('calls a supported place Found, not Ready, and says the key type without claiming support', async () => {
    onNginx('operator', rows, apacheTargetFixture);
    await renderRoute(`/servers/${apacheTargetFixture.id}`);
    const [first, second] = await screen.findAllByTestId('location-row');
    expect(within(first).getByText('Found')).toBeInTheDocument();
    expect(within(first).queryByText('Ready')).not.toBeInTheDocument();
    expect(within(second).getByText("The certificate's key is neither RSA nor ECDSA.")).toBeInTheDocument();
    expect(within(second).queryByText('Alice supports RSA and ECDSA certificates only.')).not.toBeInTheDocument();
    expect(within(second).getByText('The private key file belongs to a user other than root or can be read by a group or by others.')).toBeInTheDocument();
    expect(document.body.textContent ?? '').not.toMatch(/deployment keeps/i);
  });

  it('keeps the same texts read-only in Turkish', async () => {
    onNginx('operator', rows, untrusted('no_conf_path'), false, 'tr');
    await renderRoute(`/servers/${apacheTargetFixture.id}`, { languages: ['tr-TR'] });
    const alert = await screen.findByTestId('config-invalid');
    expect(alert).toHaveTextContent('Apache yapılandırmasının nerede olduğunu bildirmedi.');
    const [first, second] = await screen.findAllByTestId('location-row');
    expect(within(first).getByText('Bulundu')).toBeInTheDocument();
    expect(within(second).getByText('Sertifikanın anahtarı RSA veya ECDSA değil.')).toBeInTheDocument();
    expect(document.body.textContent ?? '').not.toMatch(/Nginx|http blo/);
    expectNoRawKeys();
  });
});

describe('WebsitesPanel observations of bound files (R52)', () => {
  it('shows what a bound file should have and what is observed today, the summary and the repair; nothing for an unbound one', async () => {
    let repaired = 0;
    onNginx('operator', [
      locationFixture({ certificate: CERT, observation: driftedObservationFixture() }),
      locationFixture({ id: 'l2', cert_path: '/etc/nginx/ssl/other.crt' }),
    ]);
    server.use(http.post(`/api/v1/locations/${locationFixture().id}/actions/repair`, () => (repaired++, HttpResponse.json({ deployments: [] }, { status: 202 }))));
    await renderRoute(path);
    const [bound, unbound] = await screen.findAllByTestId('location-row');
    expect(within(bound).getByText('Changed outside Alice')).toBeInTheDocument();
    expect(within(bound).getByTestId('fact-tls')).toHaveTextContent('checked from the server itself');
    expect(within(unbound).queryByTestId('location-observation')).not.toBeInTheDocument();
    expect(await screen.findByText(/^Live and verified on 0 of 1 place; 1 serves another certificate/)).toBeInTheDocument();
    await userEvent.click(within(bound).getByRole('button', { name: /^Repair / }));
    await waitFor(() => expect(repaired).toBe(1));
    expectNoRawKeys();
  });
});

describe('WebsitesPanel texts on an Nginx server that deploys', () => {
  it('keeps Ready and the support wording', async () => {
    onNginx('operator', [locationFixture({ certificate: CERT }), locationFixture({ id: 'k', cert_path: '/etc/nginx/ssl/dsa.crt', supported: false, unsupported_reason: 'unsupported_key', warnings: ['key_group_open'] })]);
    await renderRoute(path);
    const [first, second] = await screen.findAllByTestId('location-row');
    expect(within(first).getByText('Ready')).toBeInTheDocument();
    expect(within(second).getByText('Alice supports RSA and ECDSA certificates only.')).toBeInTheDocument();
    expect(within(second).getByText(/A deployment keeps these permissions\./)).toBeInTheDocument();
  });
});

// R61, design §15 Q5 (W2 Ruling 21): a Windows server's bindings are grouped by the certificate they serve.
describe('WebsitesPanel on a Windows server', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-04T12:00:00Z'));
  });
  afterEach(() => vi.useRealTimers());

  const winPath = `/servers/${windowsTargetFixture.id}`;
  const OTHER = { id: '0192c000-0000-7000-8000-0000000000c2', subject_cn: 'api.example.test', label: '', fingerprint: 'ef56'.repeat(16), not_after: '2027-01-15T00:00:00Z' };
  const host = (h: string, port = 443) => [{ names: [h], section: 'Default Web Site', listens: [{ addr: h, port, default_server: false }], file: '', line: 0 }];
  const bindings = [
    windowsBindingFixture({ id: 'w-ip', cert_path: 'http.sys/ipport/0.0.0.0:8443', certificate: CERT, servers: host('www.example.test', 8443) }),
    windowsBindingFixture({ id: 'w-none', cert_path: 'http.sys/hostnameport/old.example.test:443', certificate: null, servers: host('old.example.test') }),
    windowsBindingFixture({ id: 'w-host', cert_path: 'http.sys/hostnameport/www.example.test:443', certificate: CERT, servers: host('www.example.test') }),
    windowsBindingFixture({ id: 'w-api', cert_path: 'http.sys/hostnameport/api.example.test:443', certificate: OTHER, servers: host('api.example.test') }),
  ];

  it('groups the bindings by the certificate they serve, a last group without one, each binding with an enabled deploy control', async () => {
    onNginx('operator', bindings, windowsTargetFixture);
    await renderRoute(winPath);
    const groups = await screen.findAllByTestId('certificate-group');
    expect(groups).toHaveLength(3);
    const head = (g: HTMLElement) => within(g).getByTestId('certificate-group-row');
    expect(head(groups[0])).toHaveTextContent('api.example.test');
    expect(head(groups[0])).toHaveTextContent('1 binding');
    expect(head(groups[1])).toHaveTextContent('www.example.test');
    expect(head(groups[1])).toHaveTextContent('2 bindings');
    expect(within(head(groups[1])).getByText(/Sep 1, 2027/)).toBeInTheDocument();
    expect(head(groups[2])).toHaveTextContent('No certificate');
    expect(head(groups[2])).toHaveTextContent('1 binding');
    // A group row is a heading, not a row to point at: no hover highlight.
    for (const g of groups) expect(head(g).style.getPropertyValue('--tr-hover-bg')).toBe('transparent');
    // The bindings of a group are sorted by their canonical text.
    const texts = (g: HTMLElement) => within(g).getAllByTestId('location-row').map((r) => r.getAttribute('data-location'));
    expect(texts(groups[0])).toEqual(['w-api']);
    expect(texts(groups[1])).toEqual(['w-host', 'w-ip']);
    expect(texts(groups[2])).toEqual(['w-none']);
    for (const b of screen.getAllByRole('button', { name: /^Deploy certificate:/ })) {
      expect(b).toBeEnabled();
      expect(b).not.toHaveAttribute('aria-disabled');
    }
    expect(screen.getAllByRole('button', { name: /^Deploy certificate:/ })).toHaveLength(4);
    expect(screen.queryByText('Not available for IIS servers yet')).not.toBeInTheDocument();
    // The page's prose names http.sys (a product name, not a key): the table is checked.
    expectNoRawKeys(screen.getAllByTestId('certificate-group')[0].closest('table')!);
  });

  it('opens the deploy dialog with the bindings of the server grouped by certificate', async () => {
    onNginx('operator', bindings, windowsTargetFixture);
    server.use(http.get('/api/v1/certificates', () => HttpResponse.json({ items: [certificateFixture({ id: 'c9', subject_cn: 'fit.example.test' })], next_cursor: null })));
    await renderRoute(winPath);
    const row = (await screen.findAllByTestId('location-row')).find((r) => r.getAttribute('data-location') === 'w-ip')!;
    await userEvent.click(within(row).getByRole('button', { name: /^Deploy certificate:/ }));
    const dialog = await screen.findByRole('dialog', { name: 'Deploy a certificate' });
    expect(within(dialog).getByRole('checkbox', { name: /http\.sys\/ipport\/0\.0\.0\.0:8443/ })).toBeChecked();
    expect(within(dialog).getByRole('checkbox', { name: /http\.sys\/hostnameport\/www\.example\.test:443/ })).not.toBeChecked();
    expect(within(dialog).getByRole('button', { name: 'Select all bindings of this certificate: www.example.test' })).toBeInTheDocument();
  });

  it('keeps Nginx rows ungrouped', async () => {
    onNginx('operator', [locationFixture({ certificate: CERT }), locationFixture({ id: 'l2', cert_path: '/etc/nginx/ssl/b.crt' })]);
    await renderRoute(path);
    expect(await screen.findAllByTestId('location-row')).toHaveLength(2);
    expect(screen.queryByTestId('certificate-group')).not.toBeInTheDocument();
    expect(screen.queryByTestId('certificate-group-row')).not.toBeInTheDocument();
  });

  it('words the groups in Turkish', async () => {
    onNginx('operator', bindings, windowsTargetFixture, false, 'tr');
    await renderRoute(winPath, { languages: ['tr-TR'] });
    const groups = await screen.findAllByTestId('certificate-group');
    expect(within(groups[1]).getByTestId('certificate-group-row')).toHaveTextContent('2 bağlama');
    expect(within(groups[2]).getByTestId('certificate-group-row')).toHaveTextContent('Sertifika yok');
    expectNoRawKeys(screen.getAllByTestId('certificate-group')[0].closest('table')!);
  });
});
