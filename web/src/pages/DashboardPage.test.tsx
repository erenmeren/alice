import { screen, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { adminSession, auditorSession, operatorSession, sessionFor, sessionHandlers } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const summary = (over: Record<string, unknown> = {}) => ({
  generated_at: '2026-10-07T09:00:00Z',
  certificates: { monitored: 8, expired: 1, within_7: 2, within_30: 3, within_60: 1, kv_expired: 0, kv_within_30: 2 },
  deployments: { failed_7d: 1, recent: [{ id: 'd1', certificate_name: 'api.seed.test', target_id: 't1', target_name: 'seed-web-1', status: 'failed', error_code: 'ngx.reload_failed', at: '2026-10-06T09:00:00Z' }] },
  targets: { total: 3, by_status: { ok: 2, host_key_changed: 1, unreachable: 0 } },
  license: { expired: false, phase: 'active', ends_at: '2026-11-16T09:00:00Z', days_left: 40 },
  rotation: { upcoming: [{ policy_id: 'p1', ssh_key_id: 'k1', key_label: 'ci-deploy', next_run_at: '2026-10-10T09:00:00Z' }], running: 0, needs_attention: 0 },
  notifications: { failing: false, consecutive_failures: 0, last_failure_at: null, last_failure_code: '', last_success_at: null, pending: 0, failed_24h: 0 },
  audit: { head_seq: 42, head_hash: 'ab'.repeat(32), checked_at: '2026-10-07T03:00:00Z', intact: true },
  attention: 2,
  ...over,
});

function handlers(over: Record<string, unknown> = {}) {
  return [
    http.get('/api/v1/dashboard/summary', () => HttpResponse.json(summary(over))),
    http.get('/api/v1/dashboard/expiring', () =>
      HttpResponse.json({
        items: [
          { kind: 'certificate_expiry', object_id: 'c0', name: 'old.seed.test', expires_at: '2026-10-05T09:00:00Z', days_left: 0, expired: true, fingerprint: 'f', websites: [], servers: ['seed-web-1'], target_ids: ['t1'], vault: '', vault_id: null },
          { kind: 'certificate_expiry', object_id: 'c1', name: 'www.seed.test', expires_at: '2026-10-14T08:00:00Z', days_left: 7, expired: false, fingerprint: 'f', websites: ['www.seed.test'], servers: ['seed-web-1'], target_ids: ['t1'], vault: '', vault_id: null },
        ],
      }),
    ),
    http.get('/api/v1/alerts', () => HttpResponse.json({ items: [{ kind: 'host_key_changed', object_id: 't3', name: 'seed-web-3', since: '2026-10-06T09:00:00Z', error_code: '' }] })),
    http.get('/api/v1/notifications/status', () => HttpResponse.json({ failing: false })),
  ];
}

describe('DashboardPage', () => {
  it('keeps the welcome line as the page heading and the server status', async () => {
    server.use(...sessionHandlers(adminSession), ...handlers());
    await renderRoute('/');
    expect(await screen.findByRole('heading', { level: 1, name: `Welcome, ${adminSession.user.display_name}` })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: 'Dashboard' })).toBeInTheDocument();
    expect(await screen.findByText('Server version: 1.2.3')).toBeInTheDocument();
    expect(screen.getByTestId('server-status')).toBeInTheDocument();
  });

  it('shows the counts as links to the filtered certificate list', async () => {
    server.use(...sessionHandlers(adminSession), ...handlers());
    await renderRoute('/');
    const counts = await screen.findByTestId('dashboard-counts');
    expect(within(counts).getByRole('link', { name: /Expired.*1/ })).toHaveAttribute('href', '/certificates?expiry=expired');
    expect(within(counts).getByRole('link', { name: /Within 7 days.*2/ })).toHaveAttribute('href', '/certificates?expiry=7');
    expect(within(counts).getByRole('link', { name: /In 8 to 30 days.*3/ })).toHaveAttribute('href', '/certificates?expiry=30');
    expect(within(counts).getByRole('link', { name: /In 31 to 60 days.*1/ })).toHaveAttribute('href', '/certificates?expiry=60');
    expect(within(counts).getByText('Certificates in use: 8')).toBeInTheDocument();
    expect(within(counts).getByRole('link', { name: /Key Vault items expiring within 30 days: 2/ })).toHaveAttribute('href', '/key-vaults');
  });

  it('lists what expires soon, the expired one marked', async () => {
    server.use(...sessionHandlers(adminSession), ...handlers());
    await renderRoute('/');
    const list = await screen.findByTestId('expiring-list');
    const rows = await within(list).findAllByRole('row');
    expect(within(rows[1]).getByText('old.seed.test')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Expired')).toBeInTheDocument();
    expect(within(rows[2]).getByText('www.seed.test')).toBeInTheDocument();
  });

  it('says so when nothing expires soon', async () => {
    server.use(...sessionHandlers(adminSession), http.get('/api/v1/dashboard/expiring', () => HttpResponse.json({ items: [] })), ...handlers());
    await renderRoute('/');
    expect(await within(await screen.findByTestId('expiring-list')).findByText('Nothing expires within 30 days.')).toBeInTheDocument();
  });

  it('shows failed deployments, targets by status, the license and upcoming rotations', async () => {
    server.use(...sessionHandlers(adminSession), ...handlers());
    await renderRoute('/');
    expect(within(await screen.findByTestId('failed-deployments')).getByRole('link', { name: /api\.seed\.test/ })).toHaveAttribute('href', '/deployments/d1');
    const targets = await screen.findByTestId('targets-by-status');
    expect(within(targets).getByText(/Connected.*2/)).toBeInTheDocument();
    expect(within(targets).queryByText(/Cannot be reached/)).not.toBeInTheDocument();
    expect(within(await screen.findByTestId('license-card')).getByText('Active')).toBeInTheDocument();
    expect(within(await screen.findByTestId('rotation-upcoming')).getByRole('link', { name: /ci-deploy/ })).toHaveAttribute('href', '/ssh-keys/k1');
    expect(within(await screen.findByTestId('attention-list')).getByText('seed-web-3')).toBeInTheDocument();
  });

  it('shows a broken audit chain in the audit head and the attention list', async () => {
    server.use(
      ...sessionHandlers(adminSession),
      http.get('/api/v1/alerts', () => HttpResponse.json({ items: [{ kind: 'audit_broken', object_id: '', name: '', since: '2026-10-07T03:00:00Z', error_code: '' }, { kind: 'notifications_failing', object_id: '', name: '', since: '2026-10-07T03:00:00Z', error_code: 'smtp.connect' }, { kind: 'deployment_failed', object_id: 'd9', name: 'x.seed.test', since: '2026-10-07T03:00:00Z', error_code: '' }] })),
      ...handlers({ audit: { head_seq: 42, head_hash: 'cd'.repeat(32), checked_at: '2026-10-07T03:00:00Z', intact: false } }),
    );
    await renderRoute('/');
    const head = await screen.findByTestId('audit-head');
    expect(within(head).getByText(/integrity problem in the audit log/)).toBeInTheDocument();
    const attention = await screen.findByTestId('attention-list');
    expect(await within(attention).findByText(/integrity problem in the audit log/)).toBeInTheDocument();
    expect(within(attention).getByText('E-mails could not be sent')).toBeInTheDocument();
  });

  it('shows the audit head to Auditors and not to Operators', async () => {
    server.use(...sessionHandlers(auditorSession), ...handlers({ notifications: null }));
    const { unmount } = await renderRoute('/');
    expect(within(await screen.findByTestId('audit-head')).getByText('ab'.repeat(32))).toBeInTheDocument();
    unmount();
    server.use(...sessionHandlers(operatorSession), ...handlers({ notifications: null, audit: null, license: { expired: false, phase: '', ends_at: null, days_left: null } }));
    await renderRoute('/');
    await screen.findByTestId('dashboard-counts');
    expect(screen.queryByTestId('audit-head')).not.toBeInTheDocument();
    expect(screen.queryByTestId('license-card')).not.toBeInTheDocument();
  });

  it('shows an Operator only an expired license', async () => {
    server.use(...sessionHandlers(operatorSession), ...handlers({ notifications: null, audit: null, license: { expired: true, phase: '', ends_at: null, days_left: null } }));
    await renderRoute('/');
    expect(within(await screen.findByTestId('license-card')).getByText('Expired')).toBeInTheDocument();
  });

  it('shows an error when the summary cannot be read', async () => {
    server.use(...sessionHandlers(adminSession), http.get('/api/v1/dashboard/summary', () => HttpResponse.json({ code: 'ALC-SYS-0001' }, { status: 500 })), ...handlers());
    await renderRoute('/');
    expect((await screen.findAllByRole('alert')).length).toBeGreaterThan(0);
  });

  it('renders in Turkish', async () => {
    server.use(...sessionHandlers(sessionFor('admin', 'tr')), ...handlers());
    await renderRoute('/', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'Pano' })).toBeInTheDocument();
    expect(await screen.findByText('Süresi yakında dolacaklar')).toBeInTheDocument();
  });
});
