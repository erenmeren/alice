import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { AuditEntry } from '../api/types';
import { adminSession, auditorSession, backupStateFixture, emptyDashboardSummary, operatorSession, sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const summary = (over: Record<string, unknown> = {}) => ({
  ...emptyDashboardSummary,
  generated_at: '2026-10-07T09:00:00Z',
  certificates: { monitored: 8, expired: 1, within_7: 3, within_30: 6, within_60: 7, kv_expired: 0, kv_within_30: 2 },
  deployments: { failed_7d: 1, recent: [{ id: 'd1', certificate_name: 'api.seed.test', target_id: 't1', target_name: 'seed-web-1', status: 'failed', error_code: 'ngx.reload_failed', at: '2026-10-06T09:00:00Z' }] },
  targets: { total: 3, by_status: { ok: 2, host_key_changed: 1, unreachable: 0 } },
  license: { expired: false, phase: 'active', ends_at: '2026-11-16T09:00:00Z', days_left: 40 },
  rotation: { upcoming: [{ policy_id: 'p1', ssh_key_id: 'k1', key_label: 'ci-deploy', next_run_at: '2026-10-10T09:00:00Z' }], running: 1, needs_attention: 0 },
  notifications: { failing: false, consecutive_failures: 0, last_failure_at: null, last_failure_code: '', last_success_at: null, pending: 0, failed_24h: 0 },
  audit: { head_seq: 42, head_hash: 'ab'.repeat(32), checked_at: '2026-10-07T03:00:00Z', intact: true },
  backup: backupStateFixture(),
  attention: 2,
  ...over,
});

const entry = (o: Partial<AuditEntry> = {}): AuditEntry => ({
  seq: 42, at: '2026-10-07T08:00:00Z', actor_type: 'user', actor_id: null, actor_name: 'ada', ip: null, action: 'auth.login',
  object_type: 'user', object_id: 'u1', result: 'success', details: {}, request_id: 'r1', hash: 'ab'.repeat(32), ...o,
});

// dashboardHandlers answers the dashboard's reads: the summary (with the overrides), two expiring items, one condition
// and the five newest audit entries.
function dashboardHandlers(over: Record<string, unknown> = {}) {
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
    http.get('/api/v1/audit', () => HttpResponse.json({ items: [entry(), entry({ seq: 41, actor_type: 'system', actor_name: 'scheduler', action: 'not.a_known_action', result: 'denied' })], next_cursor: 'n' })),
  ];
}

describe('DashboardPage', () => {
  it('has the design’s header: the date eyebrow, Overview as the only h1 and the description', async () => {
    server.use(...sessionHandlers(adminSession), ...dashboardHandlers());
    await renderRoute('/');
    expect(await screen.findByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByText('Your certificates, keys and infrastructure. In clear view.')).toBeVisible();
    const today = new Intl.DateTimeFormat('en', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' }).format(new Date());
    expect(screen.getByText(today)).toBeVisible();
    expect(screen.queryByText(/Welcome/)).not.toBeInTheDocument();
  });

  it('keeps the server status and adds when the summary was made', async () => {
    server.use(...sessionHandlers(adminSession), ...dashboardHandlers());
    await renderRoute('/');
    await waitFor(() => expect(screen.getByTestId('server-status')).toHaveTextContent('Server version: 1.2.3'));
    await waitFor(() => expect(screen.getByTestId('server-status')).toHaveTextContent(/· Updated /));
  });

  it('shows the four metrics: monitored certificates, managed targets, key rotations and what needs attention', async () => {
    server.use(...sessionHandlers(adminSession), ...dashboardHandlers());
    await renderRoute('/');
    const strip = await screen.findByRole('group', { name: 'Summary' });
    expect(within(strip).getByRole('link', { name: /Monitored certificates\s*8\s*6 expire within 30 days/ })).toHaveAttribute('href', '/certificates?expiry=30');
    expect(within(strip).getByRole('link', { name: /Managed targets\s*3\s*1 needs review/ })).toHaveAttribute('href', '/servers');
    expect(within(strip).getByRole('link', { name: /Key rotations\s*1\s*1 rotation in progress/ })).toHaveAttribute('href', '/rotations');
    expect(within(strip).getByText('Conditions to resolve')).toBeVisible();
    expect(within(strip).getAllByRole('link')).toHaveLength(3);
  });

  it('shows the counts as links to the filtered certificate list', async () => {
    server.use(...sessionHandlers(adminSession), ...dashboardHandlers());
    await renderRoute('/');
    const counts = await screen.findByTestId('dashboard-counts');
    expect(within(counts).getByRole('link', { name: /^Expired\s*1$/ })).toHaveAttribute('href', '/certificates?expiry=expired');
    expect(within(counts).getByRole('link', { name: /^Within 7 days\s*3$/ })).toHaveAttribute('href', '/certificates?expiry=7');
    expect(within(counts).getByRole('link', { name: /^Within 30 days\s*6$/ })).toHaveAttribute('href', '/certificates?expiry=30');
    expect(within(counts).getByRole('link', { name: /^Within 60 days\s*7$/ })).toHaveAttribute('href', '/certificates?expiry=60');
    expect(within(counts).getByText('Certificates in use: 8')).toBeInTheDocument();
    expect(within(counts).getByRole('link', { name: /Key Vault keys and secrets expiring within 30 days: 2/ })).toHaveAttribute('href', '/key-vaults');
  });

  it('lists what expires soon, the expired one marked', async () => {
    server.use(...sessionHandlers(adminSession), ...dashboardHandlers());
    await renderRoute('/');
    const list = await screen.findByTestId('expiring-list');
    const rows = await within(list).findAllByRole('row');
    expect(within(rows[1]).getByText('old.seed.test')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Expired')).toBeInTheDocument();
    expect(within(rows[2]).getByText('www.seed.test')).toBeInTheDocument();
    expect(within(list).getByText('The 2 soonest are shown.')).toBeVisible();
    expect(within(list).getByRole('link', { name: 'View all' })).toHaveAttribute('href', '/certificates?expiry=30');
  });

  it('keeps the expiring list a real table with the name in the first code of each row and no total', async () => {
    server.use(...sessionHandlers(adminSession), ...dashboardHandlers());
    await renderRoute('/');
    const list = await screen.findByTestId('expiring-list');
    const rows = list.querySelectorAll('tbody tr');
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0].querySelector('code')).not.toBeNull();
    expect(list).not.toHaveTextContent(/ of \d+/);
  });

  it('says so when nothing expires soon', async () => {
    server.use(...sessionHandlers(adminSession), http.get('/api/v1/dashboard/expiring', () => HttpResponse.json({ items: [] })), ...dashboardHandlers());
    await renderRoute('/');
    const list = await screen.findByTestId('expiring-list');
    expect(await within(list).findByText('Nothing expires within 30 days.')).toBeInTheDocument();
    expect(within(list).queryByText(/soonest are shown/)).not.toBeInTheDocument();
  });

  it('lists conditions as attention items with the resource name as its own text', async () => {
    // msw prefers the handler given first, so the override comes before the defaults.
    server.use(http.get('/api/v1/alerts', () => HttpResponse.json({ items: [{ kind: 'host_key_changed', object_id: 't1', name: 'seed-web-3', since: '2026-10-12T08:00:00Z', error_code: '' }] })), ...sessionHandlers(adminSession), ...dashboardHandlers());
    await renderRoute('/');
    const list = await screen.findByTestId('attention-list');
    expect(within(list).getByText('seed-web-3', { exact: true })).toBeVisible();
    expect(within(list).getByRole('link')).toHaveAttribute('href', '/servers/t1');
    expect(within(list).getByText('1 open')).toBeVisible();
  });

  it('shows failed deployments, target connectivity and upcoming rotations on the Operations tab', async () => {
    server.use(...sessionHandlers(adminSession), ...dashboardHandlers());
    await renderRoute('/');
    const failed = await screen.findByTestId('failed-deployments');
    expect(within(failed).getByRole('link', { name: /api\.seed\.test/ })).toHaveAttribute('href', '/deployments/d1');
    expect(within(failed).getByText('Failed, nothing changed')).toBeVisible();
    expect(within(failed).getByText('Failed deployments: 1')).toBeVisible();
    expect(within(failed).getByRole('link', { name: 'View history' })).toHaveAttribute('href', '/deployments');
    const targets = await screen.findByTestId('targets-by-status');
    expect(within(targets).getByText(/Connected.*2/)).toBeInTheDocument();
    expect(within(targets).queryByText(/Cannot be reached/)).not.toBeInTheDocument();
    expect(within(targets).getByText('of 3 connected')).toBeVisible();
    expect(within(targets).getByRole('img', { name: 'Server identity changed: 1, Connected: 2' })).toBeVisible();
    const rotation = await screen.findByTestId('rotation-upcoming');
    expect(within(rotation).getByRole('link', { name: /ci-deploy/ })).toHaveAttribute('href', '/ssh-keys/k1');
    expect(within(rotation).getByText('Rotations running: 1')).toBeVisible();
    expect(within(rotation).getByRole('link', { name: 'View rotations' })).toHaveAttribute('href', '/rotations');
    expect(within(await screen.findByTestId('attention-list')).getByText('seed-web-3')).toBeInTheDocument();
    expect(screen.queryByTestId('license-card')).not.toBeInTheDocument();
    expect(screen.queryByTestId('audit-head')).not.toBeInTheDocument();
  });

  it('says so when no server is connected, no deployment failed and no rotation is planned', async () => {
    server.use(...sessionHandlers(adminSession), http.get('/api/v1/dashboard/summary', () => HttpResponse.json(emptyDashboardSummary)));
    await renderRoute('/');
    expect(within(await screen.findByTestId('targets-by-status')).getByText('No servers or vaults are connected yet.')).toBeVisible();
    expect(within(screen.getByTestId('failed-deployments')).getByText('No deployment failed in the last 7 days.')).toBeVisible();
    expect(within(screen.getByTestId('rotation-upcoming')).getByText('No rotation is scheduled.')).toBeVisible();
    expect(within(await screen.findByTestId('attention-list')).getByText('Nothing needs your attention.')).toBeVisible();
    expect(screen.queryByRole('tab', { name: 'Assurance' })).not.toBeInTheDocument();
  });

  it('shows a broken audit chain in the attention list and in the audit integrity panel', async () => {
    server.use(
      ...sessionHandlers(adminSession),
      http.get('/api/v1/alerts', () => HttpResponse.json({ items: [{ kind: 'audit_broken', object_id: '', name: '', since: '2026-10-07T03:00:00Z', error_code: '' }, { kind: 'notifications_failing', object_id: '', name: '', since: '2026-10-07T03:00:00Z', error_code: 'smtp.connect' }, { kind: 'deployment_failed', object_id: 'd9', name: 'x.seed.test', since: '2026-10-07T03:00:00Z', error_code: '' }] })),
      ...dashboardHandlers({ audit: { head_seq: 42, head_hash: 'cd'.repeat(32), checked_at: null, intact: false } }),
    );
    await renderRoute('/');
    const attention = await screen.findByTestId('attention-list');
    expect(await within(attention).findByText(/integrity problem in the audit log/)).toBeInTheDocument();
    expect(within(attention).getByText('E-mails could not be sent')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: 'Assurance' }));
    const head = await screen.findByTestId('audit-head');
    expect(within(head).getByRole('alert')).toHaveTextContent(/integrity problem in the audit log/);
    expect(within(head).getByText('Integrity problem')).toBeVisible();
    expect(within(head).getByText('Not verified yet')).toBeVisible();
    expect(within(head).queryByText('Chain intact')).not.toBeInTheDocument();
  });

  it('hides the Assurance tab for an Operator, whose summary has no audit and no backup', async () => {
    server.use(...sessionHandlers(operatorSession), ...dashboardHandlers({ audit: null, backup: null, notifications: null, license: { expired: true, phase: '', ends_at: null, days_left: null } }));
    await renderRoute('/?view=assurance');
    await screen.findByTestId('dashboard-counts');
    expect(screen.queryByRole('tab', { name: 'Assurance' })).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Operations', selected: true })).toBeVisible();
    expect(screen.queryByTestId('backup-card')).not.toBeInTheDocument();
    expect(screen.queryByTestId('audit-head')).not.toBeInTheDocument();
    // An expired license reaches an Operator through the shell's banners, not through a dashboard panel.
    expect(screen.queryByTestId('license-card')).not.toBeInTheDocument();
  });

  it('shows audit integrity, recovery readiness and the license on the Assurance tab, kept in the address', async () => {
    server.use(...sessionHandlers(adminSession), ...dashboardHandlers());
    const { router } = await renderRoute('/');
    await userEvent.click(await screen.findByRole('tab', { name: 'Assurance' }));
    expect(router.state.location.search).toBe('?view=assurance');
    expect(await screen.findByTestId('audit-head')).toBeVisible();
    expect(screen.getByTestId('backup-card')).toHaveTextContent('Not established by a backup checksum');
    expect(screen.getByTestId('license-card')).toBeVisible();
    expect(screen.queryByTestId('dashboard-counts')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: 'Operations' }));
    expect(router.state.location.search).toBe('');
    expect(await screen.findByTestId('dashboard-counts')).toBeVisible();
  });

  it('shows the audit head in words: chain intact, the sequence, the hash and what it does not prove', async () => {
    server.use(...sessionHandlers(adminSession), ...dashboardHandlers());
    await renderRoute('/?view=assurance');
    const head = await screen.findByTestId('audit-head');
    expect(within(head).getByText('Chain intact')).toBeVisible();
    expect(within(head).getByText('42')).toBeVisible();
    expect(within(head).getByText('ab'.repeat(32))).toBeVisible();
    expect(within(head).getByText(/not independent proof against a compromised host/)).toBeVisible();
    expect(within(head).getByRole('link', { name: 'Inspect audit trail' })).toHaveAttribute('href', '/audit');
    expect(within(screen.getByTestId('license-card')).getByText('Active')).toBeVisible();
  });

  it('shows the five newest audit entries as the evidence trail, read only on the Assurance tab', async () => {
    let asked: string | null = null;
    server.use(
      http.get('/api/v1/audit', ({ request }) => {
        asked = new URL(request.url).search;
        return HttpResponse.json({ items: [entry(), entry({ seq: 41, actor_type: 'system', actor_name: 'scheduler', action: 'not.a_known_action', result: 'denied' })], next_cursor: 'n' });
      }),
      ...sessionHandlers(adminSession),
      ...dashboardHandlers(),
    );
    const { unmount } = await renderRoute('/');
    await screen.findByTestId('dashboard-counts');
    expect(asked).toBeNull();
    unmount();
    await renderRoute('/?view=assurance');
    const trail = await screen.findByTestId('evidence-trail');
    expect(asked).toBe('?limit=5');
    const rows = await within(trail).findAllByRole('row');
    expect(rows).toHaveLength(3);
    expect(within(rows[1]).getByText('ada')).toBeVisible();
    expect(within(rows[1]).getByText('Success')).toBeVisible();
    expect(within(rows[2]).getByText('System (scheduler)')).toBeVisible();
    expect(within(rows[2]).getByText('not.a_known_action')).toBeVisible();
    expect(within(rows[2]).getByText('Denied')).toBeVisible();
    expect(within(trail).getByRole('link', { name: 'Open audit trail' })).toHaveAttribute('href', '/audit');
    expectNoRawKeys();
  });

  it('draws no evidence trail when the audit log may not be read, and says so when it is empty', async () => {
    server.use(http.get('/api/v1/audit', () => HttpResponse.json({ error: { code: 'ALC-AUTH-0003' } }, { status: 403 })), ...sessionHandlers(adminSession), ...dashboardHandlers());
    const { unmount } = await renderRoute('/?view=assurance');
    await screen.findByTestId('audit-head');
    await waitFor(() => expect(screen.queryByText('Latest audit entries')).not.toBeInTheDocument());
    expect(screen.queryByTestId('evidence-trail')).not.toBeInTheDocument();
    unmount();
    server.use(http.get('/api/v1/audit', () => HttpResponse.json({ items: [], next_cursor: null })));
    await renderRoute('/?view=assurance');
    expect(await within(await screen.findByTestId('evidence-trail')).findByText('No audit entries yet.')).toBeVisible();
  });

  it('shows an Auditor the Assurance tab with the audit head and the detailed license', async () => {
    server.use(...sessionHandlers(auditorSession), ...dashboardHandlers({ notifications: null }));
    await renderRoute('/?view=assurance');
    expect(within(await screen.findByTestId('audit-head')).getByText('ab'.repeat(32))).toBeInTheDocument();
    expect(within(screen.getByTestId('license-card')).getByText(/^Valid until: /)).toBeVisible();
    expect(within(screen.getByTestId('license-card')).getByText('40 days left')).toBeVisible();
  });

  it('shows an error when the summary cannot be read', async () => {
    server.use(...sessionHandlers(adminSession), http.get('/api/v1/dashboard/summary', () => HttpResponse.json({ code: 'ALC-SYS-0001' }, { status: 500 })), ...dashboardHandlers());
    await renderRoute('/');
    expect((await screen.findAllByRole('alert')).length).toBeGreaterThan(0);
  });

  it('marks the grid busy while loading and shows each failing query separately', async () => {
    server.use(
      ...sessionHandlers(adminSession),
      http.get('/api/v1/dashboard/summary', () => HttpResponse.json({ error: { code: 'ALC-SYS-0001' } }, { status: 500 })),
      http.get('/api/v1/alerts', () => HttpResponse.json({ error: { code: 'ALC-SYS-0001' } }, { status: 500 })),
      ...dashboardHandlers(),
    );
    await renderRoute('/');
    expect(await screen.findByText('The dashboard could not be loaded.')).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByRole('alert').length).toBeGreaterThanOrEqual(2));
    expect(await screen.findByTestId('expiring-list')).toBeInTheDocument();
    expect(document.querySelector('[aria-busy="false"]')).not.toBeNull();
  });

  it('renders in Turkish', async () => {
    server.use(...sessionHandlers(sessionFor('admin', 'tr')), ...dashboardHandlers());
    await renderRoute('/', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { level: 1, name: 'Genel bakış' })).toBeInTheDocument();
    expect(await screen.findByText('Sertifika bitiş takvimi')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Güvence' })).toBeVisible();
    expectNoRawKeys();
  });
});
