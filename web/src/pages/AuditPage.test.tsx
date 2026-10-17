import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { auditExportUrl } from '../api/endpoints';
import en from '../locales/en.json';
import tr from '../locales/tr.json';
import { actionKey } from './AuditPage';
import type { AuditEntry, SessionInfo } from '../api/types';
import { adminSession, errorResponse, sessionFor } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';
import ui from '../components/ui/ui.module.css';

function entry(seq: number, action: string, result: AuditEntry['result'] = 'success'): AuditEntry {
  return {
    seq,
    at: '2026-09-30T08:00:00Z',
    actor_type: 'user',
    actor_id: adminSession.user.id,
    actor_name: 'admin',
    ip: '10.0.0.7',
    action,
    object_type: 'user',
    object_id: 'x',
    result,
    details: {},
    request_id: `req-${seq}`,
    hash: 'ab'.repeat(32),
  };
}

function signedInAs(session: SessionInfo) {
  server.use(
    http.get('/api/v1/auth/session', () => HttpResponse.json(session)),
    http.get('/api/v1/setup/status', () =>
      HttpResponse.json({ admin_exists: true, recovery_passphrase_set: true, completed: true, default_locale: 'en' }),
    ),
    http.get('/api/v1/version', () => HttpResponse.json({ version: '1.2.3', commit: 'abc', build_time: 't' })),
  );
}

// Every audit action Phase 2 writes (licensing, clock, wizard license step, lock gate).
const PHASE2_ACTIONS = [
  'license.activated',
  'license.renewed',
  'license.expired',
  'license.locked',
  'license.evaluation_ended',
  'license.state_changed',
  'license.warning.sent',
  'license.tampered',
  'license.installation_tampered',
  'license.installation_sealed',
  'license.installation_restored',
  'license.upload.invalid',
  'license.upload.invalid_signature',
  'license.upload.unsupported_format',
  'license.upload.unknown_key',
  'license.upload.revoked_key',
  'license.upload.wrong_installation',
  'license.upload.older_than_installed',
  'clock.rollback_detected',
  'clock.forward_jump',
  'clock.hwm_damaged',
  'clock.time_reference_reset',
  'clock.jump_accepted',
  'clock.jump_cleared',
  'setup.evaluation_chosen',
  'request.denied_license',
];

// Every audit action Phase 3 writes (servers, host keys, SSH keys, jobs, the platform key) and the
// installation record restore of the Phase 2 carry (contract "Audit actions").
const PHASE3_ACTIONS = [
  'license.installation_restored',
  'target.created',
  'target.updated',
  'target.deleted',
  'target.capabilities_synced',
  'target.add.denied_license',
  'target.status_changed',
  'target.discovered',
  'hostkey.observed',
  'hostkey.pinned',
  'hostkey.changed',
  'hostkey.repinned',
  'hostkey.change_dismissed',
  'sshkey.remove_requested',
  'sshkey.remove.denied',
  'sshkey.removed',
  'sshkey.remove_failed',
  'job.recovered',
  'job.dead',
  'job.tampered',
  'job.blocked_license',
  'job.cancelled_license',
  'job.confirmed',
  'job.discarded',
  'platform_key.created',
];

describe('AuditPage', () => {
  beforeEach(() => localStorage.clear());

  it('labels every Phase 3 audit action in English and Turkish', () => {
    for (const action of PHASE3_ACTIONS) {
      const key = actionKey(action).replace('audit.actions.', '');
      expect(en.audit.actions, action).toHaveProperty([key]);
      expect(tr.audit.actions, action).toHaveProperty([key]);
      expect((en.audit.actions as Record<string, string>)[key]).not.toEqual((tr.audit.actions as Record<string, string>)[key]);
    }
  });

  it('labels every Phase 2 audit action in English and Turkish', async () => {
    for (const action of PHASE2_ACTIONS) {
      const key = actionKey(action).replace('audit.actions.', '');
      expect(en.audit.actions, action).toHaveProperty([key]);
      expect(tr.audit.actions, action).toHaveProperty([key]);
    }
    signedInAs(adminSession);
    server.use(
      http.get('/api/v1/audit', () =>
        HttpResponse.json({ items: [entry(2, 'license.installation_tampered', 'failure'), entry(1, 'license.upload.invalid_signature', 'failure')], next_cursor: null }),
      ),
    );
    await renderRoute('/audit');
    expect(await screen.findByText('Installation record changed outside Alice')).toBeInTheDocument();
    expect(screen.getByText('License upload refused: signature does not match')).toBeInTheDocument();
  });

  it('shows localized actions, falls back to the raw action and pages with the cursor', async () => {
    signedInAs(adminSession);
    const cursors: (string | null)[] = [];
    server.use(
      http.get('/api/v1/audit', ({ request }) => {
        const cursor = new URL(request.url).searchParams.get('cursor');
        cursors.push(cursor);
        if (!cursor) {
          return HttpResponse.json({
            items: [entry(4, 'user.unlocked'), entry(3, 'user.created'), entry(2, 'custom.future_action', 'denied')],
            next_cursor: '2',
          });
        }
        return HttpResponse.json({ items: [entry(1, 'setup.admin_created')], next_cursor: null });
      }),
    );
    await renderRoute('/audit');
    expect(await screen.findByRole('heading', { name: 'Audit trail' })).toBeInTheDocument();
    expect(await screen.findByText('User created')).toBeInTheDocument();
    expect(screen.getByText('Sign-in block lifted')).toBeInTheDocument();
    const raw = screen.getByText('custom.future_action').closest('tr')!;
    expect(within(raw).getByText('Denied')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(await screen.findByText('Administrator created during setup')).toBeInTheDocument();
    expect(cursors).toEqual([null, '2']);
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
  });

  it('sends the filters to the server', async () => {
    signedInAs(adminSession);
    const queries: string[] = [];
    server.use(
      http.get('/api/v1/audit', ({ request }) => {
        queries.push(new URL(request.url).search);
        return HttpResponse.json({ items: [], next_cursor: null });
      }),
    );
    await renderRoute('/audit');
    expect(await screen.findByText('No entries match these filters.')).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText(/^Action starts with/), 'auth.');
    await userEvent.selectOptions(screen.getByLabelText(/^Result/), 'denied');
    await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
    await waitFor(() => expect(queries).toContain('?limit=50&action=auth.&result=denied'));
  });

  it('reports an intact chain and offers exports', async () => {
    signedInAs(adminSession);
    server.use(
      http.get('/api/v1/audit', () => HttpResponse.json({ items: [entry(1, 'auth.login')], next_cursor: null })),
      http.post('/api/v1/audit/verify', () =>
        HttpResponse.json({ intact: true, checked: 1234, head_seq: 1234, head_hash: 'cd'.repeat(32), first_bad_seq: null, problem: null }),
      ),
    );
    await renderRoute('/audit');
    await userEvent.click(await screen.findByRole('button', { name: 'Verify integrity' }));
    const status = await screen.findByRole('status');
    expect(status).toHaveTextContent('The audit log is intact.');
    expect(status).toHaveTextContent('1,234 entries checked.');
    expect(screen.getByRole('link', { name: 'Export CSV' })).toHaveAttribute('href', auditExportUrl('csv'));
    expect(screen.getByRole('link', { name: 'Export JSON' })).toHaveAttribute('href', auditExportUrl('json'));
  });

  it('reports a broken chain in Turkish for an auditor', async () => {
    signedInAs(sessionFor('auditor', 'tr')); // the signed-in user's locale wins over the browser language
    server.use(
      http.get('/api/v1/audit', () => HttpResponse.json({ items: [entry(1, 'auth.logout', 'failure')], next_cursor: null })),
      http.post('/api/v1/audit/verify', () =>
        HttpResponse.json({ intact: false, checked: 40, head_seq: 41, head_hash: 'ef'.repeat(32), first_bad_seq: 17, problem: 'hash_mismatch' }),
      ),
    );
    await renderRoute('/audit', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'Denetim kaydı' })).toBeInTheDocument();
    const row = (await screen.findByText('Çıkış')).closest('tr')!;
    expect(within(row).getByText('Başarısız')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Bütünlüğü doğrula' }));
    // A broken chain is announced at once (role alert), an intact one politely (role status).
    expect(await screen.findByRole('alert')).toHaveTextContent('Denetim kaydında 17 numaralı kayıtta bütünlük sorunu var.');
    // Only the page body counts: the shell header always has language and sign-out controls.
    const buttons = within(screen.getByRole('main')).getAllByRole('button').map((b) => b.textContent);
    expect(buttons).toEqual(['Bütünlüğü doğrula', 'Filtreleri uygula']);
  });

  it('renders entry values as text, never markup', async () => {
    signedInAs(adminSession);
    const evil = { ...entry(1, 'auth.login'), actor_name: '<img src=x onerror=alert(1)>' };
    server.use(http.get('/api/v1/audit', () => HttpResponse.json({ items: [evil], next_cursor: null })));
    await renderRoute('/audit');
    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
    // The page body has no image at all (the shell's brand mark is in the navigation).
    expect(screen.getByRole('main').querySelector('img')).toBeNull();
  });

  it('shows the object of a row and its details as labelled values (AUD-25 d)', async () => {
    signedInAs(adminSession);
    const revoked: AuditEntry = {
      ...entry(2, 'token.revoked'),
      object_type: 'api_token',
      object_id: '0192f000-0000-7000-8000-0000000000t1',
      details: { token_id: '0192f000-0000-7000-8000-0000000000t1', reason: 'password_reset', owner_id: 'u-7' },
    };
    const reset: AuditEntry = { ...entry(1, 'user.password_reset'), object_id: 'u-7', details: { revoked_tokens_count: '2' } };
    server.use(http.get('/api/v1/audit', () => HttpResponse.json({ items: [revoked, reset], next_cursor: null })));
    await renderRoute('/audit');
    expect(await screen.findByRole('columnheader', { name: 'Object' })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Details' })).toBeInTheDocument();
    const row = screen.getByText('API token revoked').closest('tr')!;
    const type = within(row).getByText('api_token');
    expect(type.tagName).toBe('CODE');
    expect(type.closest('[translate="no"]')).not.toBeNull();
    expect(within(row).getAllByText('0192f000-0000-7000-8000-0000000000t1')[0].tagName).toBe('CODE');

    // The details are behind a disclosure, closed at first.
    const toggle = within(row).getByRole('button', { name: 'Details (3)' });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    expect(within(row).queryByText('Reason')).not.toBeInTheDocument();
    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    const list = within(row).getByRole('group', { name: 'Details' });
    const terms = within(list).getAllByRole('term').map((e) => e.textContent);
    expect(terms).toEqual(['Owner', 'Reason', 'API token']); // sorted by key: owner_id, reason, token_id
    expect(within(list).getByText('New password set by an administrator')).toBeInTheDocument();

    const resetRow = screen.getByText('Password set by an administrator').closest('tr')!;
    await userEvent.click(within(resetRow).getByRole('button', { name: 'Details (1)' }));
    expect(within(resetRow).getByRole('term')).toHaveTextContent('API tokens revoked');
    expect(within(resetRow).getByRole('definition')).toHaveTextContent('2');
    expectNoRawKeys();
  });

  it('shows details it has no label for as data, never as markup', async () => {
    signedInAs(adminSession);
    const odd: AuditEntry = {
      ...entry(1, 'custom.future_action'),
      object_type: '',
      object_id: '',
      details: { zz_new_key: '<b onclick=alert(1)>x</b>', 'weird.key:with': 'v', reason: 'brand_new_reason', constructor: 'c' },
    };
    server.use(http.get('/api/v1/audit', () => HttpResponse.json({ items: [odd], next_cursor: null })));
    const { container } = await renderRoute('/audit');
    const row = (await screen.findByText('custom.future_action')).closest('tr')!;
    await userEvent.click(within(row).getByRole('button', { name: 'Details (4)' }));
    const list = within(row).getByRole('group', { name: 'Details' });
    expect(within(list).getByText('zz_new_key').closest('[translate="no"]')).not.toBeNull();
    expect(within(list).getByText('<b onclick=alert(1)>x</b>')).toBeInTheDocument();
    expect(within(list).getByText('weird.key:with')).toBeInTheDocument();
    expect(within(list).getByText('brand_new_reason').closest('[translate="no"]')).not.toBeNull();
    expect(within(list).getByText('constructor')).toBeInTheDocument();
    expect(container.querySelector('b')).toBeNull();
    expectNoRawKeys();
  });

  it('formats time details in the reader\'s language and labels details in Turkish', async () => {
    signedInAs(sessionFor('auditor', 'tr'));
    const denied: AuditEntry = {
      ...entry(1, 'authz.denied', 'denied'),
      details: { suppressed_count: '12', window_start: '2026-09-30T07:50:00Z', reason: 'unverified' },
    };
    server.use(http.get('/api/v1/audit', () => HttpResponse.json({ items: [denied], next_cursor: null })));
    await renderRoute('/audit', { languages: ['tr-TR'] });
    const row = (await screen.findByText('Erişim reddedildi')).closest('tr')!;
    await userEvent.click(within(row).getByRole('button', { name: 'Ayrıntılar (3)' }));
    const list = within(row).getByRole('group', { name: 'Ayrıntılar' });
    expect(within(list).getAllByRole('term').map((e) => e.textContent)).toEqual(['Neden', 'Kaydedilmeyen benzer kayıt sayısı', 'Dönem başlangıcı']);
    expect(within(list).getByText('Lisans denetlenemedi')).toBeInTheDocument();
    expect(within(list).queryByText('2026-09-30T07:50:00Z')).not.toBeInTheDocument();
    expect(within(list).getByText(/2026/)).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('summarises coalesced refusals: how many more, when, from where (AUD-06)', async () => {
    signedInAs(adminSession);
    const summary: AuditEntry = {
      ...entry(3, 'authz.denied', 'denied'),
      ip: null,
      request_id: '',
      object_id: '',
      details: {
        permission: 'users.manage',
        reason: 'not_owner',
        suppressed_count: '49',
        window_start: '2026-09-30T07:50:00Z',
        window_end: '2026-09-30T08:00:00Z',
        distinct_ip_count: '5',
        ip_samples: '10.0.0.7,10.0.0.8,2001:db8::1',
        distinct_object_count: '256+',
        distinct_token_count: '2',
      },
    };
    server.use(http.get('/api/v1/audit', () => HttpResponse.json({ items: [summary], next_cursor: null })));
    await renderRoute('/audit');
    const row = (await screen.findByText('Access denied')).closest('tr')!;
    // Visible without opening the details.
    expect(within(row).getByText(/^49 more like these between .+ and .+\.$/)).toBeInTheDocument();
    await userEvent.click(within(row).getByRole('button', { name: 'Details (9)' }));
    const list = within(row).getByRole('group', { name: 'Details' });
    expect(within(list).getByText('Addresses seen')).toBeInTheDocument();
    const samples = within(list).getByText('10.0.0.7,10.0.0.8,2001:db8::1');
    expect(samples.closest('[translate="no"]')).not.toBeNull();
    expect(within(list).getByText('Different objects')).toBeInTheDocument();
    expect(within(list).getByText('256+')).toBeInTheDocument();
    expect(within(list).getByText('Different API tokens')).toBeInTheDocument();
    expect(within(list).getByText('Different addresses')).toBeInTheDocument();
    expect(within(list).getByText('Not the owner')).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('words a summary of one more refusal in the singular, in English and Turkish', async () => {
    const one: AuditEntry = {
      ...entry(1, 'authz.denied', 'denied'),
      details: { suppressed_count: '1', window_start: '2026-09-30T07:50:00Z', window_end: '2026-09-30T08:00:00Z' },
    };
    signedInAs(adminSession);
    server.use(http.get('/api/v1/audit', () => HttpResponse.json({ items: [one], next_cursor: null })));
    const { unmount } = await renderRoute('/audit');
    expect(await screen.findByText(/^1 more like this between .+ and .+\.$/)).toBeInTheDocument();
    unmount();
    signedInAs(sessionFor('auditor', 'tr'));
    await renderRoute('/audit', { languages: ['tr-TR'] });
    expect(await screen.findByText(/^.+ ile .+ arasında buna benzer 1 kayıt daha\.$/)).toBeInTheDocument();
  });

  it('labels a refused export or verification so it never reads as a real one', async () => {
    signedInAs(sessionFor('auditor', 'tr'));
    const busyExport: AuditEntry = { ...entry(2, 'audit.exported', 'denied'), object_type: 'audit_log', details: { format: 'csv', reason: 'busy' } };
    const busyVerify: AuditEntry = { ...entry(1, 'audit.verified', 'denied'), object_type: 'audit_log', details: { reason: 'busy' } };
    const realExport: AuditEntry = { ...entry(3, 'audit.exported'), details: { format: 'json' } };
    server.use(http.get('/api/v1/audit', () => HttpResponse.json({ items: [realExport, busyExport, busyVerify], next_cursor: null })));
    await renderRoute('/audit', { languages: ['tr-TR'] });
    expect(await screen.findByText('Denetim kaydı dışa aktarımı reddedildi: başka bir doğrulama veya dışa aktarım sürüyordu')).toBeInTheDocument();
    expect(screen.getByText('Denetim kaydı bütünlük doğrulaması reddedildi: başka bir doğrulama veya dışa aktarım sürüyordu')).toBeInTheDocument();
    expect(screen.getAllByText(tr.audit.actions.audit_exported)).toHaveLength(1);
  });

  it('shows a busy audit log in words and explains a failed download (ALC-AUD-0001)', async () => {
    signedInAs(adminSession);
    server.use(
      http.get('/api/v1/audit', () => HttpResponse.json({ items: [entry(1, 'auth.login')], next_cursor: null })),
      http.post('/api/v1/audit/verify', () => errorResponse(503, 'ALC-AUD-0001', 'audit.busy', { retryable: true })),
    );
    await renderRoute('/audit');
    expect(await screen.findByText(en.audit.exportHint)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Verify integrity' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Alice is already checking or exporting the audit log.');
  });

  it('shows system actors with their name and hides the page from operators', async () => {
    signedInAs(adminSession);
    server.use(
      http.get('/api/v1/audit', () =>
        HttpResponse.json({ items: [{ ...entry(1, 'setup.completed'), actor_type: 'system', actor_name: 'setup', ip: null }], next_cursor: null }),
      ),
    );
    await renderRoute('/audit');
    expect(await screen.findByText('System (setup)')).toBeInTheDocument();
  });

  it('has the design header, the filters in the table toolbar, design rows and the cursor footer', async () => {
    signedInAs(adminSession);
    server.use(
      http.get('/api/v1/audit', () =>
        HttpResponse.json({
          items: [
            { ...entry(7, 'user.created', 'success'), actor_name: 'Ada Lovelace' },
            { ...entry(6, 'auth.login', 'failure'), details: { reason: 'bad_password' } },
            { ...entry(5, 'authz.denied', 'denied'), actor_type: 'system', actor_name: 'scheduler', ip: null },
          ],
          next_cursor: '5',
        }),
      ),
    );
    await renderRoute('/audit');
    expect(await screen.findByRole('heading', { level: 1, name: 'Audit trail' })).toBeInTheDocument();
    const main = screen.getByRole('main');
    expect(within(main).getByText('Who did what, where, and with which result.')).toBeInTheDocument();
    // Header actions: the two exports (plain downloads) and Verify integrity as the primary button.
    const header = within(main).getByRole('heading', { level: 1 }).closest('header')!;
    expect(within(header).getByRole('link', { name: 'Export CSV' })).toHaveAttribute('href', auditExportUrl('csv'));
    expect(within(header).getByRole('link', { name: 'Export JSON' })).toHaveAttribute('href', auditExportUrl('json'));
    expect(within(header).getByRole('button', { name: 'Verify integrity' })).toHaveAttribute('data-variant', 'filled');
    expect(within(main).getByText(en.audit.exportHint)).toBeInTheDocument();
    // The exports ignore the filters: the page says so (GET /audit/export takes only the format).
    expect(within(main).getByText('Exports contain the whole log, not only the entries the filters show.')).toBeInTheDocument();

    // The filter form sits in the table panel's toolbar, above the named table.
    const table = await screen.findByRole('table', { name: 'Audit events' });
    const tablePanel = table.closest(`.${ui.tablePanel}`) as HTMLElement;
    expect(tablePanel).not.toBeNull();
    const toolbar = tablePanel.querySelector(`.${ui.toolbar}`) as HTMLElement;
    expect(within(toolbar).getByLabelText(/^Action starts with/)).toBeInTheDocument();
    expect(within(toolbar).getByLabelText(/^Result/).tagName).toBe('SELECT');
    expect(within(toolbar).getByRole('button', { name: 'Apply filters' })).toBeInTheDocument();
    expect(within(tablePanel).getByRole('group', { name: 'Table, scrolls sideways' })).toBeInTheDocument();

    // Rows: time with the sequence number, the actor with initials, the action, the object, the result badge.
    const created = screen.getByText('User created').closest('tr')!;
    expect(within(created).getByText('#7')).toBeInTheDocument();
    expect(within(created).getByText('AL')).toHaveAttribute('aria-hidden', 'true');
    expect(within(created).getByText('Ada Lovelace')).toBeInTheDocument();
    expect(within(created).getByText('10.0.0.7')).toBeInTheDocument();
    expect(within(created).getByText('IP address')).toBeInTheDocument();
    expect(within(created).getByText('Success').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'success');
    const failed = screen.getByText('#6').closest('tr')!;
    expect(within(failed).getByText('Failure').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'warning');
    const toggle = within(failed).getByRole('button', { name: 'Details (1)' });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await userEvent.click(toggle);
    expect(within(failed).getByRole('group', { name: 'Details' })).toBeInTheDocument();
    const denied = screen.getByText('System (scheduler)').closest('tr')!;
    expect(within(denied).getByText('Denied').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'danger');

    // Footer: how many are shown (never a total), the order and Load more.
    const bottom = tablePanel.querySelector(`.${ui.tableBottom}`) as HTMLElement;
    expect(within(bottom).getByText('3 shown')).toBeInTheDocument();
    expect(within(bottom).getByText('Newest first')).toBeInTheDocument();
    expect(within(bottom).getByRole('button', { name: 'Load more' })).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('shows an empty trail inside the table panel and keeps the filters', async () => {
    signedInAs(adminSession);
    server.use(http.get('/api/v1/audit', () => HttpResponse.json({ items: [], next_cursor: null })));
    await renderRoute('/audit');
    const empty = await screen.findByText('No entries match these filters.');
    const tablePanel = empty.closest(`.${ui.tablePanel}`) as HTMLElement;
    expect(tablePanel).not.toBeNull();
    expect(within(tablePanel).getByRole('button', { name: 'Apply filters' })).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('reports the verification as a notice with its scope and, for administrators, the forwarding settings', async () => {
    signedInAs(adminSession);
    server.use(
      http.get('/api/v1/audit', () => HttpResponse.json({ items: [entry(1, 'auth.login')], next_cursor: null })),
      http.post('/api/v1/audit/verify', () =>
        HttpResponse.json({ intact: true, checked: 3, head_seq: 3, head_hash: 'cd'.repeat(32), first_bad_seq: null, problem: null }),
      ),
    );
    await renderRoute('/audit');
    await userEvent.click(await screen.findByRole('button', { name: 'Verify integrity' }));
    const status = await screen.findByRole('status');
    expect(status.getAttribute('style')).toContain('--alert-bg: var(--alice-brand-soft)');
    expect(status).toHaveTextContent('The audit log is intact.');
    expect(status).toHaveTextContent('Hash-chain continuity, not independent proof against a compromised host.');
    // The design's "verified through #N", from the report's head_seq.
    expect(status).toHaveTextContent('Hash chain verified through entry #3.');
    expect(within(status).getByRole('link', { name: 'Audit forwarding settings' })).toHaveAttribute('href', '/settings?tab=forwarding');
    expect(within(status).getByText('cd'.repeat(32)).tagName).toBe('CODE');
  });

  it('reports a broken chain as a danger notice without the settings link for auditors', async () => {
    signedInAs(sessionFor('auditor'));
    server.use(
      http.get('/api/v1/audit', () => HttpResponse.json({ items: [entry(1, 'auth.login')], next_cursor: null })),
      http.post('/api/v1/audit/verify', () =>
        HttpResponse.json({ intact: false, checked: 40, head_seq: 41, head_hash: 'ef'.repeat(32), first_bad_seq: 17, problem: 'hash_mismatch' }),
      ),
    );
    await renderRoute('/audit');
    await userEvent.click(await screen.findByRole('button', { name: 'Verify integrity' }));
    const status = await screen.findByRole('alert');
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    expect(status.getAttribute('style')).toContain('--alert-bg: var(--alice-danger-soft)');
    expect(status).toHaveTextContent('Audit log integrity problem at entry 17.');
    expect(status).toHaveTextContent(en.audit.brokenHelp);
    expect(status).toHaveTextContent(en.audit.page.scope);
    expect(status).not.toHaveTextContent('verified through');
    expect(within(status).queryByRole('link')).not.toBeInTheDocument();
  });

  it('does not show the audit log to operators', async () => {
    signedInAs(sessionFor('operator'));
    await renderRoute('/audit');
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Audit trail' })).not.toBeInTheDocument();
  });
});
