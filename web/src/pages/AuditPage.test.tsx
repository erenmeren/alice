import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { auditExportUrl } from '../api/endpoints';
import en from '../locales/en.json';
import tr from '../locales/tr.json';
import { actionKey } from './AuditPage';
import type { AuditEntry, SessionInfo } from '../api/types';
import { adminSession, sessionFor } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

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
    expect(await screen.findByRole('heading', { name: 'Audit log' })).toBeInTheDocument();
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
    expect(await screen.findByRole('status')).toHaveTextContent('Denetim kaydında 17 numaralı kayıtta bütünlük sorunu var.');
    // Only the page body counts: the shell header always has language and sign-out controls.
    const buttons = within(screen.getByRole('main')).getAllByRole('button').map((b) => b.textContent);
    expect(buttons).toEqual(['Bütünlüğü doğrula', 'Filtreleri uygula']);
  });

  it('renders entry values as text, never markup', async () => {
    signedInAs(adminSession);
    const evil = { ...entry(1, 'auth.login'), actor_name: '<img src=x onerror=alert(1)>' };
    server.use(http.get('/api/v1/audit', () => HttpResponse.json({ items: [evil], next_cursor: null })));
    const { container } = await renderRoute('/audit');
    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
    expect(container.querySelector('img')).toBeNull();
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

  it('does not show the audit log to operators', async () => {
    signedInAs(sessionFor('operator'));
    await renderRoute('/audit');
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Audit log' })).not.toBeInTheDocument();
  });
});
