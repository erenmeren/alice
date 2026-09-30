import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { auditExportUrl } from '../api/endpoints';
import type { AuditEntry, SessionInfo } from '../api/types';
import { adminSession, sessionFor } from '../test/fixtures';
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

describe('AuditPage', () => {
  beforeEach(() => localStorage.clear());

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
