import { screen, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import type { ApiToken, AuditEntry } from './api/types';
import { sessionHandlers, userFor } from './test/fixtures';
import { expectNoRawKeys } from './test/i18nAssert';
import { renderRoute } from './test/render';
import { SCREENS } from './test/screens';
import { server } from './test/server';

const token: ApiToken = {
  id: '0192a000-0000-7000-8000-0000000000a1',
  user_id: userFor('operator').id,
  name: 'backup script',
  prefix: 'alice_Ab12Cd',
  scope: 'read',
  expires_at: '2026-12-29T08:00:00Z',
  last_used_at: null,
  created_at: '2026-09-30T08:00:00Z',
};

const auditEntry: AuditEntry = {
  seq: 1,
  at: '2026-09-30T08:00:00Z',
  actor_type: 'user',
  actor_id: userFor('admin').id,
  actor_name: 'admin',
  ip: '10.0.0.7',
  action: 'user.created',
  object_type: 'user',
  object_id: 'x',
  result: 'success',
  details: {},
  request_id: 'req-1',
  hash: 'ab'.repeat(32),
};

// Data for the list screens, so the sweep also covers rendered rows, not only the page chrome.
const dataHandlers = [
  http.get('/api/v1/users', () => HttpResponse.json({ items: [userFor('admin'), userFor('operator'), userFor('auditor')] })),
  http.get('/api/v1/tokens', () => HttpResponse.json({ items: [token] })),
  http.get('/api/v1/audit', () => HttpResponse.json({ items: [auditEntry], next_cursor: null })),
];

describe.each(['en', 'tr'] as const)('every screen in %s', (lang) => {
  it.each(SCREENS.map((s) => [s.path, s] as const))('%s has no untranslated keys', async (_path, s) => {
    const session = s.session ? { ...s.session, user: { ...s.session.user, locale: lang } } : null;
    server.use(...sessionHandlers(session, s.status), ...dataHandlers);
    await renderRoute(s.path, { languages: [lang] });
    await waitFor(() => expect(screen.getAllByText(s.ready[lang]).length).toBeGreaterThan(0));
    expectNoRawKeys();
  });
});
