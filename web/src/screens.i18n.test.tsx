import { screen, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import type { ApiToken, AuditEntry } from './api/types';
import {
  aliceKeyLocation,
  certificateDetailFixture,
  certificateFixture,
  csrFixture,
  deploymentDetailFixture,
  deploymentFixture,
  hostKeyFixture,
  keyLocationFixture,
  locationFixture,
  nginxTargetFixture,
  platformKeyFixture,
  sessionHandlers,
  sshKeyFixture,
  stepFixture,
  targetFixture,
  userFor,
  vaultFixture,
} from './test/fixtures';
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
  http.get('/api/v1/targets', ({ request }) => HttpResponse.json({ items: new URL(request.url).searchParams.get('type') === 'azure_key_vault' ? [vaultFixture] : [targetFixture], next_cursor: null })),
  http.get('/api/v1/targets/:id', ({ params }) => HttpResponse.json(params.id === nginxTargetFixture.id ? nginxTargetFixture : params.id === vaultFixture.id ? vaultFixture : targetFixture)),
  http.get('/api/v1/targets/:id/certificate-locations', () =>
    HttpResponse.json({
      items: [
        locationFixture({ warnings: ['symlinked', 'key_mode_open', 'san_mismatch'], key_mode: '0644', changed_outside_at: '2026-10-02T09:00:00Z' }),
        locationFixture({ id: 'l2', supported: false, unsupported_reason: 'file_problem', problem: 'hard_linked', key_problem: 'unreadable' }),
        locationFixture({ id: 'l3', missing_since: '2026-10-01T00:00:00Z', active_deployment_id: 'x' }),
      ],
      truncated: true,
    }),
  ),
  http.get('/api/v1/targets/:id/host-keys', () => HttpResponse.json({ items: [hostKeyFixture()] })),
  http.get('/api/v1/targets/:id/ssh-keys', () => HttpResponse.json({ items: [keyLocationFixture(), aliceKeyLocation] })),
  http.get('/api/v1/ssh-keys', () =>
    HttpResponse.json({
      items: [sshKeyFixture(), sshKeyFixture({ id: 'k9', fingerprint: 'SHA256:aliceAliceAlice', is_platform_key: true, comment: 'alice-platform' })],
      next_cursor: 'next',
    }),
  ),
  // Declared before /ssh-keys/:id, which would otherwise answer the platform key request too.
  http.get('/api/v1/ssh-keys/platform-key', () => HttpResponse.json(platformKeyFixture)),
  http.get('/api/v1/ssh-keys/:id', () => HttpResponse.json({ ...sshKeyFixture(), locations: [keyLocationFixture(), aliceKeyLocation] })),
  http.get('/api/v1/certificates/csr', () => HttpResponse.json({ items: [csrFixture()] })),
  http.get('/api/v1/certificates', () => HttpResponse.json({ items: [certificateFixture(), certificateFixture({ id: 'c2', has_private_key: false, not_after: '2020-01-01T00:00:00Z' })], next_cursor: 'next' })),
  http.get('/api/v1/certificates/:id', () => HttpResponse.json(certificateDetailFixture({ id: '0192c000-0000-7000-8000-0000000000c1', chain_complete: false }))),
  http.get('/api/v1/deployments', () => HttpResponse.json({ items: [deploymentFixture(), deploymentFixture({ id: 'd2', status: 'needs_attention' })], next_cursor: null })),
  http.get('/api/v1/deployments/:id', () =>
    HttpResponse.json(
      deploymentDetailFixture({
        status: 'rollback_failed',
        state: 'recovering',
        recovery_attempts: 2,
        recover_after: '2026-10-04T13:00:00Z',
        backup_dir: '/var/lib/alice-helper/backups/x',
        failed_step: 'verify_current',
        helper_error: 'file_changed',
        error: { code: 'ALC-DEP-0020', reason: 'deployment.rollback_file_changed' },
        verify_failed: { code: 'ALC-DEP-0005', reason: 'deployment.verify_unreachable', params: { port: '443' } },
        steps: [stepFixture(1, 'verify_current'), stepFixture(2, 'backup'), stepFixture(3, 'journal', 'failed', { error: 'file_changed' }), stepFixture(4, 'restore')],
      }),
    ),
  ),
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
