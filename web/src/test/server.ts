import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { backupListFixture, backupScheduleFixture, emptyDashboardSummary, forwardingFixture, httpsInfoFixture, licenseDetailFixture, platformKeyFixture, servicePolicyFixture, sessionHandlers, smtpFixture } from './fixtures';

// Default handlers: an installed system with nobody signed in. Tests override
// them with server.use(...); unknown requests fail the test (onUnhandledRequest: 'error').
export const handlers = [
  ...sessionHandlers(null),
  http.get('/api/v1/version', () => HttpResponse.json({ version: '1.2.3', commit: 'abc', build_time: 't' })),
  http.put('/api/v1/auth/locale', () => new HttpResponse(null, { status: 204 })),
  http.get('/api/v1/license/status', () => HttpResponse.json({ expired: false, banners: [] })),
  http.get('/api/v1/license', () => HttpResponse.json(licenseDetailFixture)),
  http.get('/api/v1/ssh-keys/platform-key', () => HttpResponse.json(platformKeyFixture)),
  http.get('/api/v1/jobs', () => HttpResponse.json({ items: [], next_cursor: null })),
  // Phase 7: every signed-in screen reads the delivery status, the dashboard reads three lists, the list pages read views.
  http.get('/api/v1/notifications/status', () => HttpResponse.json({ failing: false })),
  http.get('/api/v1/dashboard/summary', () => HttpResponse.json(emptyDashboardSummary)),
  http.get('/api/v1/dashboard/expiring', () => HttpResponse.json({ items: [] })),
  http.get('/api/v1/alerts', () => HttpResponse.json({ items: [] })),
  http.get('/api/v1/views', () => HttpResponse.json({ items: [] })),
  // R55: a service's policy (the incident dialog reads its revocation default); no rules unless a test says otherwise.
  http.get('/api/v1/services/:id/policy', () => HttpResponse.json(servicePolicyFixture())),
  // R56: the service page's Overview reads the owner team; none unless a test says otherwise.
  http.get('/api/v1/services/:id/owners', () => HttpResponse.json({ version: 1, items: [] })),
  // Phase 7 single sign-on: the sign-in page lists the public providers (none by default).
  http.get('/api/v1/auth/oidc/providers', () => HttpResponse.json({ items: [] })),
  // Directory sign-in: the sign-in page lists the switched-on directories (none by default: no "Sign in to" select).
  http.get('/api/v1/auth/ldap/directories', () => HttpResponse.json({ items: [] })),
  http.post('/api/v1/auth/logout', () => new HttpResponse(null, { status: 204 })),
  // Phase 8: the Backups, HTTPS certificate and Audit forwarding tabs and the wizard's HTTPS step.
  http.get('/api/v1/backups', () => HttpResponse.json(backupListFixture())),
  http.get('/api/v1/settings/backups', () => HttpResponse.json(backupScheduleFixture())),
  http.get('/api/v1/settings/https', () => HttpResponse.json(httpsInfoFixture())),
  http.get('/api/v1/settings/audit-forwarding', () => HttpResponse.json(forwardingFixture())),
  // The wizard's mail step is the Settings mail form.
  http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)),
  // Phase 9: the Key rotations page and the run page read every policy; the rotations page reads the runs.
  http.get('/api/v1/rotation/policies', () => HttpResponse.json({ items: [] })),
  http.get('/api/v1/rotation/runs', () => HttpResponse.json({ items: [], next_cursor: null })),
  // Network discovery: the Certificates page reads the summary for its link (no scope by default: no link).
  // Services (R49): the list toolbars read the services and the environments for their filters.
  http.get('/api/v1/services', () => HttpResponse.json({ items: [] })),
  http.get('/api/v1/environments', () => HttpResponse.json({ items: [] })),
  http.get('/api/v1/discovery/summary', () => HttpResponse.json({ unmanaged_total: 0, unmanaged_expiring_30d: 0, scopes: 0, last_scan_at: null })),
];

export const server = setupServer(...handlers);
