import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { licenseDetailFixture, platformKeyFixture, sessionHandlers } from './fixtures';

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
  http.post('/api/v1/auth/logout', () => new HttpResponse(null, { status: 204 })),
];

export const server = setupServer(...handlers);
