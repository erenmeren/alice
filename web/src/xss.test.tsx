// A-11 (spec §25): hostile names and reasons that reach the browser through the API (certificate common
// names and labels, server names and addresses, SSH key comments, audit actors, objects and reasons) are
// shown as text: no element, attribute or script of theirs enters the page. React escapes every text
// node and SEC-035 bans dangerouslySetInnerHTML (ESLint); the CSP of the page (csp.test.ts, the Go
// TestSecurityHeadersOnEveryResponse and the e2e smoke "security headers are present") is the second line.
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { AuditEntry } from './api/types';
import { adminSession, certificateFixture, sessionHandlers, sshKeyFixture, targetWith } from './test/fixtures';
import { renderRoute } from './test/render';
import { server } from './test/server';

const PAYLOADS = [
  '<script>window.__xss=1</script>',
  '<img src=x onerror="window.__xss=1">',
  '"><svg onload=window.__xss=1>',
  "javascript:window.__xss=1//<a href='javascript:1'>x</a>",
];

declare global {
  interface Window {
    __xss?: number;
  }
}

function expectInert(container: HTMLElement) {
  expect(window.__xss).toBeUndefined();
  expect(container.querySelector('script, svg[onload], img[onerror], [onerror], [onload]')).toBeNull();
  for (const a of container.querySelectorAll('a')) {
    expect(a.getAttribute('href') ?? '').not.toMatch(/^\s*javascript:/i);
  }
}

describe('A-11: hostile names render as text', () => {
  beforeEach(() => {
    delete window.__xss;
    server.use(...sessionHandlers(adminSession));
  });

  it('the check sees an injected element (positive control)', () => {
    const div = document.createElement('div');
    div.innerHTML = PAYLOADS[1];
    expect(() => expectInert(div)).toThrow();
  });

  it.each(PAYLOADS)('certificates list: %s', async (p) => {
    server.use(
      http.get('/api/v1/targets', () => HttpResponse.json({ items: [], next_cursor: null })),
      http.get('/api/v1/certificates/csr', () => HttpResponse.json({ items: [] })),
      http.get('/api/v1/certificates', () =>
        HttpResponse.json({
          items: [certificateFixture({ id: 'c1', subject_cn: p }), certificateFixture({ id: 'c2', subject_cn: 'x', label: `label ${p}` })],
          next_cursor: null,
        }),
      ),
    );
    const { container } = await renderRoute('/certificates');
    expect(await screen.findByText(p)).toBeInTheDocument();
    expect(screen.getByText(`label ${p}`)).toBeInTheDocument();
    expectInert(container);
  });

  it.each(PAYLOADS)('servers list: %s', async (p) => {
    server.use(http.get('/api/v1/targets', () => HttpResponse.json({ items: [targetWith({ name: p, host: `h${p}` })], next_cursor: null })));
    const { container } = await renderRoute('/servers');
    expect(await screen.findByText(p)).toBeInTheDocument();
    expectInert(container);
  });

  it.each(PAYLOADS)('SSH keys list: %s', async (p) => {
    server.use(
      http.get('/api/v1/targets', () => HttpResponse.json({ items: [], next_cursor: null })),
      http.get('/api/v1/ssh-keys', () => HttpResponse.json({ items: [sshKeyFixture({ comment: p })], next_cursor: null })),
    );
    const { container } = await renderRoute('/ssh-keys');
    expect(await screen.findByText(p)).toBeInTheDocument();
    expectInert(container);
  });

  it.each(PAYLOADS)('audit log actor, object and reason: %s', async (p) => {
    const entry: AuditEntry = {
      seq: 1,
      at: '2026-09-30T08:00:00Z',
      actor_type: 'user',
      actor_id: adminSession.user.id,
      actor_name: `actor ${p}`,
      ip: '10.0.0.7',
      action: 'sshkey.private_key_downloaded',
      object_type: 'ssh_key',
      object_id: `object ${p}`,
      result: 'success',
      details: { reason: `reason ${p}` },
      request_id: 'req-1',
      hash: 'ab'.repeat(32),
    };
    server.use(http.get('/api/v1/audit', () => HttpResponse.json({ items: [entry], next_cursor: null })));
    const { container } = await renderRoute('/audit');
    const row = (await screen.findAllByRole('row'))[1];
    await userEvent.click(within(row).getByRole('button', { name: /Details/ }));
    expect(within(row).getByText(`reason ${p}`)).toBeInTheDocument();
    expect(within(row).getByText(`actor ${p}`, { exact: false })).toBeInTheDocument();
    expectInert(container);
  });
});
