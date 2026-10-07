import { screen } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import type { Condition } from '../../api/phase7';
import { adminSession, sessionHandlers, targetFixture } from '../../test/fixtures';
import { renderWithAuth } from '../../test/render';
import { server } from '../../test/server';
import { AttentionList } from './AttentionList';

const cond = (kind: string, id: string, name: string): Condition => ({ kind, object_id: id, name, since: '2026-10-06T09:00:00Z', error_code: '' });
const vault = { ...targetFixture, id: 'v-1', name: 'prod-vault', type: 'azure_key_vault' };

describe('AttentionList', () => {
  it('links an authentication failure of a Key Vault to its Key Vault page and of a server to the server', async () => {
    server.use(
      ...sessionHandlers(adminSession),
      http.get('/api/v1/targets', ({ request }) =>
        HttpResponse.json({ items: new URL(request.url).searchParams.get('type') === 'azure_key_vault' ? [vault] : [], next_cursor: null }),
      ),
    );
    await renderWithAuth(<AttentionList items={[cond('auth_failed', 'v-1', 'prod-vault'), cond('auth_failed', 's-1', 'web-1'), cond('host_key_changed', 's-2', 'web-2')]} />);
    const links = await screen.findAllByRole('link');
    await vi.waitFor(() => expect(screen.getAllByRole('link').map((l) => l.getAttribute('href'))).toEqual(['/key-vaults/v-1', '/servers/s-1', '/servers/s-2']));
    expect(links).toHaveLength(3);
  });

  it('asks for the vaults only when a condition could name one', async () => {
    let asked = 0;
    server.use(...sessionHandlers(adminSession), http.get('/api/v1/targets', () => { asked++; return HttpResponse.json({ items: [], next_cursor: null }); }));
    await renderWithAuth(<AttentionList items={[cond('host_key_changed', 's-2', 'web-2'), cond('deployment_failed', 'd-1', 'x'), cond('audit_broken', '', ''), cond('notifications_failing', '', '')]} />);
    expect(await screen.findByRole('link', { name: 'Server identity changed' })).toHaveAttribute('href', '/servers/s-2');
    expect(asked).toBe(0);
  });
});
