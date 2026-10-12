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
    // A failed sign-in is linked once the vaults are read (it could be a Key Vault's).
    await vi.waitFor(() => expect(screen.getAllByRole('link').map((l) => l.getAttribute('href'))).toEqual(['/key-vaults/v-1', '/servers/s-1', '/servers/s-2']));
    expect(screen.getAllByRole('listitem')).toHaveLength(3);
    expect(screen.getByText('prod-vault', { exact: true })).toBeVisible();
    expect(screen.getByText('3 open')).toBeVisible();
  });

  it('asks for the vaults only when a condition could name one', async () => {
    let asked = 0;
    server.use(...sessionHandlers(adminSession), http.get('/api/v1/targets', () => { asked++; return HttpResponse.json({ items: [], next_cursor: null }); }));
    await renderWithAuth(<AttentionList items={[cond('host_key_changed', 's-2', 'web-2'), cond('deployment_failed', 'd-1', 'x'), cond('audit_broken', '', ''), cond('notifications_failing', '', '')]} />);
    // The link is named by what happened, then the resource and since when (the design's attention row).
    expect(await screen.findByRole('link', { name: /^Server identity changed\s*web-2\s*Since / })).toHaveAttribute('href', '/servers/s-2');
    expect(screen.getByRole('link', { name: /^The last check found an integrity problem/ })).toHaveAttribute('href', '/audit');
    expect(asked).toBe(0);
  });
});
