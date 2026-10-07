import { screen } from '@testing-library/react';
import type { ExpiringItem } from '../../api/phase7';
import { renderWithAuth } from '../../test/render';
import { ExpiringList } from './ExpiringList';

const item = (over: Partial<ExpiringItem>): ExpiringItem => ({
  kind: 'certificate_expiry', object_id: 'c1', name: 'n', expires_at: '2026-10-14T08:00:00Z', days_left: 7, expired: false,
  fingerprint: 'f', websites: [], servers: [], target_ids: [], vault: '', vault_id: null, ...over,
});

describe('ExpiringList', () => {
  it('links by kind and the vault of the item, never by the shape of an id', async () => {
    await renderWithAuth(
      <ExpiringList
        items={[
          item({ kind: 'certificate_expiry', object_id: 'c1', name: 'cert-a' }),
          item({ kind: 'kv_certificate_expiry', object_id: 'weird id/1', name: 'kv-cert', vault: 'prod', vault_id: 'v-1' }),
          item({ kind: 'kv_key_expiry', object_id: 'kx', name: 'kv-key', vault: 'prod', vault_id: 'v-1' }),
          item({ kind: 'kv_certificate_expiry', object_id: 'no-vault', name: 'orphan', vault_id: null }),
          item({ kind: 'something_new', object_id: 'q', name: 'future', vault: 'prod', vault_id: 'v-1' }),
        ]}
      />,
    );
    const href = (n: string) => screen.queryByRole('link', { name: n })?.getAttribute('href') ?? null;
    expect(href('cert-a')).toBe('/certificates/c1');
    expect(href('kv-cert')).toBe('/key-vaults/v-1/certificates/weird%20id%2F1');
    expect(href('kv-key')).toBe('/key-vaults/v-1');
    expect(href('orphan')).toBeNull();
    expect(href('future')).toBeNull();
    expect(screen.getByText('future')).toBeInTheDocument();
  });
});
