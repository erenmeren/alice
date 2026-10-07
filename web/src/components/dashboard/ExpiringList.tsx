import { Anchor, Code, Group, Table, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { ExpiringItem } from '../../api/phase7';
import { Expiry } from '../Expiry';
import { WRAP } from '../wrap';
import { Widget } from './Widget';

// itemPath is where an expiring item is managed: a certificate's page, a Key Vault certificate's page, else the vault.
function itemPath(i: ExpiringItem): string | null {
  if (i.kind === 'certificate_expiry') return `/certificates/${encodeURIComponent(i.object_id)}`;
  if (!i.vault_id) return null;
  if (i.kind === 'kv_certificate_expiry') return `/key-vaults/${encodeURIComponent(i.vault_id)}/certificates/${encodeURIComponent(i.object_id)}`;
  return `/key-vaults/${encodeURIComponent(i.vault_id)}`;
}

// where names the vault, else the websites other than the certificate's own name, else the servers.
function where(i: ExpiringItem): string[] {
  if (i.vault) return [i.vault];
  const sites = i.websites.filter((w) => w !== i.name);
  return sites.length > 0 ? sites : i.servers;
}

export function ExpiringList({ items }: { items: ExpiringItem[] }) {
  const { t } = useTranslation();
  return (
    <Widget title={t('dashboard.expiringSoon')} testId="expiring-list">
      {items.length === 0 ? (
        <Text c="gray.7">{t('dashboard.noneExpiring')}</Text>
      ) : (
        <Table.ScrollContainer minWidth={420}>
          <Table aria-label={t('dashboard.expiringSoon')}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t('dashboard.columns.name')}</Table.Th>
                <Table.Th>{t('dashboard.columns.where')}</Table.Th>
                <Table.Th>{t('dashboard.columns.expires')}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((i) => {
                const to = itemPath(i);
                const name = (
                  <Code translate="no" style={WRAP}>
                    {i.name}
                  </Code>
                );
                return (
                  <Table.Tr key={`${i.kind}:${i.object_id}`}>
                    <Table.Td style={WRAP}>{to ? <Anchor component={Link} to={to}>{name}</Anchor> : name}</Table.Td>
                    <Table.Td style={WRAP}>
                      <Group gap={4}>
                        {where(i).map((w) => (
                          <Code key={w} translate="no" style={WRAP}>
                            {w}
                          </Code>
                        ))}
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Expiry notAfter={i.expires_at} />
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Widget>
  );
}
