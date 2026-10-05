import { Anchor, Button, Code, Group, Stack, Table, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router';
import { listAllTargets } from '../api/endpoints';
import { VAULTS_KEY } from '../api/queryKeys';
import { useAuth } from '../auth/AuthProvider';
import { AddKeyVaultDialog } from '../components/AddKeyVaultDialog';
import { BlockedJobsPanel } from '../components/BlockedJobsPanel';
import { ErrorAlert } from '../components/ErrorAlert';
import { reasonTitle } from '../components/JobErrorAlert';
import { LoadingIndicator } from '../components/LoadingIndicator';
import { authKey } from '../components/vaultText';
import { VaultStatusBadge } from '../components/VaultStatusBadge';
import { WRAP } from '../components/wrap';
import { formatDateTime } from '../datetime';

// KeyVaultsPage lists the Azure Key Vaults for every role (metadata only, never credentials).
// Administrators also get "Add Key Vault" and the changes paused while the license was expired.
export function KeyVaultsPage() {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  const navigate = useNavigate();
  const admin = session?.user.role === 'admin';
  const vaults = useQuery({ queryKey: VAULTS_KEY, queryFn: () => listAllTargets('azure_key_vault') });
  const [adding, setAdding] = useState(false);
  const items = vaults.data?.items ?? [];

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Title order={1}>{t('vaults.title')}</Title>
        {admin && <Button onClick={() => setAdding(true)}>{t('vaults.add')}</Button>}
      </Group>
      <Text size="sm">{t('vaults.intro')}</Text>
      <ErrorAlert error={vaults.error} />
      {vaults.isPending && <LoadingIndicator />}
      {vaults.isSuccess && items.length === 0 && <Text c="gray.7">{t('vaults.empty')}</Text>}
      {items.length > 0 && (
        <Table.ScrollContainer minWidth={720}>
          <Table striped data-testid="vaults-table" aria-label={t('vaults.tableLabel')}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t('vaults.columns.name')}</Table.Th>
                <Table.Th>{t('vaults.columns.address')}</Table.Th>
                <Table.Th>{t('vaults.columns.status')}</Table.Th>
                <Table.Th>{t('vaults.columns.auth')}</Table.Th>
                <Table.Th>{t('vaults.columns.checked')}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((v) => (
                <Table.Tr key={v.id}>
                  <Table.Td style={WRAP}>
                    <Anchor component={Link} to={`/key-vaults/${v.id}`} translate="no">
                      {v.name}
                    </Anchor>
                  </Table.Td>
                  <Table.Td>
                    <Code translate="no" style={WRAP}>
                      {v.vault?.url ?? v.host}
                    </Code>
                  </Table.Td>
                  <Table.Td>
                    <Stack gap={2}>
                      <VaultStatusBadge target={v} />
                      {v.last_error && (
                        <Text size="xs" style={WRAP}>
                          {reasonTitle(t, i18n, v.last_error.reason, v.last_error.params ?? {})}
                        </Text>
                      )}
                    </Stack>
                  </Table.Td>
                  <Table.Td>{v.vault ? t(authKey(v.vault.auth)) : ''}</Table.Td>
                  <Table.Td>{v.last_success_at ? formatDateTime(v.last_success_at, i18n.language) : t('vaults.neverChecked')}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      {admin && <BlockedJobsPanel />}
      {adding && (
        <AddKeyVaultDialog
          onClose={() => setAdding(false)}
          onAdded={(v) => {
            setAdding(false);
            navigate(`/key-vaults/${v.id}`);
          }}
        />
      )}
    </Stack>
  );
}
