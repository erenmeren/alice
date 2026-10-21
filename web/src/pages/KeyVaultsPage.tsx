import { Anchor, Button, Code, Stack, Table } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router';
import { listAllTargets } from '../api/endpoints';
import { VAULTS_KEY } from '../api/queryKeys';
import type { Target } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { can } from '../auth/permissions';
import { AddKeyVaultDialog } from '../components/AddKeyVaultDialog';
import { BlockedJobsPanel } from '../components/BlockedJobsPanel';
import { ErrorAlert } from '../components/ErrorAlert';
import { reasonTitle } from '../components/JobErrorAlert';
import { LoadingIndicator } from '../components/LoadingIndicator';
import { EmptyState, Notice, PageHeader, Panel, ResourceTable } from '../components/ui';
import { authKey } from '../components/vaultText';
import { VaultStatusBadge } from '../components/VaultStatusBadge';
import { formatDateTime } from '../datetime';
import { Icon } from '../design/Icon';
import classes from './KeyVaults.module.css';

// KeyVaultsPage lists the Azure Key Vaults for every role (metadata only, never credentials).
// Administrators also get "Add Key Vault" and the changes paused while the license was expired.
// The design draws one card per vault; the product keeps a table (one row per vault, the e2e finds rows by their
// name link, and it scales past a handful of vaults) with the card's content in its cells.
export function KeyVaultsPage() {
  const { t } = useTranslation();
  const { session } = useAuth();
  const navigate = useNavigate();
  // Adding a vault stores its credentials: credentials.manage on some service.
  const canAdd = can(session, 'credentials.manage');
  const canConfirmJobs = can(session, 'jobs.confirm');
  const vaults = useQuery({ queryKey: VAULTS_KEY, queryFn: () => listAllTargets('azure_key_vault') });
  const [adding, setAdding] = useState(false);
  const items = vaults.data?.items ?? [];

  return (
    <Stack gap={0}>
      <PageHeader
        title={t('vaults.title')}
        description={t('vaults.page.description')}
        actions={
          canAdd && (
            <Button leftSection={<Icon name="Plus" size={15} />} onClick={() => setAdding(true)}>
              {t('vaults.add')}
            </Button>
          )
        }
      />
      <Stack gap="lg">
        <ErrorAlert error={vaults.error} />
        {vaults.isPending && <LoadingIndicator />}
        {canConfirmJobs && <BlockedJobsPanel />}
        {vaults.isSuccess && items.length === 0 && (
          <Panel>
            <EmptyState icon="Cloud" title={t('vaults.empty')} description={t('vaults.intro')} />
          </Panel>
        )}
        {items.length > 0 && <VaultsTable items={items} />}
        <Notice tone="brand" title={t('vaults.page.boundaryTitle')}>
          {t('vaults.page.boundaryText')}
        </Notice>
      </Stack>
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

// VaultsTable is the design's vault card as a row: the Azure tile with the name and address, the state, how Alice
// signs in and when it last reached the vault. The design's certificate/key/secret counts are not shown: the vault
// list carries none, and counts of a paged inventory would not be totals (R20).
function VaultsTable({ items }: { items: Target[] }) {
  const { t, i18n } = useTranslation();
  return (
    <ResourceTable label={t('vaults.tableLabel')} testId="vaults-table" minWidth={720}>
      <Table.Thead>
        <Table.Tr>
          <Table.Th>{t('vaults.columns.name')}</Table.Th>
          <Table.Th>{t('vaults.columns.status')}</Table.Th>
          <Table.Th>{t('vaults.columns.auth')}</Table.Th>
          <Table.Th>{t('vaults.columns.checked')}</Table.Th>
        </Table.Tr>
      </Table.Thead>
      <Table.Tbody>
        {items.map((v) => (
          <Table.Tr key={v.id}>
            <Table.Td>
              <div className={classes.resourceName}>
                <span className={classes.resourceIcon} data-tone="info">
                  <Icon name="Cloud" size={16} />
                </span>
                <div className={classes.resourceText}>
                  <Anchor component={Link} to={`/key-vaults/${v.id}`} className={classes.name} translate="no">
                    {v.name}
                  </Anchor>
                  <p className={classes.secondary}>
                    <Code translate="no">{v.vault?.url ?? v.host}</Code>
                  </p>
                </div>
              </div>
            </Table.Td>
            <Table.Td>
              <VaultStatusBadge target={v} />
              {v.last_error && <p className={classes.secondary}>{reasonTitle(t, i18n, v.last_error.reason, v.last_error.params ?? {})}</p>}
            </Table.Td>
            <Table.Td>
              {v.vault && <span className={classes.small}>{t(authKey(v.vault.auth))}</span>}
            </Table.Td>
            <Table.Td>
              {v.last_success_at ? <span className={classes.mono}>{formatDateTime(v.last_success_at, i18n.language)}</span> : <span className={classes.small}>{t('vaults.neverChecked')}</span>}
            </Table.Td>
          </Table.Tr>
        ))}
      </Table.Tbody>
    </ResourceTable>
  );
}
