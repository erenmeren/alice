import { Anchor, Button, Stack, Table, Text } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router';
import { SERVICE_LIST_KEY } from '../api/queryKeys';
import { listServices, type Service } from '../api/services';
import { useAuth } from '../auth/AuthProvider';
import { ErrorAlert } from '../components/ErrorAlert';
import { ServiceDialog } from '../components/services/ServiceDialog';
import { EnvironmentBadge } from '../components/services/shared';
import { EmptyState, PageHeader, Panel, ResourceTable, StatusBadge } from '../components/ui';
import { Icon } from '../design/Icon';

// resourceSummary lists what a service owns, the kinds it has any of ("3 servers, 1 Key Vault, 12 certificates").
export function resourceSummary(t: (k: string, o?: Record<string, unknown>) => string, s: Service): string {
  const parts = (
    [
      ['servers', s.counts.servers],
      ['keyVaults', s.counts.key_vaults],
      ['certificates', s.counts.certificates],
      ['acmeCertificates', s.counts.acme_certificates],
      ['sshKeys', s.counts.ssh_keys],
      ['scopes', s.counts.discovery_scopes],
    ] as const
  )
    .filter(([, n]) => n > 0)
    .map(([k, n]) => t(`services.counts.${k}`, { count: n }));
  return parts.length > 0 ? parts.join(', ') : t('services.counts.none');
}

// ServicesPage lists the services (R49): every role reads them; an Administrator adds one. Every resource belongs to one
// service, the Default service until an Administrator moves it.
export function ServicesPage() {
  const { t } = useTranslation();
  const { session } = useAuth();
  const navigate = useNavigate();
  const admin = session?.user.role === 'admin';
  const services = useQuery({ queryKey: SERVICE_LIST_KEY, queryFn: ({ signal }) => listServices(signal) });
  const [adding, setAdding] = useState(false);
  const items = services.data?.items ?? [];
  return (
    <Stack gap={0}>
      <PageHeader
        title={t('services.title')}
        description={t('services.page.description')}
        actions={
          admin && (
            <Button leftSection={<Icon name="Plus" size={15} />} onClick={() => setAdding(true)}>
              {t('services.add')}
            </Button>
          )
        }
      />
      <Stack gap="lg">
        <ErrorAlert error={services.error} />
        {services.isSuccess && items.length === 0 && (
          <Panel>
            <EmptyState icon="Layers" title={t('services.empty')} />
          </Panel>
        )}
        {items.length > 0 && (
          <ResourceTable label={t('services.title')} testId="services-table" minWidth={720}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t('services.columns.service')}</Table.Th>
                <Table.Th>{t('services.columns.environment')}</Table.Th>
                <Table.Th>{t('services.columns.resources')}</Table.Th>
                <Table.Th>{t('services.columns.policy')}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((s) => (
                <Table.Tr key={s.id} data-testid="service-row">
                  <Table.Td>
                    <Stack gap={2}>
                      <Anchor component={Link} to={`/services/${s.id}`} fw={600} translate="no">
                        {s.name}
                      </Anchor>
                      {s.is_default && (
                        <StatusBadge tone="neutral" size="sm">
                          {t('services.default')}
                        </StatusBadge>
                      )}
                    </Stack>
                  </Table.Td>
                  <Table.Td>{s.environment ? <EnvironmentBadge environment={s.environment} /> : <Text size="sm" c="dimmed">{t('services.noEnvironment')}</Text>}</Table.Td>
                  <Table.Td>
                    <Text size="sm">{resourceSummary(t, s)}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{t('services.policyVersion', { version: s.policy_version })}</Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </ResourceTable>
        )}
      </Stack>
      {adding && <ServiceDialog onClose={() => setAdding(false)} onSaved={(s) => navigate(`/services/${s.id}`)} />}
    </Stack>
  );
}
