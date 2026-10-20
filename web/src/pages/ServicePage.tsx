import { Anchor, Button, Group, Loader, NativeSelect, Stack, Table, Tabs, Text } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate, useParams } from 'react-router';
import { listACMECertificates } from '../api/acme';
import { listAllDiscoveryScopes } from '../api/discovery';
import { listAllTargets, listCertificates, listSSHKeys } from '../api/endpoints';
import { SERVICE_LIST_KEY, SERVICE_TRUSTS_KEY, serviceKey, servicePolicyKey, serviceResourcesKey, SERVICES_KEY } from '../api/queryKeys';
import { createTrust, deleteService, deleteTrust, getService, getServicePolicy, listServices, listTrusts, type Service, type ServiceTrust } from '../api/services';
import { useAuth } from '../auth/AuthProvider';
import { AppModal } from '../components/AppModal';
import { ErrorAlert } from '../components/ErrorAlert';
import { MoveDialog } from '../components/services/MoveDialog';
import { ServiceDialog } from '../components/services/ServiceDialog';
import { EnvironmentBadge } from '../components/services/shared';
import { useStepUp } from '../components/StepUpProvider';
import { DialogActions, EmptyState, FactList, PageHeader, Panel, StatusBadge } from '../components/ui';
import { formatDateTime } from '../datetime';
import { useUrlFilters } from '../hooks/useUrlFilters';
import { resourceSummary } from './ServicesPage';

const TABS = ['overview', 'resources', 'trusts'] as const;
type Tab = (typeof TABS)[number];
const TAB_KEYS = ['tab'] as const;

// ServicePage is one service (R49): its environment, description and policy (Overview), what it owns (Resources, with
// Move here) and which services it accepts certificates and keys from or sends them to (Trusts). Every role reads it;
// changes are an Administrator's with a fresh step-up.
export function ServicePage() {
  const { id = '' } = useParams();
  const { t } = useTranslation();
  const { session } = useAuth();
  const admin = session?.user.role === 'admin';
  const navigate = useNavigate();
  const [filters, setFilters] = useUrlFilters(TAB_KEYS);
  const tab: Tab = (TABS as readonly string[]).includes(filters.tab) ? (filters.tab as Tab) : 'overview';
  const service = useQuery({ queryKey: serviceKey(id), queryFn: ({ signal }) => getService(id, signal) });
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const s = service.data;
  if (!s) {
    return (
      <Stack>
        <ErrorAlert error={service.error} />
        {service.isPending && <Loader size="sm" aria-label={t('ui.loading')} />}
      </Stack>
    );
  }
  const empty = s.counts.servers + s.counts.key_vaults + s.counts.certificates + s.counts.signing_requests + s.counts.acme_certificates + s.counts.ssh_keys + s.counts.discovery_scopes === 0;
  return (
    <Stack gap="md">
      <PageHeader
        back={{ to: '/services', label: t('services.back') }}
        icon="Layers"
        title={<span translate="no">{s.name}</span>}
        status={
          <Group gap={6}>
            <EnvironmentBadge environment={s.environment} />
            {s.is_default && (
              <StatusBadge tone="neutral" size="sm">
                {t('services.default')}
              </StatusBadge>
            )}
          </Group>
        }
        description={resourceSummary(t, s)}
        actions={
          admin && (
            <>
              <Button variant="default" onClick={() => setEditing(true)}>
                {t('services.edit')}
              </Button>
              {!s.is_default && (
                <Button variant="light" color="red" disabled={!empty} title={empty ? undefined : t('services.deleteNotEmpty')} onClick={() => setDeleting(true)}>
                  {t('services.delete')}
                </Button>
              )}
            </>
          )
        }
      />
      <Tabs value={tab} onChange={(v) => v && setFilters({ tab: v === 'overview' ? '' : v })} keepMounted={false}>
        <Tabs.List aria-label={t('services.tabsLabel')}>
          {TABS.map((x) => (
            <Tabs.Tab key={x} value={x}>
              {t(`services.tabs.${x}`)}
            </Tabs.Tab>
          ))}
        </Tabs.List>
        <Tabs.Panel value="overview" pt="md">
          <Overview service={s} />
        </Tabs.Panel>
        <Tabs.Panel value="resources" pt="md">
          <Resources service={s} admin={admin} />
        </Tabs.Panel>
        <Tabs.Panel value="trusts" pt="md">
          <Trusts service={s} admin={admin} />
        </Tabs.Panel>
      </Tabs>
      {editing && <ServiceDialog service={s} onClose={() => setEditing(false)} />}
      {deleting && <DeleteService service={s} onClose={() => setDeleting(false)} onDeleted={() => navigate('/services')} />}
    </Stack>
  );
}

function Overview({ service }: { service: Service }) {
  const { t, i18n } = useTranslation();
  const policy = useQuery({ queryKey: servicePolicyKey(service.id), queryFn: ({ signal }) => getServicePolicy(service.id, signal) });
  return (
    <Stack gap="md">
      <Panel title={t('services.overview.title')}>
        <FactList
          facts={[
            { label: t('services.fields.environment'), value: service.environment ? <EnvironmentBadge environment={service.environment} /> : t('services.noEnvironment') },
            { label: t('services.fields.description'), value: service.description || t('services.overview.noDescription') },
            { label: t('services.overview.created'), value: formatDateTime(service.created_at, i18n.language) },
          ]}
        />
      </Panel>
      <Panel title={t('services.policy.title')} description={t('services.policy.description')}>
        <ErrorAlert error={policy.error} />
        {policy.data && (
          <FactList
            facts={[
              { label: t('services.policy.version'), value: t('services.policyVersion', { version: policy.data.version }), testId: 'policy-version' },
              { label: t('services.policy.rules'), value: Object.keys(policy.data.body).filter((k) => k !== 'schema').length === 0 ? t('services.policy.none') : t('services.policy.some') },
              {
                label: t('services.policy.changed'),
                value: policy.data.created_by_name
                  ? t('services.policy.changedBy', { name: policy.data.created_by_name, date: formatDateTime(policy.data.created_at, i18n.language) })
                  : formatDateTime(policy.data.created_at, i18n.language),
              },
            ]}
          />
        )}
      </Panel>
    </Stack>
  );
}

interface Row {
  id: string;
  name: string;
  to: string;
}

// ResourceList is one kind of what the service owns: the first rows, each linked to its page, and a link to the full list
// filtered on the service.
function ResourceList({ title, rows, error, loading, more, empty }: { title: string; rows: Row[] | undefined; error: unknown; loading: boolean; more?: string; empty: string }) {
  const { t } = useTranslation();
  return (
    <Panel title={title} action={more ? <Anchor component={Link} to={more} size="sm">{t('services.resources.all')}</Anchor> : undefined}>
      <ErrorAlert error={error} />
      {loading && <Loader size="xs" aria-label={t('ui.loading')} />}
      {rows && rows.length === 0 && (
        <Text size="sm" c="dimmed">
          {empty}
        </Text>
      )}
      {rows && rows.length > 0 && (
        <Stack gap={4}>
          {rows.map((r) => (
            <Anchor key={r.id} component={Link} to={r.to} size="sm" translate="no">
              {r.name}
            </Anchor>
          ))}
        </Stack>
      )}
    </Panel>
  );
}

function Resources({ service, admin }: { service: Service; admin: boolean }) {
  const { t } = useTranslation();
  const [moving, setMoving] = useState(false);
  const sid = service.id;
  const mine = <T extends { service?: { id: string } }>(items: T[]) => items.filter((x) => x.service?.id === sid);
  const targets = useQuery({ queryKey: serviceResourcesKey(sid, 'targets'), queryFn: async () => mine((await listAllTargets()).items) });
  const certs = useQuery({ queryKey: serviceResourcesKey(sid, 'certificates'), queryFn: () => listCertificates({ service_id: sid, limit: 50 }) });
  const acme = useQuery({ queryKey: serviceResourcesKey(sid, 'acme'), queryFn: () => listACMECertificates({ service_id: sid, limit: 50 }) });
  const keys = useQuery({ queryKey: serviceResourcesKey(sid, 'ssh-keys'), queryFn: () => listSSHKeys({ service_id: sid, limit: 50 }) });
  const scopes = useQuery({ queryKey: serviceResourcesKey(sid, 'scopes'), queryFn: async () => mine((await listAllDiscoveryScopes()).items) });
  const servers = targets.data?.filter((x) => x.type !== 'azure_key_vault');
  const vaults = targets.data?.filter((x) => x.type === 'azure_key_vault');
  const q = `service_id=${encodeURIComponent(sid)}`;
  const sections: ReactNode[] = [
    <ResourceList key="servers" title={t('services.kinds.servers')} rows={servers?.map((x) => ({ id: x.id, name: x.name, to: `/servers/${x.id}` }))} error={targets.error} loading={targets.isPending} more={`/servers?${q}`} empty={t('services.resources.none')} />,
    <ResourceList key="vaults" title={t('services.kinds.keyVaults')} rows={vaults?.map((x) => ({ id: x.id, name: x.name, to: `/key-vaults/${x.id}` }))} error={targets.error} loading={targets.isPending} empty={t('services.resources.none')} />,
    <ResourceList
      key="certificates"
      title={t('services.kinds.certificate')}
      rows={certs.data?.items.map((x) => ({ id: x.id, name: x.label || x.subject_cn || x.fingerprint.slice(0, 16), to: `/certificates/${x.id}` }))}
      error={certs.error}
      loading={certs.isPending}
      more={`/certificates?${q}`}
      empty={t('services.resources.none')}
    />,
    <ResourceList key="acme" title={t('services.kinds.acme_certificate')} rows={acme.data?.items.map((x) => ({ id: x.id, name: x.names[0] ?? x.id, to: `/acme/${x.id}` }))} error={acme.error} loading={acme.isPending} more={`/acme?${q}`} empty={t('services.resources.none')} />,
    <ResourceList key="keys" title={t('services.kinds.ssh_key')} rows={keys.data?.items.map((x) => ({ id: x.id, name: x.comment || x.fingerprint, to: `/ssh-keys/${x.id}` }))} error={keys.error} loading={keys.isPending} more={`/ssh-keys?${q}`} empty={t('services.resources.none')} />,
    <ResourceList key="scopes" title={t('services.kinds.discovery_scope')} rows={scopes.data?.map((x) => ({ id: x.id, name: x.name, to: '/discovery?tab=scopes' }))} error={scopes.error} loading={scopes.isPending} empty={t('services.resources.none')} />,
  ];
  return (
    <Stack gap="md">
      {admin && (
        <Group>
          <Button onClick={() => setMoving(true)}>{t('services.moveHere')}</Button>
        </Group>
      )}
      {sections}
      {moving && <MoveDialog destination={{ id: service.id, name: service.name, environment: service.environment }} onClose={() => setMoving(false)} />}
    </Stack>
  );
}

function Trusts({ service, admin }: { service: Service; admin: boolean }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const trusts = useQuery({ queryKey: [...SERVICE_TRUSTS_KEY, service.id], queryFn: ({ signal }) => listTrusts(service.id, signal) });
  const services = useQuery({ queryKey: SERVICE_LIST_KEY, queryFn: ({ signal }) => listServices(signal), enabled: admin });
  const [direction, setDirection] = useState<'accepts' | 'sends'>('accepts');
  const [other, setOther] = useState('');
  const refresh = () => client.invalidateQueries({ queryKey: SERVICES_KEY });
  const add = useMutation({
    mutationFn: () => run(() => (direction === 'accepts' ? createTrust(other, service.id) : createTrust(service.id, other))),
    onSuccess: async () => {
      setOther('');
      await refresh();
    },
  });
  const remove = useMutation({ mutationFn: (id: string) => run(() => deleteTrust(id)), onSuccess: refresh });
  const items = trusts.data?.items ?? [];
  const accepts = items.filter((x) => x.target.id === service.id);
  const sends = items.filter((x) => x.source.id === service.id);
  const list = (rows: ServiceTrust[], side: 'source' | 'target', testId: string) =>
    !trusts.isSuccess ? null : rows.length === 0 ? (
      <EmptyState icon="Link2" title={t('services.trusts.none')} testId={testId} />
    ) : (
      <Table data-testid={testId}>
        <Table.Tbody>
          {rows.map((x) => (
            <Table.Tr key={x.id}>
              <Table.Td>
                <Group gap={6}>
                  <Anchor component={Link} to={`/services/${x[side].id}`} translate="no">
                    {x[side].name}
                  </Anchor>
                  <EnvironmentBadge environment={x[side].environment} />
                </Group>
              </Table.Td>
              {admin && (
                <Table.Td style={{ textAlign: 'end' }}>
                  <Button size="xs" variant="subtle" color="red" loading={remove.isPending && remove.variables === x.id} onClick={() => remove.mutate(x.id)}>
                    {t('services.trusts.remove')}
                  </Button>
                </Table.Td>
              )}
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    );
  return (
    <Stack gap="md">
      <Text size="sm">{t('services.trusts.intro')}</Text>
      <ErrorAlert error={trusts.error ?? remove.error} />
      <Panel title={t('services.trusts.accepts')}>{list(accepts, 'source', 'trusts-accepts')}</Panel>
      <Panel title={t('services.trusts.sends')}>{list(sends, 'target', 'trusts-sends')}</Panel>
      {admin && (
        <Panel title={t('services.trusts.addTitle')}>
          <Stack gap="sm">
            <Group align="flex-end">
              <NativeSelect
                label={t('services.trusts.direction')}
                value={direction}
                onChange={(e) => setDirection(e.currentTarget.value as 'accepts' | 'sends')}
                data={[
                  { value: 'accepts', label: t('services.trusts.accepts') },
                  { value: 'sends', label: t('services.trusts.sends') },
                ]}
              />
              <NativeSelect
                label={t('services.trusts.other')}
                value={other}
                onChange={(e) => setOther(e.currentTarget.value)}
                data={[{ value: '', label: t('services.move.pickService') }, ...(services.data?.items ?? []).filter((x) => x.id !== service.id).map((x) => ({ value: x.id, label: x.name }))]}
              />
              <Button disabled={!other} loading={add.isPending} onClick={() => add.mutate()}>
                {t('services.trusts.add')}
              </Button>
            </Group>
            <ErrorAlert error={add.error} />
          </Stack>
        </Panel>
      )}
    </Stack>
  );
}

function DeleteService({ service, onClose, onDeleted }: { service: Service; onClose: () => void; onDeleted: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const del = useMutation({
    mutationFn: () => run(() => deleteService(service.id, service.version)),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: SERVICES_KEY });
      onDeleted();
    },
  });
  return (
    <AppModal opened onClose={onClose} title={t('services.deleteTitle', { name: service.name })}>
      <Stack gap="md">
        <Text size="sm">{t('services.deleteText')}</Text>
        <ErrorAlert error={del.error} />
      </Stack>
      <DialogActions>
        <Button variant="default" onClick={onClose}>
          {t('ui.cancel')}
        </Button>
        <Button color="red" loading={del.isPending} onClick={() => del.mutate()}>
          {t('services.delete')}
        </Button>
      </DialogActions>
    </AppModal>
  );
}
