import { Anchor, Group, NativeSelect } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { ENVIRONMENTS_KEY, SERVICE_LIST_KEY } from '../../api/queryKeys';
import { listEnvironments, listServices, SEEDED_ENVIRONMENTS, type EnvironmentRef, type ServiceFilter, type ServiceRef } from '../../api/services';
import { useUrlFilters } from '../../hooks/useUrlFilters';
import { StatusBadge } from '../ui';

// environmentLabel is an environment's name in the reader's language: a seeded environment (production, staging, test,
// development) that nobody renamed is translated by its key; any other shows its stored name.
export function environmentLabel(t: TFunction, env: Pick<EnvironmentRef, 'key' | 'name'>): string {
  return SEEDED_ENVIRONMENTS[env.key] === env.name ? t(`services.environmentKeys.${env.key}`) : env.name;
}

// EnvironmentBadge is the environment of a service as a pill (nothing for a service without one).
export function EnvironmentBadge({ environment }: { environment: EnvironmentRef | null | undefined }) {
  const { t } = useTranslation();
  if (!environment) return null;
  return (
    <StatusBadge tone={environment.key === 'production' ? 'brand' : 'neutral'} size="sm" data-environment={environment.key}>
      {environmentLabel(t, environment)}
    </StatusBadge>
  );
}

// ServiceBadge is the owning service of a row (design §8.2): its name, linked to its page, and its environment. A row of
// an older answer has none and shows nothing.
export function ServiceBadge({ service }: { service: ServiceRef | null | undefined }) {
  if (!service) return null;
  return (
    <Group gap={6} wrap="nowrap" data-testid="service-badge">
      <Anchor component={Link} to={`/services/${service.id}`} size="sm" translate="no">
        {service.name || service.id}
      </Anchor>
      <EnvironmentBadge environment={service.environment} />
    </Group>
  );
}

const SERVICE_FILTER_KEYS = ['service_id', 'environment_id'] as const;

// useServiceFilters keeps a list's service and environment filters in the address (?service_id=, ?environment_id=). They
// are kept apart from a page's own filters: saved views store the page's filters only.
export function useServiceFilters(): [ServiceFilter, (next: ServiceFilter) => void] {
  const [values, set] = useUrlFilters(SERVICE_FILTER_KEYS);
  const filter: ServiceFilter = {};
  if (values.service_id) filter.service_id = values.service_id;
  if (values.environment_id) filter.environment_id = values.environment_id;
  return [filter, (next) => set({ service_id: next.service_id ?? '', environment_id: next.environment_id ?? '' })];
}

// ServiceFilters are the two selects of a list toolbar: one service, or the services of one environment.
export function ServiceFilters({ value, onChange, className }: { value: ServiceFilter; onChange: (next: ServiceFilter) => void; className?: string }) {
  const { t } = useTranslation();
  const services = useQuery({ queryKey: SERVICE_LIST_KEY, queryFn: ({ signal }) => listServices(signal) });
  const environments = useQuery({ queryKey: ENVIRONMENTS_KEY, queryFn: ({ signal }) => listEnvironments(signal) });
  return (
    <>
      <NativeSelect
        className={className}
        label={t('services.filter.service')}
        value={value.service_id ?? ''}
        onChange={(e) => onChange({ ...value, service_id: e.currentTarget.value || undefined })}
        data={[{ value: '', label: t('services.filter.allServices') }, ...(services.data?.items ?? []).map((s) => ({ value: s.id, label: s.name }))]}
      />
      <NativeSelect
        className={className}
        label={t('services.filter.environment')}
        value={value.environment_id ?? ''}
        onChange={(e) => onChange({ ...value, environment_id: e.currentTarget.value || undefined })}
        data={[
          { value: '', label: t('services.filter.allEnvironments') },
          ...(environments.data?.items ?? []).map((env) => ({ value: env.id, label: environmentLabel(t, env) })),
        ]}
      />
    </>
  );
}
