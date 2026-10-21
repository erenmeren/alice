import { Loader, Stack, Text } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { listRoleBindings } from '../../api/access';
import { roleBindingsKey } from '../../api/queryKeys';
import type { Service } from '../../api/services';
import { useAuth } from '../../auth/AuthProvider';
import { canPlatform } from '../../auth/permissions';
import { ErrorAlert } from '../ErrorAlert';
import { Notice, Panel } from '../ui';
import { AddBinding, BindingsList } from './shared';

// ServiceAccess is the Access tab of a service (design §9): who reaches it through a role on the service itself or on
// every service of its environment, with a note that the holders of a role on all services reach it too. Reading it is a
// global Administrator's (users.read); adding and removing is access.manage with a fresh step-up.
export function ServiceAccess({ service }: { service: Service }) {
  const { t } = useTranslation();
  const { session } = useAuth();
  const canRead = canPlatform(session, 'users.read');
  const canManage = canPlatform(session, 'access.manage');
  const filter = { service_id: service.id };
  const bindings = useQuery({ queryKey: roleBindingsKey(filter), queryFn: ({ signal }) => listRoleBindings(filter, signal), enabled: canRead });
  if (!canRead) return <Notice tone="neutral" title={t('access.service.adminOnly')} testId="service-access-admin-only" />;
  const items = bindings.data?.items ?? [];
  const direct = items.filter((b) => b.service?.id === service.id);
  const through = items.filter((b) => b.service?.id !== service.id);
  return (
    <Stack gap="md" data-testid="service-access">
      <Text size="sm">{t('access.service.intro')}</Text>
      <Notice tone="info" title={t('access.service.globalTitle')} testId="service-access-global">
        {t('access.service.globalNote')}
      </Notice>
      <ErrorAlert error={bindings.error} />
      {bindings.isPending && <Loader size="xs" aria-label={t('ui.loading')} />}
      {bindings.isSuccess && (
        <>
          <Panel title={t('access.service.direct')} headingOrder={3}>
            <BindingsList bindings={direct} showPerson canManage={canManage} emptyText={t('access.service.noneDirect')} testId="service-bindings" />
          </Panel>
          <Panel title={t('access.service.throughEnvironment')} headingOrder={3}>
            <BindingsList bindings={through} showPerson canManage={canManage} emptyText={t('access.service.noneThrough')} testId="service-env-bindings" />
          </Panel>
        </>
      )}
      {canManage && <AddBinding serviceId={service.id} />}
    </Stack>
  );
}
