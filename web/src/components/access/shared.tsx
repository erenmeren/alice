import { Button, Group, NativeSelect, Stack, Table, Text, VisuallyHidden } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { createRoleBinding, deleteRoleBinding, type RoleBinding, type RoleBindingCreate } from '../../api/access';
import { listUsers } from '../../api/endpoints';
import { ACCESS_KEY, ENVIRONMENTS_KEY, SERVICE_LIST_KEY } from '../../api/queryKeys';
import { listEnvironments, listServices } from '../../api/services';
import type { Role } from '../../api/types';
import { formatDateTime } from '../../datetime';
import { ErrorAlert } from '../ErrorAlert';
import { EnvironmentBadge, environmentLabel } from '../services/shared';
import { useStepUp } from '../StepUpProvider';
import { EmptyState, Panel } from '../ui';

export const BINDING_ROLES: Role[] = ['admin', 'operator', 'auditor'];

// roleLabel is a global role in the reader's language, or that the person has none (R49 Phase 2: role null).
export function roleLabel(t: TFunction, role: Role | null | undefined): string {
  return role ? t(`enum.role.${role}`) : t('access.noGlobalRole');
}

// whereText is the scope of a binding as plain text: the service's name, or every service of the environment.
export function whereText(t: TFunction, b: Pick<RoleBinding, 'service' | 'environment'>): string {
  if (b.service) return b.service.name;
  if (b.environment) return t('access.where.environment', { name: environmentLabel(t, b.environment) });
  return '';
}

// BindingWhere is the scope of a binding: the service with its environment badge, or "every service in <environment>".
export function BindingWhere({ binding: b }: { binding: Pick<RoleBinding, 'service' | 'environment'> }) {
  const { t } = useTranslation();
  if (b.service) {
    return (
      <Group gap={6} wrap="nowrap">
        <Text size="sm" translate="no">
          {b.service.name}
        </Text>
        <EnvironmentBadge environment={b.service.environment} />
      </Group>
    );
  }
  return <Text size="sm">{whereText(t, b)}</Text>;
}

// BindingsTable lists role bindings: the person (on a service's page), the role, where, what it covers now, who added it
// and when, and Remove for a person who manages access (with a fresh step-up).
export function BindingsTable({ bindings, showPerson = false, canManage, testId }: { bindings: RoleBinding[]; showPerson?: boolean; canManage: boolean; testId?: string }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const remove = useMutation({
    mutationFn: (id: string) => run(() => deleteRoleBinding(id)),
    onSuccess: () => client.invalidateQueries({ queryKey: ACCESS_KEY }),
  });
  return (
    <Stack gap="sm">
      <Table.ScrollContainer minWidth={640}>
        <Table data-testid={testId} aria-label={t('access.title')}>
          <Table.Thead>
            <Table.Tr>
              {showPerson && <Table.Th>{t('access.columns.person')}</Table.Th>}
              <Table.Th>{t('access.columns.role')}</Table.Th>
              <Table.Th>{t('access.columns.where')}</Table.Th>
              <Table.Th>{t('access.columns.covers')}</Table.Th>
              <Table.Th>{t('access.columns.added')}</Table.Th>
              {canManage && (
                <Table.Th>
                  <VisuallyHidden>{t('access.columns.actions')}</VisuallyHidden>
                </Table.Th>
              )}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {bindings.map((b) => (
              <Table.Tr key={b.id} data-testid="binding-row">
                {showPerson && (
                  <Table.Td>
                    <Text size="sm">{b.display_name || b.username}</Text>
                    {b.username && (
                      <Text size="xs" c="dimmed" translate="no">
                        {b.username}
                      </Text>
                    )}
                  </Table.Td>
                )}
                <Table.Td>{roleLabel(t, b.role)}</Table.Td>
                <Table.Td>
                  <BindingWhere binding={b} />
                </Table.Td>
                <Table.Td>
                  <Text size="sm" translate="no">
                    {b.services.length > 0 ? b.services.map((s) => s.name).join(', ') : t('access.coversNone')}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="sm">
                    {b.created_by_name
                      ? t('access.addedBy', { name: b.created_by_name, date: formatDateTime(b.created_at, i18n.language) })
                      : formatDateTime(b.created_at, i18n.language)}
                  </Text>
                </Table.Td>
                {canManage && (
                  <Table.Td style={{ textAlign: 'end' }}>
                    <Button
                      size="xs"
                      variant="subtle"
                      color="red"
                      loading={remove.isPending && remove.variables === b.id}
                      aria-label={t('access.removeNamed', { role: roleLabel(t, b.role), where: whereText(t, b) })}
                      onClick={() => remove.mutate(b.id)}
                    >
                      {t('access.remove')}
                    </Button>
                  </Table.Td>
                )}
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      <ErrorAlert error={remove.error} />
    </Stack>
  );
}

// BindingsList is the bindings, or the empty state.
export function BindingsList({ bindings, showPerson, canManage, emptyText, testId }: { bindings: RoleBinding[]; showPerson?: boolean; canManage: boolean; emptyText: string; testId: string }) {
  if (bindings.length === 0) return <EmptyState icon="Users" title={emptyText} testId={`${testId}-empty`} />;
  return <BindingsTable bindings={bindings} showPerson={showPerson} canManage={canManage} testId={testId} />;
}

// AddBinding adds a role binding with a fresh step-up: for one person or automation account (userId), or one directory
// group (groupId, R54): pick the role and a service or an environment; or on one service (pick the person and the role).
export function AddBinding({ userId, groupId, serviceId }: { userId?: string; groupId?: string; serviceId?: string }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const [role, setRole] = useState<Role>('operator');
  const [where, setWhere] = useState('');
  const [person, setPerson] = useState('');
  const services = useQuery({ queryKey: SERVICE_LIST_KEY, queryFn: ({ signal }) => listServices(signal), enabled: !serviceId });
  const environments = useQuery({ queryKey: ENVIRONMENTS_KEY, queryFn: ({ signal }) => listEnvironments(signal), enabled: !serviceId });
  const subjectGiven = Boolean(userId ?? groupId);
  const users = useQuery({ queryKey: ['users'], queryFn: listUsers, enabled: !subjectGiven });
  const add = useMutation({
    mutationFn: () => {
      const subject = groupId ? { directory_group_id: groupId } : { user_id: userId ?? person };
      let body: RoleBindingCreate;
      if (serviceId) body = { ...subject, role, service_id: serviceId };
      else if (where.startsWith('e:')) body = { ...subject, role, environment_id: where.slice(2) };
      else body = { ...subject, role, service_id: where.slice(2) };
      return run(() => createRoleBinding(body));
    },
    onSuccess: async () => {
      setWhere('');
      setPerson('');
      await client.invalidateQueries({ queryKey: ACCESS_KEY });
    },
  });
  const ready = (subjectGiven ? true : person !== '') && (serviceId ? true : where !== '');
  const sorted = (users.data?.items ?? []).slice().sort((a, b) => a.display_name.localeCompare(b.display_name, i18n.language));
  return (
    <Panel title={t('access.add.title')} description={t('access.add.stepUp')} headingOrder={3}>
      <Stack gap="sm">
        <Group align="flex-end">
          {!subjectGiven && (
            <NativeSelect
              label={t('access.add.person')}
              value={person}
              onChange={(e) => setPerson(e.currentTarget.value)}
              data={[{ value: '', label: t('access.add.pickPerson') }, ...sorted.map((u) => ({ value: u.id, label: `${u.display_name} (${u.username})` }))]}
            />
          )}
          <NativeSelect
            label={t('access.add.role')}
            value={role}
            onChange={(e) => setRole(e.currentTarget.value as Role)}
            data={BINDING_ROLES.map((r) => ({ value: r, label: roleLabel(t, r) }))}
          />
          {!serviceId && (
            <NativeSelect
              label={t('access.add.where')}
              value={where}
              onChange={(e) => setWhere(e.currentTarget.value)}
              data={[
                { value: '', label: t('access.add.pick') },
                { group: t('access.add.services'), items: (services.data?.items ?? []).map((s) => ({ value: `s:${s.id}`, label: s.environment ? `${s.name} (${environmentLabel(t, s.environment)})` : s.name })) },
                {
                  group: t('access.add.environments'),
                  items: (environments.data?.items ?? []).map((e) => ({ value: `e:${e.id}`, label: t('access.where.environment', { name: environmentLabel(t, e) }) })),
                },
              ]}
            />
          )}
          <Button disabled={!ready} loading={add.isPending} onClick={() => add.mutate()}>
            {t('access.add.submit')}
          </Button>
        </Group>
        <ErrorAlert error={add.error ?? users.error} />
      </Stack>
    </Panel>
  );
}
