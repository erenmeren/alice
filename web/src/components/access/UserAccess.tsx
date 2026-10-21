import { Button, Group, List, Loader, Stack, Table, Text } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getUserAccess, listRoleBindings } from '../../api/access';
import { roleBindingsKey, userAccessKey } from '../../api/queryKeys';
import type { User } from '../../api/types';
import { useAuth } from '../../auth/AuthProvider';
import { canPlatform } from '../../auth/permissions';
import { ErrorAlert } from '../ErrorAlert';
import { Notice, Panel } from '../ui';
import { AddBinding, BindingsList, roleLabel } from './shared';

// UserAccess is a person's Access section in People & access (design §9): the global role as the first row ("All
// services"), then their roles on single services and on every service of an environment, Add and Remove for a person
// who manages access (a fresh step-up), and Explain: what it all adds up to (GET /users/{id}/access).
export function UserAccess({ user }: { user: User }) {
  const { t } = useTranslation();
  const { session } = useAuth();
  const canManage = canPlatform(session, 'access.manage');
  const filter = { user_id: user.id };
  const bindings = useQuery({ queryKey: roleBindingsKey(filter), queryFn: ({ signal }) => listRoleBindings(filter, signal) });
  const [explaining, setExplaining] = useState(false);
  return (
    <Stack gap="md" data-testid="user-access">
      <Text size="sm">{t('access.section.description')}</Text>
      <Table data-testid="global-role">
        <Table.Tbody>
          <Table.Tr>
            <Table.Th scope="row">{t('access.allServices')}</Table.Th>
            <Table.Td>{roleLabel(t, user.role)}</Table.Td>
          </Table.Tr>
        </Table.Tbody>
      </Table>
      <ErrorAlert error={bindings.error} />
      {bindings.isPending && <Loader size="xs" aria-label={t('ui.loading')} />}
      {bindings.data && <BindingsList bindings={bindings.data.items} canManage={canManage} emptyText={t('access.empty')} testId="user-bindings" />}
      {canManage && <AddBinding userId={user.id} />}
      <Group>
        <Button variant="default" size="xs" aria-expanded={explaining} onClick={() => setExplaining((x) => !x)}>
          {explaining ? t('access.explain.hide') : t('access.explain.button')}
        </Button>
      </Group>
      {explaining && <Explain userId={user.id} />}
    </Stack>
  );
}

function Explain({ userId }: { userId: string }) {
  const { t } = useTranslation();
  const access = useQuery({ queryKey: userAccessKey(userId), queryFn: ({ signal }) => getUserAccess(userId, signal) });
  const a = access.data;
  return (
    <Panel title={t('access.explain.title')} description={t('access.explain.intro')} headingOrder={3} testId="access-explain">
      <ErrorAlert error={access.error} />
      {access.isPending && <Loader size="xs" aria-label={t('ui.loading')} />}
      {a && (
        <Stack gap="sm">
          {a.admin_capped && (
            <Notice tone="warning" title={t('access.explain.cappedTitle')} testId="admin-capped">
              {t('access.explain.capped')}
            </Notice>
          )}
          {a.global_role === null && a.grants.length === 0 && <Text size="sm">{t('access.explain.none')}</Text>}
          <List size="sm" spacing={4}>
            {a.global_role && <List.Item>{t('access.explain.global', { role: roleLabel(t, a.global_role) })}</List.Item>}
            {a.grants.map((g, i) => (
              <List.Item key={`${g.role}-${i}`}>
                {t('access.explain.grant', { role: roleLabel(t, g.role) })}{' '}
                <span translate="no">{g.services.length > 0 ? g.services.map((s) => s.name).join(', ') : t('access.coversNone')}</span>
              </List.Item>
            ))}
          </List>
        </Stack>
      )}
    </Panel>
  );
}
