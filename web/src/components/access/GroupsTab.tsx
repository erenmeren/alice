import { useState, type FormEvent } from 'react';
import { Button, Group, NativeSelect, Stack, Table, Text, TextInput, VisuallyHidden } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { createDirectoryGroup, deleteDirectoryGroup, listDirectoryGroups, listRoleBindings, type DirectoryGroup, type DirectorySource, type SeenGroup } from '../../api/access';
import { listDirectories } from '../../api/ldap';
import { ACCESS_KEY, DIRECTORY_GROUPS_KEY, LDAP_DIRECTORIES_KEY, roleBindingsKey, SSO_PROVIDERS_KEY } from '../../api/queryKeys';
import { listProviders } from '../../api/sso';
import { useAuth } from '../../auth/AuthProvider';
import { canPlatform } from '../../auth/permissions';
import { Icon } from '../../design/Icon';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { useStepUp } from '../StepUpProvider';
import { DialogActions, EmptyState, Notice, Panel, ResourceTable } from '../ui';
import { AddBinding, BindingsList } from './shared';

// groupName is how a group is named in the UI: its label, or its value.
const groupName = (g: Pick<DirectoryGroup, 'label' | 'value'>) => g.label || g.value;

// GroupsTab is People & access, Groups (R54, design §6.1, §9): the groups of an identity provider or a directory that
// role bindings name. A person in a bound group reaches the group's services from their next sign-in, even without a
// group mapped to a role on all services. Adding and removing a group and its roles ask for a fresh verification code.
export function GroupsTab() {
  const { t } = useTranslation();
  const { session } = useAuth();
  const canManage = canPlatform(session, 'access.manage');
  const groups = useQuery({ queryKey: DIRECTORY_GROUPS_KEY, queryFn: ({ signal }) => listDirectoryGroups(signal) });
  const [adding, setAdding] = useState(false);
  const [access, setAccess] = useState<DirectoryGroup | null>(null);
  const [deleting, setDeleting] = useState<DirectoryGroup | null>(null);
  return (
    <Stack gap="md" data-testid="groups-tab">
      <Notice tone="brand" title={t('groups.introTitle')}>
        {t('groups.intro')}
      </Notice>
      {canManage && (
        <Group>
          <Button leftSection={<Icon name="Plus" size={15} />} onClick={() => setAdding(true)}>
            {t('groups.add')}
          </Button>
        </Group>
      )}
      <ErrorAlert error={groups.error} />
      {groups.isSuccess && groups.data.items.length === 0 && (
        <Panel>
          <EmptyState icon="Users" title={t('groups.empty')} testId="groups-empty" />
        </Panel>
      )}
      {groups.isSuccess && groups.data.items.length > 0 && (
        <ResourceTable label={t('groups.table')} minWidth={720} testId="groups-table">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('groups.columns.group')}</Table.Th>
              <Table.Th>{t('groups.columns.source')}</Table.Th>
              <Table.Th>{t('groups.columns.members')}</Table.Th>
              <Table.Th>{t('groups.columns.bindings')}</Table.Th>
              <Table.Th>
                <VisuallyHidden>{t('groups.columns.actions')}</VisuallyHidden>
              </Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {groups.data.items.map((g) => (
              <Table.Tr key={g.id} data-testid="group-row">
                <Table.Td>
                  {g.label && <Text size="sm">{g.label}</Text>}
                  <Text size={g.label ? 'xs' : 'sm'} c={g.label ? 'dimmed' : undefined} translate="no" style={{ wordBreak: 'break-all' }}>
                    {g.value}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="sm">{t(`groups.source.${g.source}`)}</Text>
                  <Text size="xs" c="dimmed" translate="no">
                    {g.source_name}
                  </Text>
                </Table.Td>
                <Table.Td>{t('groups.membersCount', { count: g.members })}</Table.Td>
                <Table.Td>{g.bindings}</Table.Td>
                <Table.Td>
                  <Group gap={4} justify="flex-end" wrap="nowrap">
                    <Button size="xs" variant="default" onClick={() => setAccess(g)} aria-label={t('groups.accessNamed', { name: groupName(g) })}>
                      {t('groups.access')}
                    </Button>
                    {canManage && (
                      <Button size="xs" variant="subtle" color="red" onClick={() => setDeleting(g)} aria-label={t('groups.deleteNamed', { name: groupName(g) })}>
                        {t('groups.delete')}
                      </Button>
                    )}
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </ResourceTable>
      )}
      {adding && groups.data && <AddGroupModal seen={groups.data.seen} onClose={() => setAdding(false)} />}
      {access && <GroupAccessModal group={access} canManage={canManage} onClose={() => setAccess(null)} />}
      {deleting && <DeleteGroupModal group={deleting} onClose={() => setDeleting(null)} />}
    </Stack>
  );
}

// AddGroupModal declares a group: the identity provider or the directory, then the value, typed or chosen from the
// values seen at sign-ins (with how many people had each). The providers and directories are settings read with a fresh
// verification code.
function AddGroupModal({ seen, onClose }: { seen: SeenGroup[]; onClose: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const providers = useQuery({ queryKey: SSO_PROVIDERS_KEY, queryFn: () => run(listProviders), retry: false });
  const directories = useQuery({ queryKey: LDAP_DIRECTORIES_KEY, queryFn: () => run(listDirectories), retry: false });
  const [from, setFrom] = useState('');
  const [value, setValue] = useState('');
  const [label, setLabel] = useState('');
  const source: DirectorySource | '' = from.startsWith('o:') ? 'oidc' : from.startsWith('l:') ? 'ldap' : '';
  const fromId = from.slice(2);
  const values = seen.filter((s) => !s.directory_group_id && s.source === source && (source === 'oidc' ? s.provider_id : s.directory_id) === fromId);
  const add = useMutation({
    mutationFn: () => run(() => createDirectoryGroup(source === 'oidc' ? { source, provider_id: fromId, value, label } : { source: 'ldap', directory_id: fromId, value, label })),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ACCESS_KEY });
      onClose();
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    add.mutate();
  };
  return (
    <AppModal opened onClose={onClose} title={t('groups.add')}>
      <form onSubmit={submit}>
        <Stack gap="sm">
          <NativeSelect
            label={t('groups.fields.from')}
            value={from}
            onChange={(e) => {
              setFrom(e.currentTarget.value);
              setValue('');
            }}
            required
            data={[
              { value: '', label: t('groups.fields.pickFrom') },
              { group: t('groups.source.oidc'), items: (providers.data?.items ?? []).map((p) => ({ value: `o:${p.id}`, label: p.name })) },
              { group: t('groups.source.ldap'), items: (directories.data?.items ?? []).map((d) => ({ value: `l:${d.id}`, label: d.name })) },
            ]}
          />
          {values.length > 0 && (
            <NativeSelect
              label={t('groups.fields.seen')}
              description={t('groups.fields.seenHelp')}
              value={values.some((s) => s.value === value) ? value : ''}
              onChange={(e) => setValue(e.currentTarget.value)}
              data={[{ value: '', label: t('groups.fields.pickSeen') }, ...values.map((s) => ({ value: s.value, label: t('groups.seenOption', { value: s.value, count: s.users }) }))]}
            />
          )}
          <TextInput label={t('groups.fields.value')} description={t('groups.fields.valueHelp')} value={value} onChange={(e) => setValue(e.currentTarget.value)} required maxLength={1024} />
          <TextInput label={t('groups.fields.label')} value={label} onChange={(e) => setLabel(e.currentTarget.value)} maxLength={100} />
          <ErrorAlert error={add.error ?? providers.error ?? directories.error} />
          <DialogActions>
            <Button type="submit" disabled={!source || value.trim() === ''} loading={add.isPending}>
              {t('groups.submit')}
            </Button>
          </DialogActions>
        </Stack>
      </form>
    </AppModal>
  );
}

// GroupAccessModal is a group's roles on services and environments, with Add and Remove.
function GroupAccessModal({ group, canManage, onClose }: { group: DirectoryGroup; canManage: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const filter = { directory_group_id: group.id };
  const bindings = useQuery({ queryKey: roleBindingsKey(filter), queryFn: ({ signal }) => listRoleBindings(filter, signal) });
  return (
    <AppModal opened onClose={onClose} size="xl" title={t('groups.accessTitle', { name: groupName(group) })}>
      <Stack gap="md" data-testid="group-access">
        <Text size="sm">{t('groups.accessIntro')}</Text>
        <ErrorAlert error={bindings.error} />
        {bindings.data && <BindingsList bindings={bindings.data.items} canManage={canManage} emptyText={t('groups.noBindings')} testId="group-bindings" />}
        {canManage && <AddBinding groupId={group.id} />}
      </Stack>
    </AppModal>
  );
}

// DeleteGroupModal removes a group with its roles and owner entries, then says how many went with it.
function DeleteGroupModal({ group, onClose }: { group: DirectoryGroup; onClose: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const remove = useMutation({
    mutationFn: () => run(() => deleteDirectoryGroup(group.id)),
    onSuccess: () => client.invalidateQueries({ queryKey: ACCESS_KEY }),
  });
  return (
    <AppModal opened onClose={onClose} title={t('groups.deleteTitle', { name: groupName(group) })}>
      <Stack gap="sm">
        {remove.data ? (
          <Text size="sm" data-testid="group-deleted">
            {t('groups.deleted', { bindings: remove.data.bindings_removed, owners: remove.data.owners_removed })}
          </Text>
        ) : (
          <Text size="sm">{t('groups.deleteText', { count: group.bindings })}</Text>
        )}
        <ErrorAlert error={remove.error} />
        <DialogActions>
          {remove.data ? (
            <Button onClick={onClose}>{t('tokens.done')}</Button>
          ) : (
            <>
              <Button variant="default" onClick={onClose}>
                {t('users.cancel')}
              </Button>
              {/* The theme's red is the danger tone, with --alice-on-strong text on it (≥ 4.5:1 in both schemes). */}
              <Button color="red" loading={remove.isPending} onClick={() => remove.mutate()}>
                {t('groups.delete')}
              </Button>
            </>
          )}
        </DialogActions>
      </Stack>
    </AppModal>
  );
}
