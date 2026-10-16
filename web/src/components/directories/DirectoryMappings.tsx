import { Button, Code, Group, NativeSelect, Stack, Table, Text, TextInput, Title, VisuallyHidden } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { createDirectoryMapping, deleteDirectoryMapping, listDirectoryMappings, type DirectoryMapping } from '../../api/ldap';
import { ldapMappingsKey } from '../../api/queryKeys';
import type { Role } from '../../api/types';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { LoadingIndicator } from '../LoadingIndicator';
import { useStepUp } from '../StepUpProvider';
import { WRAP } from '../wrap';
import { DialogActions, ResourceTable } from '../ui';
import classes from '../settings/settings.module.css';

const ROLES: Role[] = ['admin', 'operator', 'auditor'];

// DirectoryMappings lists the groups of one directory that give a role, with a row to add one. The group value is matched
// exactly and case-sensitively (copy it from Test sign-in). A mapping to Administrator is refused by the server
// (ALC-SSO-0002) while "SSO users may be Admin" is off; the refusal is shown next to the form.
export function DirectoryMappings({ directoryId }: { directoryId: string }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const [group, setGroup] = useState('');
  const [role, setRole] = useState<Role>('operator');
  const [confirm, setConfirm] = useState<DirectoryMapping | null>(null);
  const key = ldapMappingsKey(directoryId);
  const list = useQuery({ queryKey: key, queryFn: () => run(() => listDirectoryMappings(directoryId)) });
  const refresh = () => client.invalidateQueries({ queryKey: key });
  // The group value is sent as typed: a DN may carry meaningful spaces inside, only the ends are trimmed.
  const add = useMutation({
    mutationFn: () => run(() => createDirectoryMapping({ directory_id: directoryId, group: group.trim(), role })),
    onSuccess: () => {
      setGroup('');
      void refresh();
    },
  });
  const remove = useMutation({ mutationFn: (id: string) => run(() => deleteDirectoryMapping(id, directoryId)), onSuccess: () => void refresh() });
  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    if (group.trim()) add.mutate();
  };
  const items = list.data?.items ?? [];

  return (
    <Stack gap="xs">
      <Title order={5} className={classes.mappingsTitle}>
        {t('directories.mappings')}
      </Title>
      {list.isPending && <LoadingIndicator />}
      <ErrorAlert error={list.error} />
      {list.isSuccess &&
        (items.length === 0 ? (
          <Text size="sm" c="dimmed">
            {t('directories.noMappings')}
          </Text>
        ) : (
          <ResourceTable label={t('directories.mappings')} minWidth={320}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t('sso.columns.group')}</Table.Th>
                <Table.Th>{t('sso.columns.role')}</Table.Th>
                <Table.Th>
                  <VisuallyHidden>{t('sso.columns.actions')}</VisuallyHidden>
                </Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((m) => (
                <Table.Tr key={m.id}>
                  <Table.Td style={WRAP}>
                    <Code translate="no" style={WRAP}>
                      {m.group}
                    </Code>
                  </Table.Td>
                  <Table.Td>{t(`enum.role.${m.role}`)}</Table.Td>
                  <Table.Td>
                    <Button
                      size="xs"
                      variant="default"
                      loading={remove.isPending && remove.variables === m.id}
                      onClick={() => setConfirm(m)}
                      aria-label={t('directories.removeMapping', { group: m.group })}
                    >
                      <span aria-hidden>×</span>
                    </Button>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </ResourceTable>
        ))}
      <ErrorAlert error={remove.error} />
      {confirm && (
        <AppModal opened onClose={() => setConfirm(null)} title={t('directories.removeMappingTitle', { group: confirm.group })}>
          <Stack gap="sm">
            <Text size="sm">{t('directories.removeMappingText')}</Text>
            <DialogActions>
              <Button variant="default" onClick={() => setConfirm(null)}>
                {t('ui.cancel')}
              </Button>
              <Button
                color="red"
                onClick={() => {
                  remove.mutate(confirm.id);
                  setConfirm(null);
                }}
              >
                {t('directories.removeMappingConfirm')}
              </Button>
            </DialogActions>
          </Stack>
        </AppModal>
      )}
      <form onSubmit={submit}>
        <Group align="flex-end" gap="sm">
          <TextInput
            label={t('directories.group')}
            description={t('directories.groupHelp')}
            value={group}
            onChange={(e) => setGroup(e.currentTarget.value)}
            autoComplete="off"
            spellCheck={false}
            style={{ flex: '1 1 240px' }}
          />
          <NativeSelect label={t('directories.role')} value={role} onChange={(e) => setRole(e.currentTarget.value as Role)} data={ROLES.map((r) => ({ value: r, label: t(`enum.role.${r}`) }))} />
          <Button type="submit" loading={add.isPending}>
            {t('directories.addMapping')}
          </Button>
        </Group>
        <ErrorAlert error={add.error} />
      </form>
    </Stack>
  );
}
