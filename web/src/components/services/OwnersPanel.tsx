import { Button, Group, Loader, NativeSelect, Stack, Table, Text, VisuallyHidden } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { listDirectoryGroups, type DirectoryGroup } from '../../api/access';
import { isApiError } from '../../api/client';
import { listUsers } from '../../api/endpoints';
import { DIRECTORY_GROUPS_KEY, serviceOwnersKey, SERVICES_KEY } from '../../api/queryKeys';
import { getServiceOwners, MAX_SERVICE_OWNERS, putServiceOwners, type Service, type ServiceOwner, type ServiceOwnerInput, type ServiceOwners } from '../../api/services';
import type { User } from '../../api/types';
import { useAuth } from '../../auth/AuthProvider';
import { canPlatform } from '../../auth/permissions';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { useStepUp } from '../StepUpProvider';
import { DialogActions, EmptyState, Notice, Panel, StatusBadge } from '../ui';

// OwnerRow is an owner as the list and the editor show it: a person or a directory group, with what the server said
// about it (absent for one just picked in the editor).
interface OwnerRow {
  key: string;
  input: ServiceOwnerInput;
  kind: 'person' | 'group';
  name: string;
  detail: string;
  owner?: ServiceOwner;
}

// groupSource is a directory group's identity provider or directory: "Single sign-on · Corp IdP".
const groupSource = (t: TFunction, g: { source: DirectoryGroup['source']; source_name: string }) => `${t(`groups.source.${g.source}`)} · ${g.source_name}`;

function rowOf(t: TFunction, o: ServiceOwner): OwnerRow {
  if (o.kind === 'group' && o.directory_group_id) {
    const g = o.group;
    return { key: `g:${o.directory_group_id}`, input: { directory_group_id: o.directory_group_id }, kind: 'group', name: g ? g.label || g.value : o.directory_group_id, detail: g ? groupSource(t, g) : '', owner: o };
  }
  const id = o.user_id ?? '';
  return { key: `u:${id}`, input: { user_id: id }, kind: 'person', name: o.display_name || o.username || id, detail: o.username ?? '', owner: o };
}

const personRow = (u: User): OwnerRow => ({ key: `u:${u.id}`, input: { user_id: u.id }, kind: 'person', name: u.display_name || u.username, detail: u.username });
const groupRow = (t: TFunction, g: DirectoryGroup): OwnerRow => ({ key: `g:${g.id}`, input: { directory_group_id: g.id }, kind: 'group', name: g.label || g.value, detail: groupSource(t, g) });

// OwnerNotes are the badges and the warning of one owner: a disabled person or one without an address receives
// nothing; an owner without a role on the service receives its e-mails but cannot open it (shown to people readers only).
function OwnerNotes({ row }: { row: OwnerRow }) {
  const { t } = useTranslation();
  const o = row.owner;
  if (!o) return null;
  return (
    <Group gap={6}>
      {row.kind === 'person' && o.disabled && (
        <StatusBadge tone="neutral" size="sm">
          {t('services.owners.disabled')}
        </StatusBadge>
      )}
      {row.kind === 'person' && !o.disabled && !o.receives_email && (
        <StatusBadge tone="warning" size="sm">
          {t('services.owners.noEmail')}
        </StatusBadge>
      )}
      {row.kind === 'group' && (
        <Text size="xs" c="dimmed">
          {t('services.owners.membersSeen', { count: o.members })}
        </Text>
      )}
      {o.reaches_service === false && (
        <StatusBadge tone="warning" size="sm" icon="CircleAlert" testId="owner-no-reach">
          {row.kind === 'group' ? t('services.owners.noReachGroup') : t('services.owners.noReach')}
        </StatusBadge>
      )}
    </Group>
  );
}

// OwnersTable lists owners; with onRemove, each row has Remove.
function OwnersTable({ rows, onRemove, testId }: { rows: OwnerRow[]; onRemove?: (key: string) => void; testId: string }) {
  const { t } = useTranslation();
  return (
    <Table.ScrollContainer minWidth={520}>
      <Table data-testid={testId} aria-label={t('services.owners.title')}>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>{t('services.owners.columns.owner')}</Table.Th>
            <Table.Th>{t('services.owners.columns.kind')}</Table.Th>
            <Table.Th>{t('services.owners.columns.notes')}</Table.Th>
            {onRemove && (
              <Table.Th>
                <VisuallyHidden>{t('services.owners.columns.actions')}</VisuallyHidden>
              </Table.Th>
            )}
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {rows.map((r) => (
            <Table.Tr key={r.key} data-testid="owner-row">
              <Table.Td>
                <Text size="sm" translate="no">
                  {r.name}
                </Text>
                {r.detail && (
                  <Text size="xs" c="dimmed" translate={r.kind === 'person' ? 'no' : undefined}>
                    {r.detail}
                  </Text>
                )}
              </Table.Td>
              <Table.Td>
                <Text size="sm">{t(`services.owners.kind.${r.kind}`)}</Text>
              </Table.Td>
              <Table.Td>
                <OwnerNotes row={r} />
              </Table.Td>
              {onRemove && (
                <Table.Td style={{ textAlign: 'end' }}>
                  <Button size="xs" variant="subtle" color="red" aria-label={t('services.owners.removeNamed', { name: r.name })} onClick={() => onRemove(r.key)}>
                    {t('services.owners.remove')}
                  </Button>
                </Table.Td>
              )}
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}

// OwnersPanel is the owner team on a service's Overview (R56, design §7.1, §9): the people and directory groups who are
// responsible for the service and receive its e-mails. Ownership gives no access. Everyone who sees the service reads
// it; a global Administrator (services.manage) edits it with a fresh step-up.
export function OwnersPanel({ service }: { service: Service }) {
  const { t } = useTranslation();
  const { session } = useAuth();
  const canManage = canPlatform(session, 'services.manage');
  const owners = useQuery({ queryKey: serviceOwnersKey(service.id), queryFn: ({ signal }) => getServiceOwners(service.id, signal) });
  const [editing, setEditing] = useState(false);
  const rows = (owners.data?.items ?? []).map((o) => rowOf(t, o));
  return (
    <Panel
      title={t('services.owners.title')}
      description={t('services.owners.description')}
      testId="service-owners"
      action={
        canManage && owners.data ? (
          <Button size="xs" variant="default" onClick={() => setEditing(true)}>
            {t('services.owners.edit')}
          </Button>
        ) : undefined
      }
    >
      <ErrorAlert error={owners.error} />
      {owners.isPending && <Loader size="xs" aria-label={t('ui.loading')} />}
      {owners.isSuccess && rows.length === 0 && <EmptyState icon="Users" title={t('services.owners.empty')} testId="service-owners-empty" />}
      {owners.isSuccess && rows.length > 0 && <OwnersTable rows={rows} testId="service-owners-table" />}
      {editing && owners.data && <OwnersDialog service={service} owners={owners.data} onClose={() => setEditing(false)} />}
    </Panel>
  );
}

// OwnersDialog replaces the owner list: pick people (automation accounts are not in the people list) and declared
// directory groups, remove entries, save with the version read. A stale version (409) shows the refusal and reloads the
// list, so the Administrator checks what changed before saving again.
function OwnersDialog({ service, owners, onClose }: { service: Service; owners: ServiceOwners; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const [version, setVersion] = useState(owners.version);
  const [draft, setDraft] = useState<OwnerRow[]>(() => owners.items.map((o) => rowOf(t, o)));
  const [person, setPerson] = useState('');
  const [group, setGroup] = useState('');
  const [reloaded, setReloaded] = useState(false);
  const users = useQuery({ queryKey: ['users'], queryFn: listUsers });
  const groups = useQuery({ queryKey: DIRECTORY_GROUPS_KEY, queryFn: ({ signal }) => listDirectoryGroups(signal) });
  const taken = new Set(draft.map((r) => r.key));
  const people = (users.data?.items ?? []).filter((u) => !taken.has(`u:${u.id}`)).sort((a, b) => a.display_name.localeCompare(b.display_name, i18n.language));
  const declared = (groups.data?.items ?? []).filter((g) => !taken.has(`g:${g.id}`));
  const full = draft.length >= MAX_SERVICE_OWNERS;

  const save = useMutation({
    mutationFn: () =>
      run(() =>
        putServiceOwners(
          service.id,
          version,
          draft.map((r) => r.input),
        ),
      ),
    onMutate: () => setReloaded(false),
    onSuccess: async (saved) => {
      client.setQueryData(serviceOwnersKey(service.id), saved);
      await client.invalidateQueries({ queryKey: SERVICES_KEY });
      onClose();
    },
    onError: async (e) => {
      if (!isApiError(e, 'service.version_conflict')) return;
      const fresh = await client.fetchQuery({ queryKey: serviceOwnersKey(service.id), queryFn: ({ signal }) => getServiceOwners(service.id, signal), staleTime: 0 });
      void client.invalidateQueries({ queryKey: SERVICES_KEY });
      setVersion(fresh.version);
      setDraft(fresh.items.map((o) => rowOf(t, o)));
      setReloaded(true);
    },
  });

  const addPerson = () => {
    const u = users.data?.items.find((x) => x.id === person);
    if (u) setDraft((d) => [...d, personRow(u)]);
    setPerson('');
  };
  const addGroup = () => {
    const g = groups.data?.items.find((x) => x.id === group);
    if (g) setDraft((d) => [...d, groupRow(t, g)]);
    setGroup('');
  };

  return (
    <AppModal opened onClose={onClose} title={t('services.owners.dialogTitle', { name: service.name })} size="lg">
      <Stack gap="md">
        <Text size="sm">{t('services.owners.intro')}</Text>
        {draft.length === 0 ? <EmptyState icon="Users" title={t('services.owners.empty')} testId="owners-draft-empty" /> : <OwnersTable rows={draft} onRemove={(key) => setDraft((d) => d.filter((r) => r.key !== key))} testId="owners-draft" />}
        {full ? (
          <Text size="sm" c="dimmed">
            {t('services.owners.max', { max: MAX_SERVICE_OWNERS })}
          </Text>
        ) : (
          <>
            <Group align="flex-end">
              <NativeSelect
                label={t('services.owners.person')}
                value={person}
                onChange={(e) => setPerson(e.currentTarget.value)}
                data={[{ value: '', label: t('services.owners.pickPerson') }, ...people.map((u) => ({ value: u.id, label: `${u.display_name} (${u.username})` }))]}
                style={{ flex: 1 }}
              />
              <Button variant="default" disabled={!person} onClick={addPerson}>
                {t('services.owners.addPerson')}
              </Button>
            </Group>
            <Group align="flex-end">
              <NativeSelect
                label={t('services.owners.group')}
                value={group}
                onChange={(e) => setGroup(e.currentTarget.value)}
                data={[{ value: '', label: declared.length === 0 && groups.isSuccess ? t('services.owners.noGroups') : t('services.owners.pickGroup') }, ...declared.map((g) => ({ value: g.id, label: `${g.label || g.value} (${groupSource(t, g)})` }))]}
                style={{ flex: 1 }}
              />
              <Button variant="default" disabled={!group} onClick={addGroup}>
                {t('services.owners.addGroup')}
              </Button>
            </Group>
          </>
        )}
        <ErrorAlert error={save.error ?? users.error ?? groups.error} />
        {reloaded && <Notice tone="info" title={t('services.owners.reloaded')} testId="owners-reloaded" />}
      </Stack>
      <DialogActions note={t('services.owners.stepUp')}>
        <Button variant="default" onClick={onClose}>
          {t('ui.cancel')}
        </Button>
        <Button loading={save.isPending} onClick={() => save.mutate()} data-testid="owners-save">
          {t('services.owners.save')}
        </Button>
      </DialogActions>
    </AppModal>
  );
}
