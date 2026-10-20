import { Button, Group, NumberInput, Stack, Table, Text, TextInput } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { ENVIRONMENTS_KEY, SERVICES_KEY } from '../../api/queryKeys';
import { createEnvironment, deleteEnvironment, ENVIRONMENT_KEY_RE, listEnvironments, MAX_ENVIRONMENT_NAME, updateEnvironment, type Environment } from '../../api/services';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { environmentLabel } from '../services/shared';
import { useStepUp } from '../StepUpProvider';
import { DialogActions } from '../ui';

// EnvironmentsSettings is Settings → Environments (R49): the labels services carry (production, staging, test,
// development are seeded). An Administrator adds, renames and reorders them, and deletes one no service uses. A key never
// changes: bindings and the translations name it.
export function EnvironmentsSettings() {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const environments = useQuery({ queryKey: ENVIRONMENTS_KEY, queryFn: ({ signal }) => listEnvironments(signal) });
  const [editing, setEditing] = useState<Environment | null>(null);
  const [key, setKey] = useState('');
  const [name, setName] = useState('');
  const refresh = async () => {
    await client.invalidateQueries({ queryKey: ENVIRONMENTS_KEY });
    await client.invalidateQueries({ queryKey: SERVICES_KEY });
  };
  const add = useMutation({
    mutationFn: () => {
      const items = environments.data?.items ?? [];
      const sort = items.length > 0 ? Math.min(32767, Math.max(...items.map((e) => e.sort)) + 10) : 10;
      return run(() => createEnvironment({ key, name, sort }));
    },
    onSuccess: async () => {
      setKey('');
      setName('');
      await refresh();
    },
  });
  const remove = useMutation({ mutationFn: (e: Environment) => run(() => deleteEnvironment(e.id, e.version)), onSuccess: refresh });
  const fields = fieldErrorsOf(add.error, t, i18n);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    add.mutate();
  };
  const items = environments.data?.items ?? [];
  return (
    <Stack gap="md">
      <ErrorAlert error={environments.error ?? remove.error} />
      {items.length > 0 && (
        <Table data-testid="environments-table">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('services.environments.name')}</Table.Th>
              <Table.Th>{t('services.environments.key')}</Table.Th>
              <Table.Th>{t('services.environments.order')}</Table.Th>
              <Table.Th>{t('services.environments.services')}</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((env) => (
              <Table.Tr key={env.id}>
                <Table.Td>{environmentLabel(t, env)}</Table.Td>
                <Table.Td>
                  <Text size="sm" ff="monospace" translate="no">
                    {env.key}
                  </Text>
                </Table.Td>
                <Table.Td>{env.sort}</Table.Td>
                <Table.Td>{env.services}</Table.Td>
                <Table.Td>
                  <Group gap="xs" justify="flex-end" wrap="nowrap">
                    <Button size="xs" variant="default" onClick={() => setEditing(env)}>
                      {t('services.environments.rename')}
                    </Button>
                    <Button
                      size="xs"
                      variant="subtle"
                      color="red"
                      disabled={env.services > 0}
                      title={env.services > 0 ? t('services.environments.inUse') : undefined}
                      loading={remove.isPending && remove.variables?.id === env.id}
                      onClick={() => remove.mutate(env)}
                    >
                      {t('services.environments.delete')}
                    </Button>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
      <form onSubmit={submit}>
        <Group align="flex-end">
          <TextInput
            label={t('services.environments.key')}
            description={t('services.environments.keyHelp')}
            value={key}
            onChange={(e) => setKey(e.currentTarget.value)}
            maxLength={32}
            error={fields.key ?? (key !== '' && !ENVIRONMENT_KEY_RE.test(key) ? t('services.environments.keyPattern') : undefined)}
          />
          <TextInput label={t('services.environments.name')} value={name} onChange={(e) => setName(e.currentTarget.value)} maxLength={MAX_ENVIRONMENT_NAME} error={fields.name} />
          <Button type="submit" disabled={!ENVIRONMENT_KEY_RE.test(key) || name.trim() === ''} loading={add.isPending}>
            {t('services.environments.add')}
          </Button>
        </Group>
      </form>
      <ErrorAlert error={add.error} />
      {editing && <RenameEnvironment environment={editing} onClose={() => setEditing(null)} onSaved={refresh} />}
    </Stack>
  );
}

function RenameEnvironment({ environment, onClose, onSaved }: { environment: Environment; onClose: () => void; onSaved: () => Promise<void> }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const [name, setName] = useState(environment.name);
  const [sort, setSort] = useState<number>(environment.sort);
  const save = useMutation({
    mutationFn: () => run(() => updateEnvironment(environment.id, environment.version, { name, sort })),
    onSuccess: async () => {
      await onSaved();
      onClose();
    },
  });
  const fields = fieldErrorsOf(save.error, t, i18n);
  return (
    <AppModal opened onClose={onClose} title={t('services.environments.renameTitle', { key: environment.key })}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
      >
        <Stack gap="md">
          <TextInput label={t('services.environments.name')} value={name} onChange={(e) => setName(e.currentTarget.value)} maxLength={MAX_ENVIRONMENT_NAME} required error={fields.name} data-autofocus />
          <NumberInput label={t('services.environments.order')} value={sort} onChange={(v) => setSort(typeof v === 'number' ? v : 0)} min={0} max={32767} error={fields.sort} />
          <ErrorAlert error={save.error} />
        </Stack>
        <DialogActions>
          <Button variant="default" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button type="submit" loading={save.isPending}>
            {t('services.dialog.save')}
          </Button>
        </DialogActions>
      </form>
    </AppModal>
  );
}
