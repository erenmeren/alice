import { Button, Code, Group, Stack, Table, Text, Title, VisuallyHidden } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { isApiError } from '../../api/client';
import { useTranslation } from 'react-i18next';
import { LDAP_DIRECTORIES_KEY } from '../../api/queryKeys';
import { deleteDirectory, listDirectories, testDirectoryConnection, type Directory } from '../../api/ldap';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { LoadingIndicator } from '../LoadingIndicator';
import { useStepUp } from '../StepUpProvider';
import { Icon } from '../../design/Icon';
import { WRAP } from '../wrap';
import { DialogActions, EmptyState, Notice, ResourceTable, StatusBadge } from '../ui';
import ui from '../ui/ui.module.css';
import classes from '../settings/settings.module.css';
import { DirectoryDialog } from './DirectoryDialog';
import { DirectoryMappings } from './DirectoryMappings';
import { TestSignInDialog } from './TestSignInDialog';

type Dialog = { kind: 'form'; directory: Directory | null } | { kind: 'delete'; directory: Directory } | { kind: 'test'; directory: Directory };

// MAX_DIRECTORIES is the server's limit (ALC-LDAP-0005); the page says so once it is reached, the server still decides.
const MAX_DIRECTORIES = 3;

// DirectoriesSettings is the Directories tab: the LDAP and Active Directory directories people can sign in with, each one's
// connection and sign-in tests and its group mappings. Everything here needs a fresh verification, like the other settings.
export function DirectoriesSettings() {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const directories = useQuery({ queryKey: LDAP_DIRECTORIES_KEY, queryFn: () => run(listDirectories) });
  const items = directories.data?.items ?? [];

  return (
    <Stack gap="md">
      <Stack gap="xs">
        <Text size="sm">{t('directories.adminNote')}</Text>
        <Text size="sm">{t('directories.passwordNote')}</Text>
      </Stack>

      <section className={classes.subSection}>
        <Group justify="space-between" align="center" mb="sm">
          <Title order={3} className={classes.subTitle} mb={0}>
            {t('directories.list')}
          </Title>
          <Button leftSection={<Icon name="Plus" size={15} />} onClick={() => setDialog({ kind: 'form', directory: null })}>
            {t('directories.add')}
          </Button>
        </Group>
        <Stack gap="md">
          {directories.isPending && <LoadingIndicator />}
          <ErrorAlert error={directories.error} />
          {directories.isSuccess && items.length === 0 && (
            <div className={ui.tablePanel}>
              <EmptyState icon="Server" title={t('directories.none')} />
            </div>
          )}
          {items.length >= MAX_DIRECTORIES && (
            <Text size="sm" c="dimmed">
              {t('directories.max')}
            </Text>
          )}
          {items.length > 0 && (
            <ResourceTable label={t('directories.table')} minWidth={640}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('directories.columns.name')}</Table.Th>
                  <Table.Th>{t('directories.columns.addresses')}</Table.Th>
                  <Table.Th>{t('directories.columns.mfa')}</Table.Th>
                  <Table.Th>{t('directories.columns.enabled')}</Table.Th>
                  <Table.Th>{t('directories.columns.version')}</Table.Th>
                  <Table.Th>
                    <VisuallyHidden>{t('directories.columns.actions')}</VisuallyHidden>
                  </Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {items.map((d) => (
                  <Table.Tr key={d.id}>
                    <Table.Td style={WRAP}>{d.name}</Table.Td>
                    <Table.Td>
                      <Stack gap={2}>
                        {d.addresses.map((a) => (
                          <Code key={a} translate="no" style={WRAP}>
                            {a}
                          </Code>
                        ))}
                      </Stack>
                    </Table.Td>
                    <Table.Td>{d.mfa_required ? t('directories.mfa.on') : t('directories.mfa.off')}</Table.Td>
                    <Table.Td>
                      <StatusBadge tone={d.enabled ? 'success' : 'neutral'} icon={d.enabled ? 'CircleCheck' : undefined}>
                        {d.enabled ? t('directories.status.enabled') : t('directories.status.disabled')}
                      </StatusBadge>
                    </Table.Td>
                    <Table.Td>{d.version}</Table.Td>
                    <Table.Td>
                      <Group gap={6} wrap="nowrap">
                        <Button size="xs" variant="default" onClick={() => setDialog({ kind: 'form', directory: d })} aria-label={t('directories.edit', { name: d.name })}>
                          {t('users.actions.edit')}
                        </Button>
                        <Button size="xs" variant="default" onClick={() => setDialog({ kind: 'delete', directory: d })} aria-label={t('directories.delete', { name: d.name })}>
                          {t('directories.deleteShort')}
                        </Button>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </ResourceTable>
          )}
          {items.map((d) => (
            <DirectorySection key={d.id} directory={d} onTestSignIn={() => setDialog({ kind: 'test', directory: d })} />
          ))}
        </Stack>
      </section>

      <Notice tone="brand" title={t('settings.page.breakGlassTitle')}>
        {t('settings.page.breakGlassText')}
      </Notice>

      {dialog?.kind === 'form' && <DirectoryDialog directory={dialog.directory} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'delete' && <DeleteDialog directory={dialog.directory} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'test' && <TestSignInDialog directory={dialog.directory} onClose={() => setDialog(null)} />}
    </Stack>
  );
}

// DirectorySection is one directory's head (name, the two tests) and its group mappings.
function DirectorySection({ directory: d, onTestSignIn }: { directory: Directory; onTestSignIn: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const test = useMutation({ mutationFn: () => run(() => testDirectoryConnection(d.id)) });
  return (
    <section aria-label={d.name} className={classes.provider}>
      <div className={classes.providerHead}>
        <span className={classes.providerIcon}>
          <Icon name="Server" size={16} />
        </span>
        <div className={classes.providerText}>
          <Title order={4} className={classes.providerName}>
            {d.name}
          </Title>
        </div>
        <div className={classes.providerActions}>
          <Button
            size="xs"
            variant="default"
            leftSection={<Icon name="Unplug" size={14} />}
            loading={test.isPending}
            onClick={() => test.mutate()}
            aria-label={t('directories.testConnectionNamed', { name: d.name })}
          >
            {t('directories.testConnection')}
          </Button>
          <Button size="xs" variant="default" leftSection={<Icon name="UserRound" size={14} />} onClick={onTestSignIn} aria-label={t('directories.testSignInNamed', { name: d.name })}>
            {t('directories.testSignIn')}
          </Button>
        </div>
      </div>
      {test.isSuccess && (
        <Text role="status" size="sm" c="var(--alice-success)" mt="xs">
          {t('directories.connectionOk')}
        </Text>
      )}
      <ErrorAlert error={test.error} />
      <DirectoryMappings directoryId={d.id} />
    </section>
  );
}

function DeleteDialog({ directory, onClose }: { directory: Directory; onClose: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  // The version sent as If-Match; after a 412 (somebody else changed the directory) the list is read again and the newer
  // version is used by the next attempt.
  const [version, setVersion] = useState(directory.version);
  const remove = useMutation({
    mutationFn: () => run(() => deleteDirectory(directory.id, version)),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: LDAP_DIRECTORIES_KEY });
      onClose();
    },
    onError: async (e) => {
      if (!isApiError(e) || e.status !== 412) return;
      await client.invalidateQueries({ queryKey: LDAP_DIRECTORIES_KEY });
      const list = await client.fetchQuery({ queryKey: LDAP_DIRECTORIES_KEY, queryFn: () => run(listDirectories) });
      const fresh = list.items.find((d) => d.id === directory.id);
      if (fresh) setVersion(fresh.version);
    },
  });
  return (
    <AppModal opened onClose={onClose} title={t('directories.deleteTitle', { name: directory.name })}>
      <Stack gap="sm">
        <Text size="sm">{t('directories.deleteText')}</Text>
        <ErrorAlert error={remove.error} />
        <DialogActions>
          <Button variant="default" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button color="red" loading={remove.isPending} onClick={() => remove.mutate()}>
            {t('directories.deleteConfirm')}
          </Button>
        </DialogActions>
      </Stack>
    </AppModal>
  );
}
