import { Button, Code, PasswordInput, Stack, Text, TextInput } from '@mantine/core';
import { useMutation } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { testDirectorySignIn, type Directory } from '../../api/ldap';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { useStepUp } from '../StepUpProvider';
import { WRAP } from '../wrap';
import { DialogActions, FactList } from '../ui';

// TestSignInDialog runs a directory sign-in without signing anybody in: it shows who the directory says the person is, the
// groups found (the values to copy into a group mapping) and the role they would give. The password lives only in this
// form's state and is cleared as soon as the request is built, whatever the answer; closing the dialog drops the rest.
export function TestSignInDialog({ directory, onClose }: { directory: Directory; onClose: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const test = useMutation({
    gcTime: 0, // the password is a mutation variable: do not keep it in the mutation cache
    mutationFn: (secret: string) => run(() => testDirectorySignIn(directory.id, username.trim(), secret)),
  });
  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    const secret = password;
    setPassword('');
    if (!username.trim() || !secret) return;
    test.mutate(secret);
  };
  const r = test.data;

  return (
    <AppModal opened onClose={onClose} title={t('directories.testSignInTitle', { name: directory.name })}>
      <form onSubmit={submit}>
        <Stack gap="sm">
          <Text size="sm">{t('directories.testSignInText')}</Text>
          <TextInput label={t('directories.testUsername')} value={username} onChange={(e) => setUsername(e.currentTarget.value)} autoComplete="off" spellCheck={false} required data-autofocus />
          <PasswordInput label={t('directories.testPassword')} value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoComplete="off" required />
          <ErrorAlert error={test.error} />
          {r && (
            <Stack gap="xs" role="status">
              <Text size="sm" fw={600} c="var(--alice-success)">
                {t('directories.result.title')}
              </Text>
              <FactList
                facts={[
                  { key: 'login', label: t('directories.result.login'), value: <span translate="no">{r.login}</span> },
                  { key: 'name', label: t('directories.result.displayName'), value: r.display_name || '—' },
                  { key: 'email', label: t('directories.result.email'), value: r.email ? <span translate="no">{r.email}</span> : '—' },
                  { key: 'id', label: t('directories.result.uniqueId'), value: <Code translate="no" style={WRAP}>{r.unique_id}</Code> },
                  {
                    key: 'groups',
                    label: t('directories.result.groups'),
                    value:
                      r.groups.length === 0 ? (
                        t('directories.result.noGroups')
                      ) : (
                        <Stack gap={2}>
                          {r.groups.map((g) => (
                            <Code key={g} translate="no" style={WRAP}>
                              {g}
                            </Code>
                          ))}
                        </Stack>
                      ),
                  },
                  { key: 'role', label: t('directories.result.role'), value: r.role ? t(`enum.role.${r.role}`) : t('directories.result.noRole') },
                ]}
              />
            </Stack>
          )}
          <DialogActions>
            <Button variant="default" onClick={onClose}>
              {t('ui.cancel')}
            </Button>
            <Button type="submit" loading={test.isPending}>
              {t('directories.runTest')}
            </Button>
          </DialogActions>
        </Stack>
      </form>
    </AppModal>
  );
}
