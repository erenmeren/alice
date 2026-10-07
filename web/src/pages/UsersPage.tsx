import { useState, type FormEvent } from 'react';
import {
  Badge,
  Button,
  Group,
  NativeSelect,
  PasswordInput,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  VisuallyHidden,
} from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { listProviders } from '../api/sso';
import { SSO_PROVIDERS_KEY } from '../api/queryKeys';
import {
  createUser,
  listUsers,
  resetUserMfa,
  resetUserPassword,
  revokeUserSessions,
  updateUser,
} from '../api/endpoints';
import type { Role, User } from '../api/types';
import { ErrorAlert } from '../components/ErrorAlert';
import { useStepUp } from '../components/StepUpProvider';
import { formatDateTime } from '../datetime';
import { AppModal } from '../components/AppModal';

const ROLES: Role[] = ['admin', 'operator', 'auditor'];

type Dialog =
  | { kind: 'create' }
  | { kind: 'manage'; user: User }
  | { kind: 'edit'; user: User }
  | { kind: 'resetPassword'; user: User }
  | { kind: 'resetMfa'; user: User }
  | { kind: 'revoke'; user: User }
  | { kind: 'toggle'; user: User };

export function UsersPage() {
  const { t, i18n } = useTranslation();
  const users = useQuery({ queryKey: ['users'], queryFn: listUsers });
  const [dialog, setDialog] = useState<Dialog | null>(null);
  // The identity providers name the SSO users' provider. Read without a prompt: when it needs a fresh verification the
  // name is simply left out.
  const hasSSO = users.data?.items.some((u) => u.auth_source === 'oidc') ?? false;
  const providers = useQuery({ queryKey: SSO_PROVIDERS_KEY, queryFn: listProviders, enabled: hasSSO, retry: false });
  const providerName = (id: string | null) => providers.data?.items.find((p) => p.id === id)?.name;
  const close = () => setDialog(null);

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Title order={1}>{t('users.title')}</Title>
        <Button onClick={() => setDialog({ kind: 'create' })}>{t('users.add')}</Button>
      </Group>
      {users.isError && <ErrorAlert error={users.error} />}
      {users.isSuccess && (
        <Table striped highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('users.columns.username')}</Table.Th>
              <Table.Th>{t('users.columns.name')}</Table.Th>
              <Table.Th>{t('users.columns.role')}</Table.Th>
              <Table.Th>{t('users.columns.status')}</Table.Th>
              <Table.Th>{t('users.columns.mfa')}</Table.Th>
              <Table.Th>{t('users.columns.lastLogin')}</Table.Th>
              <Table.Th>
                <VisuallyHidden>{t('users.columns.actions')}</VisuallyHidden>
              </Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {users.data.items.map((u) => (
              <Table.Tr key={u.id}>
                <Table.Td>
                  <Text ff="monospace" size="sm">
                    {u.username}
                  </Text>
                  {u.auth_source === 'oidc' && (
                    <Group gap={4} mt={2}>
                      <Badge variant="outline" color="indigo.9" tt="none">
                        {t('users.sso')}
                      </Badge>
                      {providerName(u.sso_provider_id) && (
                        <Text size="xs" translate="no">
                          {providerName(u.sso_provider_id)}
                        </Text>
                      )}
                    </Group>
                  )}
                </Table.Td>
                <Table.Td>{u.display_name}</Table.Td>
                <Table.Td>{t(`enum.role.${u.role}`)}</Table.Td>
                <Table.Td>
                  <Badge color={u.disabled ? 'gray' : 'green'} variant="light">
                    {u.disabled ? t('users.status.disabled') : t('users.status.active')}
                  </Badge>
                </Table.Td>
                <Table.Td>{u.auth_source === 'oidc' ? t('users.mfa.atProvider') : u.mfa_enrolled ? t('users.mfa.enrolled') : t('users.mfa.notEnrolled')}</Table.Td>
                <Table.Td>{u.last_login_at ? formatDateTime(u.last_login_at, i18n.language) : t('users.never')}</Table.Td>
                <Table.Td>
                  <Button size="xs" variant="light" onClick={() => setDialog({ kind: 'manage', user: u })} aria-label={t('users.manageNamed', { name: u.username })}>
                    {t('users.manage')}
                  </Button>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
      {dialog?.kind === 'create' && <CreateUserModal onClose={close} />}
      {dialog?.kind === 'manage' && <ManageModal user={dialog.user} onChoose={setDialog} onClose={close} />}
      {dialog?.kind === 'edit' && <EditUserModal user={dialog.user} onClose={close} />}
      {dialog?.kind === 'resetPassword' && <ResetPasswordModal user={dialog.user} onClose={close} />}
      {(dialog?.kind === 'resetMfa' || dialog?.kind === 'revoke' || dialog?.kind === 'toggle') && (
        <ConfirmModal kind={dialog.kind} user={dialog.user} onClose={close} />
      )}
    </Stack>
  );
}

function ManageModal({ user, onChoose, onClose }: { user: User; onChoose: (d: Dialog) => void; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <AppModal opened onClose={onClose} title={t('users.manageTitle', { name: user.username })}>
      <Stack gap="xs">
        <Button variant="default" onClick={() => onChoose({ kind: 'edit', user })}>
          {t('users.actions.edit')}
        </Button>
        {/* An SSO user has no Alice password or authenticator (the server refuses with ALC-USR-0003 anyway). */}
        {user.auth_source !== 'oidc' && (
          <>
            <Button variant="default" onClick={() => onChoose({ kind: 'resetMfa', user })}>
              {t('users.actions.resetMfa')}
            </Button>
            <Button variant="default" onClick={() => onChoose({ kind: 'resetPassword', user })}>
              {t('users.actions.resetPassword')}
            </Button>
          </>
        )}
        <Button variant="default" onClick={() => onChoose({ kind: 'revoke', user })}>
          {t('users.actions.revokeSessions')}
        </Button>
        <Button variant="default" color={user.disabled ? undefined : 'red'} onClick={() => onChoose({ kind: 'toggle', user })}>
          {user.disabled ? t('users.actions.enable') : t('users.actions.disable')}
        </Button>
      </Stack>
    </AppModal>
  );
}

// useUserAction runs a mutating call through step-up, then refreshes the list.
function useUserAction(onDone: () => void) {
  const { run } = useStepUp();
  const client = useQueryClient();
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  async function perform(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await run(fn);
      await client.invalidateQueries({ queryKey: ['users'] });
      onDone();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  return { perform, error, busy };
}

function RoleSelect({ value, onChange }: { value: Role; onChange: (r: Role) => void }) {
  const { t } = useTranslation();
  return (
    <NativeSelect
      label={t('users.fields.role')}
      value={value}
      onChange={(e) => onChange(e.currentTarget.value as Role)}
      data={ROLES.map((r) => ({ value: r, label: t(`enum.role.${r}`) }))}
    />
  );
}

function CreateUserModal({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<Role>('operator');
  const [password, setPassword] = useState('');
  const { perform, error, busy } = useUserAction(onClose);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void perform(() => createUser({ username, display_name: displayName, email, role, password }));
  };
  return (
    <AppModal opened onClose={onClose} title={t('users.add')}>
      <form onSubmit={submit}>
        <Stack gap="sm">
          <TextInput
            label={t('users.fields.username')}
            description={t('ui.usernameHelp')}
            value={username}
            onChange={(e) => setUsername(e.currentTarget.value)}
            required
            autoComplete="off"
          />
          <TextInput label={t('users.fields.name')} value={displayName} onChange={(e) => setDisplayName(e.currentTarget.value)} required />
          <TextInput label={t('users.fields.email')} type="email" value={email} onChange={(e) => setEmail(e.currentTarget.value)} />
          <RoleSelect value={role} onChange={setRole} />
          <PasswordInput
            label={t('users.fields.initialPassword')}
            description={t('users.fields.initialPasswordHelp')}
            value={password}
            onChange={(e) => setPassword(e.currentTarget.value)}
            required
            autoComplete="new-password"
          />
          <ErrorAlert error={error} />
          <Button type="submit" loading={busy}>
            {t('users.create')}
          </Button>
        </Stack>
      </form>
    </AppModal>
  );
}

function EditUserModal({ user, onClose }: { user: User; onClose: () => void }) {
  const { t } = useTranslation();
  const [displayName, setDisplayName] = useState(user.display_name);
  const [email, setEmail] = useState(user.email);
  const [role, setRole] = useState<Role>(user.role);
  const sso = user.auth_source === 'oidc';
  const { perform, error, busy } = useUserAction(onClose);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    // The role of an SSO user comes from their groups: it is neither offered nor sent.
    void perform(() => updateUser(user.id, sso ? { display_name: displayName, email } : { display_name: displayName, email, role }));
  };
  return (
    <AppModal opened onClose={onClose} title={t('users.editTitle', { name: user.username })}>
      <form onSubmit={submit}>
        <Stack gap="sm">
          <TextInput label={t('users.fields.name')} value={displayName} onChange={(e) => setDisplayName(e.currentTarget.value)} required />
          <TextInput label={t('users.fields.email')} type="email" value={email} onChange={(e) => setEmail(e.currentTarget.value)} />
          {!sso && <RoleSelect value={role} onChange={setRole} />}
          <ErrorAlert error={error} />
          <Button type="submit" loading={busy}>
            {t('users.save')}
          </Button>
        </Stack>
      </form>
    </AppModal>
  );
}

function ResetPasswordModal({ user, onClose }: { user: User; onClose: () => void }) {
  const { t } = useTranslation();
  const [password, setPassword] = useState('');
  const { perform, error, busy } = useUserAction(onClose);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void perform(() => resetUserPassword(user.id, password));
  };
  return (
    <AppModal opened onClose={onClose} title={t('users.resetPasswordTitle', { name: user.username })}>
      <form onSubmit={submit}>
        <Stack gap="sm">
          <Text size="sm">{t('users.resetPasswordText')}</Text>
          <PasswordInput label={t('users.fields.newPassword')} value={password} onChange={(e) => setPassword(e.currentTarget.value)} required autoComplete="new-password" />
          <ErrorAlert error={error} />
          <Button type="submit" loading={busy}>
            {t('users.setPassword')}
          </Button>
        </Stack>
      </form>
    </AppModal>
  );
}

function ConfirmModal({ kind, user, onClose }: { kind: 'resetMfa' | 'revoke' | 'toggle'; user: User; onClose: () => void }) {
  const { t } = useTranslation();
  const { perform, error, busy } = useUserAction(onClose);
  const name = user.username;
  let title: string;
  let text: string;
  let button: string;
  let action: () => Promise<unknown>;
  if (kind === 'resetMfa') {
    title = t('users.confirm.resetMfaTitle', { name });
    text = t('users.confirm.resetMfaText');
    button = t('users.actions.resetMfa');
    action = () => resetUserMfa(user.id);
  } else if (kind === 'revoke') {
    title = t('users.confirm.revokeTitle', { name });
    text = t('users.confirm.revokeText');
    button = t('users.actions.revokeSessions');
    action = () => revokeUserSessions(user.id);
  } else if (user.disabled) {
    title = t('users.confirm.enableTitle', { name });
    text = t('users.confirm.enableText');
    button = t('users.confirm.enableButton');
    action = () => updateUser(user.id, { disabled: false });
  } else {
    title = t('users.confirm.disableTitle', { name });
    text = t('users.confirm.disableText');
    button = t('users.confirm.disableButton');
    action = () => updateUser(user.id, { disabled: true });
  }
  return (
    <AppModal opened onClose={onClose} title={title}>
      <Stack gap="sm">
        <Text size="sm">{text}</Text>
        <ErrorAlert error={error} />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            {t('users.cancel')}
          </Button>
          {/* red 9: white text 5.4:1; the default red shade is below WCAG AA (4.5:1). */}
          <Button color={kind === 'toggle' && !user.disabled ? 'red.9' : undefined} loading={busy} onClick={() => void perform(action)}>
            {button}
          </Button>
        </Group>
      </Stack>
    </AppModal>
  );
}
