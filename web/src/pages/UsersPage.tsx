import { useState, type FormEvent } from 'react';
import { Button, NativeSelect, PasswordInput, Stack, Table, Text, TextInput, VisuallyHidden } from '@mantine/core';
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
import { DialogActions, PageHeader, ResourceTable, StatusBadge } from '../components/ui';
import { formatDateTime } from '../datetime';
import { Icon, type IconName } from '../design/Icon';
import { initials } from '../initials';
import { AppModal } from '../components/AppModal';
import classes from './People.module.css';

const ROLES: Role[] = ['admin', 'operator', 'auditor'];
const ROLE_ICON: Record<Role, IconName> = { admin: 'ShieldCheck', operator: 'Settings2', auditor: 'Eye' };

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
    <Stack gap={0}>
      <PageHeader
        title={t('users.title')}
        description={t('users.page.description')}
        actions={
          <Button leftSection={<Icon name="Plus" size={15} />} onClick={() => setDialog({ kind: 'create' })}>
            {t('users.add')}
          </Button>
        }
      />
      <div role="group" aria-label={t('users.page.roles')} className={classes.roleCards}>
        {ROLES.map((r) => (
          <div key={r} className={classes.roleCard}>
            <div className={classes.roleHead}>
              <h2 className={classes.roleName}>{t(`enum.role.${r}`)}</h2>
              <Icon name={ROLE_ICON[r]} size={17} />
            </div>
            <p className={classes.roleText}>{t(`users.page.${r}`)}</p>
          </div>
        ))}
      </div>
      {users.isError && <ErrorAlert error={users.error} />}
      {users.isSuccess && (
        <ResourceTable label={t('users.page.table')} minWidth={760}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('users.page.person')}</Table.Th>
              <Table.Th>{t('users.columns.role')}</Table.Th>
              <Table.Th>{t('users.page.signIn')}</Table.Th>
              <Table.Th>{t('users.columns.status')}</Table.Th>
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
                  <div className={classes.person}>
                    <span className={classes.avatar} aria-hidden="true">
                      {initials(u.display_name, i18n.language)}
                    </span>
                    <div>
                      <p className={classes.name}>{u.display_name}</p>
                      <p className={classes.secondary}>
                        <span className={classes.mono} translate="no">
                          {u.username}
                        </span>
                        {u.email && <span translate="no">{u.email}</span>}
                      </p>
                    </div>
                  </div>
                </Table.Td>
                <Table.Td>
                  <span className={classes.userRole}>{t(`enum.role.${u.role}`)}</span>
                </Table.Td>
                <Table.Td>
                  <SignInMethod user={u} provider={providerName(u.sso_provider_id)} />
                </Table.Td>
                <Table.Td>
                  <StatusBadge tone={u.disabled ? 'neutral' : 'success'}>{u.disabled ? t('users.status.disabled') : t('users.status.active')}</StatusBadge>
                </Table.Td>
                <Table.Td className={classes.time}>{u.last_login_at ? formatDateTime(u.last_login_at, i18n.language) : t('users.never')}</Table.Td>
                <Table.Td>
                  <Button
                    size="xs"
                    variant="default"
                    leftSection={<Icon name="Settings2" size={14} />}
                    onClick={() => setDialog({ kind: 'manage', user: u })}
                    aria-label={t('users.manageNamed', { name: u.username })}
                  >
                    {t('users.manage')}
                  </Button>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </ResourceTable>
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

// SignInMethod is the design's sign-in method badge: a local account (toned by whether the authenticator app is set up)
// or single sign-on with its provider, whose second factor is the identity provider's.
function SignInMethod({ user, provider }: { user: User; provider: string | undefined }) {
  const { t } = useTranslation();
  if (user.auth_source === 'oidc') {
    return (
      <div className={classes.method}>
        <StatusBadge tone="info" icon="Building2">
          {t('users.sso')}
        </StatusBadge>
        {provider && (
          <Text size="xs" translate="no">
            {provider}
          </Text>
        )}
        <p className={classes.secondary}>{t('users.mfa.atProvider')}</p>
      </div>
    );
  }
  return (
    <div className={classes.method}>
      <StatusBadge tone={user.mfa_enrolled ? 'success' : 'warning'} icon={user.mfa_enrolled ? 'ShieldCheck' : 'CircleAlert'}>
        {t('users.page.local')}
      </StatusBadge>
      <p className={classes.secondary}>{user.mfa_enrolled ? t('users.page.mfaEnrolled') : t('users.page.mfaPending')}</p>
    </div>
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
          <DialogActions>
            <Button type="submit" loading={busy}>
              {t('users.create')}
            </Button>
          </DialogActions>
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
          <DialogActions>
            <Button type="submit" loading={busy}>
              {t('users.save')}
            </Button>
          </DialogActions>
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
          <DialogActions>
            <Button type="submit" loading={busy}>
              {t('users.setPassword')}
            </Button>
          </DialogActions>
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
        <DialogActions>
          <Button variant="default" onClick={onClose}>
            {t('users.cancel')}
          </Button>
          {/* The theme's red is the danger tone, with --alice-on-strong text on it (≥ 4.5:1 in both schemes). */}
          <Button color={kind === 'toggle' && !user.disabled ? 'red' : undefined} loading={busy} onClick={() => void perform(action)}>
            {button}
          </Button>
        </DialogActions>
      </Stack>
    </AppModal>
  );
}
