import { useState, type FormEvent } from 'react';
import { Alert, Button, Code, CopyButton, Group, NativeSelect, NumberInput, Stack, Table, Text, Textarea, TextInput, VisuallyHidden } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import {
  createAutomationAccount,
  createAutomationToken,
  listAutomationAccounts,
  listAutomationTokens,
  revokeAutomationToken,
  updateAutomationAccount,
  type AutomationAccount,
  type AutomationRole,
} from '../../api/access';
import { ACCESS_KEY, AUTOMATION_KEY, automationTokensKey } from '../../api/queryKeys';
import type { TokenScope } from '../../api/types';
import { useAuth } from '../../auth/AuthProvider';
import { canPlatform } from '../../auth/permissions';
import { formatDateTime } from '../../datetime';
import { Icon } from '../../design/Icon';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { useStepUp } from '../StepUpProvider';
import { DialogActions, EmptyState, Notice, Panel, ResourceTable, StatusBadge } from '../ui';
import { roleLabel } from './shared';
import { ServiceLimitSelect, TokenLimit } from './ServiceLimit';
import { UserAccess } from './UserAccess';

const AUTOMATION_ROLES: AutomationRole[] = ['operator', 'auditor'];
const SCOPES: TokenScope[] = ['read', 'operate'];

type Dialog =
  | { kind: 'create' }
  | { kind: 'edit'; account: AutomationAccount }
  | { kind: 'access'; account: AutomationAccount }
  | { kind: 'tokens'; account: AutomationAccount }
  | { kind: 'toggle'; account: AutomationAccount };

// AutomationTab is People & access, Automation accounts (R54, design §6.2, §9): a non-person that never signs in and
// only holds API tokens, which an Administrator makes on its page. Its role on all services is none, Operator or
// Auditor; on services and environments it may hold any role (its Access). Every change asks for a fresh code.
export function AutomationTab() {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  const canManage = canPlatform(session, 'access.manage');
  const accounts = useQuery({ queryKey: AUTOMATION_KEY, queryFn: ({ signal }) => listAutomationAccounts(signal) });
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const close = () => setDialog(null);
  return (
    <Stack gap="md" data-testid="automation-tab">
      <Notice tone="brand" title={t('automation.introTitle')}>
        {t('automation.intro')}
      </Notice>
      {canManage && (
        <Group>
          <Button leftSection={<Icon name="Plus" size={15} />} onClick={() => setDialog({ kind: 'create' })}>
            {t('automation.add')}
          </Button>
        </Group>
      )}
      <ErrorAlert error={accounts.error} />
      {accounts.isSuccess && accounts.data.items.length === 0 && (
        <Panel>
          <EmptyState icon="KeyRound" title={t('automation.empty')} testId="automation-empty" />
        </Panel>
      )}
      {accounts.isSuccess && accounts.data.items.length > 0 && (
        <ResourceTable label={t('automation.table')} minWidth={760} testId="automation-table">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('automation.columns.account')}</Table.Th>
              <Table.Th>{t('automation.columns.role')}</Table.Th>
              <Table.Th>{t('automation.columns.status')}</Table.Th>
              <Table.Th>{t('automation.columns.tokens')}</Table.Th>
              <Table.Th>{t('automation.columns.lastUsed')}</Table.Th>
              <Table.Th>
                <VisuallyHidden>{t('automation.columns.actions')}</VisuallyHidden>
              </Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {accounts.data.items.map((a) => (
              <Table.Tr key={a.id} data-testid="automation-row">
                <Table.Td>
                  <Text size="sm">{a.display_name}</Text>
                  <Text size="xs" c="dimmed" translate="no">
                    {a.username}
                  </Text>
                  {a.description && <Text size="xs">{a.description}</Text>}
                </Table.Td>
                <Table.Td>{roleLabel(t, a.role)}</Table.Td>
                <Table.Td>
                  <StatusBadge tone={a.disabled ? 'neutral' : 'success'}>{a.disabled ? t('users.status.disabled') : t('users.status.active')}</StatusBadge>
                </Table.Td>
                <Table.Td>{a.tokens}</Table.Td>
                <Table.Td>{a.last_used_at ? formatDateTime(a.last_used_at, i18n.language) : t('tokens.never')}</Table.Td>
                <Table.Td>
                  <Group gap={4} justify="flex-end" wrap="nowrap">
                    <Button size="xs" variant="default" onClick={() => setDialog({ kind: 'tokens', account: a })} aria-label={t('automation.tokensNamed', { name: a.username })}>
                      {t('automation.tokens')}
                    </Button>
                    <Button size="xs" variant="default" onClick={() => setDialog({ kind: 'access', account: a })} aria-label={t('automation.accessNamed', { name: a.username })}>
                      {t('users.actions.access')}
                    </Button>
                    {canManage && (
                      <>
                        <Button size="xs" variant="default" onClick={() => setDialog({ kind: 'edit', account: a })} aria-label={t('automation.editNamed', { name: a.username })}>
                          {t('users.actions.edit')}
                        </Button>
                        <Button
                          size="xs"
                          variant="subtle"
                          color={a.disabled ? undefined : 'red'}
                          onClick={() => setDialog({ kind: 'toggle', account: a })}
                          aria-label={t(a.disabled ? 'automation.enableNamed' : 'automation.disableNamed', { name: a.username })}
                        >
                          {a.disabled ? t('users.actions.enable') : t('users.actions.disable')}
                        </Button>
                      </>
                    )}
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </ResourceTable>
      )}
      {dialog?.kind === 'create' && <AccountModal onClose={close} />}
      {dialog?.kind === 'edit' && <AccountModal account={dialog.account} onClose={close} />}
      {dialog?.kind === 'toggle' && <ToggleModal account={dialog.account} onClose={close} />}
      {dialog?.kind === 'access' && (
        <AppModal opened onClose={close} size="xl" title={t('access.modalTitle', { name: dialog.account.username })}>
          <UserAccess user={{ id: dialog.account.id, role: dialog.account.role, auth_source: 'automation' }} />
        </AppModal>
      )}
      {dialog?.kind === 'tokens' && <TokensModal account={dialog.account} canManage={canManage} onClose={close} />}
    </Stack>
  );
}

// useAccountChange runs a change with a fresh step-up, then reads the accounts and bindings again.
function useAccountChange<T>(fn: () => Promise<T>, onDone: () => void) {
  const { run } = useStepUp();
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => run(fn),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ACCESS_KEY });
      onDone();
    },
  });
}

// AccountModal creates an automation account or changes its display name, description and role on all services.
function AccountModal({ account, onClose }: { account?: AutomationAccount; onClose: () => void }) {
  const { t } = useTranslation();
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState(account?.display_name ?? '');
  const [description, setDescription] = useState(account?.description ?? '');
  const [role, setRole] = useState<AutomationRole | null>(account ? account.role : null);
  const save = useAccountChange(
    () => (account ? updateAutomationAccount(account.id, { display_name: displayName, description, role }) : createAutomationAccount({ username, display_name: displayName, description, role })),
    onClose,
  );
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate();
  };
  return (
    <AppModal opened onClose={onClose} title={account ? t('automation.editTitle', { name: account.username }) : t('automation.add')}>
      <form onSubmit={submit}>
        <Stack gap="sm">
          {!account && (
            <TextInput label={t('users.fields.username')} description={t('ui.usernameHelp')} value={username} onChange={(e) => setUsername(e.currentTarget.value)} required autoComplete="off" />
          )}
          <TextInput label={t('automation.fields.displayName')} value={displayName} onChange={(e) => setDisplayName(e.currentTarget.value)} required maxLength={100} />
          <Textarea label={t('automation.fields.description')} value={description} onChange={(e) => setDescription(e.currentTarget.value)} maxLength={500} autosize minRows={2} />
          <NativeSelect
            label={t('users.fields.role')}
            description={t('automation.fields.roleHelp')}
            value={role ?? ''}
            onChange={(e) => setRole((e.currentTarget.value || null) as AutomationRole | null)}
            data={[{ value: '', label: t('access.noGlobalRole') }, ...AUTOMATION_ROLES.map((r) => ({ value: r, label: t(`enum.role.${r}`) }))]}
          />
          <ErrorAlert error={save.error} />
          <DialogActions>
            <Button type="submit" loading={save.isPending}>
              {account ? t('users.save') : t('automation.create')}
            </Button>
          </DialogActions>
        </Stack>
      </form>
    </AppModal>
  );
}

// ToggleModal disables an account (which revokes its tokens for good) or enables it again.
function ToggleModal({ account, onClose }: { account: AutomationAccount; onClose: () => void }) {
  const { t } = useTranslation();
  const disable = !account.disabled;
  const change = useAccountChange(() => updateAutomationAccount(account.id, { disabled: disable }), onClose);
  return (
    <AppModal opened onClose={onClose} title={t(disable ? 'automation.disableTitle' : 'automation.enableTitle', { name: account.username })}>
      <Stack gap="sm">
        <Text size="sm">{disable ? t('automation.disableText', { count: account.tokens }) : t('automation.enableText')}</Text>
        <ErrorAlert error={change.error} />
        <DialogActions>
          <Button variant="default" onClick={onClose}>
            {t('users.cancel')}
          </Button>
          <Button color={disable ? 'red' : undefined} loading={change.isPending} onClick={() => change.mutate()}>
            {disable ? t('users.actions.disable') : t('users.actions.enable')}
          </Button>
        </DialogActions>
      </Stack>
    </AppModal>
  );
}

// TokensModal is an account's tokens: the list, a new token (its secret shown once), revoke.
function TokensModal({ account, canManage, onClose }: { account: AutomationAccount; canManage: boolean; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const tokens = useQuery({ queryKey: automationTokensKey(account.id), queryFn: ({ signal }) => listAutomationTokens(account.id, signal) });
  // The secret lives only in this component's state: shown once, never in a URL, the query cache or storage.
  const [created, setCreated] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [scope, setScope] = useState<TokenScope>('read');
  const [days, setDays] = useState<number | string>(90);
  const [limit, setLimit] = useState<string[]>([]);
  const refresh = () => client.invalidateQueries({ queryKey: ACCESS_KEY });
  const create = useMutation({
    mutationFn: () => run(() => createAutomationToken(account.id, { name, scope, expires_in_days: Number(days), ...(limit.length > 0 ? { service_ids: limit } : {}) })),
    onSuccess: async (res) => {
      setCreated(res.token);
      setName('');
      setLimit([]);
      await refresh();
    },
  });
  const revoke = useMutation({ mutationFn: (id: string) => run(() => revokeAutomationToken(account.id, id)), onSuccess: refresh });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate();
  };
  return (
    <AppModal opened onClose={onClose} size="xl" title={t('automation.tokensTitle', { name: account.username })}>
      <Stack gap="md" data-testid="automation-tokens">
        {created && (
          <Alert color="yellow" title={t('tokens.createdTitle')} icon={<Icon name="KeyRound" size={17} />}>
            <Stack gap="xs">
              <Text size="sm">{t('tokens.createdText')}</Text>
              <Code block data-testid="new-automation-token" translate="no">
                {created}
              </Code>
              <Group>
                <CopyButton value={created}>
                  {({ copied, copy }) => (
                    <Button size="xs" variant="default" leftSection={<Icon name="Copy" size={14} />} onClick={copy}>
                      {copied ? t('tokens.copied') : t('tokens.copy')}
                    </Button>
                  )}
                </CopyButton>
                <Button size="xs" variant="default" onClick={() => setCreated(null)}>
                  {t('tokens.done')}
                </Button>
              </Group>
            </Stack>
          </Alert>
        )}
        <ErrorAlert error={tokens.error ?? revoke.error} />
        {tokens.data && tokens.data.items.length === 0 && <Text size="sm">{t('tokens.empty')}</Text>}
        {tokens.data && tokens.data.items.length > 0 && (
          <Table.ScrollContainer minWidth={600}>
            <Table aria-label={t('automation.tokensTable')}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('tokens.columns.name')}</Table.Th>
                  <Table.Th>{t('tokens.columns.access')}</Table.Th>
                  <Table.Th>{t('tokens.columns.services')}</Table.Th>
                  <Table.Th>{t('tokens.columns.expires')}</Table.Th>
                  <Table.Th>{t('tokens.columns.lastUsed')}</Table.Th>
                  {canManage && (
                    <Table.Th>
                      <VisuallyHidden>{t('tokens.columns.actions')}</VisuallyHidden>
                    </Table.Th>
                  )}
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {tokens.data.items.map((tok) => (
                  <Table.Tr key={tok.id} data-testid="automation-token-row">
                    <Table.Td>
                      {tok.name}{' '}
                      <Text span size="xs" c="dimmed" translate="no">
                        {tok.prefix}
                      </Text>
                    </Table.Td>
                    <Table.Td>{t(`tokens.scope.${tok.scope}`)}</Table.Td>
                    <Table.Td>
                      <TokenLimit token={tok} />
                    </Table.Td>
                    <Table.Td>{formatDateTime(tok.expires_at, i18n.language)}</Table.Td>
                    <Table.Td>{tok.last_used_at ? formatDateTime(tok.last_used_at, i18n.language) : t('tokens.never')}</Table.Td>
                    {canManage && (
                      <Table.Td style={{ textAlign: 'end' }}>
                        <Button
                          size="xs"
                          variant="subtle"
                          color="red"
                          loading={revoke.isPending && revoke.variables === tok.id}
                          onClick={() => revoke.mutate(tok.id)}
                          aria-label={t('tokens.revokeNamed', { name: tok.name })}
                        >
                          {t('tokens.revoke')}
                        </Button>
                      </Table.Td>
                    )}
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
        {canManage && !account.disabled && (
          <Panel title={t('tokens.create')} description={t('automation.tokenHelp')} headingOrder={3}>
            <form onSubmit={submit}>
              <Stack gap="sm">
                <TextInput label={t('tokens.fields.name')} value={name} onChange={(e) => setName(e.currentTarget.value)} required maxLength={100} />
                <NativeSelect label={t('tokens.fields.access')} value={scope} onChange={(e) => setScope(e.currentTarget.value as TokenScope)} data={SCOPES.map((s) => ({ value: s, label: t(`tokens.scope.${s}`) }))} />
                <NumberInput label={t('tokens.fields.days')} value={days} onChange={setDays} min={1} max={365} allowDecimal={false} required />
                <ServiceLimitSelect value={limit} onChange={setLimit} />
                <ErrorAlert error={create.error} />
                <Group>
                  <Button type="submit" loading={create.isPending}>
                    {t('tokens.submit')}
                  </Button>
                </Group>
              </Stack>
            </form>
          </Panel>
        )}
        {account.disabled && (
          <Notice tone="info" title={t('automation.disabledTitle')}>
            {t('automation.disabledTokens')}
          </Notice>
        )}
      </Stack>
    </AppModal>
  );
}
