import { useState, type FormEvent } from 'react';
import { Alert, Button, Code, CopyButton, Group, NativeSelect, NumberInput, Stack, Table, Text, TextInput, VisuallyHidden } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { createToken, listTokens, revokeToken } from '../api/endpoints';
import type { ApiToken, TokenScope } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { can } from '../auth/permissions';
import { ErrorAlert } from '../components/ErrorAlert';
import { useStepUp } from '../components/StepUpProvider';
import { DialogActions, EmptyState, Notice, PageHeader, Panel, ResourceTable, StatusBadge } from '../components/ui';
import { formatDateTime } from '../datetime';
import { Icon } from '../design/Icon';
import { AppModal } from '../components/AppModal';
import { ServiceLimitSelect, TokenLimit } from '../components/access/ServiceLimit';
import classes from './People.module.css';

export function TokensPage() {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const tokens = useQuery({ queryKey: ['tokens'], queryFn: () => listTokens() });
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<ApiToken | null>(null);
  // The new token's secret lives only in this component's state: shown once, never in a URL, the query cache or storage.
  const [created, setCreated] = useState<string | null>(null);
  // A single sign-on or directory user gets no API token (the server answers ALC-USR-0003): no create control, a note instead.
  const { session } = useAuth();
  const source = session?.user.auth_source;
  const sso = source === 'oidc' || source === 'ldap';

  return (
    <Stack gap="md">
      <PageHeader
        title={t('tokens.title')}
        description={t('tokens.page.description')}
        actions={
          !sso && (
            <Button leftSection={<Icon name="Plus" size={15} />} onClick={() => setCreating(true)}>
              {t('tokens.create')}
            </Button>
          )
        }
      />
      <Notice tone="brand" title={t('tokens.page.boundTitle')}>
        {t('tokens.page.boundText')}
      </Notice>
      {sso && (
        <Notice tone="info" title={source === 'ldap' ? t('users.directory') : t('users.sso')} testId="tokens-sso-note">
          {source === 'ldap' ? t('tokens.directoryNoCreate') : t('tokens.ssoNoCreate')}
        </Notice>
      )}
      {created && (
        <Alert color="yellow" title={t('tokens.createdTitle')} icon={<Icon name="KeyRound" size={17} />}>
          <Stack gap="xs">
            <Text size="sm">{t('tokens.createdText')}</Text>
            <Code block data-testid="new-token" translate="no">
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
      {tokens.isError && <ErrorAlert error={tokens.error} />}
      {tokens.isSuccess && tokens.data.items.length === 0 && (
        <Panel>
          <EmptyState icon="KeyRound" title={t('tokens.empty')} description={t('tokens.intro')} />
        </Panel>
      )}
      {tokens.isSuccess && tokens.data.items.length > 0 && (
        <ResourceTable label={t('tokens.page.table')} minWidth={720}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('tokens.columns.name')}</Table.Th>
              <Table.Th>{t('tokens.columns.prefix')}</Table.Th>
              <Table.Th>{t('tokens.columns.access')}</Table.Th>
              <Table.Th>{t('tokens.columns.services')}</Table.Th>
              <Table.Th>{t('tokens.columns.expires')}</Table.Th>
              <Table.Th>{t('tokens.columns.lastUsed')}</Table.Th>
              <Table.Th>
                <VisuallyHidden>{t('tokens.columns.actions')}</VisuallyHidden>
              </Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {tokens.data.items.map((tok) => (
              <Table.Tr key={tok.id}>
                <Table.Td>
                  <p className={classes.name}>{tok.name}</p>
                </Table.Td>
                <Table.Td>
                  <span className={classes.time} translate="no">
                    {tok.prefix}
                  </span>
                </Table.Td>
                <Table.Td>
                  <StatusBadge tone={tok.scope === 'operate' ? 'info' : 'neutral'} icon={tok.scope === 'operate' ? 'Settings2' : 'Eye'}>
                    {t(`tokens.scope.${tok.scope}`)}
                  </StatusBadge>
                </Table.Td>
                <Table.Td>
                  <TokenLimit token={tok} />
                </Table.Td>
                <Table.Td className={classes.time}>{formatDateTime(tok.expires_at, i18n.language)}</Table.Td>
                <Table.Td className={classes.time}>{tok.last_used_at ? formatDateTime(tok.last_used_at, i18n.language) : t('tokens.never')}</Table.Td>
                <Table.Td>
                  <Button
                    size="xs"
                    variant="subtle"
                    color="red"
                    leftSection={<Icon name="X" size={14} />}
                    onClick={() => setRevoking(tok)}
                    aria-label={t('tokens.revokeNamed', { name: tok.name })}
                  >
                    {t('tokens.revoke')}
                  </Button>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </ResourceTable>
      )}
      {creating && !sso && (
        <CreateTokenModal
          onClose={() => setCreating(false)}
          onCreated={(secret) => {
            setCreating(false);
            setCreated(secret);
            void client.invalidateQueries({ queryKey: ['tokens'] });
          }}
        />
      )}
      {revoking && (
        <RevokeTokenModal
          token={revoking}
          onClose={() => setRevoking(null)}
          onDone={() => {
            setRevoking(null);
            void client.invalidateQueries({ queryKey: ['tokens'] });
          }}
        />
      )}
    </Stack>
  );
}

function CreateTokenModal({ onClose, onCreated }: { onClose: () => void; onCreated: (secret: string) => void }) {
  const { t } = useTranslation();
  const { session } = useAuth();
  const { run } = useStepUp();
  // A token never does more than its owner: a person who changes nothing anywhere gets read tokens only.
  const readOnly = !can(session, 'inventory.operate') && !can(session, 'certificates.operate') && !can(session, 'targets.manage');
  const scopes: TokenScope[] = readOnly ? ['read'] : ['read', 'operate'];
  const [name, setName] = useState('');
  const [scope, setScope] = useState<TokenScope>('read');
  const [days, setDays] = useState<number | string>(90);
  const [limit, setLimit] = useState<string[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      // No service chosen is no limit: service_ids is left out (the server refuses an empty list).
      const res = await run(() => createToken({ name, scope, expires_in_days: Number(days), ...(limit.length > 0 ? { service_ids: limit } : {}) }));
      onCreated(res.token);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <AppModal opened onClose={onClose} title={t('tokens.create')}>
      <form onSubmit={(e) => void submit(e)}>
        <Stack gap="sm">
          <TextInput label={t('tokens.fields.name')} value={name} onChange={(e) => setName(e.currentTarget.value)} required maxLength={100} />
          <NativeSelect
            label={t('tokens.fields.access')}
            value={scope}
            onChange={(e) => setScope(e.currentTarget.value as TokenScope)}
            data={scopes.map((s) => ({ value: s, label: t(`tokens.scope.${s}`) }))}
          />
          <NumberInput
            label={t('tokens.fields.days')}
            value={days}
            onChange={setDays}
            min={1}
            max={365}
            allowDecimal={false}
            required
          />
          <ServiceLimitSelect value={limit} onChange={setLimit} />
          <ErrorAlert error={error} />
          <DialogActions>
            <Button type="submit" loading={busy}>
              {t('tokens.submit')}
            </Button>
          </DialogActions>
        </Stack>
      </form>
    </AppModal>
  );
}

function RevokeTokenModal({ token, onClose, onDone }: { token: ApiToken; onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation();
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      await revokeToken(token.id);
      onDone();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <AppModal opened onClose={onClose} title={t('tokens.revokeTitle', { name: token.name })}>
      <Stack gap="sm">
        <Text size="sm">{t('tokens.revokeText')}</Text>
        <ErrorAlert error={error} />
        <DialogActions>
          <Button variant="default" onClick={onClose}>
            {t('tokens.cancel')}
          </Button>
          {/* The theme's red is the danger tone, with --alice-on-strong text on it (≥ 4.5:1 in both schemes). */}
          <Button color="red" loading={busy} onClick={() => void confirm()}>
            {t('tokens.revokeConfirm')}
          </Button>
        </DialogActions>
      </Stack>
    </AppModal>
  );
}
