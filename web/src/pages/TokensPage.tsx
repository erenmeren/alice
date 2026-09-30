import { useState, type FormEvent } from 'react';
import {
  Alert,
  Button,
  Code,
  CopyButton,
  Group,
  NativeSelect,
  NumberInput,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { createToken, listTokens, revokeToken } from '../api/endpoints';
import type { ApiToken, TokenScope } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { ErrorAlert } from '../components/ErrorAlert';
import { useStepUp } from '../components/StepUpProvider';
import { formatDateTime } from '../datetime';
import { AppModal } from '../components/AppModal';

export function TokensPage() {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const tokens = useQuery({ queryKey: ['tokens'], queryFn: () => listTokens() });
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<ApiToken | null>(null);
  const [created, setCreated] = useState<string | null>(null);

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Title order={1}>{t('tokens.title')}</Title>
        <Button onClick={() => setCreating(true)}>{t('tokens.create')}</Button>
      </Group>
      <Text size="sm">{t('tokens.intro')}</Text>
      {created && (
        <Alert color="yellow" title={t('tokens.createdTitle')}>
          <Stack gap="xs">
            <Text size="sm">{t('tokens.createdText')}</Text>
            <Code block data-testid="new-token">
              {created}
            </Code>
            <Group>
              <CopyButton value={created}>
                {({ copied, copy }) => (
                  <Button size="xs" variant="light" onClick={copy}>
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
      {tokens.isSuccess && tokens.data.items.length === 0 && <Text c="gray.7">{t('tokens.empty')}</Text>}
      {tokens.isSuccess && tokens.data.items.length > 0 && (
        <Table striped>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('tokens.columns.name')}</Table.Th>
              <Table.Th>{t('tokens.columns.prefix')}</Table.Th>
              <Table.Th>{t('tokens.columns.access')}</Table.Th>
              <Table.Th>{t('tokens.columns.expires')}</Table.Th>
              <Table.Th>{t('tokens.columns.lastUsed')}</Table.Th>
              <Table.Th>{t('tokens.columns.actions')}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {tokens.data.items.map((tok) => (
              <Table.Tr key={tok.id}>
                <Table.Td>{tok.name}</Table.Td>
                <Table.Td>
                  <Text ff="monospace" size="sm">
                    {tok.prefix}
                  </Text>
                </Table.Td>
                <Table.Td>{t(`tokens.scope.${tok.scope}`)}</Table.Td>
                <Table.Td>{formatDateTime(tok.expires_at, i18n.language)}</Table.Td>
                <Table.Td>{tok.last_used_at ? formatDateTime(tok.last_used_at, i18n.language) : t('tokens.never')}</Table.Td>
                <Table.Td>
                  <Button size="xs" variant="light" color="red" onClick={() => setRevoking(tok)} aria-label={t('tokens.revokeNamed', { name: tok.name })}>
                    {t('tokens.revoke')}
                  </Button>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
      {creating && (
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
  const readOnly = session?.user.role === 'auditor';
  const scopes: TokenScope[] = readOnly ? ['read'] : ['read', 'operate'];
  const [name, setName] = useState('');
  const [scope, setScope] = useState<TokenScope>('read');
  const [days, setDays] = useState<number | string>(90);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await run(() => createToken({ name, scope, expires_in_days: Number(days) }));
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
          <ErrorAlert error={error} />
          <Button type="submit" loading={busy}>
            {t('tokens.submit')}
          </Button>
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
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            {t('tokens.cancel')}
          </Button>
          {/* red 9: white text 5.4:1; the default red shade is below WCAG AA (4.5:1). */}
          <Button color="red.9" loading={busy} onClick={() => void confirm()}>
            {t('tokens.revokeConfirm')}
          </Button>
        </Group>
      </Stack>
    </AppModal>
  );
}
