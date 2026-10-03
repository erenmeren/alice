import { Anchor, Button, Code, CopyButton, Stack, Table, Text, Title } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useParams } from 'react-router';
import { getSSHKey } from '../api/endpoints';
import { SSH_KEYS_KEY, TARGETS_KEY } from '../api/queryKeys';
import type { KeyLocation } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { PageLoader } from '../auth/guards';
import { ErrorAlert } from '../components/ErrorAlert';
import { KeyFlags } from '../components/KeyFlags';
import { RemoveKeyDialog } from '../components/RemoveKeyDialog';
import { WRAP } from '../components/wrap';
import { formatDateTime } from '../datetime';

// SSHKeyDetailPage is one key and every place it is used (owner step 3: "open one and see where
// it is used"). Operators and Administrators can remove it from one place at a time.
export function SSHKeyDetailPage() {
  const { t, i18n } = useTranslation();
  const { id = '' } = useParams();
  const { session } = useAuth();
  const client = useQueryClient();
  const canOperate = session?.user.role === 'admin' || session?.user.role === 'operator';
  const key = useQuery({ queryKey: [...SSH_KEYS_KEY, id], queryFn: () => getSSHKey(id) });
  const [removing, setRemoving] = useState<KeyLocation | null>(null);

  if (key.isPending) return <PageLoader />;
  if (key.isError || !key.data) return <ErrorAlert error={key.error} />;
  const k = key.data;
  const state = (l: KeyLocation) => (l.removed_at ? t('sshKeys.removedByAlice') : l.missing_since ? t('sshKeys.missing') : t('sshKeys.present'));

  return (
    <Stack gap="md">
      <Title order={1}>{t('sshKeys.detailTitle')}</Title>
      <Text size="sm">{t('sshKeys.keyType', { type: k.key_type, bits: k.bits })}</Text>
      <Text size="sm" fw={600}>
        {t('sshKeys.fingerprintLabel')}
      </Text>
      <Code style={WRAP}>{k.fingerprint}</Code>
      <Text size="sm" fw={600}>
        {t('sshKeys.publicKey')}
      </Text>
      <Code block style={WRAP}>
        {k.public_key}
      </Code>
      <CopyButton value={k.public_key}>
        {({ copied, copy }) => (
          <Button size="xs" variant="light" w="fit-content" onClick={copy}>
            {copied ? t('sshKeys.copied') : t('sshKeys.copy')}
          </Button>
        )}
      </CopyButton>
      <Title order={2} size="h3">
        {t('sshKeys.usedWhere')}
      </Title>
      <Table.ScrollContainer minWidth={880}>
        <Table striped data-testid="key-locations">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('sshKeys.server')}</Table.Th>
              <Table.Th>{t('sshKeys.user')}</Table.Th>
              <Table.Th>{t('sshKeys.file')}</Table.Th>
              <Table.Th>{t('sshKeys.line')}</Table.Th>
              <Table.Th>{t('sshKeys.options')}</Table.Th>
              <Table.Th>{t('sshKeys.comment')}</Table.Th>
              <Table.Th>{t('sshKeys.lastSeen')}</Table.Th>
              <Table.Th>{t('sshKeys.state')}</Table.Th>
              <Table.Th>{t('sshKeys.actions')}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {(k.locations ?? []).map((l) => (
              <Table.Tr key={l.id}>
                <Table.Td>
                  <Anchor component={Link} to={`/servers/${l.target_id}`}>
                    {l.target_name}
                  </Anchor>
                </Table.Td>
                <Table.Td>{l.os_user}</Table.Td>
                <Table.Td>
                  <Code style={WRAP}>{l.file_path}</Code>
                </Table.Td>
                <Table.Td>{l.line_no}</Table.Td>
                <Table.Td>{l.options && <Code style={WRAP}>{l.options}</Code>}</Table.Td>
                <Table.Td style={WRAP}>
                  <Stack gap={2}>
                    <span>{l.comment}</span>
                    <KeyFlags location={l} />
                  </Stack>
                </Table.Td>
                <Table.Td>{formatDateTime(l.last_seen_at, i18n.language)}</Table.Td>
                <Table.Td>{state(l)}</Table.Td>
                <Table.Td>
                  {canOperate && !l.removed_at && !l.missing_since && (
                    <Button size="xs" variant="light" color="red.9" onClick={() => setRemoving(l)} aria-label={t('sshKeys.removeNamed', { user: l.os_user })}>
                      {t('sshKeys.removeConfirm')}
                    </Button>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      {removing && (
        <RemoveKeyDialog
          location={removing}
          onClose={() => setRemoving(null)}
          onDone={() => {
            setRemoving(null);
            void client.invalidateQueries({ queryKey: SSH_KEYS_KEY });
            void client.invalidateQueries({ queryKey: TARGETS_KEY });
          }}
        />
      )}
    </Stack>
  );
}
