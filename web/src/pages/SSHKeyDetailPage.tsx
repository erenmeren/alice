import { Anchor, Badge, Button, Code, CopyButton, Group, Stack, Table, Text, Title } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useParams } from 'react-router';
import { getSSHKey } from '../api/endpoints';
import { sshKey, SSH_KEYS_KEY, TARGETS_KEY } from '../api/queryKeys';
import type { KeyLocation } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { PageLoader } from '../auth/guards';
import { DeployKeyDialog } from '../components/DeployKeyDialog';
import { DownloadKeyDialog } from '../components/DownloadKeyDialog';
import { ErrorAlert } from '../components/ErrorAlert';
import { KeyFlags } from '../components/KeyFlags';
import { RotationPolicyPanel } from '../components/RotationPolicyPanel';
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
  const isAdmin = session?.user.role === 'admin';
  const key = useQuery({ queryKey: sshKey(id), queryFn: () => getSSHKey(id) });
  const [removing, setRemoving] = useState<KeyLocation | null>(null);
  const [deploying, setDeploying] = useState(false);
  const [downloading, setDownloading] = useState(false);

  if (key.isPending) return <PageLoader />;
  if (key.isError || !key.data)
    return (
      <Stack gap="md">
        <ErrorAlert error={key.error} />
        <Anchor component={Link} to="/ssh-keys" w="fit-content">
          {t('sshKeys.backToList')}
        </Anchor>
      </Stack>
    );
  const k = key.data;
  const mk = k.managed_key ?? null;
  const live = mk !== null && mk.destroyed_at === null;
  const state = (l: KeyLocation) => (l.removed_at ? t('sshKeys.removedByAlice') : l.missing_since ? t('sshKeys.missing') : t('sshKeys.present'));

  return (
    <Stack gap="md">
      <Title order={1}>{t('sshKeys.detailTitle')}</Title>
      {mk && (
        <Stack gap="xs" data-testid="managed-key">
          <Title order={2} size="h4">
            {t('sshKeys.managedTitle')}
          </Title>
          <Group gap={6}>
            <Badge variant="light" color="teal" tt="none">
              {t('sshKeys.managedBadge')}
            </Badge>
            {mk.retired_at && (
              <Badge variant="light" color="gray" tt="none">
                {t('sshKeys.retiredBadge')}
              </Badge>
            )}
            {mk.destroyed_at && (
              <Badge variant="light" color="gray" tt="none">
                {t('sshKeys.destroyedBadge')}
              </Badge>
            )}
          </Group>
          <Text size="sm" fw={600} translate="no">
            {mk.label}
          </Text>
          <Code translate="no" style={WRAP}>{mk.comment}</Code>
          <Text size="sm">{t('sshKeys.downloadCount', { count: mk.download_count })}</Text>
          {mk.last_downloaded_at && <Text size="sm">{t('sshKeys.lastDownloaded', { date: formatDateTime(mk.last_downloaded_at, i18n.language) })}</Text>}
          {mk.rotated_from && (
            <Anchor component={Link} to={`/ssh-keys/${encodeURIComponent(mk.rotated_from)}`} w="fit-content" size="sm">
              {t('sshKeys.rotatedFrom')}
            </Anchor>
          )}
          <Group gap="sm">
            {canOperate && mk.retired_at === null && (
              <Button size="xs" onClick={() => setDeploying(true)}>
                {t('sshKeys.deploy')}
              </Button>
            )}
            {isAdmin && live && (
              <Button size="xs" variant="default" onClick={() => setDownloading(true)}>
                {t('sshKeys.download')}
              </Button>
            )}
          </Group>
        </Stack>
      )}
      {mk && mk.retired_at === null && <RotationPolicyPanel keyId={id} policyId={mk.policy_id} isAdmin={isAdmin} />}
      {k.is_platform_key && <Text size="sm">{t('sshKeys.noDownloadPlatform')}</Text>}
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
      {mk && (
        <>
          <DeployKeyDialog keyId={id} opened={deploying} onClose={() => setDeploying(false)} />
          <DownloadKeyDialog keyId={id} label={mk.label} opened={downloading} onClose={() => setDownloading(false)} />
        </>
      )}
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
