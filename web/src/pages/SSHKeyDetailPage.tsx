import { Anchor, Button, Code, CopyButton, Group, Stack, Table, Text } from '@mantine/core';
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
import { RemoveKeyDialog } from '../components/RemoveKeyDialog';
import { RotationPolicyPanel } from '../components/RotationPolicyPanel';
import { FactList, Notice, PageHeader, Panel, StatusBadge } from '../components/ui';
import { WRAP } from '../components/wrap';
import { formatDateTime } from '../datetime';
import { Icon } from '../design/Icon';
import classes from './SSHKeysPage.module.css';

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
  // Alice's own connection key is never "managed", yet Alice certainly holds its private half (not downloadable).
  const privateFact = live ? t('sshKeys.page.privateHeld') : k.is_platform_key ? t('sshKeys.page.privatePlatform') : t('sshKeys.page.privateNotHeld');
  const state = (l: KeyLocation) => (l.removed_at ? t('sshKeys.removedByAlice') : l.missing_since ? t('sshKeys.missing') : t('sshKeys.present'));
  const origin = k.managed ? t('sshKeys.managedTitle') : k.is_platform_key ? t('sshKeys.aliceKey') : t('sshKeys.page.discoveredOnServer');

  return (
    <Stack gap={0}>
      <PageHeader
        back={{ to: '/ssh-keys', label: t('sshKeys.backToList') }}
        icon="KeyRound"
        title={t('sshKeys.detailTitle')}
        description={
          <>
            <span translate="no">{t('sshKeys.keyType', { type: k.key_type, bits: k.bits })}</span> · <span>{origin}</span>
          </>
        }
        // Deploy comes before Download: the keyboard journey goes from Deploy to Download with forward Tabs (phase6 e2e).
        actions={
          <>
            {canOperate && mk && mk.retired_at === null && (
              <Button leftSection={<Icon name="Rocket" size={15} />} onClick={() => setDeploying(true)}>
                {t('sshKeys.deploy')}
              </Button>
            )}
            {isAdmin && live && (
              <Button variant="default" leftSection={<Icon name="Download" size={15} />} onClick={() => setDownloading(true)}>
                {t('sshKeys.download')}
              </Button>
            )}
          </>
        }
      />
      <Stack gap="md">
        {k.weak && (
          <Notice tone="warning" title={t('sshKeys.page.weakDetailTitle')}>
            {t('sshKeys.page.weakDetailText')}
          </Notice>
        )}
        {k.is_platform_key && (
          <Notice tone="brand" title={t('sshKeys.aliceKey')}>
            {t('sshKeys.noDownloadPlatform')}
          </Notice>
        )}
      </Stack>
      <div className={classes.detailGrid}>
        <div className={classes.stack}>
          <Panel title={t('sshKeys.usedWhere')} description={t('sshKeys.page.locationsText')} padded={false}>
            <Table.ScrollContainer minWidth={880}>
              <Table data-testid="key-locations" aria-label={t('sshKeys.usedWhere')} highlightOnHover>
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
                        <Anchor component={Link} to={`/servers/${l.target_id}`} className={classes.name} translate="no">
                          {l.target_name}
                        </Anchor>
                      </Table.Td>
                      <Table.Td translate="no">{l.os_user}</Table.Td>
                      <Table.Td>
                        <Code translate="no" style={WRAP}>
                          {l.file_path}
                        </Code>
                      </Table.Td>
                      <Table.Td>{l.line_no}</Table.Td>
                      <Table.Td>
                        {l.options && (
                          <Code translate="no" style={WRAP}>
                            {l.options}
                          </Code>
                        )}
                      </Table.Td>
                      <Table.Td style={WRAP}>
                        <Stack gap={2}>
                          <span translate="no">{l.comment}</span>
                          <KeyFlags location={l} />
                        </Stack>
                      </Table.Td>
                      <Table.Td className={classes.mono}>{formatDateTime(l.last_seen_at, i18n.language)}</Table.Td>
                      <Table.Td>
                        <StatusBadge tone={l.removed_at || l.missing_since ? 'neutral' : 'success'} size="sm">
                          {state(l)}
                        </StatusBadge>
                      </Table.Td>
                      <Table.Td>
                        {canOperate && !l.removed_at && !l.missing_since && (
                          <Button
                            size="xs"
                            variant="light"
                            color="red"
                            leftSection={<Icon name="X" size={13} />}
                            onClick={() => setRemoving(l)}
                            aria-label={t('sshKeys.removeNamed', { user: l.os_user })}
                          >
                            {t('sshKeys.removeConfirm')}
                          </Button>
                        )}
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          </Panel>
          <Panel title={t('sshKeys.page.publicIdentity')}>
            <FactList
              label={t('sshKeys.page.publicIdentity')}
              facts={[
                {
                  key: 'fingerprint',
                  label: t('sshKeys.fingerprintLabel'),
                  value: (
                    <Code translate="no" style={WRAP}>
                      {k.fingerprint}
                    </Code>
                  ),
                },
                { key: 'algorithm', label: t('sshKeys.page.columns.algorithm'), value: <span translate="no">{t('sshKeys.keyType', { type: k.key_type, bits: k.bits })}</span> },
                ...(k.comment ? [{ key: 'comment', label: t('sshKeys.comment'), value: <span translate="no">{k.comment}</span> }] : []),
                { key: 'firstSeen', label: t('sshKeys.page.firstSeen'), value: formatDateTime(k.first_seen_at, i18n.language) },
                { key: 'private', label: t('sshKeys.page.privateKey'), value: privateFact },
              ]}
            />
            <div className={classes.publicKey}>
              <span className={classes.label}>{t('sshKeys.publicKey')}</span>
              <Code block translate="no" style={WRAP}>
                {k.public_key}
              </Code>
              <CopyButton value={k.public_key}>
                {({ copied, copy }) => (
                  <Button size="xs" variant="light" w="fit-content" leftSection={<Icon name={copied ? 'Check' : 'Copy'} size={13} />} onClick={copy}>
                    {copied ? t('sshKeys.copied') : t('sshKeys.copy')}
                  </Button>
                )}
              </CopyButton>
            </div>
          </Panel>
          {mk && (
            <Panel title={t('sshKeys.managedTitle')} testId="managed-key">
              <Stack gap="xs">
                <Group gap={6}>
                  <StatusBadge tone="success" icon="ShieldCheck">
                    {t('sshKeys.managedBadge')}
                  </StatusBadge>
                  {mk.retired_at && (
                    <StatusBadge tone="neutral" icon="CircleOff">
                      {t('sshKeys.retiredBadge')}
                    </StatusBadge>
                  )}
                  {mk.destroyed_at && (
                    <StatusBadge tone="neutral" icon="CircleOff">
                      {t('sshKeys.destroyedBadge')}
                    </StatusBadge>
                  )}
                </Group>
                <Text size="sm" fw={600} translate="no">
                  {mk.label}
                </Text>
                <Code translate="no" style={WRAP}>
                  {mk.comment}
                </Code>
                <Text size="sm">{t('sshKeys.downloadCount', { count: mk.download_count })}</Text>
                {mk.last_downloaded_at && <Text size="sm">{t('sshKeys.lastDownloaded', { date: formatDateTime(mk.last_downloaded_at, i18n.language) })}</Text>}
                {mk.rotated_from && (
                  <Anchor component={Link} to={`/ssh-keys/${encodeURIComponent(mk.rotated_from)}`} w="fit-content" size="sm">
                    {t('sshKeys.rotatedFrom')}
                  </Anchor>
                )}
              </Stack>
            </Panel>
          )}
        </div>
        <div className={classes.stack}>
          {mk && mk.retired_at === null && <RotationPolicyPanel keyId={id} policyId={mk.policy_id} isAdmin={isAdmin} />}
          {canOperate && (
            <Notice tone="info" title={t('sshKeys.page.reviewBeforeRemoving')}>
              {t('sshKeys.page.removeNote')}
            </Notice>
          )}
        </div>
      </div>
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
