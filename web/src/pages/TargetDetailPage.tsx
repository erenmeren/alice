import { Alert, Button, Card, Code, Group, Loader, Stack, Table, Text, Textarea, Title } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useLocation, useNavigate, useParams } from 'react-router';
import { confirmHostKey, deleteTarget, discoverTarget, getTarget, listHostKeys, listTargetKeys, repinHostKey, testTarget } from '../api/endpoints';
import { isAbort, JobTimeoutError, waitForJob } from '../api/jobs';
import { TARGETS_KEY, targetKey } from '../api/queryKeys';
import { useAbort } from '../api/useAbort';
import type { HostKey, JobAccepted, JobError, KeyLocation, Target, Warning } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { PageLoader } from '../auth/guards';
import { AppModal } from '../components/AppModal';
import { ErrorAlert } from '../components/ErrorAlert';
import { HostKeyConfirm } from '../components/HostKeyConfirm';
import { BlockedJobAlert, JobErrorAlert, StillWorkingAlert } from '../components/JobErrorAlert';
import { KeyFlags } from '../components/KeyFlags';
import { RemoveKeyDialog } from '../components/RemoveKeyDialog';
import { useStepUp } from '../components/StepUpProvider';
import { TargetStatusBadge } from '../components/TargetStatusBadge';
import { WRAP } from '../components/wrap';
import { formatDateTime } from '../datetime';

// TargetDetailPage is one server: its status and facts, the actions Operators and Administrators
// may run, the host-key review after a changed identity (Administrators, step-up, SEC-080), and
// the SSH keys found on it.
export function TargetDetailPage() {
  const { t } = useTranslation();
  const { id = '' } = useParams();
  const { session } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const client = useQueryClient();
  const role = session?.user.role;
  const admin = role === 'admin';
  const canOperate = role === 'admin' || role === 'operator';

  const [busy, setBusy] = useState(false);
  const addedNow = (location.state as { added?: boolean } | null)?.added === true;
  const target = useQuery({
    queryKey: targetKey(id),
    queryFn: () => getTarget(id),
    // Follow a server only while something is happening: it is being checked, a job started from
    // this page is pending, or it was just added and its first scan is still to come (bounded).
    refetchInterval: (q) => {
      const d = q.state.data;
      if (!d) return false;
      if (d.status === 'checking' || busy) return 3000;
      return addedNow && !d.last_discovery_at && q.state.dataUpdateCount < 20 ? 3000 : false;
    },
  });
  // The status is part of the key so the host keys are read again when a polled server moves on
  // (for example from checking to pending_host_key and its confirmation card).
  const hostKeys = useQuery({ queryKey: [...targetKey(id), 'host-keys', target.data?.status ?? null], queryFn: () => listHostKeys(id) });
  const keys = useQuery({
    queryKey: [...targetKey(id), 'ssh-keys', target.data?.last_discovery_at ?? null],
    queryFn: () => listTargetKeys(id),
    enabled: target.isSuccess,
  });

  const [error, setError] = useState<unknown>(null);
  const [jobError, setJobError] = useState<JobError | null>(null);
  const [done, setDone] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const abort = useAbort();
  const [repinning, setRepinning] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [removing, setRemoving] = useState<KeyLocation | null>(null);

  const refresh = () => client.invalidateQueries({ queryKey: TARGETS_KEY });

  // runJob starts a background job, waits for it and refreshes everything it may have changed.
  const runJob = async (start: () => Promise<JobAccepted>) => {
    setBusy(true);
    setError(null);
    setJobError(null);
    setDone(false);
    setBlocked(false);
    try {
      const job = await waitForJob((await start()).job_id, { signal: abort.signal() });
      if (job.status === 'succeeded') setDone(true);
      else if (job.status === 'blocked_license') setBlocked(true);
      else setJobError(job.error);
    } catch (e) {
      if (!isAbort(e)) setError(e);
    }
    setBusy(false);
    await refresh();
  };

  if (target.isPending) return <PageLoader />;
  if (target.isError || !target.data) return <ErrorAlert error={target.error} />;
  const tg = target.data;
  const pinned = hostKeys.data?.items.find((k) => k.status === 'pinned') ?? null;
  const observed = hostKeys.data?.items.find((k) => k.status === 'observed') ?? null;
  const added = addedNow;
  const visibleKeys = (keys.data?.items ?? []).filter((k) => !k.removed_at);

  return (
    <Stack gap="md">
      <Group justify="space-between" align="flex-start">
        <Stack gap={4}>
          <Title order={1} style={WRAP}>
            {tg.name}
          </Title>
          <Text size="sm" style={WRAP}>
            {t('targets.address', { user: tg.username, host: tg.host, port: tg.port })}
          </Text>
        </Stack>
        <TargetStatusBadge status={tg.status} testId="target-status" />
      </Group>
      {added && (
        <Alert color="green" role="status">
          {t('targets.added')}
        </Alert>
      )}
      {tg.status === 'host_key_changed' && (
        <Alert color="red" role="alert" data-testid="host-key-changed">
          <Stack gap="xs">
            <Text size="sm">{t('targets.hostKeyChanged')}</Text>
            {admin && (
              <Button size="xs" color="red.9" w="fit-content" onClick={() => setRepinning(true)}>
                {t('hostKeys.review')}
              </Button>
            )}
          </Stack>
        </Alert>
      )}
      {tg.status === 'pending_host_key' && admin && observed && (
        <Card withBorder padding="md">
          <Stack gap="xs">
            <Title order={2} size="h3">
              {t('hostKeys.confirmTitle')}
            </Title>
            <HostKeyConfirm host={tg.host} hostKey={observed} busy={busy} onYes={() => void runJob(() => confirmHostKey(tg.id, observed.id, observed.fingerprint))} />
          </Stack>
        </Card>
      )}
      <Facts target={tg} />
      {canOperate && (
        <Group gap="sm">
          <Button variant="default" disabled={busy} onClick={() => void runJob(() => testTarget(tg.id))}>
            {t('targets.test')}
          </Button>
          <Button variant="default" disabled={busy} onClick={() => void runJob(() => discoverTarget(tg.id))}>
            {t('targets.discover')}
          </Button>
          {admin && (
            <Button variant="light" color="red.9" disabled={busy} onClick={() => setDeleting(true)}>
              {t('targets.delete')}
            </Button>
          )}
        </Group>
      )}
      {busy && (
        <Group gap="sm" role="status" aria-live="polite">
          <Loader size="sm" aria-hidden />
          <Text size="sm">{t('targets.working')}</Text>
        </Group>
      )}
      {done && (
        <Text size="sm" role="status">
          {t('targets.jobDone')}
        </Text>
      )}
      {error instanceof JobTimeoutError ? <StillWorkingAlert /> : <ErrorAlert error={error} />}
      {blocked && <BlockedJobAlert />}
      <JobErrorAlert error={jobError} />

      <Title order={2} size="h3">
        {t('targets.keysTitle')}
      </Title>
      <ErrorAlert error={keys.error} />
      {keys.isSuccess && visibleKeys.length === 0 && <Text c="gray.7">{t('targets.noKeys')}</Text>}
      {visibleKeys.length > 0 && (
        <Table.ScrollContainer minWidth={720}>
          <Table striped data-testid="target-keys">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t('sshKeys.user')}</Table.Th>
                <Table.Th>{t('sshKeys.key')}</Table.Th>
                <Table.Th>{t('sshKeys.file')}</Table.Th>
                <Table.Th>{t('sshKeys.comment')}</Table.Th>
                <Table.Th>{t('sshKeys.actions')}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {visibleKeys.map((k) => (
                <Table.Tr key={k.id}>
                  <Table.Td>{k.os_user}</Table.Td>
                  <Table.Td>
                    <Stack gap={2}>
                      <Text size="xs">{k.key_type}</Text>
                      <Code style={WRAP}>{k.fingerprint}</Code>
                      <KeyFlags location={k} />
                    </Stack>
                  </Table.Td>
                  <Table.Td>
                    <Code style={WRAP}>{k.file_path}</Code>
                  </Table.Td>
                  <Table.Td style={WRAP}>{k.comment}</Table.Td>
                  <Table.Td>
                    {canOperate && (
                      <Button size="xs" variant="light" color="red.9" onClick={() => setRemoving(k)} aria-label={t('sshKeys.removeNamed', { user: k.os_user })}>
                        {t('sshKeys.removeConfirm')}
                      </Button>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}

      {repinning && (
        <RepinDialog
          target={tg}
          pinned={pinned}
          observed={observed}
          onClose={() => setRepinning(false)}
          onAccepted={(accepted) => {
            setRepinning(false);
            void runJob(() => Promise.resolve(accepted));
          }}
        />
      )}
      {deleting && (
        <DeleteTargetDialog
          target={tg}
          onClose={() => setDeleting(false)}
          onDeleted={() => {
            void refresh();
            navigate('/servers');
          }}
        />
      )}
      {removing && (
        <RemoveKeyDialog
          location={removing}
          onClose={() => setRemoving(null)}
          onDone={() => {
            setRemoving(null);
            void refresh();
          }}
        />
      )}
    </Stack>
  );
}

// Discovery warnings: the text key and the parameters it needs. Some helper warnings come with and
// without a parameter (unsupported_path without a path, sshd_unreadable without a user) and have
// their own text; a missing parameter would show a raw {{placeholder}}, so a warning without its
// details, and a code this version does not know, get a generic text plus the code.
const WARNING_PARAMS: Record<string, string[]> = {
  keys_managed_elsewhere: [],
  keys_managed_elsewhere_user: ['user'],
  certificates_in_use: [],
  pubkey_disabled: [],
  sshd_unreadable: [],
  sshd_unreadable_user: ['user'],
  strict_modes: ['path'],
  unsupported_path: ['path'],
  unsupported_path_unnamed: [],
  file_unreadable: ['path'],
  file_unparseable: ['path', 'user'],
  file_too_large: ['path'],
  directory_users_not_listed: [],
  too_many_users: [],
};

function warningKey(w: Warning): string {
  let code = w.code;
  if (code === 'unsupported_path' && !w.params.path) code = 'unsupported_path_unnamed';
  if (code === 'keys_managed_elsewhere' && w.params.user) code = 'keys_managed_elsewhere_user';
  if (code === 'sshd_unreadable' && w.params.user) code = 'sshd_unreadable_user';
  const need = WARNING_PARAMS[code];
  if (!need) return 'warnings.unknown';
  return need.every((p) => w.params[p]) ? `warnings.${code}` : 'warnings.incomplete';
}

function Facts({ target }: { target: Target }) {
  const { t, i18n } = useTranslation();
  const f = target.facts;
  // unreadable_line is shown per line from facts.unreadable below, so the summary warning is skipped here.
  const warnings = f.warnings.filter((w) => w.code !== 'unreadable_line');
  return (
    <Stack gap={4}>
      {f.os.pretty_name && <Text size="sm">{t('targets.facts.os', { name: f.os.pretty_name })}</Text>}
      {f.helper_version && <Text size="sm">{t('targets.facts.helper', { version: f.helper_version })}</Text>}
      <Text size="sm">
        {target.last_discovery_at
          ? t('targets.facts.lastDiscovery', { time: formatDateTime(target.last_discovery_at, i18n.language) })
          : t('targets.facts.neverScanned')}
      </Text>
      {warnings.map((w) => (
        <Alert key={`${w.code}-${JSON.stringify(w.params)}`} color="yellow" style={WRAP}>
          {t(warningKey(w), w.params)}
          {warningKey(w) === 'warnings.unknown' || warningKey(w) === 'warnings.incomplete' ? (
            <Code ml="xs">{w.code}</Code>
          ) : null}
        </Alert>
      ))}
      {f.unreadable.map((u) => (
        <Alert key={`${u.file_path}-${u.line_no}`} color="yellow" style={WRAP}>
          {t('warnings.unreadable_line', { file_path: u.file_path, line_no: u.line_no })}
        </Alert>
      ))}
    </Stack>
  );
}

// oneLine collapses every run of whitespace, line breaks included, to one space: the server refuses
// control characters in a reason, and the reason field wraps over several lines.
function oneLine(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

function RepinDialog({
  target,
  pinned,
  observed,
  onClose,
  onAccepted,
}: {
  target: Target;
  pinned: HostKey | null;
  observed: HostKey | null;
  onClose: () => void;
  onAccepted: (accepted: JobAccepted) => void;
}) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const [reason, setReason] = useState('');
  const [acting, setActing] = useState<'accept' | 'keep' | null>(null);
  const [error, setError] = useState<unknown>(null);
  const cleanReason = oneLine(reason);

  // send re-pins one host key: the new candidate (accept) or the pinned key itself (keep, the
  // API's dismiss path). Both need a fresh step-up (§25.1): run asks for a code when the server
  // says so. A refused request means the server's state moved on, so the target and its host keys
  // are read again; the dialog then shows what is true now.
  const send = async (action: 'accept' | 'keep', key: HostKey) => {
    setActing(action);
    setError(null);
    try {
      const accepted = await run(() => repinHostKey(target.id, key.id, key.fingerprint, cleanReason));
      void client.invalidateQueries({ queryKey: targetKey(target.id) });
      onAccepted(accepted);
    } catch (err) {
      setError(err);
      setActing(null);
      void client.invalidateQueries({ queryKey: targetKey(target.id) });
    }
  };

  return (
    <AppModal opened onClose={onClose} title={t('hostKeys.repinTitle')} size="lg">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (observed) void send('accept', observed);
        }}
      >
        <Stack gap="sm">
          <Text size="sm">{t('hostKeys.repinHelp')}</Text>
          {pinned && (
            <>
              <Text size="sm" fw={600}>
                {t('hostKeys.oldFingerprint')}
              </Text>
              <Code block style={WRAP}>
                {pinned.fingerprint}
              </Code>
            </>
          )}
          {observed ? (
            <>
              <Text size="sm" fw={600}>
                {t('hostKeys.newFingerprint')}
              </Text>
              <Code block data-testid="repin-new-fingerprint" style={WRAP}>
                {observed.fingerprint}
              </Code>
              <Text size="sm" fw={600}>
                {t('hostKeys.commandLabel')}
              </Text>
              <Code block style={WRAP}>
                {observed.verify_command}
              </Code>
            </>
          ) : (
            <Text size="sm">{t('hostKeys.noCandidate')}</Text>
          )}
          {(observed || pinned) && (
            <Textarea
              label={t('hostKeys.reason')}
              description={t('hostKeys.reasonHelp')}
              value={reason}
              onChange={(e) => setReason(e.currentTarget.value)}
              required
              minLength={10}
              maxLength={500}
              autosize
              minRows={2}
            />
          )}
          <ErrorAlert error={error} />
          {observed && (
            <Stack gap={4}>
              <Text size="sm">{t('hostKeys.acceptHelp')}</Text>
              <Button type="submit" color="red.9" w="fit-content" loading={acting === 'accept'} disabled={acting !== null || cleanReason.length < 10}>
                {t('hostKeys.repin')}
              </Button>
            </Stack>
          )}
          {pinned && (
            <Stack gap={4}>
              <Text size="sm">{t('hostKeys.keepHelp')}</Text>
              <Button
                type="button"
                variant="default"
                w="fit-content"
                loading={acting === 'keep'}
                disabled={acting !== null || cleanReason.length < 10}
                onClick={() => void send('keep', pinned)}
              >
                {t('hostKeys.keep')}
              </Button>
            </Stack>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              {t('hostKeys.cancel')}
            </Button>
          </Group>
        </Stack>
      </form>
    </AppModal>
  );
}

function DeleteTargetDialog({ target, onClose, onDeleted }: { target: Target; onClose: () => void; onDeleted: () => void }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      await deleteTarget(target.id);
      onDeleted();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <AppModal opened onClose={onClose} title={t('targets.deleteTitle')}>
      <Stack gap="sm">
        <Text size="sm">{t('targets.deleteHelp')}</Text>
        <ErrorAlert error={error} />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            {t('targets.cancel')}
          </Button>
          <Button color="red.9" loading={busy} onClick={() => void confirm()}>
            {t('targets.delete')}
          </Button>
        </Group>
      </Stack>
    </AppModal>
  );
}
