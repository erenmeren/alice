import { Alert, Button, Code, Group, Loader, Stack, Table, Text, Textarea } from '@mantine/core';
import type { i18n as I18n, TFunction } from 'i18next';
import { keepPreviousData, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Navigate, useLocation, useNavigate, useParams } from 'react-router';
import { confirmHostKey, deleteTarget, discoverTarget, getTarget, listHostKeys, listTargetKeys, repinHostKey, testTarget } from '../api/endpoints';
import { isAbort, JobTimeoutError, waitForJob } from '../api/jobs';
import { capabilityText } from '../api/capabilities';
import { isServerType, isWebServer, webServerState } from '../api/webServer';
import { softwareName } from '../components/software';
import { CERTIFICATES_KEY, TARGETS_KEY, targetKey } from '../api/queryKeys';
import { useAbort } from '../api/useAbort';
import { warningKey } from '../api/warnings';
import type { HostKey, JobAccepted, JobError, KeyLocation, Target } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { PageLoader } from '../auth/guards';
import { AppModal } from '../components/AppModal';
import { ErrorAlert } from '../components/ErrorAlert';
import { HostKeyConfirm } from '../components/HostKeyConfirm';
import { BlockedJobAlert, JobErrorAlert, reasonTitle, StillWorkingAlert, StoppedJobAlert } from '../components/JobErrorAlert';
import { KeyFlags } from '../components/KeyFlags';
import { RemoveKeyDialog } from '../components/RemoveKeyDialog';
import { useStepUp } from '../components/StepUpProvider';
import { TargetStatusBadge } from '../components/TargetStatusBadge';
import { useLocations, websitesAsOf } from '../components/useLocations';
import { WebsitesPanel } from '../components/WebsitesPanel';
import { DialogActions, EmptyState, FactList, Notice, PageHeader, Panel, StatusBadge, type Fact } from '../components/ui';
import { WRAP } from '../components/wrap';
import { formatDateTime } from '../datetime';
import { Icon } from '../design/Icon';
import classes from './TargetsPage.module.css';

// TargetDetailPage is one server: its status and facts, the actions Operators and Administrators
// may run, the host-key review after a changed identity (Administrators, step-up, SEC-080), and
// the SSH keys found on it.
export function TargetDetailPage() {
  const { t, i18n } = useTranslation();
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
  const hostKeys = useQuery({ queryKey: [...targetKey(id), 'host-keys', target.data?.status ?? null], queryFn: () => listHostKeys(id), placeholderData: keepPreviousData });
  const keys = useQuery({
    queryKey: [...targetKey(id), 'ssh-keys', target.data?.last_discovery_at ?? null],
    queryFn: () => listTargetKeys(id),
    enabled: target.isSuccess,
  });

  const locations = useLocations(id, false, target.data ? isWebServer(target.data.type) : false);
  const [error, setError] = useState<unknown>(null);
  const [jobError, setJobError] = useState<JobError | null>(null);
  const [done, setDone] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [stopped, setStopped] = useState(false);
  const [discoveryFailed, setDiscoveryFailed] = useState(false);
  const abort = useAbort();
  const [repinning, setRepinning] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [removing, setRemoving] = useState<KeyLocation | null>(null);

  // A scan changes the websites and certificates too, which live under their own query keys.
  const refresh = async () => {
    await Promise.all([
      client.invalidateQueries({ queryKey: TARGETS_KEY }),
      client.invalidateQueries({ queryKey: ['locations'] }),
      client.invalidateQueries({ queryKey: CERTIFICATES_KEY }),
    ]);
  };

  // runJob starts a background job, waits for it and refreshes everything it may have changed.
  const runJob = async (start: () => Promise<JobAccepted>, scan = false) => {
    setBusy(true);
    if (scan) setDiscoveryFailed(false);
    setError(null);
    setJobError(null);
    setDone(false);
    setBlocked(false);
    setStopped(false);
    try {
      const job = await waitForJob((await start()).job_id, { signal: abort.signal() });
      if (job.status === 'succeeded') setDone(true);
      else if (job.status === 'blocked_license') setBlocked(true);
      else if (job.error) setJobError(job.error);
      else setStopped(true);
      if (scan && job.status !== 'succeeded' && job.status !== 'blocked_license') setDiscoveryFailed(true);
    } catch (e) {
      if (!isAbort(e)) {
        setError(e);
        if (scan) setDiscoveryFailed(true);
      }
    }
    setBusy(false);
    await refresh();
  };

  if (target.isPending) return <PageLoader />;
  if (target.isError || !target.data) return <ErrorAlert error={target.error} />;
  const tg = target.data;
  // A Key Vault has its own page (a link to /servers/<id> from a job or the audit log still lands there).
  if (tg.type === 'azure_key_vault') return <Navigate to={`/key-vaults/${tg.id}`} replace />;
  const pinned = hostKeys.data?.items.find((k) => k.status === 'pinned') ?? null;
  const observed = hostKeys.data?.items.find((k) => k.status === 'observed') ?? null;
  const added = addedNow;
  const webServer = isWebServer(tg.type);
  const visibleKeys = (keys.data?.items ?? []).filter((k) => !k.removed_at);

  const facts = connectionFacts(t, i18n, tg, pinned, discoveryFailed, websitesAsOf(locations.data?.items ?? []));
  const scan = (
    // As in the design, no scan while the server's identity changed: the server refuses it until an administrator decides.
    <Button
      variant="default"
      leftSection={<Icon name="RefreshCw" size={15} />}
      disabled={busy || tg.status === 'host_key_changed'}
      onClick={() => void runJob(() => discoverTarget(tg.id), true)}
    >
      {t(webServer ? 'locations.discover' : 'targets.discover')}
    </Button>
  );

  return (
    <Stack gap={0}>
      <PageHeader
        back={{ to: '/servers', label: t('targets.page.back') }}
        icon="Server"
        title={<span translate="no">{tg.name}</span>}
        status={<TargetStatusBadge status={tg.status} testId="target-status" />}
        description={t('targets.address', { user: tg.username, host: tg.host, port: tg.port })}
        actions={
          canOperate && (
            <>
              {scan}
              {admin && (
                <Button variant="light" color="red" disabled={busy} onClick={() => setDeleting(true)}>
                  {t('targets.delete')}
                </Button>
              )}
            </>
          )
        }
      />
      <Stack gap="md">
        {added && (
          <Alert color="green" role="status">
            {t('targets.added')}
          </Alert>
        )}
        <IdentityNotice target={tg} admin={admin} onReview={() => setRepinning(true)} />
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
        {stopped && <StoppedJobAlert />}
        <JobErrorAlert error={jobError} />
        <FactWarnings target={tg} />
      </Stack>

      <div className={classes.detailGrid}>
        <div className={classes.stack}>
          {tg.status === 'pending_host_key' && admin && observed && (
            <Panel title={t('hostKeys.confirmTitle')}>
              <HostKeyConfirm host={tg.host} hostKey={observed} busy={busy} onYes={() => void runJob(() => confirmHostKey(tg.id, observed.id, observed.fingerprint))} />
            </Panel>
          )}
          {webServer && <WebsitesPanel target={tg} discoveryFailed={discoveryFailed} />}
          <Panel title={t('targets.keysTitle')} padded={false}>
            <ErrorAlert error={keys.error} />
            {keys.isSuccess && visibleKeys.length === 0 && <EmptyState icon="KeyRound" title={t('targets.noKeys')} />}
            {visibleKeys.length > 0 && (
              <Table.ScrollContainer minWidth={720}>
                <Table data-testid="target-keys" aria-label={t('targets.keysTitle')} highlightOnHover>
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
                        <Table.Td translate="no">{k.os_user}</Table.Td>
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
                            <Button size="xs" variant="light" color="red" onClick={() => setRemoving(k)} aria-label={t('sshKeys.removeNamed', { user: k.os_user })}>
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
          </Panel>
        </div>
        <div className={`${classes.stack} ${classes.side}`}>
          <Panel title={t('targets.page.connection')}>
            <FactList facts={facts} />
          </Panel>
          <Panel title={t('targets.page.operations')}>
            <Text className={classes.small}>{isWebServer(tg.type) ? t(capabilityText(tg, 'targets.page.operationsText'), { software: softwareName(t, tg.type) }) : t('targets.page.operationsTextLinux')}</Text>
            <Group gap="xs" mt="lg">
              {canOperate ? (
                <Button variant="default" leftSection={<Icon name="Network" size={15} />} disabled={busy} onClick={() => void runJob(() => testTarget(tg.id))}>
                  {t('targets.test')}
                </Button>
              ) : (
                <StatusBadge tone="neutral" icon="Eye">
                  {t('targets.page.readOnly')}
                </StatusBadge>
              )}
            </Group>
          </Panel>
        </div>
      </div>

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

// IdentityNotice is the design's status line under the header: the changed identity (danger, with the review for
// Administrators), a refused sign-in (danger, with the reason), a server waiting for its fingerprint (warning, for every
// role and also while the host keys load: only an Administrator can confirm it), a failed last attempt (warning) or a
// verified connection. Checking, partly working and disabled claim nothing here: the status badge and the facts say it.
function IdentityNotice({ target, admin, onReview }: { target: Target; admin: boolean; onReview: () => void }) {
  const { t, i18n } = useTranslation();
  if (target.status === 'auth_failed') {
    return (
      <Notice tone="danger" title={t('enum.targetStatus.auth_failed')}>
        {target.last_error ? reasonTitle(t, i18n, target.last_error.reason) : null}
      </Notice>
    );
  }
  if (target.status === 'pending_host_key') {
    return (
      <Notice tone="warning" title={t('enum.targetStatus.pending_host_key')}>
        {t('targets.page.pendingText')}
      </Notice>
    );
  }
  if (target.status === 'host_key_changed') {
    return (
      <Notice
        tone="danger"
        role="alert"
        testId="host-key-changed"
        title={t('targets.page.identityChangedTitle')}
        action={
          admin && (
            <Button size="xs" color="red" leftSection={<Icon name="Fingerprint" size={14} />} onClick={onReview}>
              {t('hostKeys.review')}
            </Button>
          )
        }
      >
        {t('targets.hostKeyChanged')}
      </Notice>
    );
  }
  if (target.status === 'unreachable') {
    return (
      <Notice tone="warning" title={t('targets.page.unreachableTitle')}>
        {t('targets.page.unreachableText')}
      </Notice>
    );
  }
  if (target.status === 'ok') {
    return (
      <Notice tone="brand" title={t('targets.page.verifiedTitle')}>
        {t('targets.page.verifiedText')}
      </Notice>
    );
  }
  return null;
}

// connectionFacts is the design's "Connection details" list, with the product's own facts (sign-in user, helper and
// Nginx versions, the last problem) in the same list.
function connectionFacts(t: TFunction, i18n: I18n, target: Target, pinned: HostKey | null, discoveryFailed: boolean, asOf: string | null): Fact[] {
  const lang = i18n.language;
  const f = target.facts;
  const ws = isWebServer(target.type) ? f.web_server : undefined;
  const software = softwareName(t, target.type);
  const facts: Fact[] = [
    { key: 'state', label: t('targets.page.facts.state'), value: <TargetStatusBadge status={target.status} /> },
    { key: 'address', label: t('targets.page.facts.address'), value: <Code translate="no">{`${target.host}:${target.port}`}</Code> },
    { key: 'user', label: t('targets.page.facts.user'), value: <Code translate="no">{target.username}</Code> },
  ];
  if (isServerType(target.type)) facts.push({ key: 'platform', label: t('targets.page.facts.platform'), value: t(`targets.typeLabel.${target.type}`) });
  if (f.os.pretty_name) facts.push({ key: 'os', label: t('targets.page.facts.os'), value: f.os.pretty_name });
  if (f.helper_version) facts.push({ key: 'helper', label: t('targets.page.facts.helper'), value: f.helper_version });
  if (ws?.version) facts.push({ key: 'web_server', label: t('targets.page.facts.webServer', { software }), value: ws.version });
  else if (ws && !ws.found) facts.push({ key: 'web_server', label: t('targets.page.facts.webServer', { software }), value: t('targets.facts.webServerNotFound', { software }) });
  facts.push({
    key: 'connected',
    label: t('targets.page.facts.lastConnected'),
    value: target.last_success_at ? formatDateTime(target.last_success_at, lang) : t('targets.page.never'),
  });
  facts.push({
    key: 'scan',
    label: t('targets.page.facts.lastScan'),
    value: (
      <>
        {target.last_discovery_at ? formatDateTime(target.last_discovery_at, lang) : t('targets.facts.neverScanned')}
        {ws && webServerState(target, discoveryFailed).stale && asOf && (
          <Text size="xs" c="dimmed" role="note" mt={4}>
            {t('targets.facts.webServerStale', { software, time: formatDateTime(asOf, lang) })}
          </Text>
        )}
      </>
    ),
  });
  if (target.discovery_interval_hours > 0) {
    facts.push({ key: 'interval', label: t('targets.page.facts.discoveryInterval'), value: t('targets.page.everyHours', { count: target.discovery_interval_hours }) });
  }
  if (pinned) facts.push({ key: 'fingerprint', label: t('targets.page.facts.hostFingerprint'), value: <Code translate="no">{pinned.fingerprint}</Code> });
  if (target.status !== 'ok' && target.last_error) {
    facts.push({ key: 'problem', label: t('targets.page.facts.lastProblem'), value: reasonTitle(t, i18n, target.last_error.reason) });
  }
  return facts;
}

// FactWarnings words what the last scan reported about the server (helper warnings and unreadable key lines).
function FactWarnings({ target }: { target: Target }) {
  const { t } = useTranslation();
  const software = softwareName(t, target.type);
  const f = target.facts;
  // unreadable_line is shown per line from facts.unreadable below, so the summary warning is skipped here.
  const warnings = f.warnings.filter((w) => w.code !== 'unreadable_line');
  if (warnings.length === 0 && f.unreadable.length === 0) return null;
  return (
    <Stack gap="xs">
      {warnings.map((w) => (
        <Alert key={`${w.code}-${JSON.stringify(w.params)}`} color="yellow" style={WRAP}>
          {t(capabilityText(target, warningKey(w)), { ...w.params, software })}
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
              <Button type="submit" color="red" w="fit-content" loading={acting === 'accept'} disabled={acting !== null || cleanReason.length < 10}>
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
        </Stack>
        <DialogActions>
          <Button variant="default" onClick={onClose}>
            {t('hostKeys.cancel')}
          </Button>
        </DialogActions>
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
      </Stack>
      <DialogActions>
        <Button variant="default" onClick={onClose}>
          {t('targets.cancel')}
        </Button>
        <Button color="red" loading={busy} onClick={() => void confirm()}>
          {t('targets.delete')}
        </Button>
      </DialogActions>
    </AppModal>
  );
}
