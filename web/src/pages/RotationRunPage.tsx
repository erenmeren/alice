import { Anchor, Button, Checkbox, Code, Group, List, Stack, Table, Text } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useParams } from 'react-router';
import { ROTATION_POLICIES_KEY, ROTATION_RUNS_KEY, runKey, SSH_KEYS_KEY } from '../api/queryKeys';
import { abortRun, continueRun, finishRunNow, getRun, keepOldKey, listPolicies, runPollInterval, type Run, type RunLocation, type RunStep } from '../api/rotation';
import { useAuth } from '../auth/AuthProvider';
import type { ErrorRef } from '../api/types';
import { PageLoader } from '../auth/guards';
import { AppModal } from '../components/AppModal';
import { ErrorAlert } from '../components/ErrorAlert';
import { hasRotationPath, RotationPath } from '../components/rotation/RotationPath';
import { keyTypeName, ReasonAlert, labelOf, locationTone, noteText, runTone, skipText } from '../components/rotationText';
import { reasonTitle } from '../components/JobErrorAlert';
import { useStepUp } from '../components/StepUpProvider';
import { DialogActions, FactList, Notice, PageHeader, Panel, StatusBadge, type Fact } from '../components/ui';
import { WRAP } from '../components/wrap';
import { formatDateTime } from '../datetime';
import { Icon } from '../design/Icon';
import classes from './Rotations.module.css';

// Reasons that mean "look at this", not "this went fine": a key that was already gone when Alice undid its addition,
// and a late answer that arrived after Alice had given up on a step.
const WARNING_REASONS: ReadonlySet<string> = new Set(['rotation.old_key_gone', 'rotation.late_result']);

// noticeOf is the server's word on the renewal email, as a reason to show; null when it says nothing about it.
function noticeOf(r: Run): ErrorRef | null {
  return r.notice_error ?? r.notice_state ?? null;
}

type Confirm = 'finish_now' | 'abort' | 'keep_old' | null;

function stepLabel(t: ReturnType<typeof useTranslation>['t'], i18n: ReturnType<typeof useTranslation>['i18n'], s: RunStep): string {
  if (i18n.exists(`rotation.step.${s.name}`)) return t(`rotation.step.${s.name}`);
  if (s.location_id && i18n.exists(`rotation.loc.${s.name}`)) return t(`rotation.loc.${s.name}`);
  if (i18n.exists(`rotation.status.${s.name}`)) return t(`rotation.status.${s.name}`);
  return t('rotation.step.unknown');
}

function LocationRow({ l }: { l: RunLocation }) {
  const { t, i18n } = useTranslation();
  const warn = l.error !== null && WARNING_REASONS.has(l.error.reason);
  const note = noteText(t, i18n, l.verify_note);
  return (
    <Table.Tr data-testid="run-location">
      <Table.Td style={WRAP} translate="no">
        {l.target_name}
      </Table.Td>
      <Table.Td style={WRAP} translate="no">
        {l.os_user}
      </Table.Td>
      <Table.Td>
        <Code translate="no" style={WRAP}>
          {l.file_path}
        </Code>
      </Table.Td>
      <Table.Td>
        <StatusBadge tone={locationTone(l.state)}>{labelOf(t, i18n, 'rotation.loc', l.state)}</StatusBadge>
      </Table.Td>
      <Table.Td>
        <Stack gap={4}>
          {l.skip_reason !== '' && <Text size="xs">{skipText(t, i18n, l.skip_reason)}</Text>}
          {l.add_resend_count > 0 && l.add_resent_at && <Text size="xs">{t('rotation.addResent', { count: l.add_resend_count, date: formatDateTime(l.add_resent_at, i18n.language) })}</Text>}
          {note !== '' && <Text size="xs">{note}</Text>}
          {l.error && (
            <Text size="xs" style={WRAP}>
              {warn && (
                <StatusBadge tone="warning" icon="CircleAlert" style={{ marginRight: 6 }}>
                  {t('rotation.warning')}
                </StatusBadge>
              )}
              {reasonTitle(t, i18n, l.error.reason, l.error.params ?? {})}
              {l.error.code && (
                <Text span size="xs" c="dimmed">
                  {' '}
                  {t('jobs.errorCode', { code: l.error.code })}
                </Text>
              )}
            </Text>
          )}
          {l.backup !== '' && (
            <Text size="xs">
              {/* the path is data: shown in Code, never translated */}
              <BackupText path={l.backup} />
            </Text>
          )}
        </Stack>
      </Table.Td>
    </Table.Tr>
  );
}

function BackupText({ path }: { path: string }) {
  const { t } = useTranslation();
  const MARK = '\u0001';
  const parts = t('rotation.backupAt', { path: MARK }).split(MARK);
  return (
    <>
      {parts[0]}
      <Code translate="no" style={WRAP}>
        {path}
      </Code>
      {parts[1]}
    </>
  );
}

// RotationRunPage is one rotation run: what it is doing, the decisions the API offers now, every place and every step.
// The buttons are exactly run.actions_allowed (the server works that out, including the license); the page never
// computes them. It follows a run that is still moving every three seconds, and slower when the server asks it to.
export function RotationRunPage() {
  const { t, i18n } = useTranslation();
  const { id = '' } = useParams();
  const client = useQueryClient();
  const { run: withStepUp } = useStepUp();
  const { session } = useAuth();
  // Only an Administrator may decide (rotation.manage / rotation.operate); everybody else reads. The buttons shown are the
  // intersection of that and what the API offers.
  const isAdmin = session?.user.role === 'admin';
  const [confirm, setConfirm] = useState<Confirm>(null);
  const [kept, setKept] = useState<Set<string>>(new Set());
  const closeConfirm = () => {
    setConfirm(null);
    setKept(new Set());
  };
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const query = useQuery({
    queryKey: runKey(id),
    queryFn: () => getRun(id),
    refetchInterval: (q) => runPollInterval(q.state.data, q.state.error),
  });
  // The policy's name and interval for the header and the facts: the same list the Key rotations page reads (every live
  // policy, read permission). A run whose policy is gone simply shows no policy facts.
  const policies = useQuery({ queryKey: [...ROTATION_POLICIES_KEY, 'all'], queryFn: listPolicies });

  if (query.isPending) return <PageLoader />;
  if (query.isError && !query.data)
    return (
      <Stack gap="md">
        <ErrorAlert error={query.error} />
        <Button w="fit-content" variant="default" loading={query.isFetching} onClick={() => void query.refetch()}>
          {t('imports.history.tryAgain')}
        </Button>
      </Stack>
    );
  const r: Run = query.data as Run;
  const decisions = isAdmin ? r.actions_allowed : [];
  const allowed = new Set(decisions);
  const unverifiable = (r.locations ?? []).filter((l) => l.state === 'unverifiable');
  const notice = noticeOf(r);

  // Every decision goes through the step-up wrapper, which asks for the code only when the server asks for one.
  const decide = async (call: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await withStepUp(call);
      setConfirm(null);
      setKept(new Set());
    } catch (e) {
      setError(e);
      setConfirm(null);
    }
    void client.invalidateQueries({ queryKey: runKey(id) });
    void client.invalidateQueries({ queryKey: ROTATION_RUNS_KEY });
    void client.invalidateQueries({ queryKey: ROTATION_POLICIES_KEY });
    void client.invalidateQueries({ queryKey: SSH_KEYS_KEY });
    setBusy(false);
  };

  const resultWarn = r.result !== null && (WARNING_REASONS.has(r.result.reason) || ['aborted', 'cancelled', 'completed'].includes(r.status));
  const locationName = (lid: string | null) => {
    const l = (r.locations ?? []).find((x) => x.id === lid);
    return l ? `${l.target_name}, ${l.os_user}` : '';
  };

  const policy = policies.data?.items.find((p) => p.id === r.policy_id);
  const total = r.location_counts.total;
  const description = [policy?.name, r.new_key_type ? keyTypeName(r.new_key_type) : undefined, total !== undefined ? t('rotation.page.locations', { count: total }) : undefined].filter(Boolean).join(' · ');
  const facts: Fact[] = [
    ...(policy
      ? [
          { key: 'policy', label: t('rotation.page.policy'), value: <span translate="no">{policy.name}</span> },
          { key: 'interval', label: t('rotation.page.interval'), value: policy.interval_days === 1 ? t('rotation.everyDay') : t('rotation.every', { count: policy.interval_days }) },
        ]
      : []),
    { key: 'trigger', label: t('rotation.page.trigger'), value: t(`rotation.trigger.${r.trigger === 'scheduled' ? 'scheduled' : 'manual'}`) },
    { key: 'planned', label: t('rotation.page.plannedFor'), value: formatDateTime(r.planned_for, i18n.language) },
    // notified_at is when Alice announced the run and queued the email, not a delivery mark: it is stated as the
    // announcement, and not at all while the server reports a problem with the notice (failed or still pending).
    ...(r.notified_at && notice === null ? [{ key: 'notice', label: t('rotation.page.announced'), value: formatDateTime(r.notified_at, i18n.language) }] : []),
    ...(r.finished_at ? [{ key: 'finished', label: t('rotation.page.finished'), value: formatDateTime(r.finished_at, i18n.language) }] : []),
  ];

  return (
    <Stack gap="md">
      <PageHeader
        back={{ to: `/ssh-keys/${encodeURIComponent(r.status === 'completed' && r.new_ssh_key_id ? r.new_ssh_key_id : r.old_ssh_key_id)}`, label: t('rotation.backToKey') }}
        title={t('rotation.runTitle')}
        description={description}
        status={
          // The run's state is a polite live region holding only the badge: it follows the run while the page polls.
          <div role="status" aria-live="polite">
            <StatusBadge size="lg" tone={runTone(r.status)}>
              {labelOf(t, i18n, 'rotation.status', r.status)}
            </StatusBadge>
          </div>
        }
      />
      {r.paused_license && (
        <Notice
          tone="danger"
          role="alert"
          title={t('rotation.page.pausedTitle')}
          action={
            <Anchor component={Link} to="/license" size="sm" c="inherit" underline="always">
              {t('rotation.openLicense')}
            </Anchor>
          }
        >
          <Text size="sm">{t('rotation.pausedBanner')}</Text>
          {allowed.has('abort') && <Text size="sm">{t('rotation.licensePaused')}</Text>}
        </Notice>
      )}
      {r.status === 'overlap' && (
        <Notice tone="info" title={t('rotation.page.bothKeys')}>
          {r.paused_license ? (
            <Text size="sm">{t('rotation.overlapOnHold')}</Text>
          ) : (
            r.overlap_until && <Text size="sm">{t('rotation.overlapUntil', { date: formatDateTime(r.overlap_until, i18n.language) })}</Text>
          )}
        </Notice>
      )}
      {r.awaiting_decision && !r.paused_license && r.decision_due_at && (
        <Notice tone="warning" title={t('rotation.page.decisionTitle')}>
          <Text size="sm">{t('rotation.decisionDue', { date: formatDateTime(r.decision_due_at, i18n.language) })}</Text>
        </Notice>
      )}
      {notice && notice.reason !== 'rotation.paused_license' && <ReasonAlert error={notice} color="yellow" />}
      {query.isError && query.data && <ErrorAlert error={query.error} />}
      {r.result && <ReasonAlert error={r.result} color={resultWarn ? 'yellow' : 'red'} />}
      <ErrorAlert error={error} />
      <div className={classes.grid}>
        <div className={classes.stack}>
          {/* A stopped, undoing or unknown run has no progress path: the badge and the reason say what happened. */}
          {hasRotationPath(r.status) && (
            <Panel title={t('rotation.page.path')}>
              <RotationPath status={r.status} paused={r.paused_license} />
            </Panel>
          )}
          <Panel title={t('rotation.page.results')} description={t('rotation.page.resultsSub')} aria-label={t('rotation.page.results')} padded={false}>
            {Object.keys(r.location_counts).length > 0 && (
              <List size="sm" listStyleType="none" data-testid="run-counts" className={classes.counts}>
                {Object.entries(r.location_counts).map(([k, n]) => (
                  <List.Item key={k}>{t('rotation.countLine', { label: labelOf(t, i18n, 'rotation.counts', k), count: n })}</List.Item>
                ))}
              </List>
            )}
            <Table.ScrollContainer minWidth={760}>
              <Table striped aria-label={t('rotation.places')} data-testid="run-locations">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t('rotation.col.server')}</Table.Th>
                    <Table.Th>{t('rotation.col.user')}</Table.Th>
                    <Table.Th>{t('rotation.col.file')}</Table.Th>
                    <Table.Th>{t('rotation.col.state')}</Table.Th>
                    <Table.Th>{t('rotation.col.details')}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {(r.locations ?? []).map((l) => (
                    <LocationRow key={l.id} l={l} />
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          </Panel>
          {r.kept_count > 0 && (
            <Notice tone="warning" title={t('rotation.keptCount', { count: r.kept_count })}>
              <Text size="sm">{t('rotation.keptHelp')}</Text>
            </Notice>
          )}
          {(r.steps ?? []).length > 0 && (
            <Panel title={t('rotation.steps')}>
              <List size="sm" spacing={4} listStyleType="none" data-testid="run-steps">
                {(r.steps ?? []).map((s) => (
                  <List.Item key={s.n}>
                    <Group gap={6} wrap="wrap">
                      <Text size="xs" c="dimmed">
                        {formatDateTime(s.at, i18n.language)}
                      </Text>
                      <Text size="sm">{stepLabel(t, i18n, s)}</Text>
                      {s.location_id && (
                        <Text size="xs" translate="no" style={WRAP}>
                          {locationName(s.location_id)}
                        </Text>
                      )}
                      {(s.name === 'late_result' || s.name === 'undo_not_sent') && (
                        <StatusBadge tone="warning" icon="CircleAlert">
                          {t('rotation.warning')}
                        </StatusBadge>
                      )}
                      {s.status === 'failed' && (
                        <StatusBadge tone="danger" icon="CircleX">
                          {labelOf(t, i18n, 'rotation.stepStatus', 'failed')}
                        </StatusBadge>
                      )}
                    </Group>
                  </List.Item>
                ))}
              </List>
            </Panel>
          )}
        </div>
        <div className={classes.stack}>
          <Panel title={t('rotation.page.transition')} aria-label={t('rotation.page.transition')}>
            <div className={classes.fingerprint}>
              <span className={classes.label}>{t('rotation.oldKey')}</span>
              <Code translate="no" style={WRAP}>
                {r.old_fingerprint}
              </Code>
            </div>
            {r.new_fingerprint !== '' && (
              <div className={classes.fingerprint}>
                <span className={classes.label}>{t('rotation.newKey')}</span>
                <Code translate="no" style={WRAP}>
                  {r.new_fingerprint}
                </Code>
              </div>
            )}
            <FactList facts={facts} />
          </Panel>
          {decisions.length > 0 && (
            <Panel title={t('rotation.page.decisions')} aria-label={t('rotation.page.decisions')}>
              <div className={classes.decisions}>
                {allowed.has('continue') && <Text size="sm">{t('rotation.continueHelp')}</Text>}
                {allowed.has('continue') && (
                  <Button loading={busy} leftSection={<Icon name="CirclePlay" size={15} />} onClick={() => void decide(() => continueRun(id))}>
                    {t('rotation.continue')}
                  </Button>
                )}
                {allowed.has('finish_now') && (
                  <Button variant="default" leftSection={<Icon name="CheckCheck" size={15} />} onClick={() => setConfirm('finish_now')}>
                    {t('rotation.finishNow')}
                  </Button>
                )}
                {allowed.has('keep_old') && (
                  <Button variant="default" leftSection={<Icon name="LockKeyhole" size={15} />} onClick={() => setConfirm('keep_old')}>
                    {t('rotation.keepOld')}
                  </Button>
                )}
                {allowed.has('abort') && (
                  <Button color="red" variant="light" leftSection={<Icon name="CircleOff" size={15} />} onClick={() => setConfirm('abort')}>
                    {t('rotation.abort')}
                  </Button>
                )}
              </div>
              <p className={classes.help}>{t('rotation.page.decisionsHelp')}</p>
            </Panel>
          )}
        </div>
      </div>
      {confirm === 'finish_now' && (
        <AppModal opened onClose={closeConfirm} title={t('rotation.finishNow')}>
          <Stack gap="sm">
            <Text size="sm">{t('rotation.finishNowHelp')}</Text>
          </Stack>
          <DialogActions>
            <Button variant="default" onClick={closeConfirm}>
              {t('ui.cancel')}
            </Button>
            <Button loading={busy} onClick={() => void decide(() => finishRunNow(id))}>
              {t('rotation.finishNow')}
            </Button>
          </DialogActions>
        </AppModal>
      )}
      {confirm === 'abort' && (
        <AppModal opened onClose={closeConfirm} title={t('rotation.abort')}>
          <Stack gap="sm">
            <Text size="sm">{t('rotation.abortConfirm')}</Text>
          </Stack>
          <DialogActions>
            <Button variant="default" onClick={closeConfirm}>
              {t('ui.cancel')}
            </Button>
            <Button color="red" loading={busy} onClick={() => void decide(() => abortRun(id))}>
              {t('rotation.abort')}
            </Button>
          </DialogActions>
        </AppModal>
      )}
      {confirm === 'keep_old' && (
        <AppModal opened onClose={closeConfirm} title={t('rotation.keepOld')}>
          <Stack gap="sm">
            <Text size="sm">{t('rotation.keepOldHelp')}</Text>
            <Stack gap={6} role="group" aria-label={t('rotation.keepOld')}>
              {unverifiable.map((l) => (
                <Checkbox
                  key={l.id}
                  checked={kept.has(l.id)}
                  onChange={(e) => {
                    const next = new Set(kept);
                    if (e.currentTarget.checked) next.add(l.id);
                    else next.delete(l.id);
                    setKept(next);
                  }}
                  label={
                    <span translate="no" style={WRAP}>
                      {`${l.target_name}, ${l.os_user}, ${l.file_path}`}
                    </span>
                  }
                />
              ))}
            </Stack>
          </Stack>
          <DialogActions>
            <Button variant="default" onClick={closeConfirm}>
              {t('ui.cancel')}
            </Button>
            <Button loading={busy} disabled={kept.size === 0} onClick={() => void decide(() => keepOldKey(id, unverifiable.filter((l) => kept.has(l.id)).map((l) => l.id)))}>
              {t('rotation.keepOld')}
            </Button>
          </DialogActions>
        </AppModal>
      )}
    </Stack>
  );
}
