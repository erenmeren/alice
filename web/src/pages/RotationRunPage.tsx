import { Alert, Anchor, Badge, Button, Checkbox, Code, Group, List, Stack, Table, Text, Title } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useParams } from 'react-router';
import { ROTATION_POLICIES_KEY, ROTATION_RUNS_KEY, runKey, SSH_KEYS_KEY } from '../api/queryKeys';
import { abortRun, continueRun, finishRunNow, getRun, keepOldKey, runPollInterval, type Run, type RunLocation, type RunStep } from '../api/rotation';
import { useAuth } from '../auth/AuthProvider';
import type { ErrorRef } from '../api/types';
import { PageLoader } from '../auth/guards';
import { AppModal } from '../components/AppModal';
import { ErrorAlert } from '../components/ErrorAlert';
import { ReasonAlert, labelOf, noteText, skipText } from '../components/rotationText';
import { reasonTitle } from '../components/JobErrorAlert';
import { useStepUp } from '../components/StepUpProvider';
import { WRAP } from '../components/wrap';
import { formatDateTime } from '../datetime';

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
        <Badge variant="light" color={l.state === 'removed' || l.state === 'verified' ? 'green' : l.state.endsWith('_failed') ? 'red' : l.state === 'kept_old' || l.state === 'skipped' ? 'yellow' : 'gray'} tt="none">
          {labelOf(t, i18n, 'rotation.loc', l.state)}
        </Badge>
      </Table.Td>
      <Table.Td>
        <Stack gap={4}>
          {l.skip_reason !== '' && <Text size="xs">{skipText(t, i18n, l.skip_reason)}</Text>}
          {l.add_resend_count > 0 && l.add_resent_at && <Text size="xs">{t('rotation.addResent', { count: l.add_resend_count, date: formatDateTime(l.add_resent_at, i18n.language) })}</Text>}
          {note !== '' && <Text size="xs">{note}</Text>}
          {l.error && (
            <Text size="xs" style={WRAP}>
              {warn && (
                <Badge variant="light" color="yellow" tt="none" mr={6}>
                  {t('rotation.warning')}
                </Badge>
              )}
              {reasonTitle(t, i18n, l.error.reason, l.error.params ?? {})}
              {l.error.code && (
                <Text span size="xs" c="gray.7">
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

  return (
    <Stack gap="md">
      <Group justify="space-between" align="flex-start">
        <Title order={1}>{t('rotation.runTitle')}</Title>
        <div role="status" aria-live="polite">
          <Badge size="lg" variant="light" color={r.status === 'completed' ? 'green' : r.status === 'needs_attention' ? 'orange' : 'indigo'} tt="none">
            {labelOf(t, i18n, 'rotation.status', r.status)}
          </Badge>
        </div>
      </Group>
      <Anchor component={Link} to={`/ssh-keys/${encodeURIComponent(r.status === 'completed' && r.new_ssh_key_id ? r.new_ssh_key_id : r.old_ssh_key_id)}`} w="fit-content" size="sm">
        {t('rotation.backToKey')}
      </Anchor>
      <Text size="sm">{t(`rotation.trigger.${r.trigger === 'scheduled' ? 'scheduled' : 'manual'}`)}</Text>
      <Text size="sm">{t('rotation.plannedFor', { date: formatDateTime(r.planned_for, i18n.language) })}</Text>
      <Text size="sm" fw={600}>
        {t('rotation.oldKey')}
      </Text>
      <Code translate="no" style={WRAP}>
        {r.old_fingerprint}
      </Code>
      {r.new_fingerprint !== '' && (
        <>
          <Text size="sm" fw={600}>
            {t('rotation.newKey')}
          </Text>
          <Code translate="no" style={WRAP}>
            {r.new_fingerprint}
          </Code>
        </>
      )}
      {r.status === 'overlap' && r.overlap_until && <Text size="sm">{t('rotation.overlapUntil', { date: formatDateTime(r.overlap_until, i18n.language) })}</Text>}
      {r.awaiting_decision && !r.paused_license && r.decision_due_at && <Text size="sm">{t('rotation.decisionDue', { date: formatDateTime(r.decision_due_at, i18n.language) })}</Text>}
      {r.finished_at && <Text size="sm">{t('rotation.finishedAt', { date: formatDateTime(r.finished_at, i18n.language) })}</Text>}
      {r.paused_license && (
        <Alert color="red" role="alert">
          <Text size="sm">{t('rotation.pausedBanner')}</Text>
          {allowed.has('abort') && <Text size="sm">{t('rotation.licensePaused')}</Text>}
          <Anchor component={Link} to="/license" size="sm">
            {t('rotation.openLicense')}
          </Anchor>
        </Alert>
      )}
      {notice && <ReasonAlert error={notice} color="yellow" />}
      {query.isError && query.data && <ErrorAlert error={query.error} />}
      {r.result && <ReasonAlert error={r.result} color={resultWarn ? 'yellow' : 'red'} />}
      {Object.keys(r.location_counts).length > 0 && (
        <List size="sm" listStyleType="none" data-testid="run-counts">
          {Object.entries(r.location_counts).map(([k, n]) => (
            <List.Item key={k}>{t('rotation.countLine', { label: labelOf(t, i18n, 'rotation.counts', k), count: n })}</List.Item>
          ))}
        </List>
      )}
      {r.kept_count > 0 && (
        <Stack gap={2}>
          <Text size="sm" fw={600}>
            {t('rotation.keptCount', { count: r.kept_count })}
          </Text>
          <Text size="sm">{t('rotation.keptHelp')}</Text>
        </Stack>
      )}
      <ErrorAlert error={error} />
      {decisions.length > 0 && (
        <Stack gap="xs">
          {allowed.has('continue') && <Text size="sm">{t('rotation.continueHelp')}</Text>}
          <Group gap="sm">
            {allowed.has('continue') && (
              <Button loading={busy} onClick={() => void decide(() => continueRun(id))}>
                {t('rotation.continue')}
              </Button>
            )}
            {allowed.has('finish_now') && (
              <Button variant="default" onClick={() => setConfirm('finish_now')}>
                {t('rotation.finishNow')}
              </Button>
            )}
            {allowed.has('keep_old') && (
              <Button variant="default" onClick={() => setConfirm('keep_old')}>
                {t('rotation.keepOld')}
              </Button>
            )}
            {allowed.has('abort') && (
              <Button color="red.9" variant="light" onClick={() => setConfirm('abort')}>
                {t('rotation.abort')}
              </Button>
            )}
          </Group>
        </Stack>
      )}
      <Title order={2} size="h3">
        {t('rotation.places')}
      </Title>
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
      {(r.steps ?? []).length > 0 && (
        <>
          <Title order={2} size="h3">
            {t('rotation.steps')}
          </Title>
          <List size="sm" spacing={4} listStyleType="none" data-testid="run-steps">
            {(r.steps ?? []).map((s) => (
              <List.Item key={s.n}>
                <Group gap={6} wrap="wrap">
                  <Text size="xs" c="gray.7">
                    {formatDateTime(s.at, i18n.language)}
                  </Text>
                  <Text size="sm">{stepLabel(t, i18n, s)}</Text>
                  {s.location_id && (
                    <Text size="xs" translate="no" style={WRAP}>
                      {locationName(s.location_id)}
                    </Text>
                  )}
                  {(s.name === 'late_result' || s.name === 'undo_not_sent') && (
                    <Badge variant="light" color="yellow" tt="none">
                      {t('rotation.warning')}
                    </Badge>
                  )}
                  {s.status === 'failed' && (
                    <Badge variant="light" color="red" tt="none">
                      {labelOf(t, i18n, 'rotation.stepStatus', 'failed')}
                    </Badge>
                  )}
                </Group>
              </List.Item>
            ))}
          </List>
        </>
      )}
      {confirm === 'finish_now' && (
        <AppModal opened onClose={closeConfirm} title={t('rotation.finishNow')}>
          <Stack gap="sm">
            <Text size="sm">{t('rotation.finishNowHelp')}</Text>
            <Group justify="flex-end">
              <Button variant="default" onClick={closeConfirm}>
                {t('ui.cancel')}
              </Button>
              <Button loading={busy} onClick={() => void decide(() => finishRunNow(id))}>
                {t('rotation.finishNow')}
              </Button>
            </Group>
          </Stack>
        </AppModal>
      )}
      {confirm === 'abort' && (
        <AppModal opened onClose={closeConfirm} title={t('rotation.abort')}>
          <Stack gap="sm">
            <Text size="sm">{t('rotation.abortConfirm')}</Text>
            <Group justify="flex-end">
              <Button variant="default" onClick={closeConfirm}>
                {t('ui.cancel')}
              </Button>
              <Button color="red.9" loading={busy} onClick={() => void decide(() => abortRun(id))}>
                {t('rotation.abort')}
              </Button>
            </Group>
          </Stack>
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
            <Group justify="flex-end">
              <Button variant="default" onClick={closeConfirm}>
                {t('ui.cancel')}
              </Button>
              <Button loading={busy} disabled={kept.size === 0} onClick={() => void decide(() => keepOldKey(id, unverifiable.filter((l) => kept.has(l.id)).map((l) => l.id)))}>
                {t('rotation.keepOld')}
              </Button>
            </Group>
          </Stack>
        </AppModal>
      )}
    </Stack>
  );
}
