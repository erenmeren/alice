import { Anchor, Badge, Button, Group, Stack, Table, Text } from '@mantine/core';
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { abortRollout, continueRollout, getRollout } from '../api/endpoints';
import { deploymentStateKey, deploymentStatusKey } from '../api/enums';
import { DEPLOYMENTS_KEY, rolloutKey } from '../api/queryKeys';
import type { CanaryCheck, Rollout, RolloutLocation } from '../api/types';
import { formatDateTime } from '../datetime';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { useStepUp } from './StepUpProvider';
import { DialogActions, Panel } from './ui';
import { WRAP } from './wrap';

// reasonKey is the text key of a rollout's reason (its dots become underscores: i18next reads dots as nesting).
export const rolloutReasonKey = (reason: string) => `canary.reason.${reason.replace(/\./g, '_')}`;

const ACTIVE: ReadonlySet<string> = new Set(['wave1', 'hold', 'wave2']);

// remaining is the hold left at the moment, from the server's clock (now) read with the rollout and the time since
// (the e2e build moves the server's clock, so the browser's clock is never compared with hold_until).
function remaining(r: Rollout, readAt: number, at: number): number | null {
  if (!r.hold_until || r.state !== 'hold') return null;
  const left = Date.parse(r.hold_until) - Date.parse(r.now) - (at - readAt);
  return Math.max(0, Math.floor(left / 1000));
}

// RolloutPanel is a deployment's canary rollout (R65, design §19): the state and its reason, the hold countdown, both
// waves with each website's deployment and wave 1's latest check, the wave-2 websites that were skipped, and Continue
// now (a fresh step-up) and Abort (a confirmation) as the server allows.
export function RolloutPanel({ id }: { id: string }) {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const { run } = useStepUp();
  const [readAt, setReadAt] = useState(() => Date.now());
  const [tick, setTick] = useState(() => Date.now());
  const [confirming, setConfirming] = useState(false);
  const rollout = useQuery({
    queryKey: rolloutKey(id),
    queryFn: async () => {
      const r = await getRollout(id);
      setReadAt(Date.now());
      return r;
    },
    refetchInterval: (q) => (q.state.data && ACTIVE.has(q.state.data.state) ? 10_000 : false),
    placeholderData: keepPreviousData,
  });
  useEffect(() => {
    const timer = setInterval(() => setTick(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  const done = (r: Rollout) => {
    client.setQueryData(rolloutKey(id), r);
    setReadAt(Date.now());
    void client.invalidateQueries({ queryKey: DEPLOYMENTS_KEY });
  };
  const proceed = useMutation({ mutationFn: () => run(() => continueRollout(id)), onSuccess: done });
  const abort = useMutation({ mutationFn: () => abortRollout(id), onSuccess: (r) => (setConfirming(false), done(r)) });

  const r = rollout.data;
  if (!r) return <ErrorAlert error={rollout.error} />;
  const left = remaining(r, readAt, tick);
  const time = (v: string | null) => (v ? formatDateTime(v, i18n.language) : '');
  return (
    <Panel title={t('canary.title')} testId="rollout-panel">
      <Stack gap="sm">
        <Group gap="xs">
          <Badge variant="light" tt="none" data-testid="rollout-state" data-state={r.state}>
            {t(`canary.state.${r.state}`)}
          </Badge>
          {r.reason && (
            <Text size="sm" data-testid="rollout-reason">
              {t(rolloutReasonKey(r.reason), { defaultValue: r.reason })}
            </Text>
          )}
        </Group>
        {left !== null && (
          <Text size="sm" role="timer" data-testid="rollout-countdown">
            {left > 0 ? t('canary.holdLeft', { minutes: Math.floor(left / 60), seconds: left % 60 }) : t('canary.holdOver')}
          </Text>
        )}
        <ErrorAlert error={proceed.error ?? abort.error} />
        {r.waves.map((w) => (
          <Stack key={w.wave} gap={4}>
            <Text fw={600} size="sm">
              {t('canary.wave', { wave: w.wave })}
            </Text>
            <Table data-testid={`rollout-wave-${w.wave}`}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('canary.columns.website')}</Table.Th>
                  <Table.Th>{t('canary.columns.deployment')}</Table.Th>
                  {w.wave === 1 && (
                    <>
                      <Table.Th>{t('canary.columns.lastCheck')}</Table.Th>
                      <Table.Th>{t('canary.columns.tls')}</Table.Th>
                      <Table.Th>{t('canary.columns.http')}</Table.Th>
                      <Table.Th>{t('canary.columns.latency')}</Table.Th>
                      <Table.Th>{t('canary.columns.failures')}</Table.Th>
                    </>
                  )}
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {w.locations.map((l) => (
                  <WaveRow key={l.location_id} l={l} wave={w.wave} time={time} />
                ))}
              </Table.Tbody>
            </Table>
          </Stack>
        ))}
        {r.skipped.map((s) => {
          const l = r.waves.flatMap((w) => w.locations).find((x) => x.location_id === s.location_id);
          return (
            <Text size="sm" key={s.location_id} data-testid="rollout-skipped" style={WRAP}>
              {l ? `${l.target_name} ${l.site}: ` : ''}
              {t('canary.skipped', { reason: s.reason })}
            </Text>
          );
        })}
        {r.hidden_count > 0 && (
          <Text size="sm" c="dimmed">
            {t('canary.hidden', { count: r.hidden_count })}
          </Text>
        )}
        {r.allowed_actions.length > 0 && (
          <Group>
            {r.allowed_actions.includes('continue') && (
              <Button onClick={() => proceed.mutate()} loading={proceed.isPending} title={t('canary.continueHelp')} data-testid="rollout-continue">
                {t('canary.continue')}
              </Button>
            )}
            {r.allowed_actions.includes('abort') && (
              <Button color="red" variant="light" onClick={() => setConfirming(true)} data-testid="rollout-abort">
                {t('canary.abort')}
              </Button>
            )}
          </Group>
        )}
      </Stack>
      {confirming && (
        <AppModal opened onClose={() => !abort.isPending && setConfirming(false)} title={t('canary.abort')}>
          <Stack gap="sm">
            <Text size="sm">{t('canary.abortConfirm')}</Text>
            <DialogActions>
              <Button variant="default" onClick={() => setConfirming(false)} disabled={abort.isPending}>
                {t('ui.cancel')}
              </Button>
              <Button color="red" onClick={() => abort.mutate()} loading={abort.isPending} data-testid="rollout-abort-confirm">
                {t('canary.abortYes')}
              </Button>
            </DialogActions>
          </Stack>
        </AppModal>
      )}
    </Panel>
  );
}

function WaveRow({ l, wave, time }: { l: RolloutLocation; wave: 1 | 2; time: (v: string | null) => string }) {
  const { t } = useTranslation();
  const c: CanaryCheck | null = l.canary;
  return (
    <Table.Tr data-testid="rollout-location">
      <Table.Td style={WRAP}>
        <Text span size="sm" translate="no" fw={500}>
          {l.target_name}
        </Text>{' '}
        <Text span size="sm" c="dimmed" translate="no">
          {l.site}
        </Text>
      </Table.Td>
      <Table.Td>
        {l.deployment_id ? (
          <Anchor component={Link} to={`/deployments/${l.deployment_id}`} size="sm">
            {t(deploymentStateKey(l.deployment_state ?? ''))}
            {l.deployment_status && l.deployment_status !== 'running' && l.deployment_status !== 'pending' ? ` · ${t(deploymentStatusKey(l.deployment_status))}` : ''}
          </Anchor>
        ) : (
          <Text size="sm" c="dimmed">
            {t('canary.notDeployed')}
          </Text>
        )}
      </Table.Td>
      {wave === 1 && (
        <>
          <Table.Td>
            <Text size="sm">
              {t(`canary.result.${c?.last_result || 'none'}`)}
              {c?.last_at ? ` · ${time(c.last_at)}` : ''}
            </Text>
          </Table.Td>
          <Table.Td>
            <Text size="sm">{t(`canary.tls.${c?.last_tls || 'none'}`)}</Text>
          </Table.Td>
          <Table.Td>
            <Text size="sm">{c?.last_http_status ?? '-'}</Text>
          </Table.Td>
          <Table.Td>
            <Text size="sm">{c?.last_latency_ms != null ? `${c.last_latency_ms} ms` : '-'}</Text>
          </Table.Td>
          <Table.Td>
            <Text size="sm">{c?.consecutive_failures ?? 0}</Text>
          </Table.Td>
        </>
      )}
    </Table.Tr>
  );
}
