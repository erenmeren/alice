import { Text } from '@mantine/core';
import type { i18n, TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { FINAL_STATUSES } from '../api/deployments';
import { configErrorKey, stepNameKey, stepStatusKey, trustErrorKey, trustStatusKey } from '../api/enums';
import type { DeploymentStatus, DeploymentStep } from '../api/types';
import { OperationTimeline, type StepState } from './ui';
import { WRAP } from './wrap';

// The five steps a person sees (contract "UI step grouping"): Write covers the key and the
// certificate. verify_current (the pre-check) comes first and only in the detail page; every other
// step the engine reports (restore, rollback_config_test, rollback_reload, verify_old, journal and
// names a newer server adds) is listed after them, in the order it happened.
const GROUPS: { id: string; members: string[] }[] = [
  { id: 'backup', members: ['backup'] },
  { id: 'write', members: ['write_key', 'write_cert'] },
  { id: 'config_test', members: ['config_test'] },
  { id: 'reload', members: ['reload'] },
  { id: 'verify', members: ['verify'] },
];
// kv_secret is the first step of a Key Vault deployment (the certificate is read from the vault before
// anything reaches the server); it has a row only when the deployment came from a vault.
const GROUPED = new Set(['verify_current', 'kv_secret', ...GROUPS.flatMap((g) => g.members)]);

type Shown = 'started' | 'ok' | 'failed' | 'skipped' | 'waiting' | 'notRun' | 'unknown';

function lastStatus(steps: DeploymentStep[], name: string): string | undefined {
  let found: DeploymentStep | undefined;
  for (const s of steps) if (s.name === name && (!found || s.n > found.n)) found = s;
  return found?.status;
}

// groupStatus is the status of a grouped step: the last event of its members; Write is failed when
// either member failed and done when both are done. A step with no event yet is waiting, or "not
// run" once the deployment has ended without reaching it.
function groupStatus(steps: DeploymentStep[], members: string[], ended: boolean): Shown {
  const seen = members.map((m) => lastStatus(steps, m));
  if (seen.every((s) => s === undefined)) return ended ? 'notRun' : 'waiting';
  if (seen.some((s) => s === 'failed')) return 'failed';
  const present = seen.filter((s): s is string => s !== undefined);
  if (present.some((s) => s !== 'ok' && s !== 'skipped' && s !== 'started')) return 'unknown';
  if (present.every((s) => s === 'skipped') && present.length === members.length) return 'skipped';
  const done = present.every((s) => s === 'ok' || s === 'skipped');
  if (done && (present.length === members.length || ended)) return 'ok';
  return 'started';
}

function singleStatus(steps: DeploymentStep[], name: string, ended: boolean): Shown {
  const s = lastStatus(steps, name);
  if (s === undefined) return ended ? 'notRun' : 'waiting';
  return s === 'started' || s === 'ok' || s === 'failed' || s === 'skipped' ? s : 'unknown';
}

function statusText(s: Shown): string {
  return s === 'waiting' || s === 'notRun' ? `deployments.stepStatus.${s}` : stepStatusKey(s);
}

// The design's step states (OperationTimeline): a step that never ran is "not run", never a tick.
const STATE: Record<Shown, StepState> = { ok: 'done', failed: 'failed', started: 'running', waiting: 'waiting', skipped: 'skipped', notRun: 'notRun', unknown: 'unknown' };

// Step details the server allows (DeploymentStep.params): shown only in the detail page. None: no lines.
function stepDetails(step: DeploymentStep, t: TFunction, i18n: i18n): React.ReactNode[] {
  const p = step.params ?? {};
  const lines: React.ReactNode[] = [];
  if (p.error) lines.push(<Text key="error" size="xs">{t('deployments.stepDetail.error', { reason: t(configErrorKey(p.error)) })}</Text>);
  if (p.reason) {
    const key = `errors.${p.reason}.title`;
    lines.push(
      <Text key="reason" size="xs">
        {t('deployments.stepDetail.reason', { reason: i18n.exists(key) ? t(key, { port: p.port ?? '' }) : t('ui.unexpectedError') })}
      </Text>,
    );
  }
  if (p.port) lines.push(<Text key="port" size="xs">{t('deployments.stepDetail.port', { port: p.port })}</Text>);
  if (p.mode) lines.push(<Text key="mode" size="xs">{t('deployments.stepDetail.mode', { mode: t(`deployments.verified.${['remote', 'local', 'skipped'].includes(p.mode) ? p.mode : 'none'}`) })}</Text>);
  // R51: the served chain's trust and, when it did not verify, the precise fault.
  if (p.trust) lines.push(<Text key="trust" size="xs">{t('deployments.stepDetail.trust', { trust: t(trustStatusKey(p.trust)) })}</Text>);
  if (p.trust_error) lines.push(<Text key="trustError" size="xs">{t('deployments.stepDetail.trustError', { reason: t(trustErrorKey(p.trust_error)) })}</Text>);
  if (step.name === 'recover_pending' && (step.status === 'ok' || step.status === 'skipped' || step.status === 'failed')) {
    lines.push(
      <Text key="recover" size="xs">
        {t(`deployments.stepDetail.recoverPending.${step.status}`)}
      </Text>,
    );
  }
  // The unfinished earlier change on the server (not this deployment's own backup folder).
  if (p.operation_id) {
    lines.push(
      <Text key="operation" size="xs" style={WRAP}>
        {t('deployments.operation', { id: '' }).replace(/\s*$/, ' ')}
        <code translate="no">{p.operation_id}</code>
      </Text>,
    );
  }
  if (p.served) {
    lines.push(
      <Text key="served" size="xs" style={WRAP}>
        {t('deployments.stepDetail.served', { fingerprint: '' })}
        <code translate="no">{p.served}</code>
      </Text>,
    );
  }
  return lines;
}

interface Row {
  id: string;
  label: string;
  rawName?: string;
  status: Shown;
  detail?: DeploymentStep;
}

// DeploymentSteps lists the steps of one deployment with a status each, as the design's operation
// timeline; markers never carry the meaning alone, every row says it in words. The list is not a live
// region itself: the screen that owns it announces the overall state.
export function DeploymentSteps({ steps, status, detailed = false, vault = false }: { steps: DeploymentStep[]; status: DeploymentStatus | ''; detailed?: boolean; vault?: boolean }) {
  const { t, i18n } = useTranslation();
  const ended = FINAL_STATUSES.has(status);
  const rows: Row[] = [];
  if (detailed) rows.push({ id: 'verify_current', label: t('deployments.steps.verify_current'), status: singleStatus(steps, 'verify_current', ended), detail: lastOf(steps, 'verify_current') });
  if (vault || steps.some((s) => s.name === 'kv_secret')) rows.push({ id: 'kv_secret', label: t('deployments.steps.kv_secret'), status: singleStatus(steps, 'kv_secret', ended), detail: lastOf(steps, 'kv_secret') });
  for (const g of GROUPS) {
    rows.push({
      id: g.id,
      label: t(`deployments.steps.${g.id}`),
      status: groupStatus(steps, g.members, ended),
      detail: g.members.map((m) => lastOf(steps, m)).filter((s): s is DeploymentStep => s !== undefined && s.status === 'failed')[0] ?? lastOf(steps, g.members[g.members.length - 1]),
    });
  }
  const extra: string[] = [];
  for (const s of [...steps].sort((a, b) => a.n - b.n)) if (!GROUPED.has(s.name) && !extra.includes(s.name)) extra.push(s.name);
  for (const name of extra) {
    const known = stepNameKey(name);
    rows.push({ id: name, label: t(known), rawName: known === 'deployments.steps.unknown' ? name : undefined, status: singleStatus(steps, name, ended), detail: lastOf(steps, name) });
  }
  const detail = (r: Row): React.ReactNode => {
    const lines = detailed && r.detail ? stepDetails(r.detail, t, i18n) : [];
    return lines.length > 0 ? lines : undefined;
  };
  return (
    <OperationTimeline
      label={t('deployments.stepsTitle')}
      steps={rows.map((r) => ({
        id: r.id,
        title: (
          <span>
            {r.label}
            {r.rawName && (
              <>
                {' '}
                <code translate="no">{r.rawName}</code>
              </>
            )}
          </span>
        ),
        state: STATE[r.status],
        stateLabel: t(statusText(r.status)),
        detail: detail(r),
        dataAttrs: { 'data-step': r.id, 'data-status': r.status },
      }))}
    />
  );
}

function lastOf(steps: DeploymentStep[], name: string): DeploymentStep | undefined {
  let found: DeploymentStep | undefined;
  for (const s of steps) if (s.name === name && (!found || s.n > found.n)) found = s;
  return found;
}

// currentStep is the text key of the step the deployment reached last (the one with the highest
// sequence number), or null before any step was reported. Write (key and certificate) is one step.
export function currentStep(steps: DeploymentStep[]): string | null {
  let last: DeploymentStep | undefined;
  for (const s of steps) if (!last || s.n > last.n) last = s;
  if (!last) return null;
  if (last.name === 'write_key' || last.name === 'write_cert') return 'deployments.steps.write';
  return stepNameKey(last.name);
}
