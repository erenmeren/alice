import { Alert, Stack, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import {
  deploymentStatusText,
  deploymentView,
  isCancelled,
  isCCSDeployment,
  isRDPDeployment,
  isWindowsDeployment,
  PENDING_CHANGE_RESTORED,
  rollbackForbidden,
  SERVER_OPERATION_PENDING,
  untrustedSuccess,
} from '../api/deployments';
import { trustErrorKey } from '../api/enums';
import type { Deployment, DeploymentDetail, ErrorRef } from '../api/types';
import { formatDateTime } from '../datetime';
import { Icon, type IconName } from '../design/Icon';
import { toneOf, type Tone } from '../theme';
import { withRoleCode } from './CodeText';
import { LabelledCode } from './LabelledCode';
import { deploymentTone, StatusBadge } from './ui';
import { WRAP } from './wrap';

// DeploymentStatusBadge is the deployment's status in words (a colour is only a cue). A status this
// version does not know, or '', reads "Unknown" and is neutral. The design's status pill (StatusBadge);
// the theme never upper-cases it (Turkish dotted/dotless i).
// `tone` overrides the status's own tone where a page knows more (the history marks an unverified success a warning).
export function DeploymentStatusBadge({ d, testId, tone }: { d: Pick<Deployment, 'status' | 'error'> & { state?: string }; testId?: string; tone?: Tone }) {
  const { t } = useTranslation();
  const cancelled = isCancelled(d);
  return (
    <StatusBadge tone={tone ?? deploymentTone(d) ?? 'neutral'} testId={testId} data-status={d.status} data-cancelled={cancelled ? 'true' : undefined}>
      {t(deploymentStatusText(d))}
    </StatusBadge>
  );
}

// The design's notice icon for each tone (Notice uses the same): a shield with a check only for a success.
const OUTCOME_ICON: Record<Tone, IconName> = { brand: 'ShieldCheck', success: 'ShieldCheck', warning: 'CircleAlert', danger: 'ShieldAlert', info: 'CircleDot', neutral: 'CircleDot' };

const UNRESOLVED = /\{\{\s*\w+\s*\}\}/;

// DeploymentErrorAlert shows an ErrorRef of a deployment (error or verify_failed). The server gives
// {code, reason, params} without a message key, so the texts are errors.<reason>.title|cause|action
// of the shared catalogue; a reason without text, or a text whose parameters the server did not
// give, shows the generic message. The code is detail below the texts. An operation id (the
// unfinished earlier change on the server that ALC-DEP-0023/0024 name) is shown as data, because the
// action tells the operator to use it. neutral: a decision, not a failure (a cancelled deployment).
// windows: a deployment to an http.sys binding (R61); a shared text that speaks of the files and the backup folder of a
// Linux server has its binding wording in deployments.windowsErrors.<reason>.<part>, used in its place. rdp: a deployment
// to the Remote Desktop listener (R69): its listener wording in deployments.rdpErrors.<reason>.<part> comes first, then
// the Windows one (the helper and the connection), then the shared one.
export function DeploymentErrorAlert({
  error,
  heading,
  withCause = true,
  neutral = false,
  windows = false,
  rdp = false,
}: {
  error: ErrorRef | null;
  heading?: string;
  withCause?: boolean;
  neutral?: boolean;
  windows?: boolean;
  rdp?: boolean;
}) {
  const { t, i18n } = useTranslation();
  if (!error) return null;
  const params = error.params ?? {};
  const text = (part: 'title' | 'cause' | 'action'): string => {
    const listener = `deployments.rdpErrors.${error.reason}.${part}`;
    const own = `deployments.windowsErrors.${error.reason}.${part}`;
    const key = rdp && i18n.exists(listener) ? listener : (windows || rdp) && i18n.exists(own) ? own : `errors.${error.reason}.${part}`;
    if (!i18n.exists(key)) return '';
    const out = t(key, params);
    return UNRESOLVED.test(out) ? '' : out;
  };
  const title = text('title') || t('ui.unexpectedError');
  const cause = withCause ? text('cause') : '';
  const action = text('action');
  const operation = params.operation_id ?? '';
  return (
    <Alert
      color={neutral ? 'gray' : 'red'}
      role={neutral ? 'status' : 'alert'}
      title={withRoleCode(title, params.role)}
      data-reason={error.reason}
      icon={<Icon name={OUTCOME_ICON[neutral ? 'neutral' : 'danger']} size={17} />}
    >
      <Stack gap={4}>
        {heading && (
          <Text size="xs" c="dimmed">
            {heading}
          </Text>
        )}
        {cause && <Text size="sm">{withRoleCode(cause, params.role)}</Text>}
        {action && <Text size="sm">{withRoleCode(action, params.role)}</Text>}
        {operation && <LabelledCode text={t('deployments.operation', { id: '' })} value={operation} />}
        {error.code && (
          <Text size="xs" c="dimmed" style={WRAP}>
            {t('jobs.errorCode', { code: error.code })}
          </Text>
        )}
      </Stack>
    </Alert>
  );
}

// DeploymentOutcome is what happened to one deployment, for a person: the headline sentence for its
// status (never "live" unless the status is succeeded), then the error with its cause and action.
// The detail page shows more around it (recovery counters, the backup folder).
export function DeploymentOutcome({ d }: { d: Deployment }) {
  const { t, i18n } = useTranslation();
  const view = deploymentView(d);
  const windows = isWindowsDeployment(d);
  const rdp = isRDPDeployment(d);
  // place picks the headline of the place's kind: the Remote Desktop listener's (R69), a binding's, else the files'.
  const place = (files: string, binding: string, listener: string) => (rdp ? listener : windows ? binding : files);
  let color: string;
  let headline: string;
  let extra = '';
  if (view === 'final') {
    switch (d.status) {
      case 'succeeded': {
        const checked = d.verified === 'remote' || d.verified === 'local';
        const trust = d.verification?.trust;
        color = checked ? 'green' : 'yellow';
        headline = t(checked ? 'deploy.succeeded' : windows ? 'deploy.succeededUnverifiedWindows' : isCCSDeployment(d) ? 'deploy.succeededUnverifiedCCS' : rdp ? 'deploy.succeededUnverifiedRDP' : 'deploy.succeededUnverified');
        extra = d.verified === 'local' ? t('deploy.verifiedLocally') : d.verified === 'skipped' ? t('deploy.verifySkipped') : '';
        if (checked && untrustedSuccess(d) && trust) {
          // R51: served, but the chain is not trusted: a warning that names the fault, never "verified".
          color = 'yellow';
          headline = t(trust.error === 'name_mismatch' ? 'deploy.succeededNameMismatch' : 'deploy.succeededUntrusted');
          extra = t('deploy.trustFault', { reason: t(trustErrorKey(trust.error)), port: trust.port ?? '' });
        } else if (checked && trust?.status === 'trusted') {
          extra = [extra, t('deploy.trusted')].filter(Boolean).join(' ');
        } else if (checked && trust?.status === 'unchecked') {
          extra = [extra, t('deploy.trustUnchecked')].filter(Boolean).join(' ');
        }
        break;
      }
      case 'unchanged':
        color = 'gray';
        headline = t('deploy.unchanged');
        break;
      case 'failed':
        // A cancelled deployment sent nothing: a decision, not a failure of the server.
        color = isCancelled(d) ? 'gray' : 'red';
        headline = t(d.error?.reason === SERVER_OPERATION_PENDING ? place('deploy.serverOperationPending', 'deploy.serverOperationPendingWindows', 'deploy.serverOperationPendingRDP') : 'deploy.noChange');
        break;
      case 'rolled_back':
        color = 'orange';
        headline = t(d.error?.reason === PENDING_CHANGE_RESTORED ? place('deploy.pendingChangeRestored', 'deploy.pendingChangeRestoredWindows', 'deploy.pendingChangeRestoredRDP') : 'deploy.rolledBack');
        break;
      default:
        // rollback_failed: the headline follows the phase, so it never contradicts the cause. With
        // the files back (phase restored) only the check of the website is missing; an undo the rollback
        // guard refused (R48) put nothing back on purpose.
        color = 'red';
        headline = t(
          rollbackForbidden(d)
            ? 'deploy.rollbackForbidden'
            : d.phase === 'restored'
              ? place('deploy.rollbackFailedRestored', 'deploy.rollbackFailedRestoredWindows', 'deploy.rollbackFailedRestoredRDP')
              : place('deploy.rollbackFailed', 'deploy.rollbackFailed', 'deploy.rollbackFailedRDP'),
        );
    }
  } else if (view === 'observing') {
    // R65: the new certificate is in place and verified; the canary observes it before the other websites follow.
    color = 'blue';
    headline = t('canary.observing');
    const c = (d as DeploymentDetail).canary;
    if (c && c.rounds > 0) {
      extra = t('canary.roundSummary', { rounds: c.rounds, passes: c.passes, result: t(`canary.result.${c.last_result || 'none'}`) });
    }
  } else if (view === 'held') {
    color = 'yellow';
    headline = t('deploy.held');
  } else if (view === 'recovering') {
    color = 'orange';
    headline = t('deploy.recovering');
  } else if (view === 'finishing') {
    color = 'blue';
    headline = t('deploy.finishing');
  } else if (view === 'stopped') {
    color = 'yellow';
    headline = t('deploy.jobStopped');
  } else if (view === 'unknown') {
    color = 'gray';
    headline = t('deploy.unknownStatus');
  } else {
    return null;
  }
  return (
    <Stack gap="xs">
      <Alert color={color} role="status" icon={<Icon name={OUTCOME_ICON[toneOf(color)]} size={17} />}>
        <Text size="sm" fw={500}>
          {headline}
        </Text>
        {extra && <Text size="sm">{extra}</Text>}
        {view === 'recovering' && d.recover_after && (
          <Text size="sm">{t('deployments.recovery.next', { time: formatDateTime(d.recover_after, i18n.language) })}</Text>
        )}
      </Alert>
      {d.status !== 'succeeded' && <DeploymentErrorAlert error={d.error} neutral={isCancelled(d)} windows={windows} rdp={rdp} />}
      {d.verify_failed && d.status !== 'succeeded' && (
        <DeploymentErrorAlert error={d.verify_failed} heading={t('deployments.verifyFailedTitle')} withCause={false} windows={windows} rdp={rdp} />
      )}
    </Stack>
  );
}
