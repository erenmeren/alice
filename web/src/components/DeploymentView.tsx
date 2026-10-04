import { Alert, Badge, Stack, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { deploymentStatusText, deploymentView, isCancelled, PENDING_CHANGE_RESTORED, SERVER_OPERATION_PENDING } from '../api/deployments';
import type { Deployment, ErrorRef } from '../api/types';
import { formatDateTime } from '../datetime';
import { LabelledCode } from './LabelledCode';
import { WRAP } from './wrap';

const COLORS: Record<string, string> = {
  pending: 'blue',
  running: 'blue',
  succeeded: 'green',
  unchanged: 'gray',
  failed: 'red',
  rolled_back: 'orange',
  rollback_failed: 'red',
  needs_attention: 'orange',
};

// DeploymentStatusBadge is the deployment's status in words (a colour is only a cue). A status this
// version does not know, or '', reads "Unknown".
export function DeploymentStatusBadge({ d, testId }: { d: Pick<Deployment, 'status' | 'error'>; testId?: string }) {
  const { t } = useTranslation();
  const cancelled = isCancelled(d);
  return (
    // tt="none": no CSS upper-casing of translated text (Turkish dotted/dotless i).
    <Badge
      variant="light"
      color={cancelled ? 'gray' : (COLORS[d.status] ?? 'gray')}
      tt="none"
      data-status={d.status}
      data-cancelled={cancelled ? 'true' : undefined}
      data-testid={testId}
    >
      {t(deploymentStatusText(d))}
    </Badge>
  );
}

const UNRESOLVED = /\{\{\s*\w+\s*\}\}/;

// DeploymentErrorAlert shows an ErrorRef of a deployment (error or verify_failed). The server gives
// {code, reason, params} without a message key, so the texts are errors.<reason>.title|cause|action
// of the shared catalogue; a reason without text, or a text whose parameters the server did not
// give, shows the generic message. The code is detail below the texts. An operation id (the
// unfinished earlier change on the server that ALC-DEP-0023/0024 name) is shown as data, because the
// action tells the operator to use it. neutral: a decision, not a failure (a cancelled deployment).
export function DeploymentErrorAlert({
  error,
  heading,
  withCause = true,
  neutral = false,
}: {
  error: ErrorRef | null;
  heading?: string;
  withCause?: boolean;
  neutral?: boolean;
}) {
  const { t, i18n } = useTranslation();
  if (!error) return null;
  const params = error.params ?? {};
  const text = (part: 'title' | 'cause' | 'action'): string => {
    const key = `errors.${error.reason}.${part}`;
    if (!i18n.exists(key)) return '';
    const out = t(key, params);
    return UNRESOLVED.test(out) ? '' : out;
  };
  const title = text('title') || t('ui.unexpectedError');
  const cause = withCause ? text('cause') : '';
  const action = text('action');
  const operation = params.operation_id ?? '';
  return (
    <Alert color={neutral ? 'gray' : 'red'} role={neutral ? 'status' : 'alert'} title={title} data-reason={error.reason}>
      <Stack gap={4}>
        {heading && (
          <Text size="xs" c="gray.7">
            {heading}
          </Text>
        )}
        {cause && <Text size="sm">{cause}</Text>}
        {action && <Text size="sm">{action}</Text>}
        {operation && <LabelledCode text={t('deployments.operation', { id: '' })} value={operation} />}
        {error.code && (
          <Text size="xs" c="gray.7" style={WRAP}>
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
  let color: string;
  let headline: string;
  let extra = '';
  if (view === 'final') {
    switch (d.status) {
      case 'succeeded':
        color = d.verified === 'remote' || d.verified === 'local' ? 'green' : 'yellow';
        headline = t(d.verified === 'remote' || d.verified === 'local' ? 'deploy.succeeded' : 'deploy.succeededUnverified');
        extra = d.verified === 'local' ? t('deploy.verifiedLocally') : d.verified === 'skipped' ? t('deploy.verifySkipped') : '';
        break;
      case 'unchanged':
        color = 'gray';
        headline = t('deploy.unchanged');
        break;
      case 'failed':
        // A cancelled deployment sent nothing: a decision, not a failure of the server.
        color = isCancelled(d) ? 'gray' : 'red';
        headline = t(d.error?.reason === SERVER_OPERATION_PENDING ? 'deploy.serverOperationPending' : 'deploy.noChange');
        break;
      case 'rolled_back':
        color = 'orange';
        headline = t(d.error?.reason === PENDING_CHANGE_RESTORED ? 'deploy.pendingChangeRestored' : 'deploy.rolledBack');
        break;
      default:
        // rollback_failed: the headline follows the phase, so it never contradicts the cause. With
        // the files back (phase restored) only the check of the website is missing.
        color = 'red';
        headline = t(d.phase === 'restored' ? 'deploy.rollbackFailedRestored' : 'deploy.rollbackFailed');
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
      <Alert color={color} role="status">
        <Text size="sm" fw={500}>
          {headline}
        </Text>
        {extra && <Text size="sm">{extra}</Text>}
        {view === 'recovering' && d.recover_after && (
          <Text size="sm">{t('deployments.recovery.next', { time: formatDateTime(d.recover_after, i18n.language) })}</Text>
        )}
      </Alert>
      {d.status !== 'succeeded' && <DeploymentErrorAlert error={d.error} neutral={isCancelled(d)} />}
      {d.verify_failed && d.status !== 'succeeded' && <DeploymentErrorAlert error={d.verify_failed} heading={t('deployments.verifyFailedTitle')} withCause={false} />}
    </Stack>
  );
}
