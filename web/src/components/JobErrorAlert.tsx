import { Alert, Text } from '@mantine/core';
import type { i18n as I18n, TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import type { JobError } from '../api/types';
import { withRoleCode } from './CodeText';

// reasonTitle is the one-line text of a stable error reason (errors.<reason>.title); an unknown
// reason gets the generic message, never the raw reason.
export function reasonTitle(t: TFunction, i18n: I18n, reason: string, params: Record<string, string> = {}): string {
  const key = `errors.${reason}.title`;
  return i18n.exists(key) ? t(key, params) : t('ui.unexpectedError');
}

// StillWorkingAlert: the screen stopped waiting for a job that has not finished.
// textKey says where to look: the servers' text names the server's page; a vault screen passes its own.
export function StillWorkingAlert({ textKey = 'targets.stillWorking' }: { textKey?: string }) {
  const { t } = useTranslation();
  return (
    <Alert color="yellow" role="status">
      {t(textKey)}
    </Alert>
  );
}

// BlockedJobAlert: the license paused the job; an Administrator runs or discards it (R29).
export function BlockedJobAlert() {
  const { t } = useTranslation();
  return (
    <Alert color="yellow" role="status" title={t('enum.jobStatus.blocked_license')}>
      {t('jobs.blockedNotice')}
    </Alert>
  );
}

// StoppedJobAlert: the job ended (cancelled or given up) without an error of its own to show.
export function StoppedJobAlert() {
  const { t } = useTranslation();
  return (
    <Alert color="yellow" role="status">
      {t('jobs.stopped')}
    </Alert>
  );
}

// JobErrorAlert shows why a background job failed: what happened, what to do, and the code.
export function JobErrorAlert({ error }: { error: JobError | null }) {
  const { t, i18n } = useTranslation();
  if (!error) return null;
  const params = error.params ?? {};
  const actionKey = `errors.${error.reason}.action`;
  return (
    <Alert color="red" role="alert" title={withRoleCode(reasonTitle(t, i18n, error.reason, params), params.role)}>
      {i18n.exists(actionKey) && <Text size="sm">{withRoleCode(t(actionKey, params), params.role)}</Text>}
      {error.code && (
        <Text size="xs" c="dimmed" mt="xs" translate="no">
          {t('jobs.errorCode', { code: error.code })}
        </Text>
      )}
    </Alert>
  );
}
