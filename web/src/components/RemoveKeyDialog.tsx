import { Button, Checkbox, Code, Group, Loader, Stack, Text } from '@mantine/core';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../api/client';
import { removeKeyLocation } from '../api/endpoints';
import { isAbort, JobTimeoutError, waitForJob } from '../api/jobs';
import { useAbort } from '../api/useAbort';
import type { JobError, KeyLocation } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { BlockedJobAlert, JobErrorAlert, StillWorkingAlert } from './JobErrorAlert';
import { WRAP } from './wrap';

// RemoveKeyDialog removes one key from one authorized_keys file through the sshkey.remove job.
// The server refuses Alice's own key (409 sshkey.own_key_protected, F-36) and, unless an
// Administrator confirms, the last key of root (sshkey.last_root_key); both are explained here.
export function RemoveKeyDialog({ location, onClose, onDone }: { location: KeyLocation; onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation();
  const { session } = useAuth();
  const admin = session?.user.role === 'admin';
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [jobError, setJobError] = useState<JobError | null>(null);
  const [needsRootConfirm, setNeedsRootConfirm] = useState(false);
  const [rootConfirmed, setRootConfirmed] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const abort = useAbort();

  const submit = async () => {
    setBusy(true);
    setError(null);
    setJobError(null);
    setBlocked(false);
    try {
      const accepted = await removeKeyLocation(location.id, needsRootConfirm && rootConfirmed);
      const job = await waitForJob(accepted.job_id, { signal: abort.signal() });
      if (job.status === 'succeeded') {
        onDone();
        return;
      }
      if (job.status === 'blocked_license') setBlocked(true);
      setJobError(job.error);
    } catch (e) {
      if (isAbort(e)) {
        setBusy(false);
        return;
      }
      if (isApiError(e, 'sshkey.last_root_key') && admin) setNeedsRootConfirm(true);
      setError(e);
    }
    setBusy(false);
  };

  return (
    <AppModal opened onClose={onClose} title={t('sshKeys.removeTitle')}>
      <Stack gap="sm">
        <Text size="sm">{t('sshKeys.removeHelp', { file: location.file_path })}</Text>
        <Text size="sm">{t('sshKeys.removeUser', { user: location.os_user })}</Text>
        <Text size="sm" fw={600}>
          {t('sshKeys.fingerprintLabel')}
        </Text>
        <Code block style={WRAP}>
          {location.fingerprint}
        </Code>
        {busy && (
          <Group gap="sm" role="status" aria-live="polite">
            <Loader size="sm" aria-hidden />
            <Text size="sm">{t('sshKeys.removeQueued')}</Text>
          </Group>
        )}
        {needsRootConfirm && (
          <Checkbox label={t('sshKeys.confirmLastRootKey')} checked={rootConfirmed} onChange={(e) => setRootConfirmed(e.currentTarget.checked)} />
        )}
        {error instanceof JobTimeoutError ? <StillWorkingAlert /> : <ErrorAlert error={error} />}
        {blocked && <BlockedJobAlert />}
        <JobErrorAlert error={jobError} />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            {t('sshKeys.removeCancel')}
          </Button>
          {/* red 9: white text 5.4:1 (WCAG AA). */}
          <Button color="red.9" loading={busy} disabled={needsRootConfirm && !rootConfirmed} onClick={() => void submit()}>
            {t('sshKeys.removeConfirm')}
          </Button>
        </Group>
      </Stack>
    </AppModal>
  );
}
