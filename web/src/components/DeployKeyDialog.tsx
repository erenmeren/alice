import { Alert, Button, Checkbox, Group, Loader, NativeSelect, Stack, Text, TextInput } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { listAllTargets } from '../api/endpoints';
import { isAbort, JobTimeoutError, waitForJob } from '../api/jobs';
import { keyFiles, sshKey, SSH_KEYS_KEY, TARGETS_KEY } from '../api/queryKeys';
import { deployKey, getKeyFiles } from '../api/sshkeys';
import { isServerType } from '../api/webServer';
import type { JobError, Target } from '../api/types';
import { useAbort } from '../api/useAbort';
import { Icon } from '../design/Icon';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { ReasonAlert, noteText } from './rotationText';
import { fieldErrorsOf } from './fieldErrors';
import { DialogActions } from './ui';
import { BlockedJobAlert, JobErrorAlert, StillWorkingAlert, StoppedJobAlert } from './JobErrorAlert';

// isDeployable: a Linux or Nginx server Alice can sign in to and may change: the host key is confirmed and has not changed,
// and the server is not disabled (the server refuses those, so the screen does not offer them).
const UNUSABLE: ReadonlySet<Target['status']> = new Set<Target['status']>(['pending_host_key', 'host_key_changed', 'disabled']);
const isDeployable = (tg: Target) => isServerType(tg.type) && !UNUSABLE.has(tg.status);

// TONE: how an outcome is shown. Only a verified login or an already present key is a plain success; an unverified add or
// an undone one needs the operator's eye, and a key that did not work and could not be removed is an error.
const TONE: Record<string, string> = { verified: 'green', already_present: 'green', unverified: 'yellow', undone: 'yellow', failed: 'red', undo_failed: 'red' };

interface UserFiles {
  os_user: string;
  files: string[];
  default_file: string;
}

// offered drops what the server must never be asked to change (S7): the connection account's own entry, and any file
// that account's entry lists, wherever else it appears. The server enforces the same; the screen does not offer it.
function offered(items: UserFiles[], connectionUser: string): UserFiles[] {
  const own = new Set(items.filter((i) => i.os_user === connectionUser).flatMap((i) => i.files));
  return items
    .filter((i) => i.os_user !== connectionUser)
    .map((i) => {
      const files = i.files.filter((f) => !own.has(f));
      return { ...i, files, default_file: files.includes(i.default_file) ? i.default_file : (files[0] ?? '') };
    })
    .filter((i) => i.files.length > 0);
}

function DeployForm({ keyId, onClose }: { keyId: string; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const abort = useAbort();
  const [pickedServer, setPickedServer] = useState('');
  const [pickedUser, setPickedUser] = useState('');
  const [pickedFile, setPickedFile] = useState('');
  const [from, setFrom] = useState('');
  const [restrict, setRestrict] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [jobError, setJobError] = useState<JobError | null>(null);
  const [blocked, setBlocked] = useState(false);
  const [stopped, setStopped] = useState(false);
  const [result, setResult] = useState<{ key: string; tone: string; note: string } | null>(null);
  const [outcomeKey, setOutcomeKey] = useState('');
  const [outcomeNote, setOutcomeNote] = useState('');

  const targets = useQuery({
    queryKey: [...TARGETS_KEY, 'deploy-servers'],
    queryFn: async () => (await listAllTargets()).items.filter(isDeployable),
  });
  const servers = targets.data ?? [];
  const server = servers.find((s) => s.id === pickedServer) ?? servers[0];
  const files = useQuery({
    queryKey: keyFiles(server?.id ?? ''),
    queryFn: () => getKeyFiles(server?.id ?? ''),
    enabled: !!server,
  });
  const users = server ? offered(files.data?.items ?? [], server.username) : [];
  const user = users.find((u) => u.os_user === pickedUser) ?? users[0];
  const file = user?.files.find((f) => f === pickedFile) ?? user?.default_file ?? '';
  const fieldErrors = fieldErrorsOf(error, t, i18n);
  const ready = !!server && !!user && file !== '';

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    setJobError(null);
    setBlocked(false);
    setStopped(false);
    setOutcomeKey('');
    try {
      const fromText = from.trim();
      const accepted = await deployKey(keyId, {
        target_id: server.id,
        os_user: user.os_user,
        file_path: file,
        ...(fromText !== '' && { from: fromText }),
        ...(restrict && { restrict: true }),
      });
      const job = await waitForJob(accepted.job_id, { signal: abort.signal() });
      const outcome = typeof job.result.result === 'string' ? job.result.result : '';
      void client.invalidateQueries({ queryKey: sshKey(keyId) });
      void client.invalidateQueries({ queryKey: SSH_KEYS_KEY });
      void client.invalidateQueries({ queryKey: TARGETS_KEY });
      const known = i18n.exists(`sshKeys.deployResult.${outcome}`);
      if (job.status === 'succeeded') {
        const note = typeof job.result.note === 'string' ? noteText(t, i18n, job.result.note) : '';
        setResult(known ? { key: `sshKeys.deployResult.${outcome}`, tone: TONE[outcome] ?? 'yellow', note } : { key: 'ui.unexpectedError', tone: 'yellow', note });
      } else {
        // A failed job still says what became of the key (undone, or still on the server).
        setOutcomeKey(known ? outcome : '');
        setOutcomeNote(typeof job.result.note === 'string' ? noteText(t, i18n, job.result.note) : '');
        if (job.status === 'blocked_license') setBlocked(true);
        else if (!job.error) setStopped(true);
        setJobError(job.error);
      }
    } catch (e) {
      if (!isAbort(e)) setError(e);
    }
    setBusy(false);
  };

  if (result)
    return (
      <Stack gap="sm">
        <Alert color={result.tone} role="status">
          {t(result.key)}
          {result.note !== '' && <Text size="sm">{result.note}</Text>}
        </Alert>
        <DialogActions>
          <Button onClick={onClose}>{t('ui.close')}</Button>
        </DialogActions>
      </Stack>
    );

  return (
    <form onSubmit={(e) => void submit(e)} noValidate>
      <Stack gap="sm">
        {targets.isSuccess && servers.length === 0 && <Text size="sm">{t('sshKeys.deployNoServers')}</Text>}
        <ErrorAlert error={targets.error ?? files.error} />
        {!!server && files.isPending && (
          <Group gap="sm" role="status" aria-live="polite">
            <Loader size="sm" aria-hidden />
            <Text size="sm">{t('ui.loading')}</Text>
          </Group>
        )}
        <NativeSelect
          data-autofocus
          label={t('sshKeys.deployServer')}
          value={server?.id ?? ''}
          onChange={(e) => {
            setPickedServer(e.currentTarget.value);
            setPickedUser('');
            setPickedFile('');
          }}
          data={servers.map((s) => ({ value: s.id, label: s.name }))}
          disabled={busy}
        />
        <NativeSelect
          label={t('sshKeys.deployUser')}
          value={user?.os_user ?? ''}
          onChange={(e) => {
            setPickedUser(e.currentTarget.value);
            setPickedFile('');
          }}
          data={users.map((u) => ({ value: u.os_user, label: u.os_user }))}
          error={fieldErrors.os_user}
          translate="no"
          disabled={busy}
        />
        <NativeSelect
          label={t('sshKeys.deployFile')}
          value={file}
          onChange={(e) => setPickedFile(e.currentTarget.value)}
          data={(user?.files ?? []).map((f) => ({ value: f, label: f }))}
          error={fieldErrors.file_path}
          translate="no"
          disabled={busy}
          styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
        />
        {server && files.isSuccess && files.data.refusal && <ReasonAlert error={files.data.refusal} color="yellow" />}
        {server && files.isSuccess && !files.data.refusal && !user && <Text size="sm">{t('sshKeys.deployNoFiles')}</Text>}
        <TextInput
          label={t('sshKeys.deployFrom')}
          description={t('sshKeys.deployFromHelp')}
          value={from}
          onChange={(e) => setFrom(e.currentTarget.value)}
          error={fieldErrors.from}
          maxLength={500}
          autoComplete="off"
          spellCheck={false}
          disabled={busy}
        />
        <Checkbox label={t('sshKeys.deployRestrict')} checked={restrict} onChange={(e) => setRestrict(e.currentTarget.checked)} disabled={busy} />
        {busy && (
          <Group gap="sm" role="status" aria-live="polite">
            <Loader size="sm" aria-hidden />
            <Text size="sm">{t('sshKeys.deployQueued')}</Text>
          </Group>
        )}
        {error instanceof JobTimeoutError ? <StillWorkingAlert /> : <ErrorAlert error={error} />}
        {blocked && <BlockedJobAlert />}
        {stopped && <StoppedJobAlert />}
        {outcomeKey !== '' && (
          // A job that failed is never shown as a success, whatever its result says.
          <Alert color={TONE[outcomeKey] === 'red' ? 'red' : 'yellow'} role="status">
            {t(`sshKeys.deployResult.${outcomeKey}`)}
            {outcomeNote !== '' && <Text size="sm">{outcomeNote}</Text>}
          </Alert>
        )}
        <JobErrorAlert error={jobError} />
      </Stack>
      <DialogActions>
        <Button variant="default" onClick={onClose}>
          {t('ui.cancel')}
        </Button>
        <Button type="submit" leftSection={<Icon name="Rocket" size={15} />} loading={busy} disabled={!ready}>
          {t('sshKeys.deploySubmit')}
        </Button>
      </DialogActions>
    </form>
  );
}

// DeployKeyDialog deploys a generated key to one file of one user on one server through the sshkey.add job, then reports
// what the job found (verified, unverified, already present, undone, failed). The options are the two the server accepts:
// from= and restrict. The form is rendered only while the dialog is open.
export function DeployKeyDialog({ keyId, opened, onClose }: { keyId: string; opened: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <AppModal opened={opened} onClose={onClose} title={t('sshKeys.deployTitle')} size="lg">
      {opened && <DeployForm keyId={keyId} onClose={onClose} />}
    </AppModal>
  );
}
