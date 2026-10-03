import { Button, Group, Loader, NumberInput, Stack, Text, TextInput } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { confirmHostKey, createTarget, listHostKeys } from '../api/endpoints';
import { isAbort, JobTimeoutError, waitForJob } from '../api/jobs';
import { TARGETS_KEY } from '../api/queryKeys';
import type { HostKey, Job, JobError, Target } from '../api/types';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { HostKeyConfirm } from './HostKeyConfirm';
import { BlockedJobAlert, JobErrorAlert, StillWorkingAlert } from './JobErrorAlert';

// form: nothing exists yet. working: a request or a job is running. confirm: waiting for the
// Administrator's comparison. failed: the server exists but the check did not succeed (the dialog
// can only be left, never resubmitted).
type Phase = 'form' | 'working' | 'confirm' | 'failed';

// AddServerModal creates a Linux server, waits for the first connection test and, when the server
// presented a fingerprint nobody confirmed yet, asks the Administrator to compare and confirm it.
// The server counts toward the license as soon as it is created (spec §7.3), so after the create
// call succeeds the form never comes back: problems end in the "failed" phase with a way to open
// the server. Closing the dialog stops the waiting and nothing navigates afterwards.
export function AddServerModal({ onClose, onAdded }: { onClose: () => void; onAdded: (target: Target) => void }) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const [name, setName] = useState('');
  const [host, setHost] = useState('');
  const [port, setPort] = useState<number | string>(22);
  const [username, setUsername] = useState('alice-svc');
  const [phase, setPhase] = useState<Phase>('form');
  const [error, setError] = useState<unknown>(null);
  const [jobError, setJobError] = useState<JobError | null>(null);
  const [blocked, setBlocked] = useState(false);
  const [target, setTarget] = useState<Target | null>(null);
  const [candidate, setCandidate] = useState<HostKey | null>(null);
  const abort = useRef(new AbortController());

  useEffect(() => {
    const ctrl = abort.current;
    return () => ctrl.abort();
  }, []);

  const refresh = () => void client.invalidateQueries({ queryKey: TARGETS_KEY });

  // close stops all waiting. A created server shows up in the list.
  const close = () => {
    abort.current.abort();
    if (target) refresh();
    onClose();
  };
  const openServer = () => {
    abort.current.abort();
    if (target) {
      refresh();
      onAdded(target);
    }
  };

  // settle decides what a finished connection test means for the dialog.
  const settle = async (tgt: Target, job: Job) => {
    const signal = abort.current.signal;
    if (job.status === 'succeeded') {
      refresh();
      onAdded(tgt);
      return;
    }
    if (job.status === 'blocked_license') {
      setBlocked(true);
      setPhase('failed');
      return;
    }
    if (job.error?.reason === 'target.host_key_unconfirmed') {
      const keys = await listHostKeys(tgt.id);
      if (signal.aborted) return;
      const observed = keys.items.find((k) => k.status === 'observed') ?? null;
      if (observed) {
        setCandidate(observed);
        setPhase('confirm');
        return;
      }
    }
    setJobError(job.error);
    setPhase('failed');
  };

  // afterCreate runs the steps that follow a successful create call; any problem leaves the dialog
  // in the "failed" phase (or back at the confirmation), never at the form.
  const afterCreate = async (tgt: Target, back: Phase, step: () => Promise<Job>) => {
    setError(null);
    setJobError(null);
    setBlocked(false);
    setPhase('working');
    try {
      await settle(tgt, await step());
    } catch (e) {
      if (isAbort(e) || abort.current.signal.aborted) return;
      setError(e);
      refresh();
      setPhase(back);
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setPhase('working');
    let created;
    try {
      created = await createTarget({ name: name.trim(), type: 'linux', host: host.trim(), port: Number(port), username: username.trim() });
    } catch (err) {
      if (abort.current.signal.aborted) return;
      setError(err);
      setPhase('form');
      return;
    }
    if (abort.current.signal.aborted) {
      refresh();
      return;
    }
    setTarget(created.target);
    refresh();
    await afterCreate(created.target, 'failed', () => waitForJob(created.job_id, { signal: abort.current.signal }));
  };

  const confirm = () => {
    if (!target || !candidate) return;
    void afterCreate(target, 'confirm', async () => {
      const res = await confirmHostKey(target.id, candidate.id, candidate.fingerprint);
      return waitForJob(res.job_id, { signal: abort.current.signal });
    });
  };

  const problem = error instanceof JobTimeoutError ? <StillWorkingAlert /> : <ErrorAlert error={error} />;

  return (
    <AppModal opened onClose={close} title={phase === 'confirm' ? t('hostKeys.confirmTitle') : t('targets.add')} size="lg">
      {phase === 'working' && (
        <Group gap="sm" role="status" aria-live="polite">
          <Loader size="sm" aria-hidden />
          <Text size="sm">{t('targets.connecting')}</Text>
        </Group>
      )}
      {phase === 'form' && (
        <form onSubmit={(e) => void submit(e)}>
          <Stack gap="sm">
            <TextInput label={t('targets.form.name')} value={name} onChange={(e) => setName(e.currentTarget.value)} required maxLength={100} data-autofocus />
            <TextInput
              label={t('targets.form.host')}
              description={t('targets.form.hostHelp')}
              value={host}
              onChange={(e) => setHost(e.currentTarget.value)}
              required
              maxLength={253}
              autoComplete="off"
            />
            <NumberInput label={t('targets.form.port')} value={port} onChange={setPort} min={1} max={65535} allowDecimal={false} required />
            <TextInput label={t('targets.form.username')} value={username} onChange={(e) => setUsername(e.currentTarget.value)} required maxLength={32} />
            {problem}
            <Button type="submit">{t('targets.form.submit')}</Button>
          </Stack>
        </form>
      )}
      {phase === 'confirm' && target && candidate && (
        <Stack gap="sm">
          <HostKeyConfirm host={target.host} hostKey={candidate} onYes={confirm} onNo={close} />
          {problem}
        </Stack>
      )}
      {phase === 'failed' && (
        <Stack gap="sm">
          {blocked && <BlockedJobAlert />}
          {error !== null && problem}
          <JobErrorAlert error={jobError} />
          {!blocked && error === null && <Text size="sm">{t('targets.failedHelp')}</Text>}
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>
              {t('ui.close')}
            </Button>
            <Button onClick={openServer}>{t('targets.openServer')}</Button>
          </Group>
        </Stack>
      )}
    </AppModal>
  );
}
