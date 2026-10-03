import { Alert, Button, Group, Loader, NumberInput, Stack, Text, TextInput } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { confirmHostKey, createTarget, listHostKeys } from '../api/endpoints';
import { JobTimeoutError, waitForJob } from '../api/jobs';
import { TARGETS_KEY } from '../api/queryKeys';
import type { HostKey, Job, JobError, Target } from '../api/types';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { HostKeyConfirm } from './HostKeyConfirm';
import { JobErrorAlert } from './JobErrorAlert';

type Phase = 'form' | 'working' | 'confirm' | 'failed';

// AddServerModal creates a Linux server, waits for the first connection test and, when the server
// presented a fingerprint nobody confirmed yet, asks the Administrator to compare and confirm it.
// The server counts toward the license as soon as it is created (spec §7.3).
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
  const [target, setTarget] = useState<Target | null>(null);
  const [candidate, setCandidate] = useState<HostKey | null>(null);

  const refresh = () => void client.invalidateQueries({ queryKey: TARGETS_KEY });

  // settle decides what a finished connection test means for the dialog.
  const settle = async (tgt: Target, job: Job) => {
    if (job.status === 'succeeded') {
      refresh();
      onAdded(tgt);
      return;
    }
    if (job.error?.reason === 'target.host_key_unconfirmed') {
      const keys = await listHostKeys(tgt.id);
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

  const run = async (fn: () => Promise<void>, back: Phase) => {
    setError(null);
    setJobError(null);
    setPhase('working');
    try {
      await fn();
    } catch (e) {
      setError(e);
      setPhase(back);
    }
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const res = await createTarget({ name: name.trim(), type: 'linux', host: host.trim(), port: Number(port), username: username.trim() });
      setTarget(res.target);
      refresh();
      await settle(res.target, await waitForJob(res.job_id));
    }, 'form');
  };

  const confirm = () => {
    if (!target || !candidate) return;
    void run(async () => {
      const res = await confirmHostKey(target.id, candidate.id, candidate.fingerprint);
      await settle(target, await waitForJob(res.job_id));
    }, 'confirm');
  };

  const problem =
    error instanceof JobTimeoutError ? (
      <Alert color="yellow" role="status">
        {t('targets.stillWorking')}
      </Alert>
    ) : (
      <ErrorAlert error={error} />
    );

  return (
    <AppModal opened onClose={onClose} title={phase === 'confirm' ? t('hostKeys.confirmTitle') : t('targets.add')} size="lg">
      {phase === 'working' && (
        <Group gap="sm" role="status" aria-live="polite">
          <Loader size="sm" aria-hidden />
          <Text size="sm">{t('targets.connecting')}</Text>
        </Group>
      )}
      {phase === 'form' && (
        <form onSubmit={submit}>
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
          <HostKeyConfirm host={target.host} hostKey={candidate} onYes={confirm} onNo={onClose} />
          {problem}
        </Stack>
      )}
      {phase === 'failed' && (
        <Stack gap="sm">
          <JobErrorAlert error={jobError} />
          <Text size="sm">{t('targets.failedHelp')}</Text>
          <Group justify="flex-end">
            <Button onClick={onClose}>{t('ui.close')}</Button>
          </Group>
        </Stack>
      )}
    </AppModal>
  );
}
