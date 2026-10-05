import { Alert, Button, Checkbox, Group, PasswordInput, Stack, Textarea } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { sshKey } from '../api/queryKeys';
import { downloadPrivateKey } from '../api/sshkeys';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { fieldErrorsOf } from './fieldErrors';
import { keyFileName, saveBlob } from './saveBlob';
import { useStepUp } from './StepUpProvider';

const MIN_REASON = 10;
const MIN_PASSPHRASE = 12;

type Local = { reason?: string; passphrase?: string; repeat?: string };

// DownloadForm downloads the private key of a key Alice generated. The reason and the passphrase live in this component's
// state only. The passphrase fields are wiped the moment the request is built (the request body is held by the call
// alone), so they are empty after success, after any refusal and while the step-up code is asked for; leaving the dialog
// clears everything. The file is a Blob handed to the browser by saveBlob and never kept: not in state, not in the query
// cache, not in the URL, web storage or the console. It is saved even if the dialog was closed meanwhile (the server has
// already counted and audited the download).
function DownloadForm({ keyId, label, onClose }: { keyId: string; label: string; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const { run } = useStepUp();
  const [reason, setReason] = useState('');
  const [protect, setProtect] = useState(true);
  const [passphrase, setPassphrase] = useState('');
  const [repeat, setRepeat] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [local, setLocal] = useState<Local>({});
  const [done, setDone] = useState(false);
  const fieldErrors = { ...fieldErrorsOf(error, t, i18n), ...local };

  const wipePassphrases = () => {
    setPassphrase('');
    setRepeat('');
  };
  const leave = () => {
    wipePassphrases();
    setReason('');
    onClose();
  };

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    const found: Local = {};
    if (reason.trim().length < MIN_REASON) found.reason = t('sshKeys.downloadReasonShort');
    if (protect) {
      if (passphrase.length < MIN_PASSPHRASE) found.passphrase = t('sshKeys.downloadPassphraseShort');
      else if (passphrase !== repeat) found.repeat = t('sshKeys.downloadMismatch');
    }
    setLocal(found);
    if (Object.keys(found).length > 0) return;
    const body = { reason: reason.trim(), ...(protect && { passphrase }) };
    // From here the passphrase exists only in body.
    wipePassphrases();
    setBusy(true);
    setError(null);
    try {
      const blob = await run(() => downloadPrivateKey(keyId, body));
      saveBlob(blob, keyFileName(label));
      void client.invalidateQueries({ queryKey: sshKey(keyId) });
      setReason('');
      setDone(true);
    } catch (e) {
      setError(e);
    }
    setBusy(false);
  };

  if (done)
    return (
      <Stack gap="sm">
        <Alert color="green" role="status">
          {t('sshKeys.downloadDone')}
        </Alert>
        <Group justify="flex-end">
          <Button onClick={leave}>{t('ui.close')}</Button>
        </Group>
      </Stack>
    );

  return (
    <form onSubmit={(e) => void submit(e)} noValidate autoComplete="off">
      <Stack gap="sm">
        <Alert color="yellow" role="note">
          {t('sshKeys.downloadWarning')}
        </Alert>
        <Textarea
          data-autofocus
          label={t('sshKeys.downloadReason')}
          description={t('sshKeys.downloadReasonHelp')}
          value={reason}
          onChange={(e) => setReason(e.currentTarget.value)}
          error={fieldErrors.reason}
          minLength={MIN_REASON}
          maxLength={500}
          autosize
          minRows={2}
          maxRows={5}
          autoComplete="off"
          disabled={busy}
        />
        <Checkbox label={t('sshKeys.downloadProtect')} checked={protect} onChange={(e) => setProtect(e.currentTarget.checked)} disabled={busy} />
        {protect && (
          <>
            <PasswordInput
              label={t('sshKeys.downloadPassphrase')}
              description={t('sshKeys.downloadPassphraseHelp')}
              value={passphrase}
              onChange={(e) => setPassphrase(e.currentTarget.value)}
              error={fieldErrors.passphrase}
              maxLength={1024}
              autoComplete="new-password"
              data-1p-ignore
              data-lpignore="true"
              disabled={busy}
            />
            <PasswordInput
              label={t('sshKeys.downloadPassphraseRepeat')}
              value={repeat}
              onChange={(e) => setRepeat(e.currentTarget.value)}
              error={fieldErrors.repeat}
              maxLength={1024}
              autoComplete="new-password"
              data-1p-ignore
              data-lpignore="true"
              disabled={busy}
            />
          </>
        )}
        <ErrorAlert error={error} />
        <Group justify="flex-end">
          <Button variant="default" onClick={leave}>
            {t('ui.cancel')}
          </Button>
          <Button type="submit" loading={busy}>
            {t('sshKeys.downloadSubmit')}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}

// DownloadKeyDialog: the form is rendered only while the dialog is open, so closing it drops everything typed.
export function DownloadKeyDialog({ keyId, label, opened, onClose }: { keyId: string; label: string; opened: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <AppModal opened={opened} onClose={onClose} title={t('sshKeys.downloadTitle')} size="lg">
      {opened && <DownloadForm keyId={keyId} label={label} onClose={onClose} />}
    </AppModal>
  );
}
