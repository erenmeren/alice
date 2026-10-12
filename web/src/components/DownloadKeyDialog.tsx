import { Alert, Button, Checkbox, PasswordInput, Stack, Textarea } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { sshKey } from '../api/queryKeys';
import { downloadPrivateKey } from '../api/sshkeys';
import { Icon } from '../design/Icon';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { fieldErrorsOf } from './fieldErrors';
import { keyFileName, saveBlob } from './saveBlob';
import { useStepUp } from './StepUpProvider';
import { DialogActions } from './ui';

const MIN_REASON = 10;
const MIN_PASSPHRASE = 12;

type Local = { reason?: string; passphrase?: string; repeat?: string };

// Mirrors inventory.ValidateReason: the length counts code points (an emoji is one, as on the server), and a
// control, invisible format or bidi character (a line break included) or a PEM marker is refused. Checked
// before the passphrases are wiped, so a reason the server would refuse never costs them.
const FORBIDDEN_IN_REASON = /[\p{Cc}\p{Cf}\p{Bidi_Control}]/u;
const PEM_MARKER = '-----BEGIN';

export function reasonProblem(reason: string): 'short' | 'pattern' | null {
  if ([...reason].length < MIN_REASON) return 'short';
  if (reason.includes(PEM_MARKER) || FORBIDDEN_IN_REASON.test(reason)) return 'pattern';
  return null;
}

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
    const problem = reasonProblem(reason.trim());
    if (problem === 'short') found.reason = t('sshKeys.downloadReasonShort');
    else if (problem === 'pattern') found.reason = t('validation.pattern');
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
        <DialogActions>
          <Button onClick={leave}>{t('ui.close')}</Button>
        </DialogActions>
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
      </Stack>
      <DialogActions>
        <Button variant="default" onClick={leave}>
          {t('ui.cancel')}
        </Button>
        <Button type="submit" leftSection={<Icon name="Download" size={15} />} loading={busy}>
          {t('sshKeys.downloadSubmit')}
        </Button>
      </DialogActions>
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
