import { Alert, Button, Radio, Stack, TextInput } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { SSH_KEYS_KEY } from '../api/queryKeys';
import { generateKey, KEY_TYPES, type KeyType } from '../api/sshkeys';
import { Icon } from '../design/Icon';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { fieldErrorsOf } from './fieldErrors';
import { DialogActions, Notice } from './ui';

function GenerateForm({ onClose, onGenerated }: { onClose: () => void; onGenerated: (id: string) => void }) {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const [label, setLabel] = useState('');
  const [keyType, setKeyType] = useState<KeyType>('ed25519');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState(false);
  const fieldErrors = fieldErrorsOf(error, t, i18n);

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    if (label.trim() === '') return;
    setBusy(true);
    setError(null);
    try {
      const res = await generateKey({ label: label.trim(), key_type: keyType });
      setDone(true);
      void client.invalidateQueries({ queryKey: SSH_KEYS_KEY });
      onGenerated(res.id);
    } catch (e) {
      setError(e);
    }
    setBusy(false);
  };

  if (done)
    return (
      <Stack gap="sm">
        <Alert color="green" role="status">
          {t('sshKeys.generated')}
        </Alert>
        <DialogActions>
          <Button onClick={onClose}>{t('ui.close')}</Button>
        </DialogActions>
      </Stack>
    );

  return (
    <form onSubmit={(e) => void submit(e)} noValidate>
      <Stack gap="sm">
        <TextInput
          data-autofocus
          label={t('sshKeys.label')}
          description={t('sshKeys.labelHelp')}
          value={label}
          onChange={(e) => setLabel(e.currentTarget.value)}
          error={fieldErrors.label}
          maxLength={100}
          autoComplete="off"
          required
        />
        <Radio.Group label={t('sshKeys.keyTypeLabel')} value={keyType} onChange={(v) => setKeyType(v as KeyType)} error={fieldErrors.key_type}>
          <Stack gap={6} mt={6}>
            {KEY_TYPES.map((k) => (
              <Radio key={k} value={k} label={t(`sshKeys.types.${k}`)} />
            ))}
          </Stack>
        </Radio.Group>
        {/* The design's note: the private key never reaches this page (only an Administrator's step-up download). */}
        <Notice tone="info" title={t('sshKeys.page.generateNoteTitle')}>
          {t('sshKeys.page.generateNoteText')}
        </Notice>
        <ErrorAlert error={error} />
      </Stack>
      <DialogActions>
        <Button variant="default" onClick={onClose}>
          {t('ui.cancel')}
        </Button>
        <Button type="submit" leftSection={<Icon name="KeyRound" size={15} />} loading={busy} disabled={label.trim() === ''}>
          {t('sshKeys.generateSubmit')}
        </Button>
      </DialogActions>
    </form>
  );
}

// GenerateKeyDialog generates a key pair in Alice (an Operator or an Administrator). The form is rendered only while the
// dialog is open, so closing it drops what was typed. onGenerated gets the new key's id (the page opens it).
export function GenerateKeyDialog({ opened, onClose, onGenerated }: { opened: boolean; onClose: () => void; onGenerated: (id: string) => void }) {
  const { t } = useTranslation();
  return (
    <AppModal opened={opened} onClose={onClose} title={t('sshKeys.generateTitle')}>
      {opened && <GenerateForm onClose={onClose} onGenerated={onGenerated} />}
    </AppModal>
  );
}
