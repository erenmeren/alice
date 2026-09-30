import { Alert, Button, Checkbox, PasswordInput, Progress, Stack, Text, Title } from '@mantine/core';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { setRecoveryPassphrase } from '../../api/endpoints';
import { isGone } from './gone';
import { ErrorAlert } from '../../components/ErrorAlert';
import { useStepUp } from '../../components/StepUpProvider';
import { passphraseStrength, type Strength } from './strength';

const METER: Record<Strength, { value: number; color: string }> = {
  tooShort: { value: 10, color: 'red' },
  fair: { value: 40, color: 'orange' },
  good: { value: 70, color: 'yellow' },
  strong: { value: 100, color: 'green' },
};

export function PassphraseStep({ onDone, onGone }: { onDone: () => void; onGone: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const [passphrase, setPassphrase] = useState('');
  const [repeat, setRepeat] = useState('');
  const [stored, setStored] = useState(false);
  const [mismatch, setMismatch] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const strength = passphraseStrength(passphrase);

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setError(null);
    setMismatch(passphrase !== repeat);
    if (passphrase !== repeat) return;
    setBusy(true);
    try {
      await run(() => setRecoveryPassphrase(passphrase, repeat));
      onDone();
    } catch (e) {
      if (isGone(e)) return onGone();
      setError(e);
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit}>
      <Stack>
        <Title order={2}>{t('setup.passphrase.title')}</Title>
        <Alert color="yellow">{t('setup.passphrase.warning')}</Alert>
        <ErrorAlert error={error} />
        {mismatch && (
          <Alert color="red" role="alert">
            {t('setup.passphrase.mismatch')}
          </Alert>
        )}
        <PasswordInput
          label={t('setup.passphrase.label')}
          description={t('setup.passphrase.help')}
          value={passphrase}
          onChange={(e) => setPassphrase(e.currentTarget.value)}
          autoComplete="new-password"
        />
        <Progress
          value={METER[strength].value}
          color={METER[strength].color}
          aria-label={t('setup.passphrase.strengthLabel')}
        />
        <Text size="sm" data-testid="passphrase-strength" aria-live="polite">
          {t(`setup.passphrase.strength.${strength}`)}
        </Text>
        <PasswordInput
          label={t('setup.passphrase.repeat')}
          value={repeat}
          onChange={(e) => setRepeat(e.currentTarget.value)}
          autoComplete="new-password"
        />
        <Checkbox
          label={t('setup.passphrase.stored')}
          checked={stored}
          onChange={(e) => setStored(e.currentTarget.checked)}
        />
        <Button type="submit" loading={busy} disabled={!stored}>
          {t('setup.passphrase.save')}
        </Button>
      </Stack>
    </form>
  );
}
