import { Alert, Button, Checkbox, PasswordInput, Progress, Stack, Text } from '@mantine/core';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { setRecoveryPassphrase } from '../../api/endpoints';
import { isGone } from './gone';
import { ErrorAlert } from '../../components/ErrorAlert';
import { useStepUp } from '../../components/StepUpProvider';
import { Icon } from '../../design/Icon';
import { StepActions, StepHeading } from './SetupShell';
import classes from './setup.module.css';
import { passphraseStrength, type Strength } from './strength';

// The meter's colors are the design's semantic tokens (the word under the meter carries the meaning).
const METER: Record<Strength, { value: number; color: string }> = {
  tooShort: { value: 10, color: 'var(--alice-danger)' },
  fair: { value: 40, color: 'var(--alice-warning)' },
  good: { value: 70, color: 'var(--alice-brand)' },
  strong: { value: 100, color: 'var(--alice-success)' },
};

// PassphraseStep sets the recovery passphrase. The server refuses what passphraseStrength rates tooShort or fair
// (R43 row 17), so the button follows the same rule. Once set it cannot be changed here: Back shows it as done.
export function PassphraseStep({ onDone, onGone, done = false }: { onDone: () => void; onGone: () => void; done?: boolean }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const [passphrase, setPassphrase] = useState('');
  const [repeat, setRepeat] = useState('');
  const [stored, setStored] = useState(false);
  const [mismatch, setMismatch] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const strength = passphraseStrength(passphrase);
  const acceptable = strength === 'good' || strength === 'strong';

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

  if (done) {
    return (
      <Stack>
        <StepHeading title={t('setup.passphrase.title')} />
        <Text>{t('setup.passphrase.doneState')}</Text>
        <StepActions>
          <Button onClick={onDone} rightSection={<Icon name="ArrowRight" size={15} />}>
            {t('ui.continue')}
          </Button>
        </StepActions>
      </Stack>
    );
  }

  return (
    <form onSubmit={submit}>
      <Stack>
        <StepHeading title={t('setup.passphrase.title')} />
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
        {strength === 'fair' && (
          <Text size="sm" c="var(--alice-danger)" id="passphrase-too-weak">
            {t('setup.passphrase.tooWeak')}
          </Text>
        )}
        <PasswordInput
          label={t('setup.passphrase.repeat')}
          value={repeat}
          onChange={(e) => setRepeat(e.currentTarget.value)}
          autoComplete="new-password"
        />
        <Checkbox
          className={classes.checkOption}
          label={t('setup.passphrase.stored')}
          checked={stored}
          onChange={(e) => setStored(e.currentTarget.checked)}
        />
        <StepActions>
          <Button type="submit" loading={busy} disabled={!stored || !acceptable}>
            {t('setup.passphrase.save')}
          </Button>
        </StepActions>
      </Stack>
    </form>
  );
}
