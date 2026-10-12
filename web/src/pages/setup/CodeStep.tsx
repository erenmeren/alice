import { Button, Stack, TextInput } from '@mantine/core';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { startSetupSession } from '../../api/endpoints';
import { isGone } from './gone';
import { ErrorAlert } from '../../components/ErrorAlert';
import { Icon } from '../../design/Icon';
import { StepActions, StepHeading } from './SetupShell';
import classes from './setup.module.css';

export function CodeStep({ onDone, onGone }: { onDone: () => void; onGone: () => void }) {
  const { t } = useTranslation();
  const [code, setCode] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await startSetupSession(code.trim());
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
        <StepHeading title={t('setup.code.title')} intro={t('setup.code.help')} />
        <ErrorAlert error={error} />
        <TextInput
          label={t('setup.code.label')}
          value={code}
          onChange={(e) => setCode(e.currentTarget.value)}
          autoComplete="off"
          spellCheck={false}
        />
        <p className={classes.hint}>{t('setup.code.lost')}</p>
        <StepActions>
          <Button type="submit" loading={busy} rightSection={<Icon name="ArrowRight" size={15} />}>
            {t('ui.continue')}
          </Button>
        </StepActions>
      </Stack>
    </form>
  );
}
