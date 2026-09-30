import { Button, Stack, Text, TextInput, Title } from '@mantine/core';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { startSetupSession } from '../../api/endpoints';
import { isGone } from './gone';
import { ErrorAlert } from '../../components/ErrorAlert';

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
        <Title order={2}>{t('setup.code.title')}</Title>
        <Text>{t('setup.code.help')}</Text>
        <ErrorAlert error={error} />
        <TextInput
          label={t('setup.code.label')}
          value={code}
          onChange={(e) => setCode(e.currentTarget.value)}
          autoComplete="off"
          spellCheck={false}
        />
        <Text size="sm" c="gray.7">
          {t('setup.code.lost')}
        </Text>
        <Button type="submit" loading={busy}>
          {t('ui.continue')}
        </Button>
      </Stack>
    </form>
  );
}
