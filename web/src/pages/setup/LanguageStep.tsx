import { Button, Group, Radio, Stack, Title } from '@mantine/core';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { setSetupLanguage } from '../../api/endpoints';
import { isGone } from './gone';
import { ErrorAlert } from '../../components/ErrorAlert';
import { LANGUAGES, setLanguage, type Lang } from '../../i18n';

export function LanguageStep({ onDone, onGone }: { onDone: () => void; onGone: () => void }) {
  const { t, i18n } = useTranslation();
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await setSetupLanguage(i18n.language);
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
        <Title order={2}>{t('setup.language.title')}</Title>
        <ErrorAlert error={error} />
        <Radio.Group
          label={t('setup.language.label')}
          value={i18n.language}
          onChange={(v) => void setLanguage(i18n, v as Lang)}
        >
          <Group mt="xs">
            {LANGUAGES.map((l) => (
              <Radio key={l.code} value={l.code} label={l.name} />
            ))}
          </Group>
        </Radio.Group>
        <Button type="submit" loading={busy}>
          {t('ui.continue')}
        </Button>
      </Stack>
    </form>
  );
}
