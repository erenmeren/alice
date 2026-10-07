import { Button, Group, NumberInput, Stack, TextInput } from '@mantine/core';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { getGeneral, saveGeneral, type GeneralSettings as General } from '../../api/settings';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { LoadingIndicator } from '../LoadingIndicator';
import { SavedNote } from './SavedNote';
import { useChange, useSetting } from './useSetting';

export function GeneralSettings() {
  const q = useSetting('general', getGeneral);
  if (q.isPending) return <LoadingIndicator />;
  if (q.isError) return <ErrorAlert error={q.error} />;
  return <GeneralPanel settings={q.data} />;
}

function GeneralPanel({ settings }: { settings: General }) {
  const { t, i18n } = useTranslation();
  const save = useChange('general', settings.version, saveGeneral);
  return (
    <Stack gap="sm">
      <GeneralForm key={settings.version} settings={settings} busy={save.isPending} onSave={(b) => save.mutate(b)} fieldErrors={fieldErrorsOf(save.error, t, i18n)} />
      <SavedNote show={save.isSuccess} />
      <ErrorAlert error={save.error} />
    </Stack>
  );
}

function GeneralForm({ settings, busy, onSave, fieldErrors }: { settings: General; busy: boolean; onSave: (b: Omit<General, 'version'>) => void; fieldErrors: Record<string, string> }) {
  const { t } = useTranslation();
  // When no address is set yet, the address this page was opened at is the likely answer.
  const [publicUrl, setPublicUrl] = useState(settings.public_url || window.location.origin);
  const [days, setDays] = useState<number | string>(settings.retired_key_retention_days);
  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    onSave({ public_url: publicUrl.trim(), retired_key_retention_days: Number(days) });
  };
  return (
    <form onSubmit={submit}>
      <Stack gap="sm" maw={560}>
        <TextInput
          label={t('settings.general.publicUrl')}
          description={t('settings.general.publicUrlHelp')}
          type="url"
          value={publicUrl}
          onChange={(e) => setPublicUrl(e.currentTarget.value)}
          error={fieldErrors.public_url}
          autoComplete="off"
        />
        <NumberInput label={t('settings.general.retention')} value={days} onChange={setDays} min={1} max={3650} allowDecimal={false} error={fieldErrors.retired_key_retention_days} />
        <Group>
          <Button type="submit" loading={busy}>
            {t('settings.general.save')}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
