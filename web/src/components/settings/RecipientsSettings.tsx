import { Button, Checkbox, Group, NativeSelect, Stack, TextInput } from '@mantine/core';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { getRecipients, saveRecipients, type Locale, type Recipients } from '../../api/settings';
import { LANGUAGES } from '../../i18n';
import { ErrorAlert } from '../ErrorAlert';
import { LoadingIndicator } from '../LoadingIndicator';
import { SavedNote } from './SavedNote';
import { useChange, useSetting } from './useSetting';

const MAX_ADDRESSES = 20;

export function RecipientsSettings() {
  const q = useSetting('recipients', getRecipients);
  if (q.isPending) return <LoadingIndicator />;
  if (q.isError) return <ErrorAlert error={q.error} />;
  return <RecipientsPanel settings={q.data} />;
}

function RecipientsPanel({ settings }: { settings: Recipients }) {
  const save = useChange('recipients', settings.version, saveRecipients);
  return (
    <Stack gap="sm">
      <RecipientsForm key={settings.version} settings={settings} busy={save.isPending} onSave={(b) => save.mutate(b)} />
      <SavedNote show={save.isSuccess} />
      <ErrorAlert error={save.error} />
    </Stack>
  );
}

function RecipientsForm({ settings, busy, onSave }: { settings: Recipients; busy: boolean; onSave: (b: Pick<Recipients, 'administrators' | 'addresses'>) => void }) {
  const { t } = useTranslation();
  const [administrators, setAdministrators] = useState(settings.administrators);
  const [rows, setRows] = useState(settings.addresses);
  const change = (i: number, patch: Partial<Recipients['addresses'][number]>) => setRows((r) => r.map((x, j) => (j === i ? { ...x, ...patch } : x)));
  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    onSave({ administrators, addresses: rows.map((r) => ({ email: r.email.trim(), locale: r.locale })) });
  };
  return (
    <form onSubmit={submit}>
      <Stack gap="sm" maw={560}>
        <Checkbox label={t('settings.recipients.administrators')} checked={administrators} onChange={(e) => setAdministrators(e.currentTarget.checked)} />
        <fieldset style={{ border: 0, padding: 0, margin: 0 }}>
          <legend style={{ fontWeight: 600, padding: 0, marginBottom: 8 }}>{t('settings.recipients.addresses')}</legend>
          <Stack gap="xs">
            {rows.map((r, i) => (
              // The rows have no identity of their own; the position is the key and the fields are controlled.
              <Group key={i} align="flex-end" wrap="nowrap">
                <TextInput
                  style={{ flex: 1 }}
                  aria-label={t('settings.recipients.email', { n: i + 1 })}
                  type="email"
                  value={r.email}
                  onChange={(e) => change(i, { email: e.currentTarget.value })}
                  autoComplete="off"
                />
                <NativeSelect
                  aria-label={t('settings.recipients.language', { n: i + 1 })}
                  value={r.locale}
                  onChange={(e) => change(i, { locale: e.currentTarget.value as Locale })}
                  data={LANGUAGES.map((l) => ({ value: l.code, label: l.name }))}
                />
                <Button variant="default" onClick={() => setRows((x) => x.filter((_, j) => j !== i))} aria-label={t('settings.recipients.remove', { n: i + 1 })}>
                  <span aria-hidden>×</span>
                </Button>
              </Group>
            ))}
          </Stack>
        </fieldset>
        <Group>
          <Button variant="default" disabled={rows.length >= MAX_ADDRESSES} onClick={() => setRows((x) => [...x, { email: '', locale: 'en' }])}>
            {t('settings.recipients.add')}
          </Button>
          <Button type="submit" loading={busy}>
            {t('settings.recipients.save')}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
