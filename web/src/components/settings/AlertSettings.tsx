import { Button, Group, NumberInput, Stack } from '@mantine/core';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { getThresholds, saveThresholds, type AlertThresholds } from '../../api/settings';
import { ErrorAlert } from '../ErrorAlert';
import { LoadingIndicator } from '../LoadingIndicator';
import { SavedNote } from './SavedNote';
import { useChange, useSetting } from './useSetting';

const MAX_THRESHOLDS = 10;

export function AlertSettings() {
  const q = useSetting('alerts', getThresholds);
  if (q.isPending) return <LoadingIndicator />;
  if (q.isError) return <ErrorAlert error={q.error} />;
  return <AlertPanel settings={q.data} />;
}

function AlertPanel({ settings }: { settings: AlertThresholds }) {
  const save = useChange('alerts', settings.version, saveThresholds);
  return (
    <Stack gap="sm">
      <ThresholdForm key={settings.version} settings={settings} busy={save.isPending} onSave={(days) => save.mutate(days)} />
      <SavedNote show={save.isSuccess} />
      <ErrorAlert error={save.error} />
    </Stack>
  );
}

// ThresholdForm is one number per threshold with add and remove (one to ten values); the server normalises the list.
function ThresholdForm({ settings, busy, onSave }: { settings: AlertThresholds; busy: boolean; onSave: (days: number[]) => void }) {
  const { t } = useTranslation();
  const [days, setDays] = useState<(number | string)[]>(settings.thresholds_days);
  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    onSave(days.map(Number));
  };
  return (
    <form onSubmit={submit}>
      <Stack gap="sm" maw={420}>
        <fieldset style={{ border: 0, padding: 0, margin: 0 }}>
          <legend style={{ fontWeight: 600, padding: 0, marginBottom: 8 }}>{t('settings.alerts.thresholds')}</legend>
          <Stack gap="xs">
            {days.map((d, i) => (
              <Group key={i} align="flex-end" wrap="nowrap">
                <NumberInput
                  style={{ flex: 1 }}
                  aria-label={t('settings.alerts.threshold', { n: i + 1 })}
                  value={d}
                  onChange={(v) => setDays((x) => x.map((y, j) => (j === i ? v : y)))}
                  min={1}
                  max={365}
                  allowDecimal={false}
                  allowNegative={false}
                />
                <Button variant="default" disabled={days.length <= 1} onClick={() => setDays((x) => x.filter((_, j) => j !== i))} aria-label={t('settings.alerts.remove', { n: i + 1 })}>
                  <span aria-hidden>×</span>
                </Button>
              </Group>
            ))}
          </Stack>
        </fieldset>
        <Group>
          <Button variant="default" disabled={days.length >= MAX_THRESHOLDS} onClick={() => setDays((x) => [...x, ''])}>
            {t('settings.alerts.add')}
          </Button>
          <Button type="submit" loading={busy}>
            {t('settings.alerts.save')}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
