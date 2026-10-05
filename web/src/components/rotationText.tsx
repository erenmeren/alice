import { Alert, Text } from '@mantine/core';
import type { i18n as I18n, TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import type { ErrorRef } from '../api/types';
import { reasonTitle } from './JobErrorAlert';

// label looks up prefix.<name>; a name this version has no text for gets prefix.unknown, never the raw name.
export function labelOf(t: TFunction, i18n: I18n, prefix: string, name: string): string {
  return i18n.exists(`${prefix}.${name}`) ? t(`${prefix}.${name}`) : t(`${prefix}.unknown`);
}

// skipText is the reason a place is skipped. The reasons come from the API (the planner's list may grow), so there is no
// closed list here: an unknown one gets the generic message.
export function skipText(t: TFunction, i18n: I18n, reason: string): string {
  return i18n.exists(`rotation.skip.${reason}`) ? t(`rotation.skip.${reason}`) : t('ui.unexpectedError');
}

export function noteText(t: TFunction, i18n: I18n, note: string): string {
  return i18n.exists(`rotation.note.${note}`) ? t(`rotation.note.${note}`) : '';
}

// durationText: whole days when the overlap is a multiple of a day, minutes otherwise (a policy edited by API).
export function durationText(t: TFunction, minutes: number): string {
  return minutes % 1440 === 0 ? t('rotation.duration.days', { count: minutes / 1440 }) : t('rotation.duration.minutes', { count: minutes });
}

// ReasonAlert shows a stored reason (a run's result, a location's error) as its title, what to do and the code. The
// presentation says how serious it is: a late answer or a key that was already gone is a warning, not a success.
export function ReasonAlert({ error, color = 'red' }: { error: ErrorRef; color?: 'red' | 'yellow' }) {
  const { t, i18n } = useTranslation();
  const params = error.params ?? {};
  const actionKey = `errors.${error.reason}.action`;
  return (
    <Alert color={color} role={color === 'red' ? 'alert' : 'status'} title={reasonTitle(t, i18n, error.reason, params)}>
      {i18n.exists(actionKey) && <Text size="sm">{t(actionKey, params)}</Text>}
      {error.code && (
        <Text size="xs" c="gray.7" mt="xs">
          {t('jobs.errorCode', { code: error.code })}
        </Text>
      )}
    </Alert>
  );
}
