import { Alert, Text } from '@mantine/core';
import type { i18n as I18n, TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import type { ErrorRef } from '../api/types';
import { Icon } from '../design/Icon';
import { TONE_COLOR, type Tone } from '../theme';
import { reasonTitle } from './JobErrorAlert';

// KEY_TYPE_NAMES are the SSH key types by their proper names, as the design writes them ("Ed25519"); the names are
// the same in every language, so they are not catalog text. A type this version does not know reads as sent.
const KEY_TYPE_NAMES: Record<string, string> = { ed25519: 'Ed25519', 'rsa-3072': 'RSA 3072', 'rsa-4096': 'RSA 4096', 'ecdsa-p256': 'ECDSA P-256' };

export function keyTypeName(type: string): string {
  return Object.hasOwn(KEY_TYPE_NAMES, type) ? KEY_TYPE_NAMES[type] : type;
}

// runTone is the meaning of a run's status: a finished rotation is a success, one that needs a person or is waiting
// for a decision a warning, a run that moves information, and an undone or cancelled run neutral.
export function runTone(status: string): Tone {
  switch (status) {
    case 'completed':
      return 'success';
    case 'overlap':
    case 'verifying_new':
    case 'rolling_back':
    case 'needs_attention':
      return 'warning';
    case 'dry_run_notified':
    case 'adding_new':
    case 'removing_old':
      return 'info';
    default:
      return 'neutral';
  }
}

// locationTone is the meaning of one place's state: the new key works or the old key is gone (success), a step failed
// (danger), the old key stays or the place was skipped (warning), anything else is on its way (neutral).
export function locationTone(state: string): Tone {
  if (state === 'removed' || state === 'verified') return 'success';
  if (state.endsWith('_failed')) return 'danger';
  if (state === 'kept_old' || state === 'skipped') return 'warning';
  return 'neutral';
}

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
  // The color prop keeps its old names for the callers; it maps onto the semantic danger and warning tones.
  const danger = color === 'red';
  return (
    <Alert
      color={TONE_COLOR[danger ? 'danger' : 'warning']}
      role={danger ? 'alert' : 'status'}
      title={reasonTitle(t, i18n, error.reason, params)}
      icon={<Icon name={danger ? 'ShieldAlert' : 'CircleAlert'} size={17} />}
    >
      {i18n.exists(actionKey) && <Text size="sm">{t(actionKey, params)}</Text>}
      {error.code && (
        <Text size="xs" c="dimmed" mt="xs">
          {t('jobs.errorCode', { code: error.code })}
        </Text>
      )}
    </Alert>
  );
}
