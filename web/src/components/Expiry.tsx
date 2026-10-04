import { Badge, Group } from '@mantine/core';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { formatDate } from '../datetime';

const DAY_MS = 86_400_000;

// daysLeft is the whole days until notAfter (rounded down); negative once the certificate expired.
export function daysLeft(notAfter: string, now: number): number {
  return Math.floor((Date.parse(notAfter) - now) / DAY_MS);
}

// useNow is the time a screen was opened: whole days left do not need a ticking clock, and a
// render must not read the clock (the lazy initial state runs once).
export function useNow(): number {
  const [now] = useState(() => Date.now());
  return now;
}

export type ExpiryState = 'expired' | 'within30' | 'within60' | 'ok';

// expiryState uses the server's rule for the "within N days" filter, in milliseconds: expired is
// not_after <= now, within N days is not_after < now + N days (expired ones included there).
export function expiryState(notAfter: string, now: number): ExpiryState {
  const left = Date.parse(notAfter) - now;
  if (left <= 0) return 'expired';
  if (left < 30 * DAY_MS) return 'within30';
  if (left < 60 * DAY_MS) return 'within60';
  return 'ok';
}

// The color is a cue only: the badge text always says "N days" or "Expired".
const COLORS: Record<ExpiryState, string> = { expired: 'red', within30: 'orange', within60: 'yellow', ok: 'green' };

// Expiry shows when a certificate ends: the date and a badge with the days left, or "Expired".
// part limits it to the date or the badge when a table has a column for each.
export function Expiry({ notAfter, part = 'both' }: { notAfter: string; part?: 'both' | 'date' | 'badge' }) {
  const { t, i18n } = useTranslation();
  const now = useNow();
  const end = Date.parse(notAfter);
  if (Number.isNaN(end)) return <>{notAfter}</>;
  const state = expiryState(notAfter, now);
  const expired = state === 'expired';
  const days = daysLeft(notAfter, now);
  const date = <span>{formatDate(notAfter, i18n.language)}</span>;
  const badge = (
    // tt="none": no CSS upper-casing of translated text (Turkish dotted/dotless i).
    <Badge variant="light" color={COLORS[state]} data-state={state} tt="none">
      {expired ? t('certificates.expired') : t('certificates.daysLeft', { count: days })}
    </Badge>
  );
  if (part === 'date') return date;
  if (part === 'badge') return badge;
  return (
    <Group gap="xs" wrap="wrap">
      {date}
      {badge}
    </Group>
  );
}
