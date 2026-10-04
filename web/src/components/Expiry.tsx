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

// expiryColor is a cue only: the badge text always says "N days" or "Expired".
function expiryColor(days: number, expired: boolean): string {
  if (expired) return 'red.9';
  if (days <= 30) return 'orange.9';
  if (days <= 60) return 'yellow.9';
  return 'green.9';
}

// Expiry shows when a certificate ends: the date and a badge with the days left, or "Expired".
// part limits it to the date or the badge when a table has a column for each.
export function Expiry({ notAfter, part = 'both' }: { notAfter: string; part?: 'both' | 'date' | 'badge' }) {
  const { t, i18n } = useTranslation();
  const now = useNow();
  const end = Date.parse(notAfter);
  if (Number.isNaN(end)) return <>{notAfter}</>;
  const expired = end <= now;
  const days = daysLeft(notAfter, now);
  const date = <span>{formatDate(notAfter, i18n.language)}</span>;
  const badge = (
    // tt="none": no CSS upper-casing of translated text (Turkish dotted/dotless i).
    <Badge variant="light" color={expiryColor(days, expired)} tt="none">
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
