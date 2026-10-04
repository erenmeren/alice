// Formats an RFC 3339 UTC timestamp for display in the active UI language.
// Returns an empty string for null so tables can show "never" separately.
export function formatDateTime(iso: string | null, locale: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(d);
}

// Formats the date part of an RFC 3339 timestamp for display (a certificate's last day, for example).
export function formatDate(iso: string | null, locale: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium' }).format(d);
}
