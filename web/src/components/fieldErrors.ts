import type { i18n as I18n, TFunction } from 'i18next';
import { ApiError } from '../api/client';

// fieldErrorsOf maps the field problems of an API error (details) to the translated text shown under
// each field; a code without a text gets the generic message, never the raw code.
export function fieldErrorsOf(error: unknown, t: TFunction, i18n: I18n): Record<string, string> {
  const out: Record<string, string> = {};
  if (!(error instanceof ApiError)) return out;
  for (const d of error.details) {
    if (d.field in out) continue;
    out[d.field] = i18n.exists(d.code) ? t(d.code, d.params) : t('ui.unexpectedError');
  }
  return out;
}
