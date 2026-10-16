import { ApiError } from '../api/client';
import { createI18n } from '../i18n';
import { fieldErrorsOf } from './fieldErrors';

// The directory form shows every server field problem under its field (fieldErrorsOf); these are its rules.
describe('fieldErrorsOf', () => {
  it('keeps the first problem of a field, translates known codes and never shows a raw code', async () => {
    const i18n = await createI18n(['en-US']);
    const err = new ApiError(422, {
      code: 'ALC-SYS-0006',
      reason: 'validation.failed',
      message_key: 'errors.validation.failed',
      message: '',
      request_id: 'r',
      retryable: false,
      details: [
        { field: 'bind_password', code: 'validation.required' },
        { field: 'bind_password', code: 'validation.pattern' },
        { field: 'user_filter', code: 'validation.no_such_code' },
      ],
    });
    const out = fieldErrorsOf(err, i18n.t, i18n);
    expect(Object.keys(out).sort()).toEqual(['bind_password', 'user_filter']);
    expect(out.bind_password).toBe('This field is required.');
    expect(out.user_filter).toBe(i18n.t('ui.unexpectedError'));
    expect(out.user_filter).not.toContain('validation.');
  });

  it('gives nothing for an error that is not an API error', async () => {
    const i18n = await createI18n(['en-US']);
    expect(fieldErrorsOf(new Error('x'), i18n.t, i18n)).toEqual({});
    expect(fieldErrorsOf(null, i18n.t, i18n)).toEqual({});
  });
});
