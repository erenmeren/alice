import { screen } from '@testing-library/react';
import { ApiError } from '../api/client';
import { renderApp } from '../test/render';
import { ErrorAlert } from './ErrorAlert';

function apiError(reason: string, extra: Partial<ConstructorParameters<typeof ApiError>[1]> = {}) {
  return new ApiError(422, {
    code: 'ALC-X-0001',
    reason,
    message_key: `errors.${reason}`,
    message: 'server fallback text',
    request_id: 'req-42',
    retryable: false,
    ...extra,
  });
}

describe('ErrorAlert', () => {
  it('renders nothing without an error', async () => {
    await renderApp(<ErrorAlert error={null} />);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('translates a known error and shows the request ID', async () => {
    await renderApp(<ErrorAlert error={apiError('auth.invalid_credentials')} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Incorrect username or password.');
    expect(screen.getByText('Request ID: req-42')).toBeInTheDocument();
  });

  it('translates in Turkish', async () => {
    await renderApp(<ErrorAlert error={apiError('auth.invalid_credentials')} />, ['tr-TR']);
    expect(screen.getByRole('alert')).toHaveTextContent('Kullanıcı adı veya parola hatalı.');
    expect(screen.getByText('İstek kimliği: req-42')).toBeInTheDocument();
  });

  it('falls back to the server message for an unknown key', async () => {
    await renderApp(<ErrorAlert error={apiError('brand.new_reason')} />);
    expect(screen.getByRole('alert')).toHaveTextContent('server fallback text');
  });

  it('lists field problems with translated field names', async () => {
    const err = apiError('validation.failed', {
      details: [{ field: 'username', code: 'validation.required' }],
    });
    const { i18n } = await renderApp(<ErrorAlert error={err} />);
    expect(screen.getByRole('alert')).toHaveTextContent(
      i18n.t('ui.fieldProblem', { field: 'Username', problem: i18n.t('validation.required') }),
    );
  });

  it('explains network failures', async () => {
    await renderApp(<ErrorAlert error={new TypeError('Failed to fetch')} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Alice cannot be reached.');
  });
});
