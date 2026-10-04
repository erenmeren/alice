import { screen } from '@testing-library/react';
import { ApiError, NetworkError } from '../api/client';
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

  it('shows an unchecked license as a pause to retry later, not as a locked license (ALC-LIC-0009)', async () => {
    const err = new ApiError(503, {
      code: 'ALC-LIC-0009', reason: 'license.unverified', message_key: 'errors.license.unverified',
      message: 'm', request_id: 'req-9', retryable: true,
    });
    await renderApp(<ErrorAlert error={err} />);
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent('The license could not be checked.');
    expect(alert).toHaveTextContent('changes resume after the next successful check');
    expect(alert).not.toHaveTextContent('License expired');
  });

  it('shows a refused server address (ALC-SSH-0012) and a rate limit in words', async () => {
    const refused = new ApiError(502, {
      code: 'ALC-SSH-0012', reason: 'ssh.address_not_allowed', message_key: 'errors.ssh.address_not_allowed',
      message: 'm', request_id: 'req-12', retryable: false,
    });
    const { unmount } = await renderApp(<ErrorAlert error={refused} />);
    expect(screen.getByRole('alert')).toHaveTextContent("Alice does not connect to this server's address.");
    unmount();
    const limited = new ApiError(429, {
      code: 'ALC-SYS-0005', reason: 'rate.limited', message_key: 'errors.rate.limited',
      message: 'm', request_id: 'req-5', retryable: true,
    }, 30);
    await renderApp(<ErrorAlert error={limited} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Too many requests in a short time.');
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
    await renderApp(<ErrorAlert error={new NetworkError('network failure')} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Alice cannot be reached.');
  });

  it('shows a generic message for an error without a body', async () => {
    await renderApp(<ErrorAlert error={new ApiError(502, null)} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Something went wrong.');
    expect(screen.getByRole('alert')).not.toHaveTextContent('request failed');
  });

  it('shows the generic message for an error with no message key', async () => {
    await renderApp(<ErrorAlert error={apiError('x', { message_key: '' })} />, ['tr-TR']);
    expect(screen.getByRole('alert')).toHaveTextContent('Bir sorun oluştu.');
  });

  it('does not claim the network is down for other exceptions', async () => {
    await renderApp(<ErrorAlert error={new Error('boom')} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Something went wrong.');
    expect(screen.getByRole('alert')).not.toHaveTextContent('cannot be reached');
  });

  it('never prints an unknown field problem code', async () => {
    const err = apiError('validation.failed', { details: [{ field: 'username', code: 'validation.brand_new' }] });
    await renderApp(<ErrorAlert error={err} />);
    expect(screen.getByRole('alert')).not.toHaveTextContent('validation.brand_new');
  });

  it('names the key types of a key type mismatch instead of showing raw codes', async () => {
    const err = apiError('certificate.key_type_mismatch', { params: { expected: 'rsa', actual: 'ecdsa', location_id: 'l1' } });
    await renderApp(<ErrorAlert error={err} />);
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent("This certificate's key type does not fit this place.");
    expect(alert).toHaveTextContent('Key type the website uses here: RSA. Key type of this certificate: ECDSA.');
    expect(alert).not.toHaveTextContent('rsa');
  });

  it('shows an unknown key type as Other', async () => {
    const err = apiError('certificate.key_type_mismatch', { params: { expected: 'ecdsa', actual: 'dsa' } });
    await renderApp(<ErrorAlert error={err} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Key type of this certificate: Other.');
  });
});
