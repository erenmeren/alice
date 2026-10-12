import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderApp } from '../test/render';
import auth from './auth/auth.module.css';
import { TotpEnrollment } from './TotpEnrollment';

const enrollment = { secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/Alice:olcay', qr_png: 'iVBORw0KGgo=' };

describe('TotpEnrollment', () => {
  it('puts the QR code on a light tile in the dark scheme too and keeps the key', async () => {
    await renderApp(<TotpEnrollment enrollment={enrollment} onVerify={() => Promise.resolve()} />, ['en-US'], { colorScheme: 'dark' });
    expect(document.documentElement).toHaveAttribute('data-mantine-color-scheme', 'dark');
    const qr = screen.getByRole('img', { name: 'QR code for your authenticator app' });
    expect(qr).toHaveAttribute('src', 'data:image/png;base64,iVBORw0KGgo=');
    expect(qr.closest(`.${auth.qrTile}`)).not.toBeNull();
    expect(screen.getByTestId('totp-secret')).toHaveTextContent('JBSWY3DPEHPK3PXP');
    expect(screen.getByRole('heading', { level: 2, name: 'Set up your authenticator app' })).toBeInTheDocument();
  });

  it('sends the code and shows a refusal', async () => {
    const onVerify = vi.fn().mockRejectedValue(new Error('x'));
    await renderApp(<TotpEnrollment enrollment={enrollment} onVerify={onVerify} />);
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(onVerify).toHaveBeenCalledWith('123456');
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Verify' })).toBeEnabled();
  });
});
