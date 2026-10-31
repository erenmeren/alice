import { screen } from '@testing-library/react';
import { hostKeyFixture, sessionFor, sessionHandlers, tlsHostKeyFixture } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithAuth } from '../test/render';
import { server } from '../test/server';
import { HostKeyConfirm } from './HostKeyConfirm';

describe('HostKeyConfirm', () => {
  beforeEach(() => server.use(...sessionHandlers(sessionFor('admin'))));

  it('names an SSH host key "Fingerprint" with the command to run on the server', async () => {
    await renderWithAuth(<HostKeyConfirm host="db-01" hostKey={hostKeyFixture({ status: 'observed' })} onYes={() => {}} />);
    expect(screen.getByText('Fingerprint')).toBeInTheDocument();
    expect(screen.getByText(/Alice received this fingerprint from db-01\./)).toBeInTheDocument();
    expect(screen.queryByText('TLS certificate key (SPKI SHA-256)')).not.toBeInTheDocument();
  });

  // R71 Ruling 22: a WinRM listener is pinned by its certificate's public key; the setup script prints the same value.
  it('names a tls-spki identity "TLS certificate key (SPKI SHA-256)" and points to the script\'s printed fingerprint', async () => {
    const key = tlsHostKeyFixture({ status: 'observed' });
    await renderWithAuth(<HostKeyConfirm host="iis-01" hostKey={key} onYes={() => {}} />);
    expect(screen.getByText('TLS certificate key (SPKI SHA-256)')).toBeInTheDocument();
    expect(screen.getByText(/the listener fingerprint the WinRM setup script printed/)).toBeInTheDocument();
    expect(screen.getByTestId('host-key-fingerprint')).toHaveTextContent(key.fingerprint);
    expect(screen.queryByText('Fingerprint')).not.toBeInTheDocument();
  });

  it('is worded in Turkish', async () => {
    const view = await renderWithAuth(<HostKeyConfirm host="iis-01" hostKey={tlsHostKeyFixture({ status: 'observed' })} onYes={() => {}} />, ['tr-TR']);
    expect(screen.getByText('TLS sertifika anahtarı (SPKI SHA-256)')).toBeInTheDocument();
    expectNoRawKeys(view.container);
  });
});
