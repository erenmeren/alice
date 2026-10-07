import { screen } from '@testing-library/react';
import { renderApp } from '../test/render';
import { ExportButton } from './ExportButton';

describe('ExportButton', () => {
  it('links the certificate export with the filters, dropping empty ones', async () => {
    await renderApp(<ExportButton kind="certificates" filters={{ target_id: 't1', source: '', q: '', expiry: '30' }} />);
    const link = screen.getByRole('link', { name: 'Export' });
    expect(link).toHaveAttribute('href', '/api/v1/certificates/export?target_id=t1&expiry=30');
    expect(link).toHaveAttribute('download');
  });

  it('links the SSH key export', async () => {
    await renderApp(<ExportButton kind="ssh-keys" filters={{ os_user: 'root', flag: '' }} />);
    expect(screen.getByRole('link', { name: 'Export' })).toHaveAttribute('href', '/api/v1/ssh-keys/export?os_user=root');
  });

  it('has a plain address without filters', async () => {
    await renderApp(<ExportButton kind="ssh-keys" filters={{}} />);
    expect(screen.getByRole('link', { name: 'Export' })).toHaveAttribute('href', '/api/v1/ssh-keys/export');
  });
});
