import { screen } from '@testing-library/react';
import { renderApp } from '../test/render';
import { AppModal } from './AppModal';

describe('AppModal', () => {
  it('gives the close button a name screen readers can announce', async () => {
    await renderApp(
      <AppModal opened onClose={() => undefined} title="Add user">
        body
      </AppModal>,
    );
    expect(await screen.findByRole('button', { name: 'Close' })).toBeInTheDocument();
  });

  it('names the close button in Turkish', async () => {
    await renderApp(
      <AppModal opened onClose={() => undefined} title="Kullanıcı ekle">
        body
      </AppModal>,
      ['tr-TR'],
    );
    expect(await screen.findByRole('button', { name: 'Kapat' })).toBeInTheDocument();
  });
});
