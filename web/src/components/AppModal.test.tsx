import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
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

// A dialog mounted already open (the pattern of UsersPage, TokensPage, RemoveKeyDialog and the
// signing request dialogs) gives focus back to the control that opened it.
function Host() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Open the dialog
      </button>
      {open && (
        <AppModal opened onClose={() => setOpen(false)} title="Dialog">
          <button type="button" onClick={() => setOpen(false)}>
            Done
          </button>
        </AppModal>
      )}
    </>
  );
}

describe('AppModal focus', () => {
  it('returns focus to the opener when a dialog mounted open is unmounted', async () => {
    await renderApp(<Host />);
    const opener = screen.getByRole('button', { name: 'Open the dialog' });
    await userEvent.click(opener);
    const dialog = await screen.findByRole('dialog', { name: 'Dialog' });
    await waitFor(() => expect(dialog).toContainElement(document.activeElement as HTMLElement));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Done' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await waitFor(() => expect(opener).toHaveFocus());
  });

  it('returns focus to the opener when a dialog mounted open is closed with Escape', async () => {
    await renderApp(<Host />);
    const opener = screen.getByRole('button', { name: 'Open the dialog' });
    await userEvent.click(opener);
    await screen.findByRole('dialog', { name: 'Dialog' });
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(opener).toHaveFocus());
  });
});
