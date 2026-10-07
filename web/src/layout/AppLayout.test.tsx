import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { adminSession, operatorSession, sessionHandlers } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

describe('AppLayout single sign-on refusal', () => {
  it('shows the reason of a refused step-up once and removes it from the address, keeping the rest', async () => {
    server.use(...sessionHandlers(operatorSession));
    const { router } = await renderRoute('/license?x=7&sso_error=sso.stepup_other_user');
    expect(await screen.findByTestId('sso-error')).toHaveTextContent(/another account/i);
    await waitFor(() => expect(router.state.location.search).toBe('?x=7'));
    await userEvent.click(screen.getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByTestId('sso-error')).not.toBeInTheDocument());
  });

  it('removes an unknown value without showing anything', async () => {
    server.use(...sessionHandlers(adminSession));
    const { router } = await renderRoute('/license?sso_error=<script>');
    await waitFor(() => expect(router.state.location.search).toBe(''));
    expect(screen.queryByTestId('sso-error')).not.toBeInTheDocument();
  });

  it('lists Settings for Administrators only', async () => {
    server.use(...sessionHandlers(adminSession));
    await renderRoute('/');
    expect(await screen.findByRole('link', { name: 'Settings' })).toHaveAttribute('href', '/settings');
  });
});
