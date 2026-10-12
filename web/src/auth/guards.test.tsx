import { screen, within } from '@testing-library/react';
import { sessionFor, sessionHandlers } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

describe('RequireRole', () => {
  it('shows the no-access page with one h1 and a way home', async () => {
    server.use(...sessionHandlers(sessionFor('operator')));
    await renderRoute('/users');
    const heading = await screen.findByRole('heading', { level: 1, name: 'You do not have access to this page.' });
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getAllByText('You do not have access to this page.')).toHaveLength(1);
    const main = screen.getByRole('main');
    expect(within(main).getByRole('heading', { level: 1 })).toBe(heading);
    expect(within(main).getByRole('link', { name: 'Go to the home page' })).toHaveAttribute('href', '/');
    // Announced, as before the design: the refusal is an alert that holds the heading.
    expect(screen.getByRole('alert')).toContainElement(heading);
  });

  it('shows the page to a role that may use it', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    await renderRoute('/users');
    expect(await screen.findByRole('heading', { level: 1 })).not.toHaveTextContent('You do not have access to this page.');
  });
});
