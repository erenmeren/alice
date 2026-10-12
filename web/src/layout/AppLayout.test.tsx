import { readFileSync } from 'node:fs';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { adminSession, auditorSession, operatorSession, sessionHandlers } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';
import { ACCOUNT_ITEMS, NAV_ITEMS, isActive } from './AppLayout';

// The destinations named in the navigation landmark (the brand link sits outside it, in the sidebar).
const linkNames = () =>
  within(screen.getByRole('navigation', { name: 'Main navigation' }))
    .getAllByRole('link')
    .map((a) => a.textContent ?? '');

// rule returns the declarations of a top-level rule of the shell's style sheet.
const css = readFileSync('src/layout/AppLayout.module.css', 'utf8');
const rule = (selector: string) => new RegExp(`^${selector.replace('.', '\\.')} \\{([^}]*)\\}`, 'm').exec(css)?.[1] ?? '';

describe('AppLayout sidebar scrolling', () => {
  // A short window (a 640x800 phone with the menu open, a 1280x720 laptop) must reach every link: the whole sidebar
  // scrolls as one column, so the Administration group is never clipped inside a middle scroll area.
  it('scrolls the whole sidebar, not a clipped middle part', () => {
    expect(rule('.navbar')).toMatch(/overflow-y: auto/);
    expect(rule('.navScroll')).not.toMatch(/overflow/);
    expect(rule('.navScroll')).not.toMatch(/min-height: 0/);
  });
});

describe('AppLayout design details', () => {
  it('writes the brand in lowercase, closes the installation card with a lock and sizes the phone top bar for touch', () => {
    expect(rule('.brandName')).toMatch(/text-transform: lowercase/);
    const phone = css.slice(css.indexOf('@media (max-width: 767px)'));
    expect(phone).toMatch(/\.topActions :global\(\.mantine-ActionIcon-root\),\s*\.burger \{ min-width: 42px; min-height: 42px; \}/);
  });

  it('shows the search label from 1200 px only and ends the installation card with a lock icon', async () => {
    server.use(...sessionHandlers(adminSession));
    await renderRoute('/');
    const search = await screen.findByRole('button', { name: 'Search pages' });
    expect(within(search).getByText('Search pages')).toHaveClass('mantine-visible-from-lg');
    const text = screen.getByText('Self-hosted installation').parentElement;
    expect(text?.nextElementSibling?.tagName).toBe('svg');
    expect(text?.nextElementSibling?.nextElementSibling).toBeNull();
  });
});

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

describe('AppLayout shell', () => {
  it.each([
    [adminSession, ['Overview', 'Certificates', 'SSH keys', 'Servers', 'Key Vaults', 'Deployments', 'Key rotations', 'Audit trail', 'People & access', 'Settings', 'License', 'Your account', 'API tokens']],
    [operatorSession, ['Overview', 'Certificates', 'SSH keys', 'Servers', 'Key Vaults', 'Deployments', 'Key rotations', 'Your account', 'API tokens']],
    [auditorSession, ['Overview', 'Certificates', 'SSH keys', 'Servers', 'Key Vaults', 'Deployments', 'Key rotations', 'Audit trail', 'License', 'Your account', 'API tokens']],
  ])('renders the destinations of each role, in the design’s groups', async (session, expected) => {
    server.use(...sessionHandlers(session));
    await renderRoute('/');
    await screen.findByRole('navigation', { name: 'Main navigation' });
    expect(linkNames()).toEqual(expected);
  });

  it('has one navigation landmark, group labels that are neither headings nor links, and one h1', async () => {
    server.use(...sessionHandlers(adminSession));
    await renderRoute('/license');
    await screen.findByRole('heading', { level: 1 });
    expect(screen.getAllByRole('navigation')).toHaveLength(1);
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByText('Inventory')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /Inventory|Operations|Administration/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Inventory' })).not.toBeInTheDocument();
  });

  it('names as navigation only the links: brand, installation card, account and Sign out sit outside it, in the sidebar', async () => {
    server.use(...sessionHandlers(adminSession));
    await renderRoute('/license');
    const nav = await screen.findByRole('navigation', { name: 'Main navigation' });
    const sidebar = screen.getByRole('complementary');
    expect(sidebar).toHaveAttribute('id', 'app-navbar');
    expect(sidebar).toContainElement(nav);
    expect(within(nav).getByRole('link', { name: 'People & access' })).toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: 'Your account' })).toBeInTheDocument();
    expect(within(nav).queryByRole('button', { name: 'Sign out' })).not.toBeInTheDocument();
    expect(within(nav).queryByTestId('current-user')).not.toBeInTheDocument();
    expect(within(nav).queryByText('Self-hosted installation')).not.toBeInTheDocument();
    expect(within(sidebar).getByRole('button', { name: 'Sign out' })).toBeInTheDocument();
    expect(within(sidebar).getByTestId('current-user')).toBeInTheDocument();
  });

  it('marks the current page and keeps nav names exact', async () => {
    server.use(...sessionHandlers(adminSession));
    await renderRoute('/license');
    const link = await screen.findByRole('link', { name: 'License' });
    expect(link).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('link', { name: 'Overview' })).not.toHaveAttribute('aria-current');
  });

  it('shows the signed-in name alone, a visible Sign out button, the language toggle and the footer version', async () => {
    server.use(...sessionHandlers(adminSession));
    await renderRoute('/');
    expect(await screen.findByTestId('current-user')).toHaveTextContent(new RegExp(`^${adminSession.user.display_name}$`));
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Türkçe' })).toBeVisible();
    expect(await screen.findByText(/Self-hosted · Alice/)).toBeVisible();
  });

  it('puts the skip link, the navigation, the top bar and the main area in this order (Tab budget)', async () => {
    server.use(...sessionHandlers(adminSession));
    const { container } = await renderRoute('/');
    await screen.findByRole('navigation', { name: 'Main navigation' });
    const skip = screen.getByRole('link', { name: 'Skip to content' });
    const nav = screen.getByRole('navigation', { name: 'Main navigation' });
    const search = screen.getByRole('button', { name: 'Search pages' });
    const main = screen.getByRole('main');
    expect(skip.compareDocumentPosition(nav) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(nav.compareDocumentPosition(search) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(search.compareDocumentPosition(main) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(main).toHaveAttribute('id', 'main');
    expect(container.querySelector('a[href="#main"]')).toBe(skip);
  });

  it('closes the phone menu on Escape and gives focus back to the menu button', async () => {
    server.use(...sessionHandlers(adminSession));
    await renderRoute('/');
    await userEvent.click(await screen.findByRole('button', { name: 'Open navigation' }));
    const close = screen.getByRole('button', { name: 'Close navigation' });
    expect(close).toHaveAttribute('aria-expanded', 'true');
    await userEvent.keyboard('a');
    // A modal dialog in front takes Escape for itself.
    const other = document.createElement('div');
    other.setAttribute('role', 'dialog');
    other.setAttribute('aria-modal', 'true');
    document.body.appendChild(other);
    await userEvent.keyboard('{Escape}');
    other.remove();
    expect(close).toHaveAttribute('aria-expanded', 'true');
    await userEvent.keyboard('{Escape}');
    const open = screen.getByRole('button', { name: 'Open navigation' });
    expect(open).toHaveAttribute('aria-expanded', 'false');
    expect(open).toHaveFocus();
  });

  it('writes the breadcrumb as plain text', async () => {
    // The server page itself may fail here (no target 'abc'): only the shell is under test.
    server.use(...sessionHandlers(adminSession), http.get(/\/api\/v1\/targets\/.*/, () => new HttpResponse(null, { status: 404 })));
    await renderRoute('/servers/abc');
    const crumb = await screen.findByTestId('breadcrumb');
    expect(crumb).toHaveTextContent('Workspace');
    expect(crumb).toHaveTextContent('Servers');
    expect(crumb).toHaveTextContent('Details');
    expect(within(crumb).queryByRole('link')).not.toBeInTheDocument();
  });

  it('activates Key rotations for run pages through match', () => {
    expect(isActive({ to: '/rotations', labelKey: 'nav.rotations', roles: [], icon: 'RotateCw', group: 'operations', match: ['/rotation/'] }, '/rotation/runs/1')).toBe(true);
    expect(isActive(NAV_ITEMS[0], '/servers')).toBe(false);
    expect(ACCOUNT_ITEMS.map((i) => i.to)).toEqual(['/account', '/tokens']);
  });
});
