import { readFileSync } from 'node:fs';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { renderApp } from '../../test/render';
import { server } from '../../test/server';
import { AuthLayout } from './AuthLayout';

const css = readFileSync('src/components/auth/auth.module.css', 'utf8');

describe('AuthLayout', () => {
  it('has a brand side (an aside without a heading) and a form side with the toggles and the content', async () => {
    await renderApp(
      <AuthLayout>
        <h1>Form title</h1>
      </AuthLayout>,
    );
    const brand = screen.getByRole('complementary', { name: 'Alice' });
    expect(within(brand).queryByRole('heading')).not.toBeInTheDocument();
    expect(within(brand).getByText('A little less uncertainty. A lot more control.').tagName).toBe('P');
    expect(within(brand).getByText('Certificates. Keys. Clarity.')).toBeInTheDocument();
    expect(within(brand).getByText(/One considered workspace/)).toBeInTheDocument();
    const footer = within(brand).getAllByRole('listitem').map((li) => li.textContent);
    expect(footer).toEqual(['Self-hosted', 'Offline-ready', 'Built for control']);

    const main = screen.getByRole('main');
    expect(within(main).getByRole('heading', { level: 1, name: 'Form title' })).toBeInTheDocument();
    expect(within(main).getByRole('button', { name: 'Switch color mode' })).toBeInTheDocument();
    expect(within(main).getByRole('button', { name: 'Türkçe' })).toBeInTheDocument();
    expect(screen.getAllByRole('main')).toHaveLength(1);
  });

  it('shows only the form side without the brand', async () => {
    await renderApp(
      <AuthLayout brand={false}>
        <p>content</p>
      </AuthLayout>,
    );
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
    expect(within(screen.getByRole('main')).getByText('content')).toBeInTheDocument();
  });

  it('widens the form for the enrollment and recovery-code steps', async () => {
    await renderApp(
      <AuthLayout wide>
        <p>content</p>
      </AuthLayout>,
    );
    expect(screen.getByText('content').parentElement).toHaveAttribute('data-wide', 'true');
  });

  it('switches the page to Turkish without a session (no PUT /auth/locale)', async () => {
    let saved = false;
    server.use(http.put('/api/v1/auth/locale', () => {
      saved = true;
      return new HttpResponse(null, { status: 204 });
    }));
    await renderApp(
      <AuthLayout>
        <p>content</p>
      </AuthLayout>,
    );
    await userEvent.click(screen.getByRole('button', { name: 'Türkçe' }));
    expect(await screen.findByText('Daha az belirsizlik. Daha fazla kontrol.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'English' })).toBeInTheDocument();
    expect(saved).toBe(false);
  });

  it('keeps the design rules: fixed brand colors from tokens, the brand side hidden on phones, a white QR tile', () => {
    expect(css).toMatch(/\.brandSide\s*{[^}]*background:\s*var\(--alice-auth-brand-bg\)/);
    expect(css).toMatch(/\.brandSide\s*{[^}]*color:\s*var\(--alice-auth-brand-text\)/);
    expect(css).toMatch(/grid-template-columns:\s*1\.05fr 1fr/);
    expect(css).toMatch(/@media \(max-width: 767px\)\s*{[^@]*\.brandSide\s*{\s*display:\s*none/);
    expect(css).toMatch(/\.form\s*{[^}]*max-width:\s*350px/);
    expect(css).toMatch(/\.form\[data-wide\]\s*{[^}]*max-width:\s*420px/);
    expect(css).toMatch(/\.qrTile\s*{[^}]*background:\s*#ffffff/);
    expect(css).toMatch(/li \+ li::before\s*{[^}]*content:\s*'·'/);
  });
});
