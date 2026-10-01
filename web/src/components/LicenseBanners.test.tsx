import { screen, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import type { LicenseBanner } from '../api/types';
import { sessionFor, sessionHandlers, statusWith } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';
import { bannerValues } from './LicenseBanners';

const evaluation: LicenseBanner = {
  kind: 'evaluation',
  severity: 'info',
  params: { days_left: '22', max_targets: '5', ends_at: '2026-10-31T09:00:00Z' },
};
const warning: LicenseBanner = {
  kind: 'expiry_warning',
  severity: 'caution',
  params: { days_left: '1', valid_until: '2027-10-01T00:00:00Z' },
};
const grace: LicenseBanner = {
  kind: 'grace',
  severity: 'danger',
  params: { valid_until: '2027-10-01T00:00:00Z', locks_at: '2027-10-08T00:00:00Z', grace_day: '3' },
};
const locked: LicenseBanner = { kind: 'locked', severity: 'danger', params: { valid_until: '2027-10-01T00:00:00Z' } };

function useStatus(...banners: LicenseBanner[]) {
  server.use(http.get('/api/v1/license/status', () => HttpResponse.json(statusWith(...banners))));
}

describe('license banners', () => {
  it('shows the evaluation banner to everyone, in plain words', async () => {
    server.use(...sessionHandlers(sessionFor('operator')));
    useStatus(evaluation);
    await renderRoute('/');
    const banner = await screen.findByTestId('license-banner-evaluation');
    expect(banner).toHaveTextContent('Evaluation mode: 22 days left, up to 5 targets.');
    expect(banner).toHaveAttribute('role', 'status');
    expect(within(banner).queryByRole('link')).not.toBeInTheDocument();
  });

  it('shows a one-day warning with the singular and a link for administrators', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    useStatus(warning);
    await renderRoute('/');
    const banner = await screen.findByTestId('license-banner-expiry_warning');
    expect(banner).toHaveTextContent('Your license expires in 1 day (');
    expect(banner).toHaveAttribute('role', 'status');
    expect(within(banner).getByRole('link', { name: 'Open the License page' })).toHaveAttribute('href', '/license');
  });

  it('announces grace and lock as alerts', async () => {
    server.use(...sessionHandlers(sessionFor('auditor')));
    useStatus(grace, locked);
    await renderRoute('/');
    const g = await screen.findByTestId('license-banner-grace');
    expect(g).toHaveAttribute('role', 'alert');
    expect(g).toHaveTextContent('Grace day 3 of 7.');
    expect(screen.getByTestId('license-banner-locked')).toHaveTextContent('Automatic tasks are paused.');
    expect(within(g).queryByRole('link')).not.toBeInTheDocument();
  });

  it('is translated into Turkish', async () => {
    server.use(...sessionHandlers(sessionFor('admin', 'tr')));
    useStatus(evaluation, grace, locked, warning);
    await renderRoute('/', { languages: ['tr-TR'] });
    expect(await screen.findByTestId('license-banner-evaluation')).toHaveTextContent('Deneme modu: 22 gün kaldı, en fazla 5 hedef.');
    expect(screen.getByTestId('license-banner-grace')).toHaveTextContent('Ek süre günü: 3 / 7.');
    expectNoRawKeys();
  });

  it('never shows raw text for a banner kind it does not know', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    useStatus({ kind: 'from_the_future', severity: 'info', params: {} }, locked);
    await renderRoute('/');
    await screen.findByTestId('license-banner-locked');
    expect(screen.queryByTestId('license-banner-from_the_future')).not.toBeInTheDocument();
    expectNoRawKeys();
  });

  it('shows nothing when there is nothing to say', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    await renderRoute('/');
    await screen.findByRole('heading', { name: 'Welcome, Ayşe Yılmaz' });
    expect(screen.queryByTestId(/license-banner-/)).not.toBeInTheDocument();
  });
});

describe('bannerValues', () => {
  it('formats times for the reader and passes counts for plurals', () => {
    const v = bannerValues(evaluation, 'en');
    expect(v.count).toBe(22);
    expect(v.max_targets).toBe('5');
    expect(v.ends_at).not.toBe('2026-10-31T09:00:00Z');
    expect(String(v.ends_at)).toMatch(/2026/);
    expect(bannerValues({ kind: 'clock_jump', severity: 'caution', params: { jump_days: '200' } }, 'en').count).toBe(200);
  });
});
