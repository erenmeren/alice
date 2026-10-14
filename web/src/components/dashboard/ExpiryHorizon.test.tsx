import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { renderApp } from '../../test/render';
import { ExpiryHorizon, exclusiveBuckets } from './ExpiryHorizon';

const counts = { monitored: 8, expired: 1, within_7: 4, within_30: 7, within_60: 8, kv_expired: 5, kv_within_30: 9 };

describe('ExpiryHorizon', () => {
  it('derives exclusive buckets from cumulative counts (IMPLEMENTATION §3)', () => {
    expect(exclusiveBuckets(counts)).toEqual([
      { key: 'expired', count: 1 },
      { key: 'd7', count: 3 },
      { key: 'd30', count: 3 },
      { key: 'd60', count: 1 },
    ]);
  });
  it('never adds Key Vault keys and secrets to the certificate buckets', () => {
    const sum = exclusiveBuckets(counts).reduce((n, b) => n + b.count, 0);
    expect(sum).toBe(counts.within_60);
  });
  it('clamps a window that the server reports smaller than the one inside it', () => {
    expect(exclusiveBuckets({ ...counts, within_30: 3 }).find((b) => b.key === 'd30')!.count).toBe(0);
  });
  it('keeps the cumulative links, each named by its label and number only, and the monitored line', async () => {
    await renderApp(<MemoryRouter><ExpiryHorizon counts={counts} /></MemoryRouter>);
    const box = screen.getByTestId('dashboard-counts');
    expect(within(box).getByRole('link', { name: /^Expired\s*1$/ })).toHaveAttribute('href', '/certificates?expiry=expired');
    expect(within(box).getByRole('link', { name: /^Within 7 days\s*4$/ })).toHaveAttribute('href', '/certificates?expiry=7');
    expect(within(box).getByRole('link', { name: /^Within 30 days\s*7$/ })).toHaveAttribute('href', '/certificates?expiry=30');
    expect(within(box).getByRole('link', { name: /^Within 60 days\s*8$/ })).toHaveAttribute('href', '/certificates?expiry=60');
    expect(within(box).getByText('Certificates in use: 8', { exact: true })).toBeVisible();
    expect(screen.getByRole('img', { name: /1 expired, 3 within 7 days, 3 in 8 to 30 days, 1 in 31 to 60 days/ })).toBeVisible();
  });
  it('states the chosen cumulative window in the headline', async () => {
    await renderApp(<MemoryRouter><ExpiryHorizon counts={counts} /></MemoryRouter>);
    // Each window is named in words ("7 days"); the visible label stays the design's short "7d".
    for (const d of ['7', '30', '60']) {
      expect(screen.getByRole('radio', { name: `${d} days` })).toBeInTheDocument();
      expect(screen.getByText(`${d}d`)).toHaveAttribute('aria-hidden', 'true');
    }
    await userEvent.click(screen.getByRole('radio', { name: '7 days' }));
    expect(screen.getByTestId('horizon-headline')).toHaveTextContent('4');
    expect(screen.getByTestId('horizon-headline')).toHaveTextContent('expiring within 7 days, expired included');
  });
  it('links the Key Vault keys and secrets on their own line, only when there are some, and draws a zero bucket at the minimum height', async () => {
    const { unmount } = await renderApp(<MemoryRouter><ExpiryHorizon counts={counts} /></MemoryRouter>);
    expect(screen.getByRole('link', { name: 'Key Vault keys and secrets expiring within 30 days: 9' })).toHaveAttribute('href', '/key-vaults');
    expect(screen.getByTestId('horizon-headline')).toHaveTextContent('1 already expired');
    unmount();
    await renderApp(<MemoryRouter><ExpiryHorizon counts={{ ...counts, expired: 0, within_7: 0, kv_within_30: 0 }} /></MemoryRouter>);
    expect(screen.queryByRole('link', { name: /Key Vault/ })).not.toBeInTheDocument();
    expect(screen.getByTestId('horizon-headline')).not.toHaveTextContent('already expired');
    const bars = screen.getByRole('img').querySelectorAll<HTMLElement>('[data-bucket]');
    expect(bars).toHaveLength(4);
    expect(bars[0].style.height).toBe('3px');
    expect(bars[2].style.height).not.toBe('3px');
  });
  it('shows the unmanaged certificates found on the network on their own line, apart from the managed counts (D2)', async () => {
    const { unmount } = await renderApp(<MemoryRouter><ExpiryHorizon counts={counts} discovery={{ unmanaged_expiring_30d: 3 }} /></MemoryRouter>);
    const box = screen.getByTestId('dashboard-counts');
    const line = within(box).getByTestId('discovery-unmanaged');
    expect(within(line).getByRole('link', { name: 'Found on the network, not managed by Alice, expiring within 30 days: 3' })).toHaveAttribute(
      'href',
      '/discovery?view=unmanaged&expiry=30',
    );
    // The managed numbers are the same as without it.
    expect(within(box).getByRole('link', { name: /^Within 30 days\s*7$/ })).toBeVisible();
    expect(screen.getByTestId('horizon-headline')).toHaveTextContent('7');
    expect(screen.getByRole('img', { name: /1 expired, 3 within 7 days, 3 in 8 to 30 days, 1 in 31 to 60 days/ })).toBeVisible();
    unmount();
    await renderApp(<MemoryRouter><ExpiryHorizon counts={counts} discovery={{ unmanaged_expiring_30d: 0 }} /></MemoryRouter>);
    expect(screen.getByRole('link', { name: 'Found on the network, not managed by Alice, expiring within 30 days: 0' })).toBeVisible();
  });
  it('draws no discovery line without the metric (no scope, or a caller who may not see the network map)', async () => {
    await renderApp(<MemoryRouter><ExpiryHorizon counts={counts} discovery={null} /></MemoryRouter>);
    expect(screen.queryByTestId('discovery-unmanaged')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /not managed by Alice/ })).not.toBeInTheDocument();
  });
});
