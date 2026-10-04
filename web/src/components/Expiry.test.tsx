import { screen } from '@testing-library/react';
import { renderApp } from '../test/render';
import { daysLeft, Expiry, expiryState } from './Expiry';

const now = Date.parse('2026-10-03T12:00:00Z');

describe('daysLeft', () => {
  it('counts whole days, rounding down, and is negative once expired', () => {
    expect(daysLeft('2026-10-15T12:00:00Z', now)).toBe(12);
    expect(daysLeft('2026-10-15T11:59:00Z', now)).toBe(11);
    expect(daysLeft('2026-10-03T12:00:00Z', now)).toBe(0);
    expect(daysLeft('2026-09-01T00:00:00Z', now)).toBeLessThan(0);
  });
});

describe('expiryState', () => {
  const at = (ms: number) => new Date(now + ms).toISOString();
  const DAY = 86_400_000;
  it('agrees with the server filter at the boundaries', () => {
    expect(expiryState(at(0), now)).toBe('expired'); // not_after <= now
    expect(expiryState(at(1), now)).toBe('within30');
    expect(expiryState(at(30 * DAY - 1), now)).toBe('within30'); // not_after < now + 30d
    expect(expiryState(at(30 * DAY), now)).toBe('within60');
    expect(expiryState(at(60 * DAY - 1), now)).toBe('within60');
    expect(expiryState(at(60 * DAY), now)).toBe('ok');
    expect(expiryState(at(-DAY), now)).toBe('expired');
  });
});

describe('Expiry', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(now);
  });
  afterEach(() => vi.useRealTimers());

  it.each([
    ['2026-10-15T12:00:00Z', '12 days'],
    ['2026-10-04T12:00:00Z', '1 day'],
    ['2026-12-01T00:00:00Z', '58 days'],
    ['2027-09-01T00:00:00Z', '332 days'],
    ['2026-09-01T00:00:00Z', 'Expired'],
    ['2026-10-03T12:00:00Z', 'Expired'],
  ])('%s shows %s as text', async (notAfter, text) => {
    await renderApp(<Expiry notAfter={notAfter} />);
    expect(screen.getByText(text)).toBeInTheDocument();
  });

  it('shows the date in the UI language', async () => {
    await renderApp(<Expiry notAfter="2026-10-15T12:00:00Z" />);
    expect(screen.getByText('Oct 15, 2026')).toBeInTheDocument();
  });

  it('can show only the date or only the badge', async () => {
    const { unmount } = await renderApp(<Expiry notAfter="2026-10-15T12:00:00Z" part="date" />);
    expect(screen.queryByText('12 days')).not.toBeInTheDocument();
    unmount();
    await renderApp(<Expiry notAfter="2026-10-15T12:00:00Z" part="badge" />);
    expect(screen.queryByText('Oct 15, 2026')).not.toBeInTheDocument();
    expect(screen.getByText('12 days')).toBeInTheDocument();
  });
});
