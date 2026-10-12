import { screen } from '@testing-library/react';
import type { KeyLocation } from '../api/types';
import { renderApp } from '../test/render';
import { KeyFlags } from './KeyFlags';
import { TargetStatusBadge } from './TargetStatusBadge';

describe('TargetStatusBadge', () => {
  it.each([
    ['ok', 'Connected', 'success', true],
    ['host_key_changed', 'Server identity changed', 'danger', true],
    ['unreachable', 'Cannot be reached', 'warning', true],
    ['pending_host_key', 'Waiting for fingerprint confirmation', 'warning', false],
    ['disabled', 'Disabled', 'neutral', false],
  ] as const)('names %s with text, tone and an icon or a dot', async (status, text, tone, icon) => {
    await renderApp(<TargetStatusBadge status={status} testId="s" />);
    const badge = screen.getByTestId('s');
    expect(badge).toHaveTextContent(new RegExp(`^${text}$`));
    expect(badge).toHaveAttribute('data-tone', tone);
    expect(badge.classList.contains('mantine-Badge-root')).toBe(true);
    expect(badge.querySelector('svg') !== null).toBe(icon);
  });
});

describe('KeyFlags', () => {
  it("shows Alice's key and the findings as status badges, the risky ones as warnings", async () => {
    await renderApp(<KeyFlags location={{ is_alice_connection_key: true, flags: ['weak', 'duplicate', 'not_a_flag' as KeyLocation['flags'][number]] }} />);
    expect(screen.getByText("Alice's key").closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'brand');
    expect(screen.getByText('Weak key').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'warning');
    expect(screen.getByText('Listed more than once').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'neutral');
    expect(screen.queryByText('not_a_flag')).not.toBeInTheDocument();
  });

  it('renders nothing without flags', async () => {
    const { container } = await renderApp(<KeyFlags location={{ is_alice_connection_key: false, flags: [] }} />);
    expect(container.querySelector('.mantine-Badge-root')).toBeNull();
  });
});
