import { readFileSync } from 'node:fs';
import { screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { renderApp } from '../../test/render';
import { FailedDeployments } from './FailedDeployments';
import { LicenseCard } from './LicenseCard';
import { RotationUpcoming } from './RotationUpcoming';
import { TargetsByStatus } from './TargetsByStatus';

const inRouter = (ui: React.ReactElement) => renderApp(<MemoryRouter>{ui}</MemoryRouter>);
const deployment = (id: string, status: string) => ({ id, certificate_name: `${id}.seed.test`, target_id: 't1', target_name: 'seed-web-1', status, error_code: '', at: '2026-10-06T09:00:00Z' });

describe('dashboard widgets', () => {
  it('marks each failed deployment by its status, and an unknown status without a raw value', async () => {
    await inRouter(<FailedDeployments deployments={{ failed_7d: 3, recent: [deployment('a', 'rolled_back'), deployment('b', 'needs_attention'), deployment('c', 'something_new')] }} />);
    const panel = screen.getByTestId('failed-deployments');
    expect(within(panel).getByText('Failed, restored')).toBeVisible();
    expect(within(panel).getByText('Needs attention')).toBeVisible();
    expect(within(panel).queryByText('something_new')).not.toBeInTheDocument();
    expect(within(panel).getAllByRole('listitem')).toHaveLength(3);
  });

  it('says no deployment failed with a success badge', async () => {
    await inRouter(<FailedDeployments deployments={{ failed_7d: 0, recent: [] }} />);
    expect(screen.getByText('Failed deployments: 0').closest('[data-tone]')).toHaveAttribute('data-tone', 'success');
  });

  it('counts the connected targets as 0 when none is connected and keeps an unknown status as data', async () => {
    await inRouter(<TargetsByStatus targets={{ total: 2, by_status: { unreachable: 1, mystery: 1 } }} />);
    const panel = screen.getByTestId('targets-by-status');
    expect(within(panel).getByText('0')).toBeVisible();
    expect(within(panel).getByText('of 2 connected')).toBeVisible();
    expect(within(panel).getByRole('link', { name: 'mystery: 1' })).toHaveAttribute('href', '/servers');
    const segments = within(panel).getByRole('img').querySelectorAll('i');
    expect([...segments].map((s) => s.dataset.tone)).toEqual(['neutral', 'warning']);
  });

  it('marks rotations that need a decision', async () => {
    await inRouter(<RotationUpcoming rotation={{ upcoming: [], running: 0, needs_attention: 2 }} />);
    expect(screen.getByText('Rotations that need attention: 2').closest('[data-tone]')).toHaveAttribute('data-tone', 'warning');
    expect(screen.getByText('Rotations running: 0').closest('[data-tone]')).toHaveAttribute('data-tone', 'neutral');
  });

  it('shows an Operator only an expired license, and nothing otherwise', async () => {
    const { unmount } = await inRouter(<LicenseCard license={{ expired: true, phase: '', ends_at: null, days_left: null }} detailed={false} />);
    const card = screen.getByTestId('license-card');
    expect(within(card).getByText('Expired')).toBeVisible();
    expect(within(card).queryByRole('link')).not.toBeInTheDocument();
    unmount();
    await inRouter(<LicenseCard license={{ expired: false, phase: '', ends_at: null, days_left: null }} detailed={false} />);
    expect(screen.queryByTestId('license-card')).not.toBeInTheDocument();
  });

  it('shows an expired license phase in danger to Administrators', async () => {
    await inRouter(<LicenseCard license={{ expired: true, phase: 'locked', ends_at: '2026-10-01T00:00:00Z', days_left: 0 }} detailed />);
    const card = screen.getByTestId('license-card');
    expect(within(card).getByText('Expired, locked').closest('[data-tone]')).toHaveAttribute('data-tone', 'danger');
    expect(within(card).getByRole('link', { name: 'License' })).toHaveAttribute('href', '/license');
  });

  it('shows a running evaluation in the info tone, as the License page and the server banner do', async () => {
    await inRouter(<LicenseCard license={{ expired: false, phase: 'evaluation', ends_at: '2026-11-01T00:00:00Z', days_left: 20 }} detailed />);
    const card = screen.getByTestId('license-card');
    expect(within(card).getByText('Evaluation').closest('[data-tone]')).toHaveAttribute('data-tone', 'info');
  });

  it('shows an active license in the success tone', async () => {
    await inRouter(<LicenseCard license={{ expired: false, phase: 'active', ends_at: '2027-11-01T00:00:00Z', days_left: 300 }} detailed />);
    expect(within(screen.getByTestId('license-card')).getByText('Active').closest('[data-tone]')).toHaveAttribute('data-tone', 'success');
  });

  it('lays the attention list out in three columns between 768 and 1020 px, without chevrons, as the design does', () => {
    const css = readFileSync('src/components/dashboard/dashboard.module.css', 'utf8');
    const block = css.slice(css.indexOf('@media (min-width: 768px) and (max-width: 1020px)'));
    expect(block).toMatch(/^@media \(min-width: 768px\) and \(max-width: 1020px\) \{\s*\.attentionList \{ display: grid; grid-template-columns: repeat\(3, minmax\(0, 1fr\)\)/);
    expect(block).toContain('.attentionList > li > * > svg:last-child { display: none; }');
  });
});
