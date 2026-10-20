import { render, screen } from '@testing-library/react';
import type { Deployment } from '../api/types';
import { Icon, type IconName } from '../design/Icon';
import { deploymentFixture } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderApp } from '../test/render';
import { DeploymentOutcome, DeploymentStatusBadge } from './DeploymentView';

// iconMarkup is the drawing of one design icon, to tell which icon a notice carries.
function iconMarkup(name: IconName): string {
  const { container, unmount } = render(<Icon name={name} />);
  const html = (container.querySelector('svg') as SVGElement).innerHTML;
  unmount();
  return html;
}

// outcome renders the outcome of d and returns the Alert that carries the headline.
async function outcome(d: Deployment, headline: string | RegExp): Promise<HTMLElement> {
  await renderApp(<DeploymentOutcome d={d} />);
  return (await screen.findByText(headline)).closest('.mantine-Alert-root') as HTMLElement;
}

const TONE_ICON = { success: 'ShieldCheck', warning: 'CircleAlert', danger: 'ShieldAlert', neutral: 'CircleDot', info: 'CircleDot' } as const;

function expectTone(alert: HTMLElement, tone: keyof typeof TONE_ICON) {
  // The theme draws a Mantine color as its design tone: the soft background of that tone.
  expect(alert.getAttribute('style')).toContain(`--alert-bg: var(--alice-${tone}-soft)`);
  const svg = alert.querySelector('.mantine-Alert-icon svg');
  expect(svg, 'the outcome has an icon').not.toBeNull();
  expect(svg?.innerHTML).toBe(iconMarkup(TONE_ICON[tone]));
}

describe('DeploymentOutcome', () => {
  it.each([
    ['succeeded, verified from Alice', { verified: 'remote' }, 'The new certificate is live and verified.', null, 'success'],
    ['succeeded, verified on the server itself', { verified: 'local' }, 'The new certificate is live and verified.', 'Alice checked it from the server itself because it cannot reach the website directly.', 'success'],
    ['succeeded, verification skipped', { verified: 'skipped' }, 'The new certificate was deployed and Nginx was reloaded.', 'The check was skipped for this website, so Alice did not confirm that the new certificate is served.', 'warning'],
    ['succeeded, not verified', { verified: '' }, 'The new certificate was deployed and Nginx was reloaded.', null, 'warning'],
  ] as const)('%s', async (_name, o, headline, extra, tone) => {
    const alert = await outcome(deploymentFixture({ status: 'succeeded', ...o }), headline);
    expectTone(alert, tone);
    if (extra) expect(alert).toHaveTextContent(extra);
    // A success never claims more than the verification proved.
    if (tone === 'warning') expect(alert).not.toHaveTextContent('live and verified');
    expectNoRawKeys();
  });

  it('unchanged: already in place, neutral', async () => {
    expectTone(await outcome(deploymentFixture({ status: 'unchanged', result: 'unchanged' }), 'This certificate was already in place. Nothing was changed.'), 'neutral');
  });

  it('failed: nothing changed, danger, with the error and its code', async () => {
    const alert = await outcome(deploymentFixture({ status: 'failed', error: { code: 'ALC-DEP-0007', reason: 'deployment.config_test_failed' } }), 'Nothing was changed on the server.');
    expectTone(alert, 'danger');
    expect(screen.getByRole('alert')).toHaveTextContent('ALC-DEP-0007');
  });

  it('failed because an unfinished earlier change blocks the files: never "nothing was changed"', async () => {
    const alert = await outcome(
      deploymentFixture({ status: 'failed', error: { code: 'ALC-DEP-0023', reason: 'deployment.server_operation_pending', params: { operation_id: '0192c000-0000-7000-8000-00000000abcd' } } }),
      /An unfinished earlier change on the server blocks these files/,
    );
    expectTone(alert, 'danger');
    expect(screen.queryByText('Nothing was changed on the server.')).not.toBeInTheDocument();
  });

  it('cancelled before sending: neutral, the reason as information, never an alert', async () => {
    const alert = await outcome(deploymentFixture({ status: 'failed', error: { code: 'ALC-DEP-0022', reason: 'deployment.cancelled' } }), 'Nothing was changed on the server.');
    expectTone(alert, 'neutral');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByText('An administrator cancelled this deployment before anything was sent to the server.')).toBeInTheDocument();
  });

  it('rolled back: restored to the previous certificate, a warning, never a success', async () => {
    const alert = await outcome(deploymentFixture({ status: 'rolled_back', result: 'rolled_back', error: { code: 'ALC-DEP-0006', reason: 'deployment.reload_failed' } }), 'Your server was restored to its previous certificate.');
    expectTone(alert, 'warning');
  });

  it('pending change restored: its own headline, a warning', async () => {
    const alert = await outcome(
      deploymentFixture({ status: 'rolled_back', error: { code: 'ALC-DEP-0024', reason: 'deployment.pending_change_restored', params: { operation_id: '0192c000-0000-7000-8000-00000000abcd' } } }),
      /The new certificate was not written. Alice put back the files from before an unfinished earlier change/,
    );
    expectTone(alert, 'warning');
    expect(alert).not.toHaveTextContent('Your server was restored to its previous certificate.');
  });

  it.each([
    ['restored', /The previous files are back, but Alice could not confirm/],
    ['restore_failed', 'Alice cannot confirm which certificate the website serves. Manual action is needed.'],
  ] as const)('rollback failed (phase %s): danger, the headline follows the phase', async (phase, headline) => {
    const alert = await outcome(deploymentFixture({ status: 'rollback_failed', phase, error: { code: 'ALC-DEP-0008', reason: 'deployment.rollback_failed' } }), headline);
    expectTone(alert, 'danger');
  });

  it('rollback forbidden (R48): danger, its own headline, never "restored"', async () => {
    const alert = await outcome(
      deploymentFixture({ status: 'rollback_failed', phase: 'restore_forbidden', error: { code: 'ALC-DEP-0025', reason: 'deployment.rollback_forbidden' } }),
      /Alice did not undo the failed change: the previous certificate is revoked or compromised/,
    );
    expectTone(alert, 'danger');
    expect(alert).not.toHaveTextContent('Manual action is needed.');
  });

  it('held for the license: a warning', async () => {
    const alert = await outcome(deploymentFixture({ status: 'pending', state: 'queued', job_status: 'blocked_license' }), /The license has expired, so this deployment is on hold/);
    expectTone(alert, 'warning');
  });

  it('recovering: a warning with the next attempt', async () => {
    const alert = await outcome(
      deploymentFixture({ status: 'needs_attention', state: 'recovering', recover_after: '2026-10-04T13:15:00Z', finished_at: null }),
      'Alice has not yet confirmed how this deployment ended. It is checking the server and will finish or undo the change.',
    );
    expectTone(alert, 'warning');
    expect(alert).toHaveTextContent(/Next attempt after: .*Oct 4, 2026/);
  });

  it('finishing: information', async () => {
    expectTone(await outcome(deploymentFixture({ status: 'running', state: 'deploying', job_status: 'succeeded', finished_at: null }), 'The background job has finished. Alice is recording the result.'), 'info');
  });

  it('stopped: a warning', async () => {
    expectTone(await outcome(deploymentFixture({ status: 'running', state: 'deploying', job_status: 'dead', finished_at: null }), /The background job ended before the deployment did/), 'warning');
  });

  it('unknown: neutral', async () => {
    expectTone(await outcome(deploymentFixture({ status: '', state: '' }), /Alice cannot tell the state of this deployment/), 'neutral');
  });

  it('says nothing while a deployment is queued or running: a queued job is no outcome', async () => {
    const { container } = await renderApp(<DeploymentOutcome d={deploymentFixture({ status: 'running', state: 'deploying', job_status: 'running', finished_at: null })} />);
    expect(container.querySelector('.mantine-Alert-root')).toBeNull();
  });
});

describe('DeploymentStatusBadge', () => {
  it('renders through the design status badge and keeps data-status and data-cancelled', async () => {
    await renderApp(
      <>
        <DeploymentStatusBadge d={{ status: 'succeeded', error: null }} testId="ok" />
        <DeploymentStatusBadge d={{ status: 'failed', error: { code: 'ALC-DEP-0022', reason: 'deployment.cancelled' } }} testId="cancelled" />
        <DeploymentStatusBadge d={{ status: 'rolled_back', error: null }} testId="rolled" />
        <DeploymentStatusBadge d={{ status: '', error: null }} testId="unknown" />
      </>,
    );
    const ok = screen.getByTestId('ok');
    expect(ok).toHaveClass('mantine-Badge-root');
    expect(ok).toHaveAttribute('data-status', 'succeeded');
    expect(ok).toHaveAttribute('data-tone', 'success');
    expect(ok).not.toHaveAttribute('data-cancelled');
    expect(ok).toHaveTextContent('Succeeded');
    const cancelled = screen.getByTestId('cancelled');
    expect(cancelled).toHaveAttribute('data-status', 'failed');
    expect(cancelled).toHaveAttribute('data-cancelled', 'true');
    expect(cancelled).toHaveAttribute('data-tone', 'neutral');
    expect(cancelled).toHaveTextContent('Cancelled');
    expect(screen.getByTestId('rolled')).toHaveAttribute('data-tone', 'warning');
    expect(screen.getByTestId('rolled')).toHaveTextContent('Failed, restored');
    expect(screen.getByTestId('unknown')).toHaveAttribute('data-tone', 'neutral');
    expect(screen.getByTestId('unknown')).toHaveTextContent('Unknown');
  });

  it('gives a status a newer server sends the neutral tone', async () => {
    await renderApp(<DeploymentStatusBadge d={{ status: 'brand_new' as Deployment['status'], error: null }} testId="new" />);
    expect(screen.getByTestId('new')).toHaveAttribute('data-tone', 'neutral');
  });
});
