import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { Rollout } from '../api/types';
import { errorResponse, globalSession, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithStepUp } from '../test/render';
import { server } from '../test/server';
import { RolloutPanel, rolloutReasonKey } from './RolloutPanel';

const ROLLOUT_ID = '0192c000-0000-7000-8000-0000000000a1';

function rolloutFixture(o: Partial<Rollout> = {}): Rollout {
  return {
    id: ROLLOUT_ID,
    state: 'hold',
    reason: '',
    reason_params: {},
    origin: 'manual',
    certificate: { id: 'c1', name: 'Web' },
    service: { id: 's1', name: 'Payments' },
    policy_version: 2,
    settings: { count: 1, percent: 0, hold: '10m', interval: '30s', failures: 2, check: null, override_allowed: true },
    hold_started_at: '2026-10-25T10:00:00Z',
    hold_until: '2026-10-25T10:10:00Z',
    now: '2026-10-25T10:05:00Z',
    waves: [
      {
        wave: 1,
        locations: [
          {
            location_id: 'l1',
            target_id: 't1',
            target_name: 'web-01',
            site: '/etc/nginx/ssl/www.crt',
            deployment_id: 'd1',
            deployment_state: 'holding',
            deployment_status: 'running',
            canary: { rounds: 4, passes: 4, consecutive_failures: 0, last_at: '2026-10-25T10:04:30Z', last_result: 'pass', last_reason: '', last_tls: 'pass', last_http_status: 200, last_latency_ms: 12, next_check_at: '2026-10-25T10:05:00Z' },
          },
        ],
      },
      { wave: 2, locations: [{ location_id: 'l2', target_id: 't2', target_name: 'web-02', site: '/etc/nginx/ssl/www.crt', deployment_id: null, deployment_state: null, deployment_status: null, canary: null }] },
    ],
    skipped: [],
    allowed_actions: ['continue', 'abort'],
    hidden_count: 0,
    created_at: '2026-10-25T09:59:00Z',
    finished_at: null,
    ...o,
  };
}

function world(r: Rollout, actions: { continue?: () => Response; abort?: () => Response } = {}, locale = 'en') {
  const posted: string[] = [];
  server.use(
    ...sessionHandlers(globalSession('operator', locale)),
    http.get(`/api/v1/deployment-rollouts/${ROLLOUT_ID}`, () => HttpResponse.json(r)),
    http.post(`/api/v1/deployment-rollouts/${ROLLOUT_ID}/actions/continue`, () => {
      posted.push('continue');
      return actions.continue ? actions.continue() : HttpResponse.json({ ...r, state: 'wave2', allowed_actions: [] });
    }),
    http.post(`/api/v1/deployment-rollouts/${ROLLOUT_ID}/actions/abort`, () => {
      posted.push('abort');
      return actions.abort ? actions.abort() : HttpResponse.json({ ...r, state: 'aborted', reason: 'canary.aborted', allowed_actions: [] });
    }),
  );
  return posted;
}

describe('RolloutPanel (R65)', () => {
  it('shows the state, the countdown from the server clock, both waves and the last round', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      world(rolloutFixture());
      await renderWithStepUp(<RolloutPanel id={ROLLOUT_ID} />);
      expect(await screen.findByTestId('rollout-state')).toHaveTextContent('Observing the first wave');
      expect(screen.getByTestId('rollout-countdown')).toHaveTextContent('Observation ends in 5 min 0 s.');
      await act(async () => {
        await vi.advanceTimersByTimeAsync(3000);
      });
      expect(screen.getByTestId('rollout-countdown')).toHaveTextContent(/Observation ends in 4 min 5[67] s\./);
      const w1 = screen.getByTestId('rollout-wave-1');
      expect(within(w1).getByText('web-01')).toBeInTheDocument();
      expect(within(w1).getByRole('link')).toHaveAttribute('href', '/deployments/d1');
      expect(within(w1).getByText('200')).toBeInTheDocument();
      expect(within(w1).getByText('12 ms')).toBeInTheDocument();
      expect(within(screen.getByTestId('rollout-wave-2')).getByText('Not deployed yet')).toBeInTheDocument();
      expectNoRawKeys();
    } finally {
      vi.useRealTimers();
    }
  });

  it('continues after the step-up and aborts after a confirmation', async () => {
    const posted = world(rolloutFixture());
    await renderWithStepUp(<RolloutPanel id={ROLLOUT_ID} />);
    await userEvent.click(await screen.findByTestId('rollout-continue'));
    await waitFor(() => expect(posted).toEqual(['continue']));
    expect(await screen.findByTestId('rollout-state')).toHaveTextContent('Deploying the rest');
    expect(screen.queryByTestId('rollout-continue')).not.toBeInTheDocument();
  });

  it('asks before aborting and shows the reason afterwards', async () => {
    const posted = world(rolloutFixture());
    await renderWithStepUp(<RolloutPanel id={ROLLOUT_ID} />);
    await userEvent.click(await screen.findByTestId('rollout-abort'));
    expect(posted).toEqual([]);
    await userEvent.click(await screen.findByTestId('rollout-abort-confirm'));
    await waitFor(() => expect(posted).toEqual(['abort']));
    expect(await screen.findByTestId('rollout-reason')).toHaveTextContent('A person stopped the canary deployment; the first wave was put back.');
  });

  it('shows only the actions the server allows, the skipped websites and the hidden count', async () => {
    world(rolloutFixture({ state: 'wave2', allowed_actions: [], skipped: [{ location_id: 'l2', reason: 'target_not_ready' }], hidden_count: 2 }));
    await renderWithStepUp(<RolloutPanel id={ROLLOUT_ID} />);
    expect(await screen.findByTestId('rollout-skipped')).toHaveTextContent('web-02 /etc/nginx/ssl/www.crt: Not deployed: target_not_ready');
    expect(screen.getByText('2 websites outside your services are not shown.')).toBeInTheDocument();
    expect(screen.queryByTestId('rollout-continue')).not.toBeInTheDocument();
    expect(screen.queryByTestId('rollout-abort')).not.toBeInTheDocument();
    expect(screen.queryByTestId('rollout-countdown')).not.toBeInTheDocument();
  });

  it('shows the refusal of a state that moved on', async () => {
    world(rolloutFixture(), { abort: () => errorResponse(409, 'ALC-DEP-0034', 'deployment.rollout_state', { params: { state: 'wave2' } }) });
    await renderWithStepUp(<RolloutPanel id={ROLLOUT_ID} />);
    await userEvent.click(await screen.findByTestId('rollout-abort'));
    await userEvent.click(await screen.findByTestId('rollout-abort-confirm'));
    expect(await screen.findByText('The canary deployment cannot do this now.')).toBeInTheDocument();
  });

  it('reads in Turkish and names every reason', async () => {
    world(rolloutFixture({ state: 'failed', reason: 'canary.check_failed', allowed_actions: [] }), {}, 'tr');
    await renderWithStepUp(<RolloutPanel id={ROLLOUT_ID} />, ['tr-TR']);
    expect(await screen.findByTestId('rollout-state')).toHaveTextContent('Başarısız');
    expect(screen.getByTestId('rollout-reason')).toHaveTextContent('İlk dalgadaki bir web sitesinin denetimi çok kez başarısız oldu');
    expectNoRawKeys();
    expect(rolloutReasonKey('license.locked')).toBe('canary.reason.license_locked');
  });
});
