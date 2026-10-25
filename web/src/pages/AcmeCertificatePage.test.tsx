import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import commonEn from '@locales/common/en.json';
import type { ACMEBinding, ACMECertificate, ACMEOrder } from '../api/acme';
import type { SessionInfo } from '../api/types';
import { Problem } from '../components/acme/issued';
import {
  ACME_CERT_ID,
  ACME_CURRENT_ID,
  acmeBindingFixture,
  acmeCertificateFixture,
  acmeCurrentFixture,
  acmeHookFixture,
  acmeOrderFixture,
  acmeProviderFixture,
  certificateDetailFixture,
  deployableLocationFixture,
  driftedObservationFixture,
  errorResponse,
  LOCATION_ID,
  nginxTargetFixture,
  observationFixture,
  SERVICE_ID,
  serviceRef,
  servicePolicyFixture,
  sessionFor,
  sessionHandlers,
} from '../test/fixtures';
import { goErrorPairs } from '../test/goSources';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderApp, renderRoute } from '../test/render';
import { CERTIFICATES_KEY, DEPLOYMENTS_KEY } from '../api/queryKeys';
import { server } from '../test/server';

const ID = ACME_CERT_ID;
const BASE = `/api/v1/acme/certificates/${ID}`;
const steppedUp = (role: 'admin' | 'operator' = 'admin') => ({ ...sessionFor(role), stepup_until: '2099-01-01T00:00:00Z' });

interface Counts {
  cert: number;
  orders: number;
  bindings: number;
  list: number;
}

function base(opts: { session?: SessionInfo; cert?: ACMECertificate | (() => ACMECertificate); orders?: ACMEOrder[] | (() => ACMEOrder[]); bindings?: ACMEBinding[]; extra?: Parameters<typeof server.use> } = {}): Counts {
  const counts: Counts = { cert: 0, orders: 0, bindings: 0, list: 0 };
  const cert = () => (typeof opts.cert === 'function' ? opts.cert() : (opts.cert ?? acmeCertificateFixture()));
  server.use(
    ...((opts.extra ?? []) as Parameters<typeof server.use>),
    ...sessionHandlers(opts.session ?? steppedUp()),
    http.get(BASE, () => {
      counts.cert++;
      return HttpResponse.json(cert());
    }),
    http.get(`${BASE}/orders`, () => {
      counts.orders++;
      return HttpResponse.json({ items: typeof opts.orders === 'function' ? opts.orders() : (opts.orders ?? []) });
    }),
    http.get(`${BASE}/bindings`, () => {
      counts.bindings++;
      return HttpResponse.json({ items: opts.bindings ?? [] });
    }),
    http.get('/api/v1/acme/certificates', () => {
      counts.list++;
      return HttpResponse.json({ items: [cert()], next_cursor: null });
    }),
    http.get('/api/v1/acme/providers', () => HttpResponse.json({ items: [acmeProviderFixture()] })),
    http.get('/api/v1/acme/hooks', () => HttpResponse.json({ items: [acmeHookFixture()] })),
    http.get('/api/v1/certificates/:id', () => HttpResponse.json(certificateDetailFixture({ id: ACME_CURRENT_ID, issuer: 'CN=Fake LE Intermediate' }))),
    http.get('/api/v1/targets', () => HttpResponse.json({ items: [nginxTargetFixture], next_cursor: null })),
  );
  return counts;
}

const issued = (o: Partial<ACMECertificate> = {}) => acmeCertificateFixture({ current: acmeCurrentFixture(), ...o });
const open = (languages?: string[]) => renderRoute(`/acme/${ID}`, languages ? { languages } : {});
const stepUpFlow = async () => {
  const stepUp = await screen.findByRole('dialog', { name: "Confirm it's you" });
  await userEvent.type(within(stepUp).getByLabelText('6-digit code'), '123456');
  await userEvent.click(within(stepUp).getByRole('button', { name: 'Confirm' }));
};

describe('Issued certificate status page', () => {
  it('shows a certificate not issued yet to an Operator: order and test, no definition controls', async () => {
    base({ session: sessionFor('operator'), cert: acmeCertificateFixture({ state: 'pending', names: ['www.example.com', 'example.com'] }) });
    await open();
    expect(await screen.findByRole('heading', { level: 1, name: 'www.example.com' })).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByRole('link', { name: 'Issued certificates', current: 'page' })).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: 'Issued certificates' }).some((a) => a.getAttribute('href') === '/acme')).toBe(true);
    expect(screen.getByTestId('acme-state')).toHaveTextContent('Not issued yet');
    expect(screen.getByRole('button', { name: 'Test run' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Get certificate now' })).toBeEnabled();
    expect(screen.getByText(/Nothing is issued or installed/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
    expect(screen.queryByRole('switch')).not.toBeInTheDocument();
    expect(await screen.findByText('No certificate issued yet')).toBeInTheDocument();
    expect(screen.getByText('Websites come after the first certificate')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add websites' })).not.toBeInTheDocument();
    expect(screen.getByText('After the first certificate is issued')).toBeInTheDocument();
    const summary = screen.getByRole('list', { name: 'Names' });
    expect(within(summary).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['www.example.com', 'example.com']);
    expect(await screen.findByText('Internal DNS')).toBeInTheDocument();
    expect(screen.getByText('LE staging')).toBeInTheDocument();
    expect(screen.getByText('ECDSA P-256 (recommended)')).toBeInTheDocument();
    expect(screen.getAllByText('Only an administrator can change this.').length).toBeGreaterThan(0);
    expectNoRawKeys();
  });

  it('shows an active certificate to an Administrator: the current certificate, renewal date and the definition controls', async () => {
    base({ cert: issued({ renew_before_days: 30 }), orders: [acmeOrderFixture()] });
    await open();
    expect(await screen.findByRole('button', { name: 'Order now' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();
    const current = screen.getByTestId('current-panel');
    expect(within(current).getByText('0123456789abcdef…')).toBeInTheDocument();
    expect(await within(current).findByText('CN=Fake LE Intermediate')).toBeInTheDocument();
    expect(within(current).getByRole('link', { name: 'Open in the certificate list' })).toHaveAttribute('href', `/certificates/${ACME_CURRENT_ID}`);
    expect(within(current).getByText('Complete')).toBeInTheDocument();
    expect(screen.getByTestId('renews')).toHaveTextContent(/\(30 days before it expires\)/);
    expect(screen.getByRole('switch', { name: 'Automatic renewal' })).toBeChecked();
    const orders = screen.getByRole('table', { name: 'Orders' });
    expect(within(orders).getByText('Succeeded')).toBeInTheDocument();
    expect(within(orders).getByText('By a person')).toBeInTheDocument();
    expect(within(orders).getByText('Certificate')).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('explains a failing renewal with the next attempt and the last problem in plain words', async () => {
    base({
      session: sessionFor('auditor'),
      cert: issued({ state: 'failing', failures: 2, next_attempt_at: '2026-10-14T10:00:00Z', last_attempt_at: '2026-10-13T10:00:00Z', last_error: { code: 'ALC-ACM-0006', reason: 'acme.validation_failed_dns' } }),
    });
    await open();
    const failing = await screen.findByTestId('failing');
    expect(failing).toHaveTextContent(/The last 2 attempts failed\. Alice tries again at/);
    expect(screen.getByTestId('next-attempt')).not.toBeEmptyDOMElement();
    const last = screen.getByTestId('last-error');
    expect(within(last).getByText('The DNS proof failed.')).toBeInTheDocument();
    expect(within(last).getByText(/What to do: Check that the DNS hook adds the record/)).toBeInTheDocument();
    expect(within(last).getByText('Error code: ALC-ACM-0006')).toBeInTheDocument();
    // An Auditor reads, never acts.
    expect(screen.queryByRole('button', { name: 'Test run' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Order now' })).not.toBeInTheDocument();
    expect(screen.getByText(/You can look, not change/)).toBeInTheDocument();
    expect(screen.queryAllByRole('button').filter((b) => !b.closest('aside') && !b.closest('header'))).toEqual([]);
  });

  it('tells an outage from a cause that needs a person, and offers Check again and resume while it fails', async () => {
    let rearms = 0;
    base({
      session: sessionFor('admin'),
      cert: issued({ state: 'failing', failures: 4, last_failure_class: 'transient', next_attempt_at: '2026-10-14T10:00:00Z',
        last_error: { code: 'ALC-ACM-0001', reason: 'acme.provider_unreachable' },
        last_notice: { template: 'acme.renewal_failed', queued_at: '2026-10-13T09:00:00Z', recipients: 3, sent: 2, pending: 0, failed: 1, skipped: 0,
          sent_at: '2026-10-13T09:01:00Z', last_failure_code: 'smtp.auth' } }),
      extra: [http.post(`${BASE}/rearm`, () => (rearms++, HttpResponse.json(issued({ state: 'issuing', running_order_id: 'b1b1b1b1-0000-4000-8000-000000000001' }))))],
    });
    await open();
    const failing = await screen.findByTestId('failing');
    expect(failing).toHaveTextContent('The cause looks temporary');
    expect(failing).toHaveTextContent('Alice keeps trying by itself, at least once a day');
    expect(screen.getByTestId('failure-class')).toHaveTextContent('Temporary (an outage)');
    expect(screen.getByTestId('last-notice')).toHaveTextContent(/Not delivered to 1 of 3 recipients \(smtp\.auth;/);
    await userEvent.click(within(failing).getByRole('button', { name: 'Check again and resume' }));
    await waitFor(() => expect(rearms).toBe(1));
  });

  it('counts down the permanent failures that stop renewal, and shows a recovering stop', async () => {
    base({ session: sessionFor('operator'), cert: issued({ state: 'failing', failures: 3, permanent_failures: 3, last_failure_class: 'permanent' }) });
    await open();
    const failing = await screen.findByTestId('failing');
    expect(failing).toHaveTextContent('If 2 more attempts fail like this, Alice stops trying by itself.');
    expect(within(failing).queryByRole('button', { name: 'Check again and resume' })).not.toBeInTheDocument();
    expect(screen.getByTestId('failure-class')).toHaveTextContent('Needs a person');
  });

  it('says that a certificate stopped after an outage is still retried by itself', async () => {
    base({
      session: sessionFor('admin'),
      cert: issued({ state: 'stopped', stopped_reason: 'renewal_failures', failures: 6, last_failure_class: 'transient', recovering: true,
        next_attempt_at: '2026-10-14T10:00:00Z', last_notice: { template: 'acme.renewal_expiring_transient', queued_at: '2026-10-13T09:00:00Z',
          recipients: 2, sent: 0, pending: 0, failed: 0, skipped: 2, sent_at: null, last_failure_code: 'smtp.not_configured' } }),
    });
    await open();
    const notice = await screen.findByTestId('stopped');
    expect(notice).toHaveTextContent('the last problem was a temporary outage: Alice still tries again by itself');
    expect(screen.getByTestId('next-attempt')).toBeInTheDocument();
    expect(screen.getByTestId('renews')).toHaveTextContent('Next attempt');
    expect(screen.getByTestId('last-notice')).toHaveTextContent('Not sent: no mail server is set');
  });

  it('says that the certificate authority asked Alice to wait, and does not offer an order before then (R47)', async () => {
    base({
      session: sessionFor('admin'),
      cert: issued({ state: 'failing', failures: 1, last_failure_class: 'transient', next_attempt_at: '2026-10-15T09:00:00Z', ca_not_before: '2026-10-15T09:00:00Z',
        last_error: { code: 'ALC-ACM-0005', reason: 'acme.ca_rate_limited' } }),
    });
    await open();
    const notice = await screen.findByTestId('ca-wait');
    expect(notice).toHaveTextContent('Waiting for the certificate authority');
    expect(notice).toHaveTextContent('The certificate authority asked Alice to wait until');
    expect(notice).toHaveTextContent('ordering sooner only makes the wait longer');
    expect(notice).not.toHaveTextContent('Little time is left');
    expect(screen.getByRole('button', { name: 'Order now' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Test run' })).toBeDisabled();
  });

  it('warns more strongly when the wait the certificate authority asked for leaves little time', async () => {
    base({
      session: sessionFor('admin'),
      cert: issued({ state: 'failing', failures: 2, last_failure_class: 'transient', next_attempt_at: '2026-10-20T09:00:00Z', ca_not_before: '2026-10-20T09:00:00Z',
        ca_wait_critical: true }),
    });
    await open();
    const notice = await screen.findByTestId('ca-wait');
    expect(notice).toHaveTextContent('Little time is left after this wait: the current certificate ends at');
    expect(notice).toHaveTextContent('The administrators were e-mailed.');
  });

  it('says when Alice renews: a time it chose in the window the certificate authority suggests (R50)', async () => {
    base({
      cert: issued({ ari_window: { start: '2026-11-20T00:00:00Z', end: '2026-11-25T00:00:00Z' }, renew_at: '2026-11-22T13:37:00Z', renew_at_source: 'ca_window' }),
    });
    await open();
    const renews = await screen.findByTestId('renews');
    expect(renews).toHaveTextContent('a time Alice chose in the window the authority suggests');
    expect(renews).toHaveTextContent('2026');
    expect(screen.getByTestId('ari-note')).toHaveTextContent('chose this time at random');
  });

  it('says the same in Turkish', async () => {
    base({
      session: sessionFor('admin', 'tr'),
      cert: issued({ ari_window: { start: '2026-11-20T00:00:00Z', end: '2026-11-25T00:00:00Z' }, renew_at: '2026-11-22T13:37:00Z', renew_at_source: 'ca_window' }),
    });
    await open(['tr']);
    expect(await screen.findByTestId('renews')).toHaveTextContent("Alice'in yetkilinin önerdiği aralıkta seçtiği zaman");
    expect(screen.getByTestId('ari-note')).toHaveTextContent('rastgele');
  });

  it('follows the local rule when the server says so, without the note', async () => {
    base({ cert: issued({ renew_at: '2026-12-01T09:00:00Z', renew_at_source: 'local', renew_before_days: 30 }) });
    await open();
    expect(await screen.findByTestId('renews')).toHaveTextContent(/\(30 days before it expires\)/);
    expect(screen.queryByTestId('ari-note')).not.toBeInTheDocument();
  });

  it('offers the order again once the wait is over (no ca_not_before)', async () => {
    base({ session: sessionFor('admin'), cert: issued({ state: 'failing', failures: 1, next_attempt_at: '2026-10-14T10:00:00Z' }) });
    await open();
    await screen.findByTestId('failing');
    expect(screen.queryByTestId('ca-wait')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Order now' })).toBeEnabled();
  });

  it('lets an Administrator resume a stopped certificate (Check again and resume) after a fresh step-up, and reads it again', async () => {
    let rearms = 0;
    let stopped = true;
    const counts = base({
      session: sessionFor('admin'),
      cert: () => (stopped ? issued({ state: 'stopped', stopped_reason: 'renewal_failures', failures: 5, auto_renew: true, last_error: { code: 'ALC-ACM-0008', reason: 'acme.hook_refused' } }) : issued()),
      extra: [
        http.post(`${BASE}/rearm`, () => {
          rearms++;
          if (rearms === 1) return errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required');
          stopped = false;
          return HttpResponse.json(issued({ state: 'issuing', running_order_id: 'b1b1b1b1-0000-4000-8000-000000000001' }));
        }),
        http.post('/api/v1/auth/stepup', () => HttpResponse.json(steppedUp())),
      ],
    });
    await open();
    const notice = await screen.findByTestId('stopped');
    expect(notice).toHaveTextContent('Automatic renewal stopped');
    expect(notice).toHaveTextContent(/after 5 failed attempts in a row/);
    expect(screen.getByTestId('renews')).toHaveTextContent('Stopped');
    // Check again and resume switches renewal on again and orders at once (owner decision 2026-10-20).
    expect(notice).toHaveTextContent('choose Check again and resume: Alice orders the certificate at once');
    const before = counts.cert;
    await userEvent.click(within(notice).getByRole('button', { name: 'Check again and resume' }));
    await stepUpFlow();
    expect(await screen.findByText(/Automatic renewal is on again, and Alice is ordering the certificate now\./)).toBeInTheDocument();
    expect(rearms).toBe(2);
    await waitFor(() => expect(counts.cert).toBeGreaterThan(before));
    await waitFor(() => expect(screen.queryByTestId('stopped')).not.toBeInTheDocument());
  });

  it('tells an Operator how to go on with a stopped certificate, without Check again and resume', async () => {
    base({ session: sessionFor('operator'), cert: issued({ state: 'stopped', stopped_reason: 'renewal_failures', failures: 5 }) });
    await open();
    const notice = await screen.findByTestId('stopped');
    expect(within(notice).queryByRole('button', { name: 'Check again and resume' })).not.toBeInTheDocument();
    expect(notice).toHaveTextContent(/Only an administrator can resume automatic renewal \(Check again and resume\)/);
    expect(notice).toHaveTextContent('use Test run or Order now.');
    expect(screen.getByRole('button', { name: 'Order now' })).toBeEnabled();
  });

  it('names the button an Operator really sees in the stopped text before the first issuance', async () => {
    base({ session: sessionFor('operator'), cert: acmeCertificateFixture({ state: 'stopped', stopped_reason: 'renewal_failures', failures: 5 }) });
    await open();
    const notice = await screen.findByTestId('stopped');
    expect(notice).toHaveTextContent('use Test run or Get certificate now.');
    expect(notice).not.toHaveTextContent('Order now');
    expect(screen.getByRole('button', { name: 'Get certificate now' })).toBeEnabled();
  });

  it('keeps the stopped state when the step-up is cancelled', async () => {
    base({
      session: sessionFor('admin'),
      cert: issued({ state: 'stopped', stopped_reason: 'renewal_failures', failures: 5 }),
      extra: [http.post(`${BASE}/rearm`, () => errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required'))],
    });
    await open();
    await userEvent.click(within(await screen.findByTestId('stopped')).getByRole('button', { name: 'Check again and resume' }));
    const stepUp = await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.click(within(stepUp).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getByTestId('stopped')).toBeInTheDocument();
    expect(screen.queryByText(/Automatic renewal is on again/)).not.toBeInTheDocument();
  });

  it('switches automatic renewal off and on for an Administrator with the step-up', async () => {
    const bodies: unknown[] = [];
    base({ cert: issued(), extra: [http.patch(BASE, async ({ request }) => (bodies.push(await request.json()), HttpResponse.json(issued({ auto_renew: false }))))] });
    await open();
    await userEvent.click(await screen.findByRole('switch', { name: 'Automatic renewal' }));
    await waitFor(() => expect(bodies).toEqual([{ auto_renew: false }]));
  });

  describe('following a running order', () => {
    beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }));
    afterEach(() => vi.useRealTimers());

    it('polls while an order runs and stops when it has ended; the inventory is read again', async () => {
      let runningNow = true;
      const counts = base({
        session: sessionFor('operator'),
        cert: () => (runningNow ? acmeCertificateFixture({ state: 'issuing', running_order_id: 'o-run' }) : issued()),
        orders: () => [acmeOrderFixture({ id: 'o-run', state: runningNow ? 'running' : 'succeeded', finished_at: runningNow ? null : '2026-10-13T09:01:00Z' })],
      });
      const view = await open();
      const invalidate = vi.spyOn(view.client, 'invalidateQueries');
      expect(await screen.findByTestId('order-running')).toHaveTextContent('Alice is talking to the certificate authority');
      expect(screen.getByRole('button', { name: 'Test run' })).toBeDisabled();
      const first = counts.cert;
      await vi.advanceTimersByTimeAsync(3_100);
      expect(counts.cert).toBeGreaterThan(first);
      runningNow = false;
      await vi.advanceTimersByTimeAsync(3_100);
      await waitFor(() => expect(screen.queryByTestId('order-running')).not.toBeInTheDocument());
      expect(await screen.findByTestId('current-panel')).toHaveTextContent('0123456789abcdef');
      // The end of an order refreshes the inventory, the deployments (automatic deployment may follow) and the websites.
      const keys = invalidate.mock.calls.map((c) => JSON.stringify(c[0]?.queryKey));
      expect(keys).toEqual(expect.arrayContaining([JSON.stringify(CERTIFICATES_KEY), JSON.stringify(DEPLOYMENTS_KEY), JSON.stringify(['locations'])]));
      await vi.advanceTimersByTimeAsync(1_000);
      const settled = { cert: counts.cert, orders: counts.orders };
      await vi.advanceTimersByTimeAsync(30_000);
      expect({ cert: counts.cert, orders: counts.orders }).toEqual(settled);
    });

    it('runs a Test run and reports that the names were verified, nothing issued', async () => {
      let state: ACMEOrder['state'] | 'none' = 'none';
      let posts = 0;
      const counts = base({
        session: sessionFor('operator'),
        cert: () => acmeCertificateFixture({ state: 'pending', running_order_id: state === 'running' ? 't1' : null }),
        orders: () => (state === 'none' ? [] : [acmeOrderFixture({ id: 't1', kind: 'test', state, certificate_id: null })]),
        extra: [
          http.post(`${BASE}/test`, () => {
            posts++;
            state = 'running';
            return HttpResponse.json(acmeOrderFixture({ id: 't1', kind: 'test', state: 'running', certificate_id: null }), { status: 202 });
          }),
        ],
      });
      await open();
      const ordersBefore = counts.orders;
      await userEvent.click(await screen.findByRole('button', { name: 'Test run' }));
      expect(await screen.findByText('Test run in progress')).toBeInTheDocument();
      await waitFor(() => expect(counts.orders).toBeGreaterThan(ordersBefore));
      state = 'succeeded';
      await vi.advanceTimersByTimeAsync(3_100);
      await vi.advanceTimersByTimeAsync(3_100);
      expect(await screen.findByText('Test run succeeded: the authority verified every name')).toBeInTheDocument();
      expect(screen.getByTestId('test-result')).toHaveTextContent('Nothing was issued or installed.');
      expect(within(screen.getByRole('table', { name: 'Orders' })).getByText('Test run')).toBeInTheDocument();
      expect(posts).toBe(1);
    });
  });

  it('follows the Test run the wizard started ("Run a test first") with its result panel', async () => {
    base({
      session: sessionFor('admin'),
      cert: acmeCertificateFixture({ state: 'pending' }),
      orders: [acmeOrderFixture({ id: 'from-wizard', kind: 'test', state: 'succeeded', certificate_id: null })],
    });
    const { router } = await renderRoute({ pathname: `/acme/${ID}`, state: { testOrderId: 'from-wizard' } });
    expect(await screen.findByText('Test run succeeded: the authority verified every name')).toBeInTheDocument();
    expect(screen.getByTestId('test-result')).toHaveTextContent('Nothing was issued or installed.');
    // Read once: the state is cleared from the history entry, so a reload or a way back never shows it again.
    await waitFor(() => expect(router.state.location.state).toBeNull());
    expect(router.state.location.pathname).toBe(`/acme/${ID}`);
    expect(screen.getByTestId('test-result')).toBeInTheDocument();
  });

  it('shows nothing for a Test run of the navigation state that is not listed while no order runs', async () => {
    const counts = base({ session: sessionFor('admin'), cert: acmeCertificateFixture({ state: 'pending', running_order_id: null }), orders: [acmeOrderFixture({ id: 'other', kind: 'issue', state: 'failed' })] });
    await renderRoute({ pathname: `/acme/${ID}`, state: { testOrderId: 'gone' } });
    expect(await screen.findByRole('table', { name: 'Orders' })).toBeInTheDocument();
    await waitFor(() => expect(counts.orders).toBeGreaterThan(0));
    expect(screen.queryByTestId('test-result')).not.toBeInTheDocument();
    expect(screen.queryByText('Test run in progress')).not.toBeInTheDocument();
  });

  it('ignores a navigation state that is not a Test run', async () => {
    base({ session: sessionFor('admin'), cert: acmeCertificateFixture({ state: 'pending' }) });
    await renderRoute({ pathname: `/acme/${ID}`, state: { testOrderId: 42 } });
    expect(await screen.findByRole('heading', { level: 1 })).toBeInTheDocument();
    expect(screen.queryByTestId('test-result')).not.toBeInTheDocument();
  });

  it('reports a failed Test run with the reason and what to do', async () => {
    base({
      session: sessionFor('operator'),
      cert: acmeCertificateFixture({ state: 'pending' }),
      orders: [acmeOrderFixture({ id: 't2', kind: 'test', state: 'failed', certificate_id: null, error: { code: 'ALC-ACM-0007', reason: 'acme.validation_failed_http' } })],
      extra: [http.post(`${BASE}/test`, () => HttpResponse.json(acmeOrderFixture({ id: 't2', kind: 'test', state: 'running' }), { status: 202 }))],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Test run' }));
    const result = await screen.findByTestId('test-result');
    await waitFor(() => expect(result).toHaveTextContent('Test run failed'));
    expect(result).toHaveTextContent('The web proof failed.');
    expect(result).toHaveTextContent(/What to do: Check that the name points to the right server/);
  });

  it('shows the refusal of an order (one at a time) in plain words', async () => {
    base({ session: sessionFor('operator'), cert: issued(), extra: [http.post(`${BASE}/order`, () => errorResponse(409, 'ALC-ACM-0016', 'acme.order_running'))] });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Order now' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('An order is already running.');
    expect(alert).toHaveTextContent('ALC-ACM-0016');
  });

  it('operates the Test run from the keyboard', async () => {
    let posts = 0;
    base({ session: sessionFor('operator'), cert: issued(), extra: [http.post(`${BASE}/test`, () => (posts++, HttpResponse.json(acmeOrderFixture({ kind: 'test', state: 'running' }), { status: 202 })))] });
    await open();
    const button = await screen.findByRole('button', { name: 'Test run' });
    button.focus();
    expect(button).toHaveFocus();
    await userEvent.keyboard('{Enter}');
    await waitFor(() => expect(posts).toBe(1));
  });

  it('disables the actions that contact a CA or a server while the license refuses changes, and says why', async () => {
    base({ cert: issued({ state: 'stopped', stopped_reason: 'renewal_failures', failures: 5 }), bindings: [acmeBindingFixture()] });
    server.use(http.get('/api/v1/license/status', () => HttpResponse.json({ expired: true, banners: [{ kind: 'locked', severity: 'danger', params: {} }] })));
    await open();
    expect(await screen.findByText('The license does not allow changes now')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Test run' })).toBeDisabled());
    expect(screen.getByRole('button', { name: 'Order now' })).toBeDisabled();
    expect(within(screen.getByTestId('stopped')).getByRole('button', { name: 'Check again and resume' })).toBeDisabled();
    expect(screen.getByTestId('stopped')).toHaveTextContent('The license does not allow this now.');
    expect(await screen.findByRole('button', { name: 'Deploy now' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Add websites' })).toBeDisabled();
    // Removing still works (it only reduces what Alice does).
    expect(screen.getByRole('button', { name: /^Remove / })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Delete' })).toBeEnabled();
  });

  it('deletes the definition after a confirmation and a step-up, then goes back to the list', async () => {
    let deletes = 0;
    const counts = base({
      cert: issued(),
      extra: [
        http.delete(BASE, () => {
          deletes++;
          return deletes === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : new HttpResponse(null, { status: 204 });
        }),
        http.post('/api/v1/auth/stepup', () => HttpResponse.json(steppedUp())),
      ],
    });
    const { router, client } = await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }));
    const certReads = counts.cert;
    const dialog = await screen.findByRole('dialog', { name: 'Delete this certificate?' });
    expect(within(dialog).getByText(/The websites keep the certificate they serve now/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete certificate' }));
    await stepUpFlow();
    await waitFor(() => expect(router.state.location.pathname).toBe('/acme'));
    expect(deletes).toBe(2);
    // It leaves before the lists are read again: the deleted certificate is never read again (no "not found" flash).
    await waitFor(() => expect(counts.list).toBeGreaterThan(0));
    expect(counts.cert).toBe(certReads);
    // Its reads are forgotten once the page has gone (not while it is still mounted).
    await waitFor(() => expect(client.getQueryState(['acme', 'certificates', ID])).toBeUndefined());
    expect(screen.queryByText(/not found/i)).not.toBeInTheDocument();
  });

  it('shows the error of a certificate that does not exist, with the way back', async () => {
    server.use(...sessionHandlers(sessionFor('operator')), http.get(BASE, () => errorResponse(404, 'ALC-SYS-0001', 'system.not_found')), http.get(`${BASE}/orders`, () => errorResponse(404, 'ALC-SYS-0001', 'system.not_found')), http.get('/api/v1/acme/providers', () => HttpResponse.json({ items: [] })), http.get('/api/v1/acme/hooks', () => HttpResponse.json({ items: [] })));
    await open();
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Issued certificates', current: false })).toHaveAttribute('href', '/acme');
  });

  it('renders in Turkish with the e-mail labels', async () => {
    base({ session: { ...sessionFor('admin', 'tr'), stepup_until: null }, cert: issued({ state: 'stopped', stopped_reason: 'renewal_failures', failures: 3 }), bindings: [acmeBindingFixture()] });
    await open(['tr']);
    expect(await screen.findByRole('button', { name: 'Yeniden dene ve sürdür' })).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Şimdi dağıt' })).toBeInTheDocument();
    expect(screen.getAllByText('Verilen sertifikalar').length).toBeGreaterThan(0);
    expectNoRawKeys();
  });
});

describe('websites using an issued certificate', () => {
  it('lists the websites with what they serve, attention marks and the by-hand guidance', async () => {
    base({
      session: sessionFor('operator'),
      cert: issued(),
      bindings: [
        acmeBindingFixture(),
        acmeBindingFixture({ location_id: 'l2', target_name: 'web-2', cert_path: '/etc/nginx/b.crt', state: 'pending', served_certificate_id: 'older' }),
        acmeBindingFixture({ location_id: 'l3', target_name: 'web-3', cert_path: '/etc/nginx/c.crt', state: 'attention', served_certificate_id: null, attention_at: '2026-10-13T10:00:00Z', attention: { code: 'ALC-DEP-0006', reason: 'deployment.reload_failed' } }),
      ],
    });
    await open();
    const rows = await screen.findAllByTestId('acme-binding');
    expect(rows).toHaveLength(3);
    expect(within(rows[0]).getByText('Up to date')).toBeInTheDocument();
    expect(within(rows[0]).getByText('Serves the current certificate.')).toBeInTheDocument();
    expect(within(rows[0]).getByRole('link', { name: 'web-nginx' })).toHaveAttribute('href', `/servers/${nginxTargetFixture.id}`);
    expect(within(rows[1]).getByText('Waiting for deployment')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Serves an older certificate.')).toBeInTheDocument();
    expect(within(rows[2]).getByText('Needs attention').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'warning');
    expect(within(rows[2]).getByText('Does not serve a certificate from here yet.')).toBeInTheDocument();
    expect(within(within(rows[2]).getByTestId('attention')).getByText(/Error code: ALC-DEP-0006/)).toBeInTheDocument();
    expect(screen.getByText(/Remove the website here, or switch off its automatic deployment and choose Report only for its changes, before you change its certificate by hand/)).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('explains the license hold and lets an Administrator release it with the step-up', async () => {
    let releases = 0;
    let held = true;
    base({
      session: sessionFor('admin'),
      cert: () => issued({ deploy_held_reason: held ? 'license' : '', auto_deploy: true }),
      bindings: [acmeBindingFixture({ auto_deploy: true })],
      extra: [
        http.post(`${BASE}/release-hold`, () => {
          releases++;
          if (releases === 1) return errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required');
          held = false;
          return HttpResponse.json(issued());
        }),
        http.post('/api/v1/auth/stepup', () => HttpResponse.json(steppedUp())),
      ],
    });
    await open();
    const notice = await screen.findByTestId('held-license');
    expect(notice).toHaveTextContent('Automatic deployment is waiting for an administrator');
    await userEvent.click(within(notice).getByRole('button', { name: 'Release' }));
    await stepUpFlow();
    await waitFor(() => expect(screen.queryByTestId('held-license')).not.toBeInTheDocument());
    expect(releases).toBe(2);
  });

  it('tells an Operator about the license hold, the chain hold and a stopped automatic deployment', async () => {
    base({ session: sessionFor('operator'), cert: issued({ deploy_held_reason: 'license', deploy_stopped: true }), bindings: [acmeBindingFixture()] });
    await open();
    const held = await screen.findByTestId('held-license');
    expect(within(held).queryByRole('button', { name: 'Release' })).not.toBeInTheDocument();
    expect(held).toHaveTextContent(/An administrator checks it and releases it/);
    expect(screen.getByTestId('deploy-stopped')).toHaveTextContent(/stopped after repeated failures/);
  });

  it('explains the chain hold', async () => {
    base({ session: sessionFor('admin'), cert: issued({ deploy_held_reason: 'chain_incomplete', current: acmeCurrentFixture({ chain_complete: false }) }) });
    await open();
    expect(await screen.findByTestId('held-chain')).toHaveTextContent(/use Deploy now and confirm the chain/);
    expect(screen.getByTestId('current-panel')).toHaveTextContent('Incomplete: an administrator confirms before it is deployed');
  });

  it('adds websites one by one, hides the bound ones, and stops at a refused one with its reason', async () => {
    const puts: string[] = [];
    const counts = base({
      session: sessionFor('operator'),
      cert: issued(),
      bindings: [acmeBindingFixture()],
      extra: [
        http.get('/api/v1/certificate-locations', ({ request }) => {
          const u = new URL(request.url);
          expect(u.searchParams.get('key_type')).toBe('ecdsa');
          return HttpResponse.json({
            items: [
              deployableLocationFixture({ id: LOCATION_ID, key_type: 'ecdsa' }),
              deployableLocationFixture({ id: 'a1', target_name: 'web-a', cert_path: '/a.crt', key_type: 'ecdsa' }),
              deployableLocationFixture({ id: 'a2', target_name: 'web-b', cert_path: '/b.crt', key_type: 'ecdsa' }),
              deployableLocationFixture({ id: 'kv', target_name: 'web-kv', cert_path: '/kv.crt', binding_id: 'b9' }),
            ],
            next_cursor: null,
          });
        }),
        http.put(`${BASE}/bindings/:loc`, async ({ params, request }) => {
          puts.push(`${String(params.loc)} ${JSON.stringify(await request.json())}`);
          if (params.loc === 'a2') return errorResponse(409, 'ALC-ACM-0028', 'acme.location_bound', { params: { location_id: 'a2' } });
          return HttpResponse.json(acmeBindingFixture({ location_id: String(params.loc) }));
        }),
      ],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add websites' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add websites to this certificate' });
    expect(await within(dialog).findByText('web-a')).toBeInTheDocument();
    // The website that already follows this certificate is not offered; one that follows a vault certificate is disabled.
    expect(within(dialog).queryByText('/etc/nginx/ssl/www.crt')).not.toBeInTheDocument();
    expect(within(dialog).getByRole('checkbox', { name: /web-kv/ })).toBeDisabled();
    expect(within(dialog).getByText(/Follows a Key Vault certificate/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('checkbox', { name: /web-a/ }));
    await userEvent.click(within(dialog).getByRole('checkbox', { name: /web-b/ }));
    const before = counts.bindings;
    await userEvent.click(within(dialog).getByRole('button', { name: 'Add websites' }));
    expect(await within(dialog).findByText('This website already follows another certificate.')).toBeInTheDocument();
    expect(within(dialog).getByText('1 website was connected before Alice stopped at the marked one; the rest were not tried.')).toBeInTheDocument();
    // The connected website leaves the choice; the refused one stays chosen.
    expect(within(dialog).getByRole('checkbox', { name: /web-b/ })).toBeChecked();
    expect(within(dialog).getByRole('checkbox', { name: /web-a/ })).not.toBeChecked();
    expect(dialog.querySelector('[data-refused="true"]')).toHaveTextContent('web-b');
    expect(puts).toEqual(['a1 {"auto_deploy":false}', 'a2 {"auto_deploy":false}']);
    await waitFor(() => expect(counts.bindings).toBeGreaterThan(before));
  });

  it('removes a website after a confirmation, with no step-up', async () => {
    let deletes = 0;
    const counts = base({ session: sessionFor('operator'), cert: issued(), bindings: [acmeBindingFixture()], extra: [http.delete(`${BASE}/bindings/${LOCATION_ID}`, () => (deletes++, new HttpResponse(null, { status: 204 })))] });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Remove "web-nginx" /etc/nginx/ssl/www.crt' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove this website from the certificate?' });
    const before = counts.bindings;
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(deletes).toBe(1));
    await waitFor(() => expect(counts.bindings).toBeGreaterThan(before));
  });

  it('deploys now to the chosen websites (at most 20) and links the deployments', async () => {
    const many = Array.from({ length: 21 }, (_, i) => acmeBindingFixture({ location_id: `loc-${i}`, target_name: `web-${i}`, cert_path: `/c${i}.crt` }));
    let body: unknown;
    base({
      session: sessionFor('operator'),
      cert: issued(),
      bindings: many,
      extra: [
        http.post(`${BASE}/deploy`, async ({ request }) => {
          body = await request.json();
          return HttpResponse.json({ deployments: [{ id: 'd1', job_id: 'j1', location_id: 'loc-0', status_url: '', deployment_url: '', warnings: [] }] }, { status: 202 });
        }),
      ],
    });
    let deploymentReads = 0;
    server.use(http.get('/api/v1/deployments', () => (deploymentReads++, HttpResponse.json({ items: [], next_cursor: null }))));
    const { client } = await open();
    client.setQueryData(['deployments', 'probe'], 1);
    await userEvent.click(await screen.findByRole('button', { name: 'Deploy now' }));
    const dialog = await screen.findByRole('dialog', { name: 'Deploy now' });
    // More than 20: nothing is chosen up front.
    expect(within(dialog).getByText('Selected: 0')).toBeInTheDocument();
    for (const b of many) fireEvent.click(within(dialog).getByRole('checkbox', { name: new RegExp(`${b.target_name} `) }));
    expect(within(dialog).getByText(/^Selected: /)).toHaveTextContent('Selected: 21');
    expect(within(dialog).getByText('You can deploy to at most 20 websites at once. Untick some websites.')).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Deploy now' })).toBeDisabled();
    await userEvent.click(within(dialog).getByRole('checkbox', { name: /web-20 / }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Deploy now' }));
    expect(await within(dialog).findByText('1 deployment started.')).toBeInTheDocument();
    expect(within(dialog).getByRole('link', { name: 'Open this deployment' })).toHaveAttribute('href', '/deployments/d1');
    expect((body as { location_ids: string[] }).location_ids).toHaveLength(20);
    expect(body).not.toHaveProperty('confirm_incomplete_chain');
    expect(client.getQueryState(['deployments', 'probe'])?.isInvalidated).toBe(true);
    expect(deploymentReads).toBe(0);
  });

  it('says a canary goes first and sends the override when "Deploy to all at once" is chosen (R65)', async () => {
    const bodies: unknown[] = [];
    base({
      session: sessionFor('operator'),
      cert: issued({ service: serviceRef }),
      bindings: [acmeBindingFixture(), acmeBindingFixture({ location_id: 'loc-2', target_name: 'web-2', cert_path: '/c2.crt' })],
      extra: [
        http.get(`/api/v1/services/${SERVICE_ID}/policy`, () => HttpResponse.json(servicePolicyFixture({ body: { schema: 1, canary: { enabled: true, subset: { percent: 50 } } } }))),
        http.post(`${BASE}/deploy`, async ({ request }) => {
          bodies.push(await request.json());
          return HttpResponse.json(
            {
              deployments: [{ id: 'd1', job_id: 'j1', location_id: LOCATION_ID, status_url: '', deployment_url: '', warnings: [] }],
              rollout: { id: 'r1', state: 'hold', wave1: [LOCATION_ID], wave2: ['loc-2'], settings: { count: 0, percent: 50, hold: '10m', interval: '30s', failures: 2, check: null, override_allowed: true } },
            },
            { status: 202 },
          );
        }),
      ],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Deploy now' }));
    const dialog = await screen.findByRole('dialog', { name: 'Deploy now' });
    expect(await within(dialog).findByTestId('canary-note')).toHaveTextContent('Deploys to 1 website(s) first, then waits 10m before the rest.');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Deploy now' }));
    expect(await within(dialog).findByTestId('canary-started')).toHaveTextContent('Canary deployment started: 1 website(s) follow');
    expect(bodies).toEqual([{ location_ids: [LOCATION_ID, 'loc-2'] }]);
  });

  it('sends canary_override after the step-up when the canary is skipped (R65)', async () => {
    const bodies: unknown[] = [];
    base({
      session: sessionFor('operator'),
      cert: issued({ service: serviceRef }),
      bindings: [acmeBindingFixture(), acmeBindingFixture({ location_id: 'loc-2', target_name: 'web-2', cert_path: '/c2.crt' })],
      extra: [
        http.get(`/api/v1/services/${SERVICE_ID}/policy`, () => HttpResponse.json(servicePolicyFixture({ body: { schema: 1, canary: { enabled: true } } }))),
        http.post(`${BASE}/deploy`, async ({ request }) => (bodies.push(await request.json()), HttpResponse.json({ deployments: [] }, { status: 202 }))),
      ],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Deploy now' }));
    const dialog = await screen.findByRole('dialog', { name: 'Deploy now' });
    await userEvent.click(await within(dialog).findByRole('checkbox', { name: /Deploy to all at once/ }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Deploy now' }));
    await waitFor(() => expect(bodies).toEqual([{ location_ids: [LOCATION_ID, 'loc-2'], canary_override: true }]));
  });

  it('asks an Administrator to confirm an incomplete chain and keeps an Operator out', async () => {
    let body: unknown;
    base({
      session: sessionFor('admin'),
      cert: issued({ current: acmeCurrentFixture({ chain_complete: false }) }),
      bindings: [acmeBindingFixture()],
      extra: [http.post(`${BASE}/deploy`, async ({ request }) => ((body = await request.json()), HttpResponse.json({ deployments: [] }, { status: 202 })))],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Deploy now' }));
    const dialog = await screen.findByRole('dialog', { name: 'Deploy now' });
    const submit = within(dialog).getByRole('button', { name: 'Deploy now' });
    expect(submit).toBeDisabled();
    await userEvent.click(within(dialog).getByRole('checkbox', { name: /I confirm/i }));
    await userEvent.click(submit);
    await waitFor(() => expect(body).toEqual({ location_ids: [LOCATION_ID], confirm_incomplete_chain: true }));
  });

  it('lets an Operator switch a website’s automatic deployment off but not on', async () => {
    const puts: unknown[] = [];
    base({
      session: sessionFor('operator'),
      cert: issued({ auto_deploy: true }),
      bindings: [acmeBindingFixture({ auto_deploy: true }), acmeBindingFixture({ location_id: 'l2', target_name: 'web-2', cert_path: '/b.crt', auto_deploy: false })],
      extra: [http.put(`${BASE}/bindings/:loc`, async ({ request, params }) => (puts.push([params.loc, await request.json()]), HttpResponse.json(acmeBindingFixture())))],
    });
    await open();
    const on = await screen.findByRole('switch', { name: 'Automatic deployment for "web-nginx" /etc/nginx/ssl/www.crt' });
    const off = screen.getByRole('switch', { name: 'Automatic deployment for "web-2" /b.crt' });
    expect(off).toBeDisabled();
    expect(screen.getByText(/Only an administrator can switch automatic deployment on\. You can switch it off\./)).toBeInTheDocument();
    // The certificate's own switch is the Administrator's: an Operator reads it.
    expect(within(screen.getByTestId('cert-auto-deploy')).queryByRole('switch')).not.toBeInTheDocument();
    await userEvent.click(on);
    await waitFor(() => expect(puts).toEqual([[LOCATION_ID, { auto_deploy: false }]]));
  });

  it('switches a website’s automatic deployment on for an Administrator after a confirmation and a fresh step-up', async () => {
    let puts = 0;
    let body: unknown;
    const counts = base({
      session: sessionFor('admin'),
      cert: issued({ auto_deploy: true }),
      bindings: [acmeBindingFixture()],
      extra: [
        http.put(`${BASE}/bindings/${LOCATION_ID}`, async ({ request }) => {
          puts++;
          if (puts === 1) return errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required');
          body = await request.json();
          return HttpResponse.json(acmeBindingFixture({ auto_deploy: true }));
        }),
        http.post('/api/v1/auth/stepup', () => HttpResponse.json(steppedUp())),
      ],
    });
    await open();
    await userEvent.click(await screen.findByRole('switch', { name: /Automatic deployment for "web-nginx"/ }));
    const confirm = await screen.findByRole('dialog', { name: 'Switch on automatic deployment?' });
    const before = counts.bindings;
    await userEvent.click(within(confirm).getByRole('button', { name: 'Switch on' }));
    await stepUpFlow();
    await waitFor(() => expect(body).toEqual({ auto_deploy: true }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Switch on automatic deployment?' })).not.toBeInTheDocument());
    expect(counts.bindings).toBeGreaterThan(before);
  });

  it('switches the certificate’s automatic deployment on for an Administrator (PATCH with the step-up)', async () => {
    let body: unknown;
    base({ session: steppedUp(), cert: issued(), extra: [http.patch(BASE, async ({ request }) => ((body = await request.json()), HttpResponse.json(issued({ auto_deploy: true }))))] });
    await open();
    await userEvent.click(within(await screen.findByTestId('cert-auto-deploy')).getByRole('switch'));
    await userEvent.click(within(await screen.findByRole('dialog', { name: 'Switch on automatic deployment?' })).getByRole('button', { name: 'Switch on' }));
    await waitFor(() => expect(body).toEqual({ auto_deploy: true }));
  });
});

describe('the two automatic deployment switches together', () => {
  it.each([
    { cert: true, sites: [true, false], summary: 'Will deploy automatically to 1 of 2 websites.', warn: null },
    { cert: true, sites: [false], summary: 'Will deploy automatically to 0 of 1 website.', warn: 'auto-cert-only' },
    { cert: false, sites: [true, true], summary: 'Will deploy automatically to 0 of 2 websites.', warn: 'auto-sites-only' },
    { cert: false, sites: [false], summary: 'Will deploy automatically to 0 of 1 website.', warn: null },
  ])('certificate $cert, websites $sites', async ({ cert, sites, summary, warn }) => {
    base({
      session: sessionFor('operator'),
      cert: issued({ auto_deploy: cert }),
      bindings: sites.map((on, i) => acmeBindingFixture({ location_id: `l${i}`, target_name: `web-${i}`, auto_deploy: on })),
    });
    await open();
    const box = await screen.findByTestId('auto-summary');
    expect(box).toHaveTextContent(summary);
    expect(screen.queryByTestId('auto-cert-only') !== null).toBe(warn === 'auto-cert-only');
    expect(screen.queryByTestId('auto-sites-only') !== null).toBe(warn === 'auto-sites-only');
    if (warn === 'auto-sites-only') expect(screen.getByTestId('auto-sites-only')).toHaveTextContent("2 websites have their own automatic deployment on, but the certificate's automatic deployment is off");
    expectNoRawKeys();
  });

  it('shows no summary before the first certificate or without websites', async () => {
    base({ session: sessionFor('operator'), cert: issued(), bindings: [] });
    await open();
    expect(await screen.findByText('No website is connected to this certificate yet.')).toBeInTheDocument();
    expect(screen.queryByTestId('auto-summary')).not.toBeInTheDocument();
  });
});

describe('websites: refusals and the quick paths', () => {
  it('marks the website a Deploy now refusal names', async () => {
    base({
      session: sessionFor('operator'),
      cert: issued(),
      bindings: [acmeBindingFixture()],
      extra: [http.post(`${BASE}/deploy`, () => errorResponse(422, 'ALC-ACM-0029', 'acme.location_not_bound', { params: { location_id: LOCATION_ID } }))],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Deploy now' }));
    const dialog = await screen.findByRole('dialog', { name: 'Deploy now' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Deploy now' }));
    expect(await within(dialog).findByText('This website is not connected to this certificate.')).toBeInTheDocument();
    expect(dialog.querySelector('[data-refused="true"]')).toHaveTextContent('web-nginx');
  });

  it('connects every chosen website and closes', async () => {
    const puts: string[] = [];
    base({
      session: sessionFor('operator'),
      cert: issued({ key_type: 'rsa_2048' }),
      extra: [
        http.get('/api/v1/certificate-locations', ({ request }) => {
          expect(new URL(request.url).searchParams.get('key_type')).toBe('rsa');
          return HttpResponse.json({ items: [deployableLocationFixture({ id: 'a1', target_name: 'web-a' })], next_cursor: null });
        }),
        http.put(`${BASE}/bindings/:loc`, ({ params }) => (puts.push(String(params.loc)), HttpResponse.json(acmeBindingFixture()))),
      ],
    });
    await open();
    expect(await screen.findByText('No website is connected to this certificate yet.')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Add websites' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add websites to this certificate' });
    await userEvent.click(await within(dialog).findByRole('checkbox', { name: /web-a/ }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Add websites' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(puts).toEqual(['a1']);
  });

  it('shows why a website could not be removed', async () => {
    base({ session: sessionFor('operator'), cert: issued(), bindings: [acmeBindingFixture()], extra: [http.delete(`${BASE}/bindings/${LOCATION_ID}`, () => errorResponse(404, 'ALC-SYS-0001', 'system.not_found'))] });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: /^Remove "web-nginx"/ }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove this website from the certificate?' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove' }));
    expect(await within(dialog).findByRole('alert')).toBeInTheDocument();
  });

  it('switches the certificate’s automatic deployment off at once, and shows a refused release', async () => {
    let body: unknown;
    base({
      session: steppedUp(),
      cert: issued({ auto_deploy: true, deploy_held_reason: 'license' }),
      extra: [
        http.patch(BASE, async ({ request }) => ((body = await request.json()), HttpResponse.json(issued()))),
        http.post(`${BASE}/release-hold`, () => errorResponse(403, 'ALC-LIC-0001', 'license.locked')),
      ],
    });
    await open();
    await userEvent.click(within(await screen.findByTestId('cert-auto-deploy')).getByRole('switch'));
    await waitFor(() => expect(body).toEqual({ auto_deploy: false }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await userEvent.click(within(screen.getByTestId('held-license')).getByRole('button', { name: 'Release' }));
    expect(await within(screen.getByTestId('held-license')).findByRole('alert')).toHaveTextContent('ALC-LIC-0001');
  });

  it('keeps the confirmation open with the refusal of a switch-on', async () => {
    base({ session: steppedUp(), cert: issued(), bindings: [acmeBindingFixture()], extra: [http.put(`${BASE}/bindings/${LOCATION_ID}`, () => errorResponse(403, 'ALC-AUTH-0002', 'auth.forbidden'))] });
    await open();
    await userEvent.click(await screen.findByRole('switch', { name: /Automatic deployment for "web-nginx"/ }));
    const confirm = await screen.findByRole('dialog', { name: 'Switch on automatic deployment?' });
    await userEvent.click(within(confirm).getByRole('button', { name: 'Switch on' }));
    expect(await within(confirm).findByRole('alert')).toHaveTextContent('ALC-AUTH-0002');
    await userEvent.click(within(confirm).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });
});

describe('what each website should have, what Alice last deployed and what is observed today (R52)', () => {
  it('shows a website that serves another certificate although Alice deployed the right one, with the summary', async () => {
    base({
      session: sessionFor('operator'),
      cert: issued(),
      bindings: [
        acmeBindingFixture({ observation: observationFixture() }),
        acmeBindingFixture({ location_id: 'l2', target_name: 'web-2', cert_path: '/etc/nginx/b.crt', state: 'drifted', observation: driftedObservationFixture({ mode: 'observe', mode_setting: 'observe' }) }),
        acmeBindingFixture({ location_id: 'l3', target_name: 'web-3', cert_path: '/etc/nginx/c.crt', observation: observationFixture({ health: 'unreachable', tls_error: { code: 'ALC-DEP-0005', reason: 'deployment.verify_unreachable' } }) }),
      ],
    });
    await open();
    const rows = await screen.findAllByTestId('acme-binding');
    expect(within(rows[0]).getByText('In sync')).toBeInTheDocument();
    expect(within(rows[0]).getByTestId('fact-tls')).toHaveTextContent(/The website served the right certificate at .* \(checked from Alice\)\./);
    expect(within(rows[1]).getAllByText('Changed outside Alice')).toHaveLength(2);
    expect(within(rows[1]).getByTestId('fact-tls')).toHaveTextContent(/served another certificate \(fedcba9876543210\) at .* \(checked from the server itself\)/);
    expect(within(rows[1]).getByTestId('fact-file')).toHaveTextContent(/The file held another certificate \(fedcba9876543210\) at the scan of/);
    expect(within(rows[1]).getByText(/Alice last deployed the right certificate at/)).toBeInTheDocument();
    expect(within(rows[2]).getByText('Not reachable')).toBeInTheDocument();
    const summary = within(await screen.findByTestId('drift-summary'));
    expect(summary.getByText(/^Live and verified on 1 of 3 places; 1 not reachable; 1 serves another certificate \(it ends in \d+ h\)$/)).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('speaks of a Windows binding as a binding, and keeps the file wording for a certificate file (R63)', async () => {
    base({
      session: sessionFor('operator'),
      cert: issued(),
      bindings: [
        acmeBindingFixture({ location_kind: 'win_sslbinding', cert_path: 'http.sys/ipport/0.0.0.0:443', observation: driftedObservationFixture({ mode: 'observe', mode_setting: 'observe' }) }),
        acmeBindingFixture({ location_id: 'l2', observation: driftedObservationFixture({ mode: 'observe', mode_setting: 'observe' }) }),
      ],
    });
    await open();
    const rows = await screen.findAllByTestId('acme-binding');
    expect(within(rows[0]).getByTestId('fact-file')).toHaveTextContent(/^Binding \(last scan\): /);
    expect(within(rows[0]).getByTestId('fact-file')).not.toHaveTextContent('The file held');
    expect(within(rows[1]).getByTestId('fact-file')).toHaveTextContent(/^The file held /);
    expectNoRawKeys();
  });

  // FX-04 (R66 ruling 8): the place column is named by the kinds it lists.
  it('names the place column by the kinds it lists', async () => {
    const header = async (bindings: ACMEBinding[]) => {
      base({ session: sessionFor('operator'), cert: issued(), bindings });
      const view = await open();
      const table = await screen.findByRole('table', { name: 'Websites using this certificate' });
      const names = within(table).getAllByRole('columnheader').map((h) => h.textContent);
      view.unmount();
      return names[1];
    };
    const file = (id: string) => acmeBindingFixture({ location_id: id });
    const binding = (id: string) => acmeBindingFixture({ location_id: id, location_kind: 'win_sslbinding', cert_path: `http.sys/ipport/0.0.0.0:44${id.length}` });
    expect(await header([file('f1'), file('f22')])).toBe('Certificate file');
    expect(await header([binding('b1'), binding('b22')])).toBe('Binding');
    expect(await header([file('f1'), binding('b1')])).toBe('Certificate file or binding');
  });

  it('says in the add dialog that Windows (IIS) websites are listed too', async () => {
    base({
      session: sessionFor('operator'),
      cert: issued(),
      bindings: [acmeBindingFixture()],
      extra: [http.get('/api/v1/certificate-locations', () => HttpResponse.json({ items: [], next_cursor: null }))],
    });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Add websites' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add websites to this certificate' });
    expect(within(dialog).getByText(/Only websites on Nginx and Windows \(IIS\) servers whose key type fits are listed\./)).toBeInTheDocument();
  });

  it('repairs a drifted website with one action, and lets an Operator choose observe or approve but not automatic repair', async () => {
    const calls: unknown[] = [];
    base({
      session: sessionFor('operator'),
      cert: issued(),
      bindings: [acmeBindingFixture({ state: 'drifted', observation: driftedObservationFixture({ mode: 'observe', mode_setting: 'observe', default_mode: 'observe' }) })],
      extra: [
        http.post(`/api/v1/locations/${LOCATION_ID}/actions/repair`, () => (calls.push('repair'), HttpResponse.json({ deployments: [{ id: 'd1', job_id: 'j1', location_id: LOCATION_ID, status_url: '', deployment_url: '', warnings: [] }] }, { status: 202 }))),
        http.put(`/api/v1/locations/${LOCATION_ID}/drift-mode`, async ({ request }) => (calls.push(await request.json()), HttpResponse.json(driftedObservationFixture({ mode: 'approve', mode_setting: 'approve' })))),
      ],
    });
    await open();
    const row = (await screen.findAllByTestId('acme-binding'))[0];
    const select = within(row).getByRole('combobox', { name: 'When "web-nginx" /etc/nginx/ssl/www.crt changes outside Alice' });
    expect(within(select).getByRole('option', { name: 'Repair automatically' })).toBeDisabled();
    expect(within(select).getByRole('option', { name: 'Default (Report only)' })).not.toBeDisabled();
    await userEvent.selectOptions(select, 'approve');
    await waitFor(() => expect(calls).toEqual([{ mode: 'approve' }]));
    await userEvent.click(within(row).getByRole('button', { name: 'Repair "web-nginx" /etc/nginx/ssl/www.crt' }));
    await waitFor(() => expect(calls).toContain('repair'));
    expect(await within(row).findByRole('link', { name: 'Repair queued: open the deployment' })).toHaveAttribute('href', '/deployments/d1');
  });

  it('says why automatic repair stopped', async () => {
    base({ session: sessionFor('admin'), cert: issued(), bindings: [acmeBindingFixture({ state: 'drifted', observation: driftedObservationFixture({ mode: 'observe', mode_setting: 'observe', backoff_reason: 'flapping', backed_off_at: '2026-10-21T00:00:00Z' }) })] });
    await open();
    expect(await screen.findByTestId('drift-backoff')).toHaveTextContent('another tool kept changing this file');
  });
});

describe('the plain texts of every ALC-ACM error', () => {
  const pairs = [...goErrorPairs()].filter((p) => p.startsWith('ALC-ACM-')).map((p) => p.split(' ') as [string, string]);
  const errors = (commonEn as { errors: Record<string, Record<string, { title: string; action?: string }>> }).errors;

  it('reads the whole registry', () => {
    expect(pairs.length).toBeGreaterThanOrEqual(36);
  });

  it.each(pairs)('%s (%s) has a title and what to do', async (code, reason) => {
    const [ns, key] = reason.split('.');
    const text = errors[ns][key];
    await renderApp(<Problem error={{ code, reason }} />);
    expect(screen.getByText(text.title)).toBeInTheDocument();
    if (text.action) expect(screen.getByText(`What to do: ${text.action}`)).toBeInTheDocument();
    expect(screen.getByText(`Error code: ${code}`)).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('shows an ACME code on the status page as the last problem', async () => {
    base({ session: sessionFor('auditor'), cert: issued({ state: 'failing', failures: 1, last_error: { code: 'ALC-ACM-0005', reason: 'acme.ca_rate_limited' } }) });
    await open();
    expect(await within(await screen.findByTestId('last-error')).findByText('The authority is limiting requests.')).toBeInTheDocument();
  });
});
