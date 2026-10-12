import { fireEvent, screen, waitFor } from '@testing-library/react';
import { useState } from 'react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { errorResponse, POLICY_ID, policyFixture, sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderApp } from '../test/render';
import { server } from '../test/server';
import { RotationPolicyDialog } from './RotationPolicyDialog';
import ui from './ui/ui.module.css';

beforeEach(() => server.use(...sessionHandlers(sessionFor('admin'))));

describe('RotationPolicyDialog', () => {
  it('creates a policy with the defaults 90 / 7 / 24 / Same as now', async () => {
    let body: unknown;
    server.use(http.post('/api/v1/rotation/policies', async ({ request }) => ((body = await request.json()), HttpResponse.json(policyFixture(), { status: 201 }))));
    const onClose = vi.fn();
    await renderApp(<RotationPolicyDialog keyId="k1" policy={null} onClose={onClose} />);
    expect(await screen.findByLabelText(/^Rotate every/)).toHaveValue('90');
    expect(screen.getByLabelText(/^Keep the old key/)).toHaveValue('7');
    expect(screen.getByLabelText(/^Notify before/)).toHaveValue('24');
    expect(screen.getByLabelText('New key type')).toHaveValue('same');
    await userEvent.type(screen.getByLabelText(/^Name/), 'Quarterly');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(body).toEqual({ ssh_key_id: 'k1', name: 'Quarterly', interval_days: 90, overlap_days: 7, notify_before_hours: 24, new_key_type: 'same' });
    expectNoRawKeys();
  });

  it('refuses out-of-range values before any request', async () => {
    let calls = 0;
    server.use(http.post('/api/v1/rotation/policies', () => (calls++, HttpResponse.json(policyFixture(), { status: 201 }))));
    const user = userEvent.setup();
    await renderApp(<RotationPolicyDialog keyId="k1" policy={null} onClose={() => {}} />);
    await user.type(await screen.findByLabelText(/^Name/), 'x');
    await user.clear(screen.getByLabelText(/^Rotate every/));
    await user.type(screen.getByLabelText(/^Rotate every/), '5000');
    await user.clear(screen.getByLabelText(/^Notify before/));
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findAllByText(/Enter a whole number from/)).not.toHaveLength(0);
    expect(calls).toBe(0);
  });

  it('tells an Administrator before saving that editing a policy that is on switches it off, and sends only what changed with If-Match', async () => {
    let seen: { ifMatch: string | null; body: unknown } | null = null;
    server.use(
      http.patch(`/api/v1/rotation/policies/${POLICY_ID}`, async ({ request }) => {
        seen = { ifMatch: request.headers.get('If-Match'), body: await request.json() };
        return HttpResponse.json(policyFixture({ enabled: false, version: 3, interval_days: 30 }));
      }),
    );
    const onClose = vi.fn();
    await renderApp(<RotationPolicyDialog keyId="k1" policy={policyFixture({ enabled: true, version: 2 })} onClose={onClose} />);
    expect(await screen.findByText(/switches it off/)).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText(/^Rotate every/));
    await userEvent.type(screen.getByLabelText(/^Rotate every/), '30');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(seen).toEqual({ ifMatch: '"2"', body: { interval_days: 30 } });
  });

  it('does not warn for a policy that is off', async () => {
    await renderApp(<RotationPolicyDialog keyId="k1" policy={policyFixture()} onClose={() => {}} />);
    await screen.findByLabelText(/^Name/);
    expect(screen.queryByText(/switches it off/)).not.toBeInTheDocument();
  });

  it('loads the current values after a 412 when the panel hands over the newer copy', async () => {
    server.use(http.patch(`/api/v1/rotation/policies/${POLICY_ID}`, () => errorResponse(412, 'ALC-SYS-0008', 'system.precondition_failed')));
    const newer = policyFixture({ version: 2, interval_days: 45, name: 'Renamed' });
    function Host() {
      const [p, setP] = useState(policyFixture({ version: 1, interval_days: 90 }));
      return (
        <>
          <button onClick={() => setP(newer)}>swap</button>
          <RotationPolicyDialog keyId="k1" policy={p} onClose={() => {}} />
        </>
      );
    }
    await renderApp(<Host />);
    await userEvent.clear(await screen.findByLabelText(/^Rotate every/));
    await userEvent.type(screen.getByLabelText(/^Rotate every/), '10');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    await screen.findByText(/Your change was not saved/);
    fireEvent.click(screen.getByText('swap'));
    await waitFor(() => expect(screen.getByLabelText(/^Rotate every/)).toHaveValue('45'));
    expect(screen.getByLabelText(/^Name/)).toHaveValue('Renamed');
  });

  it('says the policy changed meanwhile after a 412 and keeps the dialog open', async () => {
    server.use(http.patch(`/api/v1/rotation/policies/${POLICY_ID}`, () => errorResponse(412, 'ALC-SYS-0008', 'system.precondition_failed')));
    server.use(http.get(`/api/v1/rotation/policies/${POLICY_ID}`, () => HttpResponse.json(policyFixture({ version: 5 }))));
    const onClose = vi.fn();
    await renderApp(<RotationPolicyDialog keyId="k1" policy={policyFixture()} onClose={onClose} />);
    await userEvent.clear(await screen.findByLabelText(/^Rotate every/));
    await userEvent.type(screen.getByLabelText(/^Rotate every/), '10');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/Your change was not saved because the policy changed in the meantime/)).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('puts Cancel and Save in the design footer, inside the form', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    await renderApp(<RotationPolicyDialog keyId="k1" policy={null} onClose={() => {}} />);
    const submit = await screen.findByRole('button', { name: 'Save' });
    expect(submit.parentElement).toHaveClass(ui.dialogActions);
    expect(submit.closest('form')).not.toBeNull();
  });
});
