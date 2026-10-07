import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { useState } from 'react';
import { createMemoryRouter, MemoryRouter, RouterProvider } from 'react-router';
import { apiFetch, ApiError, getCsrfToken, isApiError } from '../api/client';
import { AuthProvider } from '../auth/AuthProvider';
import * as navigation from '../navigation';
import { errorResponse, sessionFor, sessionHandlers, ssoSessionFor } from '../test/fixtures';
import { renderApp } from '../test/render';
import { server } from '../test/server';
import { StepUpProvider, useStepUp } from './StepUpProvider';

function Probe() {
  const { run } = useStepUp();
  const [done, setDone] = useState<string[]>([]);
  const attempt = (name: string) => {
    let first = true;
    void run(async () => {
      if (first) {
        first = false;
        throw stepUpError();
      }
      return name;
    }).then((v) => setDone((d) => [...d, v]));
  };
  return (
    <>
      <button onClick={() => { attempt('one'); attempt('two'); }}>go</button>
      <p data-testid="done">{done.sort().join(',')}</p>
    </>
  );
}

function stepUpError() {
  return new ApiError(403, {
    code: 'ALC-AUTH-0003', reason: 'auth.stepup_required', message_key: 'errors.auth.stepup_required',
    message: 'm', request_id: 'r', retryable: false,
  });
}

function Harness() {
  const { run } = useStepUp();
  const [result, setResult] = useState('');
  const go = async () => {
    try {
      await run(() => apiFetch('/api/v1/sensitive', { method: 'POST' }));
      setResult('done');
    } catch (e) {
      setResult(isApiError(e) ? `failed: ${e.reason}` : 'failed');
    }
  };
  return (
    <>
      <button onClick={() => void go()}>Do it</button>
      <output data-testid="result">{result}</output>
    </>
  );
}

async function renderHarness() {
  return renderApp(
    <MemoryRouter>
      <AuthProvider>
        <StepUpProvider>
          <Harness />
        </StepUpProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe('StepUpProvider', () => {
  it('runs directly when no step-up is needed', async () => {
    server.use(...sessionHandlers(sessionFor('admin')), http.post('/api/v1/sensitive', () => HttpResponse.json({})));
    await renderHarness();
    await userEvent.click(await screen.findByRole('button', { name: 'Do it' }));
    await waitFor(() => expect(screen.getByTestId('result')).toHaveTextContent('done'));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('asks for a code, survives a wrong one and retries with the renewed session', async () => {
    let attempts = 0;
    const csrfSeen: (string | null)[] = [];
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/sensitive', ({ request }) => {
        attempts += 1;
        csrfSeen.push(request.headers.get('X-CSRF-Token'));
        return attempts === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json({});
      }),
      http.post('/api/v1/auth/stepup', async ({ request }) => {
        const { code } = (await request.json()) as { code: string };
        return code === '111111'
          ? HttpResponse.json({ ...sessionFor('admin'), csrf_token: 'csrf-stepped-up' })
          : errorResponse(401, 'ALC-AUTH-0006', 'auth.mfa_invalid');
      }),
    );
    await renderHarness();
    await waitFor(() => expect(getCsrfToken()).toBe('csrf-admin'));
    await userEvent.click(screen.getByRole('button', { name: 'Do it' }));
    expect(await screen.findByRole('dialog', { name: "Confirm it's you" })).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText('6-digit code'), '000000');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText('The verification code is not correct.')).toBeInTheDocument();
    expect(screen.getByRole('dialog')).toBeInTheDocument();

    await userEvent.clear(screen.getByLabelText('6-digit code'));
    await userEvent.type(screen.getByLabelText('6-digit code'), '111111');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(screen.getByTestId('result')).toHaveTextContent('done'));
    expect(csrfSeen).toEqual(['csrf-admin', 'csrf-stepped-up']);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('retries exactly once: a second refusal ends the call after two requests and opens no second dialog', async () => {
    let calls = 0;
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/sensitive', () => {
        calls += 1;
        return errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required');
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    await renderHarness();
    await userEvent.click(await screen.findByRole('button', { name: 'Do it' }));
    await userEvent.type(await screen.findByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(screen.getByTestId('result')).toHaveTextContent('failed: auth.stepup_required'));
    expect(calls).toBe(2);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await new Promise((r) => setTimeout(r, 100));
    expect(calls).toBe(2);
  });

  it('gives up with the original error when the user cancels', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/sensitive', () => errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required')),
    );
    await renderHarness();
    await userEvent.click(await screen.findByRole('button', { name: 'Do it' }));
    await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.getByTestId('result')).toHaveTextContent('failed: auth.stepup_required'));
  });

  it('closes with the session: the dialog goes away, the wait gives up with the original error and the typed code is gone (AUD-25 d)', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/sensitive', () => errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required')),
      http.get('/api/v1/other', () => errorResponse(401, 'ALC-AUTH-0001', 'auth.unauthenticated')),
    );
    await renderHarness();
    await userEvent.click(await screen.findByRole('button', { name: 'Do it' }));
    await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.type(screen.getByLabelText('6-digit code'), '123');

    // Any request learns that the session ended (it expired or was revoked elsewhere).
    await act(async () => {
      await apiFetch('/api/v1/other').catch(() => undefined);
    });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await waitFor(() => expect(screen.getByTestId('result')).toHaveTextContent('failed: auth.stepup_required'));

    // Asked again later, the field starts empty.
    await userEvent.click(screen.getByRole('button', { name: 'Do it' }));
    await screen.findByRole('dialog', { name: "Confirm it's you" });
    expect(screen.getByLabelText('6-digit code')).toHaveValue('');
  });

  it('closes and gives up when the step-up itself finds the session ended', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/sensitive', () => errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required')),
      http.post('/api/v1/auth/stepup', () => errorResponse(401, 'ALC-AUTH-0001', 'auth.unauthenticated')),
    );
    await renderHarness();
    await userEvent.click(await screen.findByRole('button', { name: 'Do it' }));
    await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await waitFor(() => expect(screen.getByTestId('result')).toHaveTextContent('failed: auth.stepup_required'));
  });

  it('clears the typed code when the dialog is cancelled', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/sensitive', () => errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required')),
    );
    await renderHarness();
    await userEvent.click(await screen.findByRole('button', { name: 'Do it' }));
    await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.type(screen.getByLabelText('6-digit code'), '654');
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: 'Do it' }));
    await screen.findByRole('dialog', { name: "Confirm it's you" });
    expect(screen.getByLabelText('6-digit code')).toHaveValue('');
  });

  it('gives up a pending wait when the provider goes away', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/sensitive', () => errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required')),
    );
    let outcome = '';
    function Starter() {
      const { run } = useStepUp();
      return (
        <button onClick={() => void run(() => apiFetch('/api/v1/sensitive', { method: 'POST' })).catch((e) => (outcome = isApiError(e) ? e.reason : 'other'))}>
          start
        </button>
      );
    }
    const { unmount } = await renderApp(
      <MemoryRouter>
        <AuthProvider>
          <StepUpProvider>
            <Starter />
          </StepUpProvider>
        </AuthProvider>
      </MemoryRouter>,
    );
    await userEvent.click(await screen.findByRole('button', { name: 'start' }));
    await screen.findByRole('dialog', { name: "Confirm it's you" });
    unmount();
    await waitFor(() => expect(outcome).toBe('auth.stepup_required'));
  });

  it('asks once for concurrent calls and completes all of them', async () => {
    let stepUps = 0;
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/auth/stepup', () => {
        stepUps++;
        return HttpResponse.json(sessionFor('admin'));
      }),
    );
    const router = createMemoryRouter([
      { path: '/', element: <AuthProvider><StepUpProvider><Probe /></StepUpProvider></AuthProvider> },
    ]);
    await renderApp(<RouterProvider router={router} />);
    await userEvent.click(await screen.findByRole('button', { name: 'go' }));
    expect(await screen.findAllByRole('dialog')).toHaveLength(1);
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(screen.getByTestId('done')).toHaveTextContent('one,two'));
    expect(stepUps).toBe(1);
  });

  it('sends an SSO user to the identity provider instead of asking for a code', async () => {
    const go = vi.spyOn(navigation, 'goTo').mockImplementation(() => {});
    let attempts = 0;
    let next: unknown;
    server.use(
      ...sessionHandlers(ssoSessionFor('admin')),
      http.get('/api/v1/auth/oidc/providers', () => HttpResponse.json({ items: [{ id: 'p1', name: 'Corp IdP' }] })),
      http.post('/api/v1/sensitive', () => (++attempts === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json({}))),
      http.post('/api/v1/auth/oidc/stepup', async ({ request }) => {
        next = ((await request.json()) as { next: string }).next;
        return HttpResponse.json({ authorize_url: 'https://idp.example.com/authorize?state=su' });
      }),
    );
    await renderHarness();
    await userEvent.click(await screen.findByRole('button', { name: 'Do it' }));
    const dialog = await screen.findByRole('dialog', { name: 'Confirm at your identity provider' });
    expect(within(dialog).queryByLabelText('6-digit code')).not.toBeInTheDocument();
    await userEvent.click(await within(dialog).findByRole('button', { name: 'Continue to Corp IdP' }));
    await waitFor(() => expect(go).toHaveBeenCalledWith('https://idp.example.com/authorize?state=su'));
    expect(next).toBe(window.location.pathname + window.location.search);
    go.mockRestore();
  });

  it('shows the refusal when the step-up cannot be started, and lets the person cancel', async () => {
    const go = vi.spyOn(navigation, 'goTo').mockImplementation(() => {});
    server.use(
      ...sessionHandlers(ssoSessionFor('admin')),
      http.get('/api/v1/auth/oidc/providers', () => HttpResponse.json({ items: [] })),
      http.post('/api/v1/sensitive', () => errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required')),
      http.post('/api/v1/auth/oidc/stepup', () => errorResponse(403, 'ALC-SSO-0013', 'sso.provider_disabled')),
    );
    await renderHarness();
    await userEvent.click(await screen.findByRole('button', { name: 'Do it' }));
    const dialog = await screen.findByRole('dialog', { name: 'Confirm at your identity provider' });
    await userEvent.click(await within(dialog).findByRole('button', { name: 'Continue to your identity provider' }));
    expect(await within(dialog).findByRole('alert')).toBeInTheDocument();
    expect(go).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.getByTestId('result')).toHaveTextContent('failed: auth.stepup_required'));
    go.mockRestore();
  });
});
