import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { useState } from 'react';
import { createMemoryRouter, MemoryRouter, RouterProvider } from 'react-router';
import { apiFetch, ApiError, getCsrfToken, isApiError } from '../api/client';
import { AuthProvider } from '../auth/AuthProvider';
import { errorResponse, sessionFor, sessionHandlers } from '../test/fixtures';
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
});
