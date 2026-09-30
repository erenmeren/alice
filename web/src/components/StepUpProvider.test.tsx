import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { createMemoryRouter, RouterProvider } from 'react-router';
import { useState } from 'react';
import { ApiError } from '../api/client';
import { AuthProvider } from '../auth/AuthProvider';
import { sessionFor, sessionHandlers } from '../test/fixtures';
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

describe('StepUpProvider', () => {
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
