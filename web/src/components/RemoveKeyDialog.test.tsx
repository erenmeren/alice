import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { vi } from 'vitest';
import { jobFixture, keyLocationFixture, sessionFor } from '../test/fixtures';
import { renderApp } from '../test/render';
import { server } from '../test/server';
import { RemoveKeyDialog } from './RemoveKeyDialog';

// The real timeout is two minutes; the test shortens it.
vi.mock('../api/jobs', async (orig) => {
  const actual = await orig<typeof import('../api/jobs')>();
  return { ...actual, waitForJob: (id: string, o = {}) => actual.waitForJob(id, { ...o, intervalMs: 1, timeoutMs: 5 }) };
});

vi.mock('../auth/AuthProvider', () => ({ useAuth: () => ({ session: sessionFor('operator') }) }));

describe('RemoveKeyDialog', () => {
  it('says that Alice is still working when the removal does not finish in time', async () => {
    server.use(
      http.post('/api/v1/ssh-keys/locations/:id/actions/remove', () => HttpResponse.json({ job_id: 'job-x', status_url: '/api/v1/jobs/job-x' }, { status: 202 })),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-x', type: 'sshkey.remove', status: 'running' }))),
    );
    await renderApp(<RemoveKeyDialog location={keyLocationFixture()} onClose={() => undefined} onDone={() => undefined} />);
    const dialog = await screen.findByRole('dialog', { name: 'Remove this key from the server?' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove key' }));
    expect(await within(dialog).findByText('Alice is still working on this. Open the server\'s page in a minute to see the result.')).toBeInTheDocument();
  });
});
