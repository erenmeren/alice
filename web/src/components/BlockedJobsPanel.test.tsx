import { screen, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { deploymentFixture, jobFixture, sessionFor, sessionHandlers, targetFixture } from '../test/fixtures';
import { renderWithAuth } from '../test/render';
import { server } from '../test/server';
import { BlockedJobsPanel } from './BlockedJobsPanel';

const held = (o: Parameters<typeof jobFixture>[0] = {}) => jobFixture({ status: 'blocked_license', finished_at: null, type: 'certificate.deploy', target_id: targetFixture.id, ...o });

function withJobs(items: ReturnType<typeof jobFixture>[], deployments = [deploymentFixture({ id: 'd-found', job_id: 'j-search', state: 'queued', status: 'pending', job_status: 'blocked_license' })]) {
  const searched: string[] = [];
  server.use(
    ...sessionHandlers(sessionFor('admin')),
    http.get('/api/v1/jobs', () => HttpResponse.json({ items, next_cursor: null })),
    http.get('/api/v1/deployments', ({ request }) => {
      searched.push(new URL(request.url).search);
      return HttpResponse.json({ items: deployments, next_cursor: null });
    }),
  );
  return searched;
}

describe('BlockedJobsPanel', () => {
  it('links a held deploy job to its deployment through the server\'s deployments while the job does not name it', async () => {
    const searched = withJobs([held({ id: 'j-search' })]);
    await renderWithAuth(<BlockedJobsPanel />);
    const row = await screen.findByTestId('blocked-job');
    expect(await within(row).findByRole('link', { name: 'Open this deployment' })).toHaveAttribute('href', '/deployments/d-found');
    expect(searched).toHaveLength(1);
    expect(searched[0]).toContain(`target_id=${targetFixture.id}`);
    expect(within(row).getByText(/Nothing has been sent to the server yet/)).toBeInTheDocument();
  });

  it('uses deployment_id when the job carries it, without searching the server\'s deployments', async () => {
    const searched = withJobs([held({ id: 'j-named', deployment_id: 'd-named' })]);
    await renderWithAuth(<BlockedJobsPanel />);
    const row = await screen.findByTestId('blocked-job');
    expect(within(row).getByRole('link', { name: 'Open this deployment' })).toHaveAttribute('href', '/deployments/d-named');
    expect(searched).toEqual([]);
  });

  it('lists a held Key Vault import and check by their names and offers Run now and Discard', async () => {
    withJobs([held({ id: 'j-imp', type: 'kv.import', target_id: null }), held({ id: 'j-poll', type: 'kv.poll' })]);
    await renderWithAuth(<BlockedJobsPanel />);
    const rows = await screen.findAllByTestId('blocked-job');
    expect(rows[0]).toHaveTextContent('Import into Key Vault');
    expect(rows[1]).toHaveTextContent('Key Vault check');
    expect(within(rows[0]).getByRole('button', { name: 'Run now: Import into Key Vault' })).toBeInTheDocument();
    expect(within(rows[0]).getByRole('button', { name: 'Discard: Import into Key Vault' })).toBeInTheDocument();
    expect(within(rows[0]).queryByRole('link')).not.toBeInTheDocument();
  });

  it('shows nothing when no job is held', async () => {
    withJobs([]);
    await renderWithAuth(<BlockedJobsPanel />);
    await screen.findByTestId('blocked-jobs').catch(() => undefined);
    expect(screen.queryByTestId('blocked-jobs')).not.toBeInTheDocument();
  });
});
