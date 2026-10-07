import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { adminSession, errorResponse, sessionHandlers } from '../../test/fixtures';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

const steppedUp = { ...adminSession, stepup_until: '2099-01-01T00:00:00Z' };

describe('AlertSettings', () => {
  it('edits the thresholds, one number each, and saves them', async () => {
    let sent: { body: unknown; ifMatch: string | null } | undefined;
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/alerts', () => HttpResponse.json({ thresholds_days: [30, 14, 7], version: 2 })),
      http.put('/api/v1/settings/alerts', async ({ request }) => {
        sent = { body: await request.json(), ifMatch: request.headers.get('If-Match') };
        return HttpResponse.json({ thresholds_days: [60, 30, 14, 1], version: 3 });
      }),
    );
    await renderRoute('/settings?tab=alerts');
    expect(await screen.findByLabelText('Threshold 1 (days)')).toHaveValue('30');
    await userEvent.click(screen.getByRole('button', { name: 'Remove threshold 3' }));
    await userEvent.click(screen.getByRole('button', { name: 'Add threshold' }));
    await userEvent.type(screen.getByLabelText('Threshold 3 (days)'), '1');
    await userEvent.clear(screen.getByLabelText('Threshold 1 (days)'));
    await userEvent.type(screen.getByLabelText('Threshold 1 (days)'), '60');
    await userEvent.click(screen.getByRole('button', { name: 'Save alert thresholds' }));
    await waitFor(() => expect(sent).toEqual({ ifMatch: '"2"', body: { thresholds_days: [60, 14, 1] } }));
    expect(await screen.findByText('Saved.')).toBeInTheDocument();
  });

  it('keeps between one and ten thresholds', async () => {
    server.use(...sessionHandlers(steppedUp), http.get('/api/v1/settings/alerts', () => HttpResponse.json({ thresholds_days: [30], version: 1 })));
    await renderRoute('/settings?tab=alerts');
    expect(await screen.findByRole('button', { name: 'Remove threshold 1' })).toBeDisabled();
    for (let i = 0; i < 9; i++) await userEvent.click(screen.getByRole('button', { name: 'Add threshold' }));
    expect(screen.getByRole('button', { name: 'Add threshold' })).toBeDisabled();
  });

  it('does not save while a threshold row is empty', async () => {
    server.use(...sessionHandlers(steppedUp), http.get('/api/v1/settings/alerts', () => HttpResponse.json({ thresholds_days: [30], version: 1 })));
    await renderRoute('/settings?tab=alerts');
    await userEvent.click(await screen.findByRole('button', { name: 'Add threshold' }));
    expect(screen.getByRole('button', { name: 'Save alert thresholds' })).toBeDisabled();
    await userEvent.type(screen.getByLabelText('Threshold 2 (days)'), '7');
    expect(screen.getByRole('button', { name: 'Save alert thresholds' })).toBeEnabled();
  });

  it('shows the refusal of a bad value', async () => {
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/alerts', () => HttpResponse.json({ thresholds_days: [30], version: 1 })),
      http.put('/api/v1/settings/alerts', () => errorResponse(422, 'ALC-SYS-0006', 'validation.failed', { details: [{ field: 'thresholds_days', code: 'validation.out_of_range', params: { min: '1', max: '365' } }] })),
    );
    await renderRoute('/settings?tab=alerts');
    await userEvent.click(await screen.findByRole('button', { name: 'Save alert thresholds' }));
    expect(await screen.findByText(/Enter a number from 1 to 365/)).toBeInTheDocument();
  });
});
