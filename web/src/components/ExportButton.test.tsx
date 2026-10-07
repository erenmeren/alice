import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { errorResponse } from '../test/fixtures';
import { renderApp } from '../test/render';
import { server } from '../test/server';
import { ExportButton } from './ExportButton';

// The file is fetched first and saved only when the server answered with the CSV: an error body is shown, never saved as a file.
const saved: { blob: Blob; name: string }[] = [];
vi.mock('./saveBlob', () => ({ saveBlob: (blob: Blob, name: string) => saved.push({ blob, name }) }));

const csv = () => new HttpResponse('name\r\nweb\r\n', { headers: { 'Content-Type': 'text/csv; charset=utf-8' } });

describe('ExportButton', () => {
  beforeEach(() => {
    saved.length = 0;
    vi.useFakeTimers({ toFake: ['Date'], now: new Date('2026-10-07T12:00:00Z') });
  });
  afterEach(() => vi.useRealTimers());

  it('fetches the certificate export with the filters, dropping empty ones, and saves the CSV', async () => {
    let search = '';
    server.use(http.get('/api/v1/certificates/export', ({ request }) => {
      search = new URL(request.url).search;
      return csv();
    }));
    await renderApp(<ExportButton kind="certificates" filters={{ target_id: 't1', source: '', q: '', expiry: '30' }} />);
    await userEvent.setup({ advanceTimers: () => {} }).click(screen.getByRole('button', { name: 'Export' }));
    await waitFor(() => expect(saved).toHaveLength(1));
    expect(search).toBe('?target_id=t1&expiry=30');
    expect(saved[0].name).toBe('alice-certificates-2026-10-07.csv');
    expect(await saved[0].blob.text()).toBe('name\r\nweb\r\n');
  });

  it('fetches the SSH key export without filters', async () => {
    server.use(http.get('/api/v1/ssh-keys/export', () => csv()));
    await renderApp(<ExportButton kind="ssh-keys" filters={{ os_user: '' }} />);
    await userEvent.setup({ advanceTimers: () => {} }).click(screen.getByRole('button', { name: 'Export' }));
    await waitFor(() => expect(saved[0]?.name).toBe('alice-ssh-keys-2026-10-07.csv'));
  });

  it.each([
    [409, 'ALC-RPT-0001', 'export.too_large', { max: '50000' }, 'The export is too large.'],
    [409, 'ALC-RPT-0004', 'export.busy', undefined, 'Another export of yours is still running.'],
    [405, 'ALC-SYS-0009', 'system.method_not_allowed', undefined, 'This request method is not accepted here.'],
  ])('shows the error of a %i answer and saves no file (%s)', async (status, code, reason, params, text) => {
    server.use(http.get('/api/v1/certificates/export', () => errorResponse(status, code, reason, { params })));
    await renderApp(<ExportButton kind="certificates" filters={{}} />);
    await userEvent.setup({ advanceTimers: () => {} }).click(screen.getByRole('button', { name: 'Export' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(text as string);
    expect(saved).toHaveLength(0);
  });
});
