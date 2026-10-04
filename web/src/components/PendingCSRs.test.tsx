import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { auditorSession, certificateDetailFixture, csrFixture, errorResponse, operatorSession, sessionHandlers } from '../test/fixtures';
import { renderApp } from '../test/render';
import { server } from '../test/server';
import { PendingCSRs } from './PendingCSRs';

const other = csrFixture({ id: 'r2', common_name: 'shop.example.test', sans: ['shop.example.test'] });
const done = csrFixture({ id: 'r3', common_name: 'done.example.test', status: 'completed' });

function csrs(items = [csrFixture(), other, done]) {
  server.use(http.get('/api/v1/certificates/csr', () => HttpResponse.json({ items })));
}

describe('PendingCSRs', () => {
  it('lists only the pending requests', async () => {
    server.use(...sessionHandlers(operatorSession));
    csrs();
    await renderApp(<PendingCSRs canOperate onCompleted={() => {}} />);
    expect(await screen.findByText('Open signing requests')).toBeInTheDocument();
    expect(screen.getByText('www.example.test, example.test')).toBeInTheDocument();
    expect(screen.getByText('shop.example.test')).toBeInTheDocument();
    expect(screen.queryByText('done.example.test')).not.toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Add signed certificate/ })).toHaveLength(2);
  });

  it('renders nothing when no request is pending', async () => {
    server.use(...sessionHandlers(operatorSession));
    csrs([done]);
    await renderApp(<PendingCSRs canOperate onCompleted={() => {}} />);
    await waitFor(() => expect(screen.queryByText('Open signing requests')).not.toBeInTheDocument());
  });

  it('adds the signed certificate to the right request', async () => {
    let seen: { path: string; body: unknown } | undefined;
    server.use(
      ...sessionHandlers(operatorSession),
      http.post('/api/v1/certificates/csr/:id/actions/complete', async ({ request, params }) => {
        seen = { path: String(params.id), body: await request.json() };
        return HttpResponse.json({ certificate: certificateDetailFixture({ id: 'c7' }), warnings: ['csr_name_mismatch'] }, { status: 201 });
      }),
    );
    csrs();
    const onCompleted = vi.fn();
    await renderApp(<PendingCSRs canOperate onCompleted={onCompleted} />);
    await userEvent.click((await screen.findAllByRole('button', { name: /Add signed certificate/ }))[1]);
    const dialog = await screen.findByRole('dialog', { name: 'Add the signed certificate' });
    expect(within(dialog).getByText(/Request: shop\.example\.test/)).toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText('Signed certificate and chain (PEM)'), 'SIGNED');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Add certificate' }));
    expect(
      await within(dialog).findByText('The domain names in the certificate differ from the signing request. Check that it is the certificate you ordered.'),
    ).toBeInTheDocument();
    expect(seen).toEqual({ path: 'r2', body: { certificate_pem: 'SIGNED' } });
    expect(within(dialog).getByText('Certificate added.')).toBeInTheDocument();
    // The result stays on screen until it is closed; only then the caller moves on.
    expect(onCompleted).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getAllByRole('button', { name: 'Close' })[0]);
    expect(onCompleted).toHaveBeenCalledWith('c7');
  });

  it('asks for the certificate before sending', async () => {
    server.use(...sessionHandlers(operatorSession));
    csrs();
    await renderApp(<PendingCSRs canOperate onCompleted={() => {}} />);
    await userEvent.click((await screen.findAllByRole('button', { name: /Add signed certificate/ }))[0]);
    await userEvent.click(await screen.findByRole('button', { name: 'Add certificate' }));
    expect(await screen.findByText('Paste the certificate.')).toBeInTheDocument();
  });

  it('shows the server text when the certificate is for another key, and keeps the text', async () => {
    server.use(
      ...sessionHandlers(operatorSession),
      http.post('/api/v1/certificates/csr/:id/actions/complete', () => errorResponse(422, 'ALC-CRT-0013', 'csr.certificate_mismatch')),
    );
    csrs();
    await renderApp(<PendingCSRs canOperate onCompleted={() => {}} />);
    await userEvent.click((await screen.findAllByRole('button', { name: /Add signed certificate/ }))[0]);
    await userEvent.type(await screen.findByLabelText('Signed certificate and chain (PEM)'), 'SIGNED');
    await userEvent.click(screen.getByRole('button', { name: 'Add certificate' }));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByLabelText('Signed certificate and chain (PEM)')).toHaveValue('SIGNED');
  });

  it('clears a private key pasted into the certificate field when the server refuses it', async () => {
    server.use(
      ...sessionHandlers(operatorSession),
      http.post('/api/v1/certificates/csr/:id/actions/complete', () =>
        errorResponse(422, 'ALC-SYS-0006', 'validation.failed', { details: [{ field: 'certificate_pem', code: 'validation.key_in_certificate' }] }),
      ),
    );
    csrs();
    await renderApp(<PendingCSRs canOperate onCompleted={() => {}} />);
    await userEvent.click((await screen.findAllByRole('button', { name: /Add signed certificate/ }))[0]);
    await userEvent.type(await screen.findByLabelText('Signed certificate and chain (PEM)'), 'PASTED-KEY');
    await userEvent.click(screen.getByRole('button', { name: 'Add certificate' }));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByLabelText('Signed certificate and chain (PEM)')).toHaveValue('');
  });

  it('cancels a request only after a confirmation, and keeps it on "Keep request"', async () => {
    let cancelled: string | undefined;
    let list = [csrFixture(), other];
    server.use(
      ...sessionHandlers(operatorSession),
      http.get('/api/v1/certificates/csr', () => HttpResponse.json({ items: list })),
      http.post('/api/v1/certificates/csr/:id/actions/cancel', ({ params }) => {
        cancelled = String(params.id);
        list = [csrFixture()];
        return HttpResponse.json(csrFixture({ id: 'r2', status: 'cancelled' }));
      }),
    );
    await renderApp(<PendingCSRs canOperate onCompleted={() => {}} />);
    await userEvent.click((await screen.findAllByRole('button', { name: /Cancel request/ }))[1]);
    let dialog = await screen.findByRole('dialog', { name: 'Cancel this signing request?' });
    expect(within(dialog).getByText('You can no longer add a certificate for this request.')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Keep request' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(cancelled).toBeUndefined();
    await userEvent.click((await screen.findAllByRole('button', { name: /Cancel request/ }))[1]);
    dialog = await screen.findByRole('dialog', { name: 'Cancel this signing request?' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel request' }));
    await waitFor(() => expect(cancelled).toBe('r2'));
    await waitFor(() => expect(screen.queryByText('shop.example.test')).not.toBeInTheDocument());
  });

  it('shows the server text when the request is no longer pending', async () => {
    server.use(
      ...sessionHandlers(operatorSession),
      http.post('/api/v1/certificates/csr/:id/actions/cancel', () => errorResponse(409, 'ALC-CRT-0012', 'csr.not_pending')),
    );
    csrs();
    await renderApp(<PendingCSRs canOperate onCompleted={() => {}} />);
    await userEvent.click((await screen.findAllByRole('button', { name: /Cancel request/ }))[0]);
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel request' }));
    expect(await within(dialog).findByRole('alert')).toBeInTheDocument();
  });

  it('shows no operating actions when the user cannot operate, but still lets them see a request', async () => {
    server.use(...sessionHandlers(auditorSession));
    csrs();
    await renderApp(<PendingCSRs canOperate={false} onCompleted={() => {}} />);
    expect(await screen.findByText('shop.example.test')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Add signed certificate/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Cancel request/ })).not.toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Show request/ })).toHaveLength(2);
  });

  it('shows a pending request again with its PEM to copy and download', async () => {
    server.use(...sessionHandlers(auditorSession));
    csrs();
    const user = userEvent.setup();
    await renderApp(<PendingCSRs canOperate={false} onCompleted={() => {}} />);
    await user.click((await screen.findAllByRole('button', { name: /Show request/ }))[0]);
    const dialog = await screen.findByRole('dialog', { name: 'Signing request (CSR)' });
    const pem = within(dialog).getByLabelText('Signing request (CSR)');
    expect(pem).toHaveAttribute('readonly');
    expect(pem).toHaveValue(csrFixture().csr_pem);
    await user.click(within(dialog).getByRole('button', { name: 'Copy request' }));
    expect(await within(dialog).findByRole('button', { name: 'Copied' })).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Download request' })).toBeInTheDocument();
  });

  it('shows the server text for a refused cancel (403) and keeps the dialog', async () => {
    server.use(
      ...sessionHandlers(operatorSession),
      http.post('/api/v1/certificates/csr/:id/actions/cancel', () => errorResponse(403, 'ALC-AUTH-0002', 'auth.forbidden')),
    );
    csrs();
    await renderApp(<PendingCSRs canOperate onCompleted={() => {}} />);
    await userEvent.click((await screen.findAllByRole('button', { name: /Cancel request/ }))[0]);
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel request' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('You do not have permission to do this.');
    expect(within(dialog).getByRole('button', { name: 'Cancel request' })).toBeEnabled();
    expect(within(dialog).getByRole('button', { name: 'Keep request' })).toBeInTheDocument();
  });
});
