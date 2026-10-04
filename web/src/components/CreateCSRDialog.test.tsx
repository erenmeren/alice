import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { useState } from 'react';
import { csrFixture, errorResponse, operatorSession, sessionHandlers } from '../test/fixtures';
import { renderApp } from '../test/render';
import { server } from '../test/server';
import { CreateCSRDialog } from './CreateCSRDialog';
import { csrFileName } from './CSRPem';

describe('CreateCSRDialog', () => {
  it('creates a request from the names and shows its PEM to copy', async () => {
    let body: unknown;
    server.use(
      ...sessionHandlers(operatorSession),
      http.post('/api/v1/certificates/csr', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(csrFixture({ id: 'r9' }), { status: 201 });
      }),
    );
    const user = userEvent.setup();
    const onCreated = vi.fn();
    await renderApp(<CreateCSRDialog opened onClose={() => {}} onCreated={onCreated} />);
    await user.type(screen.getByLabelText('Main domain name'), 'www.example.test');
    await user.type(screen.getByLabelText('Other domain names (one per line)'), 'example.test\n\nshop.example.test ');
    await user.click(screen.getByRole('button', { name: 'Create request' }));
    expect(await screen.findByText('Signing request created. Copy it and send it to your certificate authority.')).toBeInTheDocument();
    expect(body).toEqual({ common_name: 'www.example.test', sans: ['example.test', 'shop.example.test'], key_type: 'ecdsa-p256' });
    expect(onCreated).toHaveBeenCalledWith(expect.objectContaining({ id: 'r9' }));
    const pem = screen.getByLabelText('Signing request (CSR)');
    expect(pem).toHaveAttribute('readonly');
    expect(pem).toHaveValue(csrFixture().csr_pem);
    await user.click(screen.getByRole('button', { name: 'Copy request' }));
    expect(await screen.findByRole('button', { name: 'Copied' })).toBeInTheDocument();
    expect(await navigator.clipboard.readText()).toBe(csrFixture().csr_pem);
    expect(screen.getByRole('button', { name: 'Download request' })).toBeInTheDocument();
  });

  it('offers the three key types, ECDSA first', async () => {
    let body: { key_type?: string } = {};
    server.use(
      ...sessionHandlers(operatorSession),
      http.post('/api/v1/certificates/csr', async ({ request }) => {
        body = (await request.json()) as typeof body;
        return HttpResponse.json(csrFixture(), { status: 201 });
      }),
    );
    await renderApp(<CreateCSRDialog opened onClose={() => {}} onCreated={() => {}} />);
    const select = screen.getByLabelText('Key type');
    expect(within(select).getAllByRole('option').map((o) => o.textContent)).toEqual(['ECDSA P-256 (recommended)', 'RSA 3072', 'RSA 4096']);
    await userEvent.selectOptions(select, 'rsa-3072');
    await userEvent.type(screen.getByLabelText('Main domain name'), 'a.example.test');
    await userEvent.click(screen.getByRole('button', { name: 'Create request' }));
    await screen.findByText(/Signing request created/);
    expect(body).toEqual({ common_name: 'a.example.test', sans: [], key_type: 'rsa-3072' });
  });

  it('asks for the main name and shows the server text for a name it refuses', async () => {
    server.use(
      ...sessionHandlers(operatorSession),
      http.post('/api/v1/certificates/csr', () =>
        errorResponse(422, 'ALC-VAL-0001', 'validation.failed', { details: [{ field: 'common_name', code: 'validation.pattern' }] }),
      ),
    );
    await renderApp(<CreateCSRDialog opened onClose={() => {}} onCreated={() => {}} />);
    await userEvent.click(screen.getByRole('button', { name: 'Create request' }));
    expect(screen.getByText('This field is required.')).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Main domain name'), 'not a name');
    await userEvent.click(screen.getByRole('button', { name: 'Create request' }));
    expect(await screen.findByText(/Main domain name: This value contains characters that are not allowed./)).toBeInTheDocument();
  });

  it('starts empty again after it was closed', async () => {
    function Host() {
      const [opened, setOpened] = useState(true);
      return (
        <>
          <button onClick={() => setOpened(true)}>reopen</button>
          <CreateCSRDialog opened={opened} onClose={() => setOpened(false)} onCreated={() => {}} />
        </>
      );
    }
    await renderApp(<Host />);
    await userEvent.type(screen.getByLabelText('Main domain name'), 'www.example.test');
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: 'reopen' }));
    expect(await screen.findByLabelText('Main domain name')).toHaveValue('');
  });

  it('names the downloaded file safely, also for a wildcard name', () => {
    expect(csrFileName('www.example.test')).toBe('www.example.test.csr');
    expect(csrFileName('*.example.test')).toBe('wildcard.example.test.csr');
    expect(csrFileName('../a b/ü*')).toBe('_a_b__wildcard.csr');
    expect(csrFileName('')).toBe('request.csr');
  });
});
