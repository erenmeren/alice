import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { errorResponse, operatorSession, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderApp } from '../test/render';
import { server } from '../test/server';
import { GenerateKeyDialog } from './GenerateKeyDialog';

describe('GenerateKeyDialog', () => {
  beforeEach(() => server.use(...sessionHandlers(operatorSession)));

  it('offers the four key types in order with Ed25519 preselected', async () => {
    await renderApp(<GenerateKeyDialog opened onClose={() => {}} onGenerated={() => {}} />);
    const radios = await screen.findAllByRole('radio');
    expect(radios.map((r) => (r as HTMLInputElement).value)).toEqual(['ed25519', 'rsa-3072', 'rsa-4096', 'ecdsa-p256']);
    expect(screen.getByRole('radio', { name: 'Ed25519 (recommended)' })).toBeChecked();
    expect(screen.getByRole('radio', { name: 'RSA 3072' })).not.toBeChecked();
    expect(screen.getByRole('radio', { name: 'ECDSA P-256' })).toBeInTheDocument();
    expect(screen.getByText('A name you recognise, for example the team or system that uses the key.')).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('sends the name and chosen type and reports the new key', async () => {
    let body: unknown;
    server.use(
      http.post('/api/v1/ssh-keys/generate', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ id: 'k9', managed_key: {} }, { status: 201 });
      }),
    );
    const onGenerated = vi.fn();
    await renderApp(<GenerateKeyDialog opened onClose={() => {}} onGenerated={onGenerated} />);
    await userEvent.type(await screen.findByLabelText(/^Name/), ' backup ');
    await userEvent.click(screen.getByRole('radio', { name: 'RSA 4096' }));
    await userEvent.click(screen.getByRole('button', { name: 'Generate' }));
    expect(await screen.findByText('Key generated. Alice keeps its private key encrypted.')).toBeInTheDocument();
    expect(body).toEqual({ label: 'backup', key_type: 'rsa-4096' });
    expect(onGenerated).toHaveBeenCalledWith('k9');
  });

  it('shows a field error from the server under the name and keeps the form', async () => {
    server.use(
      http.post('/api/v1/ssh-keys/generate', () =>
        errorResponse(422, 'ALC-SYS-0006', 'validation.failed', { details: [{ field: 'label', code: 'validation.required' }] }),
      ),
    );
    const onGenerated = vi.fn();
    await renderApp(<GenerateKeyDialog opened onClose={() => {}} onGenerated={onGenerated} />);
    await userEvent.type(await screen.findByLabelText(/^Name/), 'x');
    await userEvent.click(screen.getByRole('button', { name: 'Generate' }));
    expect(await screen.findByText('This field is required.')).toBeInTheDocument();
    expect(onGenerated).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Generate' })).toBeEnabled();
  });

  it('does not send an empty name', async () => {
    await renderApp(<GenerateKeyDialog opened onClose={() => {}} onGenerated={() => {}} />);
    expect(await screen.findByRole('button', { name: 'Generate' })).toBeDisabled();
  });
});
