import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { useState } from 'react';
import { certificateDetailFixture, errorResponse, operatorSession, sessionHandlers } from '../test/fixtures';
import { renderApp } from '../test/render';
import { server } from '../test/server';
import { UploadCertificateDialog } from './UploadCertificateDialog';

const stored = (warnings: string[] = []) =>
  HttpResponse.json({ certificate: certificateDetailFixture({ id: 'c9' }), warnings }, { status: 201 });

function upload(handler: Parameters<typeof http.post>[1]) {
  server.use(...sessionHandlers(operatorSession), http.post('/api/v1/certificates/upload', handler));
}

async function fillPem(cert = 'CERT', key = 'KEY') {
  await userEvent.type(screen.getByLabelText('Certificate and chain (PEM)'), cert);
  await userEvent.type(screen.getByLabelText('Private key (PEM)'), key);
}

const pfxFile = (bytes: number[] | number = [1, 2, 3], name = 'site.pfx') =>
  new File([typeof bytes === 'number' ? new Uint8Array(bytes) : new Uint8Array(bytes)], name, { type: 'application/x-pkcs12' });

async function choosePfx(file: File) {
  await userEvent.click(screen.getByRole('radio', { name: 'PFX file' }));
  const input = document.querySelector<HTMLInputElement>('input[type="file"]')!;
  await userEvent.upload(input, file);
}

describe('UploadCertificateDialog', () => {
  it('uploads PEM text and shows the chain warning', async () => {
    let body: unknown;
    upload(async ({ request }) => {
      body = await request.json();
      return stored(['chain_incomplete']);
    });
    const onDone = vi.fn();
    await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={onDone} />);
    await fillPem();
    await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText('The chain is incomplete. An administrator must confirm before this certificate is deployed.'),
    ).toBeInTheDocument();
    expect(screen.getByText('Certificate uploaded.')).toBeInTheDocument();
    expect(body).toEqual({ certificate_pem: 'CERT', private_key_pem: 'KEY' });
    expect(onDone).toHaveBeenCalledWith('c9');
  });

  it.each([
    ['chain_certificate_expired', 'A certificate in the chain has expired. Browsers may refuse this certificate until the chain is replaced.'],
    ['not_yet_valid', 'This certificate is not valid yet. Websites would show an error until its start date.'],
  ])('shows the %s warning', async (code, text) => {
    upload(() => stored([code]));
    await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
    await fillPem();
    await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
    expect(await screen.findByText(text)).toBeInTheDocument();
  });

  it('sends the optional name only when it is filled in', async () => {
    let body: unknown;
    upload(async ({ request }) => {
      body = await request.json();
      return stored();
    });
    await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
    await fillPem();
    await userEvent.type(screen.getByLabelText('Name (optional)'), 'Shop');
    await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
    await screen.findByText('Certificate uploaded.');
    expect(body).toEqual({ label: 'Shop', certificate_pem: 'CERT', private_key_pem: 'KEY' });
  });

  it('shows the server message for a key that does not match and clears the key field', async () => {
    upload(() => errorResponse(422, 'ALC-CRT-0002', 'certificate.key_mismatch'));
    await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
    await fillPem();
    await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
    expect(await screen.findByText('The certificate does not match its private key.')).toBeInTheDocument();
    expect(screen.getByLabelText('Private key (PEM)')).toHaveValue('');
    expect(screen.getByLabelText('Certificate and chain (PEM)')).toHaveValue('CERT');
  });

  it('shows field problems named after the form fields', async () => {
    upload(() =>
      errorResponse(422, 'ALC-SYS-0006', 'validation.failed', { details: [{ field: 'certificate_pem', code: 'validation.key_in_certificate' }] }),
    );
    await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
    await fillPem('KEY-PASTED', 'KEY');
    await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
    expect(await screen.findByText(/Certificate: The certificate field contains a private key/)).toBeInTheDocument();
    // A private key that was pasted into the certificate field must not stay on screen.
    expect(screen.getByLabelText('Certificate and chain (PEM)')).toHaveValue('');
    expect(screen.getByLabelText('Private key (PEM)')).toHaveValue('');
    expect(document.body.innerHTML).not.toContain('KEY-PASTED');
  });

  it('has a secret warning and a password field that browsers do not remember', async () => {
    await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
    expect(screen.getByText('Paste a private key only into this form, never into a comment or reason field.')).toBeInTheDocument();
    const key = screen.getByLabelText('Private key (PEM)');
    expect(key).toHaveAttribute('autocomplete', 'off');
    expect(key).toHaveAttribute('spellcheck', 'false');
    expect(key).toHaveAttribute('data-gramm', 'false');
    expect(screen.getByLabelText('Name (optional)')).toHaveAttribute('autocomplete', 'off');
    await userEvent.click(screen.getByRole('radio', { name: 'PFX file' }));
    const password = screen.getByLabelText('PFX password');
    expect(password).toHaveAttribute('type', 'password');
    // Not a login credential: no "save" or "generate" offer from a password manager.
    expect(password).toHaveAttribute('autocomplete', 'off');
    expect(password).toHaveAttribute('data-1p-ignore');
    expect(password).toHaveAttribute('data-lpignore', 'true');
  });

  it('reads a PFX file as base64', async () => {
    let body: unknown;
    upload(async ({ request }) => {
      body = await request.json();
      return stored();
    });
    await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
    await choosePfx(pfxFile([1, 2, 3]));
    await userEvent.type(screen.getByLabelText('PFX password'), 'alice-test');
    await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
    await screen.findByText('Certificate uploaded.');
    expect(body).toEqual({ pfx_base64: 'AQID', pfx_password: 'alice-test' });
  });

  it('does not send the PEM fields when the PFX format is chosen, nor the PFX fields for PEM', async () => {
    const bodies: unknown[] = [];
    upload(async ({ request }) => {
      bodies.push(await request.json());
      return stored();
    });
    await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
    await fillPem('LEFTOVER', 'LEFTKEY');
    await choosePfx(pfxFile());
    await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
    await screen.findByText('Certificate uploaded.');
    expect(Object.keys(bodies[0] as object).sort()).toEqual(['pfx_base64', 'pfx_password']);
  });

  describe('client-side checks', () => {
    it('asks for the certificate and the key before sending anything', async () => {
      let sent = false;
      upload(() => {
        sent = true;
        return stored();
      });
      await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
      await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
      expect(await screen.findByText('Paste the certificate.')).toBeInTheDocument();
      expect(screen.getByText('Paste the private key.')).toBeInTheDocument();
      expect(sent).toBe(false);
    });

    it('asks for a PFX file', async () => {
      await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
      await userEvent.click(screen.getByRole('radio', { name: 'PFX file' }));
      await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
      expect(await screen.findByText('Choose a PFX file.')).toBeInTheDocument();
    });

    it('refuses a PFX file over 256 KiB without reading it or sending it', async () => {
      let sent = false;
      upload(() => {
        sent = true;
        return stored();
      });
      await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
      await choosePfx(pfxFile(256 * 1024 + 1, 'big.pfx'));
      await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
      expect(await screen.findByText('This file is larger than 256 KiB.')).toBeInTheDocument();
      expect(sent).toBe(false);
    });

    it('refuses pasted text over 256 KiB', async () => {
      let sent = false;
      upload(() => {
        sent = true;
        return stored();
      });
      await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
      const big = 'A'.repeat(256 * 1024 + 1);
      const cert = screen.getByLabelText('Certificate and chain (PEM)');
      await userEvent.click(cert);
      await userEvent.paste(big);
      await userEvent.type(screen.getByLabelText('Private key (PEM)'), 'KEY');
      await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
      expect(await screen.findByText('This text is longer than 256 KiB.')).toBeInTheDocument();
      expect(sent).toBe(false);
    });
  });

  describe('server refusals', () => {
    it('keeps the form and the file when Alice is busy reading PFX files, and says to try again', async () => {
      upload(() => errorResponse(503, 'ALC-CRT-0015', 'certificate.pfx_busy', { retryable: true }));
      await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
      await choosePfx(pfxFile());
      await userEvent.type(screen.getByLabelText('PFX password'), 'alice-test');
      await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
      expect(await screen.findByText('Alice is busy reading other PFX files.')).toBeInTheDocument();
      expect(screen.getByText('Wait a moment and upload the file again.')).toBeInTheDocument();
      expect(screen.getByLabelText('PFX password')).toHaveValue('alice-test');
      expect(screen.getByText('site.pfx')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Upload' })).toBeEnabled();
    });

    it('clears the PFX password but keeps the chosen file after a wrong password', async () => {
      upload(() => errorResponse(422, 'ALC-CRT-0005', 'certificate.pfx_password'));
      await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
      await choosePfx(pfxFile());
      await userEvent.type(screen.getByLabelText('PFX password'), 'wrong');
      await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
      expect(await screen.findByText('The PFX password is wrong or the file is damaged.')).toBeInTheDocument();
      expect(screen.getByLabelText('PFX password')).toHaveValue('');
      expect(screen.getByText('site.pfx')).toBeInTheDocument();
    });

    it('shows the server text for a refused upload (403), clears the key and keeps the form', async () => {
      upload(() => errorResponse(403, 'ALC-AUTH-0002', 'auth.forbidden'));
      await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
      await fillPem();
      await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
      expect(await screen.findByRole('alert')).toHaveTextContent('You do not have permission to do this.');
      expect(screen.getByLabelText('Private key (PEM)')).toHaveValue('');
      expect(screen.getByLabelText('Certificate and chain (PEM)')).toHaveValue('CERT');
      expect(screen.getByRole('button', { name: 'Upload' })).toBeEnabled();
    });

    it('keeps the whole form when the connection drops and says the upload may or may not have arrived', async () => {
      let calls = 0;
      upload(() => {
        calls += 1;
        return HttpResponse.error();
      });
      await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
      await fillPem();
      await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
      expect(await screen.findByText(/may or may not have reached Alice/)).toBeInTheDocument();
      expect(screen.getByLabelText('Private key (PEM)')).toHaveValue('KEY');
      expect(screen.getByLabelText('Certificate and chain (PEM)')).toHaveValue('CERT');
      await new Promise((r) => setTimeout(r, 50));
      expect(calls).toBe(1); // no automatic retry
    });

    it('shows a read failure of the chosen file and sends nothing', async () => {
      let sent = false;
      upload(() => {
        sent = true;
        return stored();
      });
      const spy = vi.spyOn(FileReader.prototype, 'readAsDataURL').mockImplementation(function (this: FileReader) {
        setTimeout(() => this.onerror?.(new ProgressEvent('error') as ProgressEvent<FileReader>), 0);
      });
      await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
      await choosePfx(pfxFile());
      await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
      expect(await screen.findByText('Alice could not read this file. Choose it again.')).toBeInTheDocument();
      expect(sent).toBe(false);
      spy.mockRestore();
    });

    it('explains a certificate Alice already holds', async () => {
      upload(() => errorResponse(409, 'ALC-CRT-0008', 'certificate.duplicate'));
      await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
      await fillPem();
      await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
      expect(await screen.findByText('Alice already has this certificate with its key.')).toBeInTheDocument();
    });
  });

  describe('private material stays in the dialog', () => {
    it('is gone from the screen after a success, and nothing is kept in the query cache', async () => {
      upload(async () => {
        await new Promise((r) => setTimeout(r, 20));
        return stored();
      });
      const { client } = await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
      await fillPem('CERT-PEM-TEXT', 'SECRET-KEY-TEXT');
      await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
      // While the request runs and after it settled, no mutation and no query holds the secret.
      const holdsSecret = () => JSON.stringify([...client.getMutationCache().getAll().map((m) => [m.options.mutationKey, m.state.variables]), ...client.getQueryCache().getAll().map((q) => [q.queryKey, q.state.data])]).includes('SECRET-KEY-TEXT');
      expect(holdsSecret()).toBe(false);
      await screen.findByText('Certificate uploaded.');
      expect(holdsSecret()).toBe(false);
      expect(client.getMutationCache().getAll()).toHaveLength(0);
      expect(screen.queryByLabelText('Private key (PEM)')).not.toBeInTheDocument();
      expect(document.body.innerHTML).not.toContain('SECRET-KEY-TEXT');
      expect(JSON.stringify({ ...localStorage })).not.toContain('SECRET-KEY-TEXT');
      expect(JSON.stringify({ ...sessionStorage })).not.toContain('SECRET-KEY-TEXT');
    });

    it('is cleared when the dialog is closed and opened again', async () => {
      function Host() {
        const [opened, setOpened] = useState(true);
        return (
          <>
            <button onClick={() => setOpened(true)}>reopen</button>
            <UploadCertificateDialog opened={opened} onClose={() => setOpened(false)} onUploaded={() => {}} />
          </>
        );
      }
      await renderApp(<Host />);
      await fillPem('CERT-PEM-TEXT', 'SECRET-KEY-TEXT');
      await userEvent.click(screen.getByRole('radio', { name: 'PFX file' }));
      await userEvent.type(screen.getByLabelText('PFX password'), 'SECRET-PASSWORD');
      await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
      await userEvent.click(screen.getByRole('button', { name: 'reopen' }));
      const dialog = await screen.findByRole('dialog');
      expect(within(dialog).getByLabelText('Private key (PEM)')).toHaveValue('');
      expect(within(dialog).getByLabelText('Certificate and chain (PEM)')).toHaveValue('');
      await userEvent.click(within(dialog).getByRole('radio', { name: 'PFX file' }));
      expect(within(dialog).getByLabelText('PFX password')).toHaveValue('');
      expect(within(dialog).getByText('Choose a .pfx or .p12 file')).toBeInTheDocument();
    });

    it('never writes the secrets to the console', async () => {
      const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => {}));
      upload(() => errorResponse(422, 'ALC-CRT-0002', 'certificate.key_mismatch'));
      await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
      await fillPem('CERT-PEM-TEXT', 'SECRET-KEY-TEXT');
      await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
      await screen.findByText('The certificate does not match its private key.');
      for (const s of spies) expect(JSON.stringify(s.mock.calls)).not.toContain('SECRET-KEY-TEXT');
      spies.forEach((s) => s.mockRestore());
    });
  });

  it('calls onClose from Cancel', async () => {
    const onClose = vi.fn();
    await renderApp(<UploadCertificateDialog opened onClose={onClose} onUploaded={() => {}} />);
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onClose).toHaveBeenCalled();
  });
});
