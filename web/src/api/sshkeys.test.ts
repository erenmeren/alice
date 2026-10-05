import { http, HttpResponse } from 'msw';
import { server } from '../test/server';
import { setCsrfToken } from './client';
import { deployKey, downloadPrivateKey, generateKey, getKeyFiles, KEY_TYPES } from './sshkeys';

describe('sshkeys api', () => {
  beforeEach(() => setCsrfToken('tok'));

  it('lists the four key types, Ed25519 first', () => {
    expect(KEY_TYPES).toEqual(['ed25519', 'rsa-3072', 'rsa-4096', 'ecdsa-p256']);
  });

  it('generates a key with the exact body', async () => {
    let body: unknown;
    server.use(
      http.post('/api/v1/ssh-keys/generate', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ id: 'k1', managed_key: {} }, { status: 201 });
      }),
    );
    await expect(generateKey({ label: 'ci', key_type: 'ed25519' })).resolves.toMatchObject({ id: 'k1' });
    expect(body).toEqual({ label: 'ci', key_type: 'ed25519' });
  });

  it('deploys a key to the escaped path', async () => {
    let body: unknown;
    server.use(
      http.post('/api/v1/ssh-keys/:id/actions/deploy', async ({ request, params }) => {
        body = { id: params.id, ...((await request.json()) as object) };
        return HttpResponse.json({ job_id: 'j1', status_url: '/api/v1/jobs/j1' }, { status: 202 });
      }),
    );
    await deployKey('a/b', { target_id: 't', os_user: 'deploy', file_path: '/home/deploy/.ssh/authorized_keys', restrict: true });
    expect(body).toEqual({ id: 'a/b', target_id: 't', os_user: 'deploy', file_path: '/home/deploy/.ssh/authorized_keys', restrict: true });
  });

  it('downloads the private key as a Blob and sends the reason and passphrase in the body', async () => {
    let body: unknown;
    server.use(
      http.post('/api/v1/ssh-keys/k1/actions/download-private-key', async ({ request }) => {
        body = await request.json();
        return new HttpResponse('file-bytes', { headers: { 'Content-Type': 'application/octet-stream' } });
      }),
    );
    const blob = await downloadPrivateKey('k1', { reason: 'a good reason', passphrase: 'twelve chars!' });
    expect(blob).toBeInstanceOf(Blob);
    expect(await blob.text()).toBe('file-bytes');
    expect(body).toEqual({ reason: 'a good reason', passphrase: 'twelve chars!' });
  });

  it('reads the key files of a server', async () => {
    server.use(http.get('/api/v1/targets/t1/key-files', () => HttpResponse.json({ items: [], scanned_at: null })));
    await expect(getKeyFiles('t1')).resolves.toEqual({ items: [], scanned_at: null });
  });
});
