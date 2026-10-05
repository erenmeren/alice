import { buildSignIn, emptySignIn, MAX_PFX_BYTES, PfxTooLargeError, signInReady, wipeSecrets } from './signIn';

const base = { ...emptySignIn(), tenantId: ' t ', clientId: ' c ' };

describe('buildSignIn', () => {
  it('builds exactly the fields of each method', async () => {
    expect(await buildSignIn({ ...base, auth: 'client_secret', secret: 'fake-s', secretExpires: '2027-02-01' })).toEqual({
      auth: 'client_secret', tenant_id: 't', client_id: 'c', client_secret: 'fake-s', secret_expires_on: '2027-02-01T23:59:59Z',
    });
    expect(await buildSignIn({ ...base, auth: 'client_secret', secret: 'fake-s' })).toEqual({ auth: 'client_secret', tenant_id: 't', client_id: 'c', client_secret: 'fake-s' });
    expect(await buildSignIn({ ...base, auth: 'certificate', certFormat: 'pem', certPem: 'C', keyPem: 'K', secret: 'ignored' })).toEqual({ auth: 'certificate', tenant_id: 't', client_id: 'c', certificate_pem: 'C', private_key_pem: 'K' });
    expect(await buildSignIn({ ...base, auth: 'managed_identity', tenantId: 'x', secret: 'ignored' })).toEqual({ auth: 'managed_identity', client_id: 'c' });
    expect(await buildSignIn({ ...base, auth: 'managed_identity', clientId: '  ' })).toEqual({ auth: 'managed_identity' });
  });
  it('reads a PFX in memory as base64 and leaves out an empty password', async () => {
    const pfx = new File([new Uint8Array([0, 1, 2, 250, 255])], 'a.pfx');
    expect(await buildSignIn({ ...base, auth: 'certificate', certFormat: 'pfx', pfx })).toEqual({ auth: 'certificate', tenant_id: 't', client_id: 'c', pfx_base64: btoa(String.fromCharCode(0, 1, 2, 250, 255)) });
    expect((await buildSignIn({ ...base, auth: 'certificate', certFormat: 'pfx', pfx, pfxPassword: 'fake-p' })).pfx_password).toBe('fake-p');
    expect(await buildSignIn({ ...base, auth: 'certificate', certFormat: 'pfx', pfx: null })).toEqual({ auth: 'certificate', tenant_id: 't', client_id: 'c' });
  });
  it('refuses a PFX larger than the request can carry', async () => {
    await expect(buildSignIn({ ...base, auth: 'certificate', certFormat: 'pfx', pfx: new File([new Uint8Array(MAX_PFX_BYTES + 1)], 'big.pfx') })).rejects.toBeInstanceOf(PfxTooLargeError);
  });
});

describe('wipeSecrets and signInReady', () => {
  it('clears the secret, the private key, the PFX and its password, and nothing public', () => {
    const w = wipeSecrets({ ...base, secret: 's', keyPem: 'k', pfx: new File(['x'], 'a.pfx'), pfxPassword: 'p', certPem: 'C', secretExpires: '2027-01-01' });
    expect([w.secret, w.keyPem, w.pfx, w.pfxPassword]).toEqual(['', '', null, '']);
    expect([w.certPem, w.secretExpires, w.tenantId]).toEqual(['C', '2027-01-01', ' t ']);
  });
  it('is ready when the chosen method has what it needs', () => {
    expect(signInReady({ ...emptySignIn(), auth: 'managed_identity' })).toBe(true);
    expect(signInReady({ ...emptySignIn(), auth: 'client_secret', tenantId: 't', clientId: 'c' })).toBe(false);
    expect(signInReady({ ...emptySignIn(), auth: 'client_secret', tenantId: 't', clientId: 'c', secret: 's' })).toBe(true);
    expect(signInReady({ ...emptySignIn(), tenantId: 't', clientId: 'c', certPem: 'C' })).toBe(false);
    expect(signInReady({ ...emptySignIn(), tenantId: 't', clientId: 'c', certPem: 'C', keyPem: 'K' })).toBe(true);
    expect(signInReady({ ...emptySignIn(), tenantId: 't', clientId: 'c', certFormat: 'pfx' })).toBe(false);
  });
});
