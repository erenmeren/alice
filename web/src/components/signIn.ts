import type { VaultAuth, VaultSignIn } from '../api/keyvault';

// The sign-in form of a vault (adding it or replacing its credentials). The client secret, the
// private key, the PFX file and its password exist only in this state, for the length of the form:
// they are sent once, wiped as soon as the request is built (wipeSecrets), and never go into a URL,
// a query key, an error, a log or storage.

export interface SignInState {
  auth: VaultAuth;
  tenantId: string;
  clientId: string;
  secret: string;
  secretExpires: string;
  certFormat: 'pem' | 'pfx';
  certPem: string;
  keyPem: string;
  pfx: File | null;
  pfxPassword: string;
}

export const emptySignIn = (): SignInState => ({
  auth: 'certificate',
  tenantId: '',
  clientId: '',
  secret: '',
  secretExpires: '',
  certFormat: 'pem',
  certPem: '',
  keyPem: '',
  pfx: null,
  pfxPassword: '',
});

// wipeSecrets clears what must not outlive the request: the secret, the private key, the PFX and
// its password. The certificate itself is public and stays, with the IDs and the dates.
export const wipeSecrets = (s: SignInState): SignInState => ({ ...s, secret: '', keyPem: '', pfx: null, pfxPassword: '' });

// MAX_PFX_BYTES keeps the request under the API's 768 KiB limit once the file is base64 text.
export const MAX_PFX_BYTES = 500_000;

export class PfxTooLargeError extends Error {
  constructor() {
    super('pfx too large');
    this.name = 'PfxTooLargeError';
  }
}

function toBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

// buildSignIn turns the state into the request fields the chosen method needs and nothing else. A
// PFX file is read in memory only.
export async function buildSignIn(s: SignInState): Promise<VaultSignIn> {
  const tenant = s.tenantId.trim();
  const client = s.clientId.trim();
  if (s.auth === 'managed_identity') return client ? { auth: 'managed_identity', client_id: client } : { auth: 'managed_identity' };
  const body: VaultSignIn = { auth: s.auth, tenant_id: tenant, client_id: client };
  if (s.auth === 'client_secret') {
    body.client_secret = s.secret;
    // The last second of the chosen day (UTC): "expires on" means the secret works that whole day.
    if (s.secretExpires) body.secret_expires_on = `${s.secretExpires}T23:59:59Z`;
    return body;
  }
  if (s.certFormat === 'pem') {
    body.certificate_pem = s.certPem;
    body.private_key_pem = s.keyPem;
    return body;
  }
  if (!s.pfx) return body;
  if (s.pfx.size > MAX_PFX_BYTES) throw new PfxTooLargeError();
  body.pfx_base64 = toBase64(new Uint8Array(await s.pfx.arrayBuffer()));
  if (s.pfxPassword) body.pfx_password = s.pfxPassword;
  return body;
}

// signInReady says whether the required fields of the chosen method are filled.
export function signInReady(s: SignInState): boolean {
  if (s.auth === 'managed_identity') return true;
  if (!s.tenantId.trim() || !s.clientId.trim()) return false;
  if (s.auth === 'client_secret') return s.secret !== '';
  return s.certFormat === 'pem' ? s.certPem.trim() !== '' && s.keyPem.trim() !== '' : s.pfx !== null;
}
