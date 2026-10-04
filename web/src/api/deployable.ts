import { listCertificates } from './endpoints';
import type { Certificate, CertificateLocation } from './types';

// The most websites one deploy request may name (openapi DeployRequest.location_ids maxItems).
export const MAX_DEPLOY_LOCATIONS = 20;

// Why a certificate cannot be deployed at all. The server refuses the same cases (ALC-CRT-0009,
// -0003, -0014); the client checks first so the choice never offers them.
export type CertificateBlock = 'no_key' | 'expired' | 'not_yet_valid';

export function certificateBlock(c: Pick<Certificate, 'has_private_key' | 'not_before' | 'not_after'>, now: number): CertificateBlock | null {
  if (!c.has_private_key) return 'no_key';
  if (Date.parse(c.not_after) <= now) return 'expired';
  if (Date.parse(c.not_before) > now) return 'not_yet_valid';
  return null;
}

// keyTypeFits: a place that reports its key type takes only a certificate of that type; a place
// that does not ('') takes an RSA or ECDSA one (the only types the server deploys; it still decides,
// ALC-CRT-0007 / -0010).
export function keyTypeFits(c: Pick<Certificate, 'key_algorithm'>, loc: Pick<CertificateLocation, 'key_type'>): boolean {
  if (loc.key_type === '') return c.key_algorithm === 'rsa' || c.key_algorithm === 'ecdsa'; // the only types a deployment takes
  return c.key_algorithm === loc.key_type;
}

// deployCandidates are the certificates a place can take: a private key in Alice, valid now, the
// right key type.
export function deployCandidates(certs: Certificate[], loc: CertificateLocation, now: number): Certificate[] {
  return certs.filter((c) => certificateBlock(c, now) === null && keyTypeFits(c, loc));
}

// MAX_CERTIFICATES bounds listAllCertificates (50 pages of 200).
export const MAX_CERTIFICATES = 10_000;

// listAllCertificates follows next_cursor (200 per page) so the choice sees every certificate; a
// repeating cursor ends the loop, and the list is cut (cut: true) after MAX_CERTIFICATES so the
// dialog can say so.
export async function listAllCertificates(): Promise<{ items: Certificate[]; cut: boolean }> {
  const items: Certificate[] = [];
  let cursor: string | null = null;
  const seen = new Set<string>();
  for (let page = 0; page < MAX_CERTIFICATES / 200; page++) {
    const res = await listCertificates({ limit: 200, cursor });
    items.push(...res.items);
    cursor = res.next_cursor;
    if (!cursor || seen.has(cursor)) return { items, cut: false };
    seen.add(cursor);
  }
  return { items, cut: true };
}
