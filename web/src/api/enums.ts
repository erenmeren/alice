import type { CertificateSource, CSRStatus, DeploymentStatus, KeyAlgorithm } from './types';

// Every enum the certificate API returns, with the label key the SPA shows for it. The lists are
// checked against api/openapi.yaml by enums.test.ts, which fails when the API gains a value that
// has no label in both languages.

export const CERTIFICATE_SOURCES: readonly CertificateSource[] = ['discovered', 'uploaded', 'csr', 'azure_kv'];
export const KEY_ALGORITHMS: readonly KeyAlgorithm[] = ['rsa', 'ecdsa', 'ed25519', 'other'];
export const CSR_STATUSES: readonly CSRStatus[] = ['pending', 'completed', 'cancelled'];
export const DEPLOYMENT_STATUSES: readonly DeploymentStatus[] = [
  'pending',
  'running',
  'succeeded',
  'unchanged',
  'failed',
  'rolled_back',
  'rollback_failed',
  'needs_attention',
];

// UPLOAD_WARNING_KEYS maps a warning code of an upload or a signing request's completion to its text.
// Source: internal/certs/upload.go (not_yet_valid, chain_incomplete, chain_certificate_expired) and
// internal/inventory/csr.go (csr_name_mismatch).
export const UPLOAD_WARNING_KEYS: Readonly<Record<string, string>> = {
  chain_incomplete: 'certificates.upload.chainWarning',
  chain_certificate_expired: 'certificates.upload.chainExpiredWarning',
  not_yet_valid: 'certificates.upload.notYetValid',
  csr_name_mismatch: 'certificates.upload.nameMismatchWarning',
};

// uploadWarningKey is the text for a warning code; a code from a newer server gets a generic text.
export function uploadWarningKey(code: string): string {
  return UPLOAD_WARNING_KEYS[code] ?? 'certificates.upload.otherWarning';
}

// keyAlgorithmKey is the label of a key algorithm code (ALC-CRT-0010 params carry raw codes).
export function keyAlgorithmKey(code: string): string {
  return `enum.keyAlgorithm.${KEY_ALGORITHMS.includes(code as KeyAlgorithm) ? code : 'other'}`;
}

// deploymentStatusKey is the label of a deployment status; '' (a status the server did not
// recognise) or a value from a newer server gets the neutral "Unknown".
export function deploymentStatusKey(status: string): string {
  return DEPLOYMENT_STATUSES.includes(status as DeploymentStatus) ? `enum.deploymentStatus.${status}` : 'enum.unknown';
}
