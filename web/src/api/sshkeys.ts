import { apiFetch } from './client';
import type { ErrorRef, SSHKey } from './types';

export type KeyType = 'ed25519' | 'rsa-3072' | 'rsa-4096' | 'ecdsa-p256';
export const KEY_TYPES: KeyType[] = ['ed25519', 'rsa-3072', 'rsa-4096', 'ecdsa-p256'];

// ManagedKeyInfo is what Alice knows about a key it generated. It never carries the private key.
export interface ManagedKeyInfo {
  label: string;
  comment: string;
  key_type: KeyType;
  // created_by is null for a key a rotation generated (Alice itself).
  created_by: string | null;
  created_at: string;
  retired_at: string | null;
  destroyed_at: string | null;
  rotated_from: string | null;
  download_count: number;
  last_downloaded_at: string | null;
  policy_id: string | null;
  open_rotation_id: string | null;
}

// SSHKeyDetail is the key as the detail route answers it: the inventory key plus managed_key (null for a key
// Alice found on a server and for Alice's own connection key).
// hidden_count: locations on servers outside the reader's services, left out of locations (R49 Phase 2).
export type SSHKeyDetail = SSHKey & { managed_key: ManagedKeyInfo | null; hidden_count?: number };

export interface KeyFiles {
  items: { os_user: string; files: string[]; default_file: string }[];
  scanned_at: string | null;
  // refusal says why nothing can be offered on this server (sshkey.connection_files_unknown: scan it again); null when usable.
  refusal: ErrorRef | null;
}

export function generateKey(body: { label: string; key_type: KeyType }) {
  return apiFetch<{ id: string; managed_key: ManagedKeyInfo }>('/api/v1/ssh-keys/generate', { method: 'POST', body });
}

export function deployKey(id: string, body: { target_id: string; os_user: string; file_path: string; from?: string; restrict?: boolean }) {
  return apiFetch<{ job_id: string; status_url: string }>(`/api/v1/ssh-keys/${encodeURIComponent(id)}/actions/deploy`, { method: 'POST', body });
}

// downloadPrivateKey returns the OpenSSH file as a Blob. The passphrase travels only in this request body;
// the caller drops its copy as soon as this promise settles.
export function downloadPrivateKey(id: string, body: { reason: string; passphrase?: string }): Promise<Blob> {
  return apiFetch<Blob>(`/api/v1/ssh-keys/${encodeURIComponent(id)}/actions/download-private-key`, {
    method: 'POST',
    body,
    responseType: 'blob',
  });
}

export function getKeyFiles(targetId: string) {
  return apiFetch<KeyFiles>(`/api/v1/targets/${encodeURIComponent(targetId)}/key-files`);
}
