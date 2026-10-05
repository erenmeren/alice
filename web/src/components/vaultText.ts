import type { Target } from '../api/types';
import type { VaultAuth } from '../api/keyvault';

// vaultNameOf is the vault's name in a typed address ("contoso-prod", "contoso-prod.vault.azure.net"
// or "https://contoso-prod.vault.azure.net/"); '' when there is nothing usable yet. It only decides
// what the commands show: the server validates the address.
export function vaultNameOf(input: string): string {
  const s = input.trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  const name = s.replace(/\.vault\.azure\.net$/i, '');
  return /^[A-Za-z0-9-]{3,24}$/.test(name) ? name : '';
}

// vaultStatusKey is the text key of a vault's status (the contract's UI copy): a vault that works partly
// because it may not list certificates, or whose credentials expired, says so in its own words.
export function vaultStatusKey(t: Pick<Target, 'status' | 'last_error' | 'vault'>): string {
  const reason = t.last_error?.reason ?? '';
  const listForbidden = t.vault?.access?.checks.some((c) => c.name === 'list_certificates' && c.result === 'forbidden') ?? false;
  if (t.status === 'degraded') return reason === 'azure.forbidden' && listForbidden ? 'vaults.status.noCertPermission' : 'vaults.status.degraded';
  if (t.status === 'auth_failed') return reason === 'azure.credentials_expired' ? 'vaults.status.credentialsExpired' : 'vaults.status.auth_failed';
  if (t.status === 'unreachable') return 'vaults.status.unreachable';
  return `enum.targetStatus.${t.status}`;
}

export const authKey = (a: VaultAuth | string): string => (a === 'certificate' || a === 'client_secret' || a === 'managed_identity' ? `vaults.auth.${a}` : 'enum.unknown');

// shortVersion is the first eight hex digits of a vault version ID, as the screens show it.
export const shortVersion = (v: string): string => v.slice(0, 8);

// An object seen by Alice recently: the current version was made in the vault after Alice first saw the
// certificate, within the last seven days. A UI cue only; the versions table has the facts.
const WEEK_MS = 7 * 86_400_000;
export function isRecentNewVersion(createdAt: string | null, firstSeenAt: string, now: number): boolean {
  if (!createdAt) return false;
  const created = Date.parse(createdAt);
  return !Number.isNaN(created) && created > Date.parse(firstSeenAt) && now - created < WEEK_MS;
}

// keyTypeParam maps a vault certificate's key type as Azure writes it (RSA, EC, RSA-HSM, ...) to the
// filter of the websites list; '' when it is neither (the list then shows every website).
export function keyTypeParam(keyType: string): 'rsa' | 'ecdsa' | '' {
  if (/^rsa/i.test(keyType)) return 'rsa';
  if (/^ec/i.test(keyType)) return 'ecdsa';
  return '';
}

export type VersionBlock = 'noDetails' | 'disabled' | 'expired' | 'notYetValid' | 'notExportable' | null;

// versionBlock is why Deploy now cannot work for a version (the API refuses it too): Alice has no
// details of it yet, it is disabled in the vault, expired, not valid yet or its key is not exportable.
export function versionBlock(v: { certificate_id: string | null; enabled: boolean; expires: string | null; not_before: string | null; exportable: boolean | null }, now: number): VersionBlock {
  if (v.certificate_id === null) return 'noDetails';
  if (!v.enabled) return 'disabled';
  if (v.expires && Date.parse(v.expires) <= now) return 'expired';
  if (v.not_before && Date.parse(v.not_before) > now) return 'notYetValid';
  if (v.exportable === false) return 'notExportable';
  return null;
}
