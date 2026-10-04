import type { Warning } from './types';

// Server-level warnings of a scan (Target.facts.warnings): the text key is warnings.<code> and the
// list says which parameters the text needs. Some helper warnings come with and without a
// parameter (unsupported_path without a path, sshd_unreadable without a user) and have their own
// text; a missing parameter would show a raw {{placeholder}}, so a warning without its details,
// and a code this version does not know, get a generic text plus the code.
//
// Sources: internal/providers/linuxssh/helperproto (the SSH ones), internal/providers/types.go
// (Warn*), internal/providers/nginx (warning("...")) and internal/jobs/targetjobs (nginx_*); the
// completeness test reads them.
export const WARNING_PARAMS: Readonly<Record<string, readonly string[]>> = {
  keys_managed_elsewhere: [],
  keys_managed_elsewhere_user: ['user'],
  certificates_in_use: [],
  pubkey_disabled: [],
  sshd_unreadable: [],
  sshd_unreadable_user: ['user'],
  strict_modes: ['path'],
  unsupported_path: ['path'],
  unsupported_path_unnamed: [],
  file_unreadable: ['path'],
  file_unparseable: ['path', 'user'],
  file_too_large: ['path'],
  directory_users_not_listed: [],
  too_many_users: [],
  // Alice's warnings for the accounts the helper could not list (protocol 6, AUD-03): the uid only,
  // the name may hold any byte. Only a broken helper sends one without its uid (the neutral text).
  account_name_unsupported: ['uid'],
  account_home_unsupported: ['uid'],
  account_id_unsupported: ['uid'],
  accounts_nul_byte: [],
  // list_truncated from a cut SSH listing names the account it stopped at.
  list_truncated_uid: ['uid'],
  // Key Vault: items of a listing Alice could not use.
  kv_item_unreadable: ['object', 'count'],
  // Nginx servers
  nginx_not_found: [],
  nginx_profile_missing: [],
  nginx_config_invalid: [],
  locations_dropped: [],
  list_truncated: [],
  too_many_files: [],
  stream_tls: [],
  mail_tls: [],
  config_file_writable: ['path'],
  key_mode_open: [],
  symlinked: [],
  custom_location: [],
  key_group_open: [],
  certificate_block_dropped: [],
};

export function warningKey(w: Warning): string {
  let code = w.code;
  if (code === 'unsupported_path' && !w.params.path) code = 'unsupported_path_unnamed';
  if (code === 'keys_managed_elsewhere' && w.params.user) code = 'keys_managed_elsewhere_user';
  if (code === 'sshd_unreadable' && w.params.user) code = 'sshd_unreadable_user';
  if (code === 'list_truncated' && w.params.uid) code = 'list_truncated_uid';
  const need = WARNING_PARAMS[code];
  if (!need) return 'warnings.unknown';
  return need.every((p) => w.params[p]) ? `warnings.${code}` : 'warnings.incomplete';
}

// LOCATION_WARNINGS are the codes of CertificateLocation.warnings, with the parameters their text
// takes from the location itself (mode from key_mode, site from the website's name).
// Source: internal/providers/types.go (Warn*) and internal/inventory/locations.go.
export const LOCATION_WARNINGS: Readonly<Record<string, readonly string[]>> = {
  key_mode_open: ['mode'],
  symlinked: [],
  custom_location: [],
  key_group_open: [],
  certificate_block_dropped: [],
  list_truncated: [],
  certificate_expired: [],
  san_mismatch: ['site'],
  config_file_writable: [],
  stream_tls: [],
  mail_tls: [],
  chain_unresolved: [],
};

// locationWarningKey is the text key of a location warning; a code from a newer server gets the
// generic text (never a raw code in a sentence).
export function locationWarningKey(code: string): string {
  return code in LOCATION_WARNINGS ? `locations.warnings.${code}` : 'locations.warnings.unknown';
}
