import { apiFetch, setCsrfToken } from './client';
import { ifMatch } from './settings';
import type { LoginResponse, Role, SessionInfo } from './types';

// Directory (LDAP or Active Directory) sign-in and settings (api/openapi.yaml, /auth/ldap/* and /ldap/*). The service account
// password, a sign-in password and a test password are request bodies only: never returned, never in a query key, an URL
// or storage.

export interface Directory {
  id: string;
  name: string;
  addresses: string[];
  user_base_dn: string;
  user_filter: string;
  login_attribute: string;
  unique_id_attribute: string;
  display_name_attribute: string;
  email_attribute: string;
  bind_dn: string;
  bind_password_set: boolean;
  group_base_dn: string;
  group_filter: string;
  group_name_attribute: string;
  ca_pem: string;
  mfa_required: boolean;
  enabled: boolean;
  version: number;
  created_at: string;
  updated_at: string;
}

// bind_password is write-only: absent keeps the stored one.
export interface DirectoryInput {
  name: string;
  addresses: string[];
  user_base_dn: string;
  user_filter: string;
  login_attribute: string;
  unique_id_attribute: string;
  display_name_attribute: string;
  email_attribute: string;
  bind_dn: string;
  bind_password?: string;
  group_base_dn: string;
  group_filter: string;
  group_name_attribute: string;
  ca_pem: string;
  mfa_required: boolean;
  enabled: boolean;
}

export interface DirectoryMapping {
  id: string;
  directory_id: string;
  group: string;
  role: Role;
  created_at: string;
}

export interface DirectoryTestResult {
  login: string;
  display_name: string;
  email: string;
  unique_id: string;
  groups: string[];
  role: Role | null;
}

export interface PublicDirectory {
  id: string;
  name: string;
}

// The fields whose change would send the stored service account password to another server or account: the server asks
// for the password again (422 on bind_password) when one of them changes.
export const PASSWORD_PROTECTED_FIELDS = ['addresses', 'bind_dn', 'unique_id_attribute', 'ca_pem'] as const;

const v1 = '/api/v1';
const enc = encodeURIComponent;

// Public: the sign-in page lists the switched-on directories before anybody is signed in.
export const listPublicDirectories = () => apiFetch<{ items: PublicDirectory[] }>(`${v1}/auth/ldap/directories`, { publicRoute: true });

// directoryLogin is the sign-in form's request for a directory: the answer is the local form's (a pending session for the
// MFA step, or signed_in with a full session).
export async function directoryLogin(id: string, username: string, password: string): Promise<LoginResponse> {
  const res = await apiFetch<LoginResponse>(`${v1}/auth/ldap/${enc(id)}/login`, { method: 'POST', body: { username, password }, publicRoute: true });
  setCsrfToken(res.csrf_token);
  return res;
}

// directoryStepUp confirms a directory user with the directory password (and the authenticator code when the directory asks
// for one). The server uses the directory sign-in name it stored at sign-in.
export const directoryStepUp = (body: { password: string; code?: string }) =>
  apiFetch<SessionInfo>(`${v1}/auth/ldap/stepup`, { method: 'POST', body });

export const listDirectories = () => apiFetch<{ items: Directory[] }>(`${v1}/ldap/directories`);
export const createDirectory = (body: DirectoryInput) => apiFetch<Directory>(`${v1}/ldap/directories`, { method: 'POST', body });
export const updateDirectory = (id: string, version: number, body: Partial<DirectoryInput>) =>
  apiFetch<Directory>(`${v1}/ldap/directories/${enc(id)}`, { method: 'PATCH', body, headers: ifMatch(version) });
export const deleteDirectory = (id: string, version: number) => apiFetch<void>(`${v1}/ldap/directories/${enc(id)}`, { method: 'DELETE', headers: ifMatch(version) });
export const testDirectoryConnection = (id: string) =>
  apiFetch<{ result: 'ok' }>(`${v1}/ldap/directories/${enc(id)}/actions/test-connection`, { method: 'POST', body: {} });
export const testDirectorySignIn = (id: string, username: string, password: string) =>
  apiFetch<DirectoryTestResult>(`${v1}/ldap/directories/${enc(id)}/actions/test-signin`, { method: 'POST', body: { username, password } });

export const listDirectoryMappings = (directoryId: string) => apiFetch<{ items: DirectoryMapping[] }>(`${v1}/ldap/group-mappings?directory_id=${enc(directoryId)}`);
export const createDirectoryMapping = (body: { directory_id: string; group: string; role: Role }) =>
  apiFetch<DirectoryMapping>(`${v1}/ldap/group-mappings`, { method: 'POST', body });
// The server checks that the directory holds the mapping, so the directory is part of the request.
export const deleteDirectoryMapping = (id: string, directoryId: string) =>
  apiFetch<void>(`${v1}/ldap/group-mappings/${enc(id)}?directory_id=${enc(directoryId)}`, { method: 'DELETE' });

// The two ready-made settings of the add/edit form. A preset only fills fields: nothing is sent until the form is saved,
// and the addresses, DNs, the service account and the password stay as typed.
export type DirectoryPreset = 'ad' | 'openldap';
export const DIRECTORY_PRESETS: Record<
  DirectoryPreset,
  Pick<DirectoryInput, 'login_attribute' | 'unique_id_attribute' | 'display_name_attribute' | 'email_attribute' | 'user_filter' | 'group_filter' | 'group_name_attribute'>
> = {
  ad: {
    login_attribute: 'sAMAccountName',
    unique_id_attribute: 'objectGUID',
    display_name_attribute: 'displayName',
    email_attribute: 'mail',
    user_filter: '(&(objectClass=user)(sAMAccountName={login}))',
    group_filter: '(member:1.2.840.113556.1.4.1941:={dn})',
    group_name_attribute: 'cn',
  },
  openldap: {
    login_attribute: 'uid',
    unique_id_attribute: 'entryUUID',
    display_name_attribute: 'cn',
    email_attribute: 'mail',
    user_filter: '(&(objectClass=inetOrgPerson)(uid={login}))',
    group_filter: '(member={dn})',
    group_name_attribute: 'cn',
  },
};

// directorySignInReason turns a refused directory sign-in into the one text the person sees: every 401 is the same generic
// refusal (the server answers them alike; the page never shows a variation), a 503 is "the directory cannot be used". Any
// other answer (a rate limit, a malformed form) returns null and is shown as it is.
export function directorySignInReason(status: number): 'ldap.signin_refused' | 'ldap.directory_unavailable' | null {
  if (status === 401) return 'ldap.signin_refused';
  if (status === 503) return 'ldap.directory_unavailable';
  return null;
}
