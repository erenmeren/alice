import { apiFetch, setCsrfToken } from './client';
import type {
  AdminEnrollmentRequest,
  ApiToken,
  AuditPage,
  AuditQuery,
  AuditReport,
  CreatedToken,
  LicenseDetail,
  LicenseStatus,
  LicenseUploadResult,
  LoginResponse,
  MfaEnrollment,
  MfaInput,
  SessionInfo,
  SessionWithCodes,
  SetupSessionResponse,
  SetupStatus,
  TokenCreateRequest,
  User,
  UserCreateRequest,
  UserUpdateRequest,
  VersionInfo,
  HostKey,
  Job,
  JobAccepted,
  JobPage,
  JobQuery,
  KeyLocation,
  PlatformKeyInfo,
  SSHKey,
  SSHKeyPage,
  SSHKeyQuery,
  Target,
  TargetCreated,
  TargetCreateRequest,
} from './types';

const v1 = '/api/v1';

// Setup wizard
export const getSetupStatus = () => apiFetch<SetupStatus>(`${v1}/setup/status`);

export async function startSetupSession(code: string): Promise<SetupSessionResponse> {
  const res = await apiFetch<SetupSessionResponse>(`${v1}/setup/session`, { method: 'POST', body: { code } });
  setCsrfToken(res.csrf_token);
  return res;
}

export const setSetupLanguage = (language: string) =>
  apiFetch<void>(`${v1}/setup/language`, { method: 'PUT', body: { language } });

export const startAdminEnrollment = (req: AdminEnrollmentRequest) =>
  apiFetch<MfaEnrollment>(`${v1}/setup/admin/enrollment`, { method: 'POST', body: req });

export const createAdmin = (code: string) =>
  apiFetch<SessionWithCodes>(`${v1}/setup/admin`, { method: 'POST', body: { code } });

export const setRecoveryPassphrase = (passphrase: string, passphraseConfirm: string) =>
  apiFetch<void>(`${v1}/setup/recovery-passphrase`, {
    method: 'POST',
    body: { passphrase, passphrase_confirm: passphraseConfirm },
  });

export const chooseEvaluation = () => apiFetch<SetupStatus>(`${v1}/setup/evaluation`, { method: 'POST' });

export const completeSetup = () => apiFetch<SetupStatus>(`${v1}/setup/complete`, { method: 'POST' });

// Authentication
export async function login(username: string, password: string): Promise<LoginResponse> {
  const res = await apiFetch<LoginResponse>(`${v1}/auth/login`, { method: 'POST', body: { username, password } });
  setCsrfToken(res.csrf_token);
  return res;
}

export const enrollMfa = () => apiFetch<MfaEnrollment>(`${v1}/auth/mfa/enroll`, { method: 'POST' });

export const verifyMfa = (input: MfaInput) =>
  apiFetch<SessionWithCodes>(`${v1}/auth/mfa/verify`, { method: 'POST', body: input });

export const getSession = () => apiFetch<SessionInfo>(`${v1}/auth/session`, { quietUnauthorized: true });

export const logout = () => apiFetch<void>(`${v1}/auth/logout`, { method: 'POST' });

export const stepUp = (code: string) => apiFetch<SessionInfo>(`${v1}/auth/stepup`, { method: 'POST', body: { code } });

export const changePassword = (currentPassword: string, newPassword: string) =>
  apiFetch<SessionInfo>(`${v1}/auth/password`, {
    method: 'POST',
    body: { current_password: currentPassword, new_password: newPassword },
  });

export const regenerateRecoveryCodes = () =>
  apiFetch<{ recovery_codes: string[] }>(`${v1}/auth/recovery-codes`, { method: 'POST' });

export const setMyLocale = (locale: string) => apiFetch<void>(`${v1}/auth/locale`, { method: 'PUT', body: { locale } });

export const getVersion = () => apiFetch<VersionInfo>(`${v1}/version`);

// Users (Admin)
export const listUsers = () => apiFetch<{ items: User[] }>(`${v1}/users`);

export const createUser = (req: UserCreateRequest) => apiFetch<User>(`${v1}/users`, { method: 'POST', body: req });

export const updateUser = (id: string, req: UserUpdateRequest) =>
  apiFetch<User>(`${v1}/users/${encodeURIComponent(id)}`, { method: 'PATCH', body: req });

export const resetUserMfa = (id: string) =>
  apiFetch<void>(`${v1}/users/${encodeURIComponent(id)}/actions/reset-mfa`, { method: 'POST' });

export const resetUserPassword = (id: string, password: string) =>
  apiFetch<void>(`${v1}/users/${encodeURIComponent(id)}/actions/reset-password`, {
    method: 'POST',
    body: { password },
  });

export const revokeUserSessions = (id: string) =>
  apiFetch<void>(`${v1}/users/${encodeURIComponent(id)}/actions/revoke-sessions`, { method: 'POST' });

// API tokens
export function listTokens(userId?: string): Promise<{ items: ApiToken[] }> {
  const q = userId ? `?user_id=${encodeURIComponent(userId)}` : '';
  return apiFetch<{ items: ApiToken[] }>(`${v1}/tokens${q}`);
}

export const createToken = (req: TokenCreateRequest) =>
  apiFetch<CreatedToken>(`${v1}/tokens`, { method: 'POST', body: req });

export const revokeToken = (id: string) =>
  apiFetch<void>(`${v1}/tokens/${encodeURIComponent(id)}`, { method: 'DELETE' });

// Audit log
export function listAudit(q: AuditQuery = {}): Promise<AuditPage> {
  const params = new URLSearchParams();
  if (q.limit) params.set('limit', String(q.limit));
  if (q.cursor) params.set('cursor', q.cursor);
  if (q.action) params.set('action', q.action);
  if (q.actor) params.set('actor', q.actor);
  if (q.result) params.set('result', q.result);
  const qs = params.toString();
  return apiFetch<AuditPage>(`${v1}/audit${qs ? `?${qs}` : ''}`);
}

export const verifyAudit = () => apiFetch<AuditReport>(`${v1}/audit/verify`, { method: 'POST' });

export const auditExportUrl = (format: 'csv' | 'json') => `${v1}/audit/export?format=${format}`;

// License
export const getLicenseStatus = () => apiFetch<LicenseStatus>(`${v1}/license/status`);

export const getLicense = () => apiFetch<LicenseDetail>(`${v1}/license`);

export const previewLicense = (license: string) =>
  apiFetch<LicenseUploadResult>(`${v1}/license/preview`, { method: 'POST', body: { license } });

export const installLicense = (license: string) =>
  apiFetch<LicenseUploadResult>(`${v1}/license`, { method: 'POST', body: { license } });

// Servers (targets) and host keys
const enc = encodeURIComponent;

export const listTargets = (cursor?: string | null) =>
  apiFetch<{ items: Target[]; next_cursor: string | null }>(`${v1}/targets${cursor ? `?cursor=${enc(cursor)}` : ''}`);

export const getTarget = (id: string) => apiFetch<Target>(`${v1}/targets/${enc(id)}`);

export const createTarget = (req: TargetCreateRequest) =>
  apiFetch<TargetCreated>(`${v1}/targets`, { method: 'POST', body: req });

export const deleteTarget = (id: string) => apiFetch<void>(`${v1}/targets/${enc(id)}`, { method: 'DELETE' });

export const testTarget = (id: string) =>
  apiFetch<JobAccepted>(`${v1}/targets/${enc(id)}/actions/test`, { method: 'POST' });

export const discoverTarget = (id: string) =>
  apiFetch<JobAccepted>(`${v1}/targets/${enc(id)}/actions/discover`, { method: 'POST' });

export const listHostKeys = (targetId: string) => apiFetch<{ items: HostKey[] }>(`${v1}/targets/${enc(targetId)}/host-keys`);

export const confirmHostKey = (targetId: string, keyId: string, fingerprint: string) =>
  apiFetch<JobAccepted>(`${v1}/targets/${enc(targetId)}/host-keys/${enc(keyId)}/actions/confirm`, {
    method: 'POST',
    body: { fingerprint },
  });

export const repinHostKey = (targetId: string, keyId: string, fingerprint: string, reason: string) =>
  apiFetch<JobAccepted>(`${v1}/targets/${enc(targetId)}/host-keys/${enc(keyId)}/actions/repin`, {
    method: 'POST',
    body: { fingerprint, reason },
  });

export const listTargetKeys = (targetId: string, missing = false) =>
  apiFetch<{ items: KeyLocation[] }>(`${v1}/targets/${enc(targetId)}/ssh-keys${missing ? '?missing=true' : ''}`);

// SSH keys
export function listSSHKeys(q: SSHKeyQuery = {}): Promise<SSHKeyPage> {
  const params = new URLSearchParams();
  if (q.target_id) params.set('target_id', q.target_id);
  if (q.os_user) params.set('os_user', q.os_user);
  if (q.q) params.set('q', q.q);
  if (q.flag) params.set('flag', q.flag);
  if (q.missing) params.set('missing', 'true');
  if (q.cursor) params.set('cursor', q.cursor);
  if (q.limit) params.set('limit', String(q.limit));
  const qs = params.toString();
  return apiFetch<SSHKeyPage>(`${v1}/ssh-keys${qs ? `?${qs}` : ''}`);
}

export const getSSHKey = (id: string) => apiFetch<SSHKey>(`${v1}/ssh-keys/${enc(id)}`);

export const getPlatformKey = () => apiFetch<PlatformKeyInfo>(`${v1}/ssh-keys/platform-key`);

export const removeKeyLocation = (id: string, confirmLastRootKey = false) =>
  apiFetch<JobAccepted>(`${v1}/ssh-keys/locations/${enc(id)}/actions/remove`, {
    method: 'POST',
    body: { confirm_last_root_key: confirmLastRootKey },
  });

// Jobs
export function listJobs(q: JobQuery = {}): Promise<JobPage> {
  const params = new URLSearchParams();
  if (q.status) params.set('status', q.status);
  if (q.target_id) params.set('target_id', q.target_id);
  if (q.cursor) params.set('cursor', q.cursor);
  const qs = params.toString();
  return apiFetch<JobPage>(`${v1}/jobs${qs ? `?${qs}` : ''}`);
}

export const getJob = (id: string) => apiFetch<Job>(`${v1}/jobs/${enc(id)}`);

export const confirmJob = (id: string) => apiFetch<Job>(`${v1}/jobs/${enc(id)}/actions/confirm`, { method: 'POST' });

export const discardJob = (id: string) => apiFetch<Job>(`${v1}/jobs/${enc(id)}/actions/discard`, { method: 'POST' });

// listAllTargets follows next_cursor until the list is complete (a guard stops a repeating cursor).
export async function listAllTargets(): Promise<{ items: Target[]; next_cursor: string | null }> {
  const items: Target[] = [];
  const seen = new Set<string>();
  let cursor: string | null = null;
  for (let page = 0; page < 100; page++) {
    const res = await listTargets(cursor);
    items.push(...res.items);
    cursor = res.next_cursor;
    if (!cursor || seen.has(cursor)) break;
    seen.add(cursor);
  }
  return { items, next_cursor: null };
}
