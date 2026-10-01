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
