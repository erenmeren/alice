import { apiFetch, setCsrfToken } from './client';
import { addServiceFilter } from './services';
import type { SSHKeyDetail } from './sshkeys';
import type { AdminEnrollmentRequest, ApiToken, AuditPage, AuditQuery, AuditReport, Backup, BackupList, BackupSchedule, Certificate, CertificateDetail, CertificateLocation, CertificateLocationList, CertificateQuery, CreatedToken, CSR, CSRCreateRequest, Deployment, DeploymentDetail, DeploymentQuery, DeployResult, Forwarding, ForwardingInput, HostKey, HTTPSInfo, HTTPSUpload, Job, JobAccepted, JobPage, JobQuery, KeyLocation, LicenseDetail, LicenseStatus, LicenseUploadResult, LocationPatch, LoginResponse, MfaEnrollment, MfaInput, PlatformKeyInfo, Rollout, SessionInfo, SessionWithCodes, SetupSessionResponse, SetupStatus, SSHKeyPage, SSHKeyQuery, Target, TargetCreated, TargetCreateRequest, TargetType, TokenCreateRequest, UploadRequest, UploadResult, User, UserCreateRequest, UserUpdateRequest, VersionInfo } from './types';

const v1 = '/api/v1';

// Setup wizard
// Public route: it never carries the activity mark (AUD-01), so the session probe that runs beside
// it on a page load gets the page load's mark.
export const getSetupStatus = () => apiFetch<SetupStatus>(`${v1}/setup/status`, { publicRoute: true });

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

// Phase 8 wizard steps (C12): keep the temporary certificate, skip the mail server. Both need settings.manage.
export const keepTemporaryCertificate = () => apiFetch<SetupStatus>(`${v1}/setup/https/keep-temporary`, { method: 'POST' });
export const skipMail = () => apiFetch<SetupStatus>(`${v1}/setup/mail/skip`, { method: 'POST' });

// Phase 8 backups (C12). The download is fetched as a Blob (never through the query cache), so a refusal (429, 404, an
// expired step-up) is an ApiError the page shows instead of a replaced tab.
const ifMatchVersion = (version: number) => ({ 'If-Match': `"${version}"` });
export const listBackups = () => apiFetch<BackupList>(`${v1}/backups`);
export const createBackup = () => apiFetch<Backup>(`${v1}/backups`, { method: 'POST' });
export const downloadBackup = (name: string) => apiFetch<Blob>(`${v1}/backups/${enc(name)}/download`, { responseType: 'blob' });
export const getBackupSchedule = () => apiFetch<BackupSchedule>(`${v1}/settings/backups`);
export const saveBackupSchedule = (version: number, body: Pick<BackupSchedule, 'time' | 'zone' | 'retention'>) =>
  apiFetch<BackupSchedule>(`${v1}/settings/backups`, { method: 'PUT', body, headers: ifMatchVersion(version) });

// Phase 8 HTTPS certificate and audit forwarding (C12). The upload and the CA PEM are request bodies only.
export const getHTTPSInfo = () => apiFetch<HTTPSInfo>(`${v1}/settings/https`);
export const uploadHTTPSCertificate = (body: HTTPSUpload) => apiFetch<HTTPSInfo>(`${v1}/settings/https`, { method: 'PUT', body });
export const getForwarding = () => apiFetch<Forwarding>(`${v1}/settings/audit-forwarding`);
export const saveForwarding = (version: number, body: ForwardingInput) =>
  apiFetch<Forwarding>(`${v1}/settings/audit-forwarding`, { method: 'PUT', body, headers: ifMatchVersion(version) });
export const testForwarding = (body: ForwardingInput) => apiFetch<void>(`${v1}/settings/audit-forwarding/test`, { method: 'POST', body });

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

// unlockDirectorySignIn ends a directory user's sign-in lockout after failed directory passwords.
export const unlockDirectorySignIn = (id: string) =>
  apiFetch<void>(`${v1}/users/${encodeURIComponent(id)}/actions/unlock-directory-sign-in`, { method: 'POST' });

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
export const getLicenseStatus = (opts: { keepalive?: boolean } = {}) => apiFetch<LicenseStatus>(`${v1}/license/status`, opts);

export const getLicense = () => apiFetch<LicenseDetail>(`${v1}/license`);

export const previewLicense = (license: string) =>
  apiFetch<LicenseUploadResult>(`${v1}/license/preview`, { method: 'POST', body: { license } });

export const installLicense = (license: string) =>
  apiFetch<LicenseUploadResult>(`${v1}/license`, { method: 'POST', body: { license } });

// Servers (targets) and host keys
const enc = encodeURIComponent;

export function listTargets(cursor?: string | null, type?: TargetType) {
  const params = new URLSearchParams();
  if (type) params.set('type', type);
  if (cursor) params.set('cursor', cursor);
  const qs = params.toString();
  return apiFetch<{ items: Target[]; next_cursor: string | null }>(`${v1}/targets${qs ? `?${qs}` : ''}`);
}

export const getTarget = (id: string) => apiFetch<Target>(`${v1}/targets/${enc(id)}`);

// setCertificateCleanup changes a server's switch "remove certificates Alice imported once nothing uses them" (R62).
// Only a server whose capabilities include cleanup_certificates takes it (422 otherwise); version is the server's
// current version (If-Match).
export const setCertificateCleanup = (id: string, certificateCleanup: boolean, version: number) =>
  apiFetch<Target>(`${v1}/targets/${enc(id)}`, { method: 'PATCH', body: { certificate_cleanup: certificateCleanup }, headers: ifMatchVersion(version) });

export const createTarget = (req: TargetCreateRequest) =>
  apiFetch<TargetCreated>(`${v1}/targets`, { method: 'POST', body: req });

export const deleteTarget = (id: string) => apiFetch<void>(`${v1}/targets/${enc(id)}`, { method: 'DELETE' });

// testTarget tests a server's SSH connection; for a Key Vault the optional body asks the access check to
// read one certificate's secret as well (read_secret_of).
export const testTarget = (id: string, body?: { read_secret_of?: string }) =>
  apiFetch<JobAccepted>(`${v1}/targets/${enc(id)}/actions/test`, body ? { method: 'POST', body } : { method: 'POST' });

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
  addServiceFilter(params, q);
  if (q.cursor) params.set('cursor', q.cursor);
  if (q.limit) params.set('limit', String(q.limit));
  const qs = params.toString();
  return apiFetch<SSHKeyPage>(`${v1}/ssh-keys${qs ? `?${qs}` : ''}`);
}

export const getSSHKey = (id: string) => apiFetch<SSHKeyDetail>(`${v1}/ssh-keys/${enc(id)}`);

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
// type narrows it to one kind (the Key Vaults page asks for azure_key_vault).
export async function listAllTargets(type?: TargetType): Promise<{ items: Target[]; next_cursor: string | null }> {
  const items: Target[] = [];
  const seen = new Set<string>();
  let cursor: string | null = null;
  for (let page = 0; page < 100; page++) {
    const res = await listTargets(cursor, type);
    items.push(...res.items);
    cursor = res.next_cursor;
    if (!cursor || seen.has(cursor)) break;
    seen.add(cursor);
  }
  return { items, next_cursor: null };
}

// listAllServers is the servers only (Linux and web servers): a Key Vault is a target too, but it has its own page.
export async function listAllServers(): Promise<{ items: Target[]; next_cursor: string | null }> {
  const all = await listAllTargets();
  return { items: all.items.filter((t) => t.type !== 'azure_key_vault'), next_cursor: null };
}

// Certificates (Phase 4)
// The query string order is fixed (target_id, source, q, expiry, cursor, limit; empty values omitted).
export function listCertificates(q: CertificateQuery = {}): Promise<{ items: Certificate[]; next_cursor: string | null }> {
  const params = new URLSearchParams();
  if (q.target_id) params.set('target_id', q.target_id);
  if (q.source) params.set('source', q.source);
  if (q.q) params.set('q', q.q);
  if (q.expiry) params.set('expiry', q.expiry);
  addServiceFilter(params, q);
  if (q.cursor) params.set('cursor', q.cursor);
  if (q.limit) params.set('limit', String(q.limit));
  const qs = params.toString();
  return apiFetch(`${v1}/certificates${qs ? `?${qs}` : ''}`);
}

export const getCertificate = (id: string) => apiFetch<CertificateDetail>(`${v1}/certificates/${enc(id)}`);

// uploadCertificate sends secrets (private key, PFX bytes, password). The caller keeps them in
// component state only and never in a query key or cache.
export const uploadCertificate = (req: UploadRequest) =>
  apiFetch<UploadResult>(`${v1}/certificates/upload`, { method: 'POST', body: req });

export const deployCertificate = (id: string, locationIds: string[], confirmIncompleteChain: boolean, canaryOverride = false) =>
  apiFetch<DeployResult>(`${v1}/certificates/${enc(id)}/deploy`, {
    method: 'POST',
    body: { location_ids: locationIds, confirm_incomplete_chain: confirmIncompleteChain, ...(canaryOverride ? { canary_override: true } : {}) },
  });

// Canary rollouts (R65).
export const getRollout = (id: string) => apiFetch<Rollout>(`${v1}/deployment-rollouts/${enc(id)}`);
export const continueRollout = (id: string) => apiFetch<Rollout>(`${v1}/deployment-rollouts/${enc(id)}/actions/continue`, { method: 'POST' });
export const abortRollout = (id: string) => apiFetch<Rollout>(`${v1}/deployment-rollouts/${enc(id)}/actions/abort`, { method: 'POST' });

export const listCSRs = () => apiFetch<{ items: CSR[] }>(`${v1}/certificates/csr`);

export const createCSR = (req: CSRCreateRequest) => apiFetch<CSR>(`${v1}/certificates/csr`, { method: 'POST', body: req });

export const completeCSR = (id: string, certificatePem: string, label?: string) =>
  apiFetch<UploadResult>(`${v1}/certificates/csr/${enc(id)}/actions/complete`, {
    method: 'POST',
    body: label ? { certificate_pem: certificatePem, label } : { certificate_pem: certificatePem },
  });

export const cancelCSR = (id: string) => apiFetch<CSR>(`${v1}/certificates/csr/${enc(id)}/actions/cancel`, { method: 'POST' });

export const listLocations = (targetId: string, missing = false) =>
  apiFetch<CertificateLocationList>(`${v1}/targets/${enc(targetId)}/certificate-locations${missing ? '?missing=true' : ''}`);

// updateLocation needs the location's current version as a strong If-Match validator ("3").
export const updateLocation = (id: string, version: number, patch: LocationPatch) =>
  apiFetch<CertificateLocation>(`${v1}/locations/${enc(id)}`, {
    method: 'PATCH',
    body: patch,
    headers: { 'If-Match': `"${version}"` },
  });

export function listDeployments(q: DeploymentQuery = {}): Promise<{ items: Deployment[]; next_cursor: string | null }> {
  const params = new URLSearchParams();
  if (q.target_id) params.set('target_id', q.target_id);
  if (q.certificate_id) params.set('certificate_id', q.certificate_id);
  if (q.location_id) params.set('location_id', q.location_id);
  if (q.cursor) params.set('cursor', q.cursor);
  if (q.limit) params.set('limit', String(q.limit));
  const qs = params.toString();
  return apiFetch(`${v1}/deployments${qs ? `?${qs}` : ''}`);
}

export const getDeployment = (id: string) => apiFetch<DeploymentDetail>(`${v1}/deployments/${enc(id)}`);
