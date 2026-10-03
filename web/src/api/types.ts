// Wire types for the Alice REST API (snake_case, see api/openapi.yaml).

export type Role = 'admin' | 'operator' | 'auditor';
export type TokenScope = 'read' | 'operate';

export interface VersionInfo {
  version: string;
  commit: string;
  build_time: string;
}

export interface User {
  id: string;
  username: string;
  display_name: string;
  email: string;
  role: Role;
  locale: string;
  disabled: boolean;
  mfa_enrolled: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface SessionInfo {
  user: User;
  csrf_token: string;
  expires_at: string;
  idle_expires_at: string;
  stepup_until: string | null;
}

export interface SessionWithCodes extends SessionInfo {
  recovery_codes?: string[];
}

export interface LoginResponse {
  status: 'mfa_required' | 'mfa_enrollment_required';
  csrf_token: string;
}

export interface MfaEnrollment {
  secret: string;
  otpauth_uri: string;
  qr_png: string;
}

export type MfaInput = { code: string } | { recovery_code: string };

export interface SetupStatus {
  admin_exists: boolean;
  recovery_passphrase_set: boolean;
  license_chosen: boolean;
  completed: boolean;
  default_locale: string;
}

export interface SetupSessionResponse {
  csrf_token: string;
}

export interface AdminEnrollmentRequest {
  username: string;
  display_name: string;
  email: string;
  password: string;
}

export interface UserCreateRequest {
  username: string;
  display_name: string;
  email: string;
  role: Role;
  password: string;
}

export interface UserUpdateRequest {
  display_name?: string;
  email?: string;
  role?: Role;
  disabled?: boolean;
}

export interface ApiToken {
  id: string;
  user_id: string;
  name: string;
  prefix: string;
  scope: TokenScope;
  expires_at: string;
  last_used_at: string | null;
  created_at: string;
}

export interface TokenCreateRequest {
  name: string;
  scope: TokenScope;
  expires_in_days: number;
}

export interface CreatedToken {
  token: string;
  item: ApiToken;
}

export type AuditResult = 'success' | 'failure' | 'denied';

export interface AuditEntry {
  seq: number;
  at: string;
  actor_type: string;
  actor_id: string | null;
  actor_name: string;
  ip: string | null;
  action: string;
  object_type: string;
  object_id: string;
  result: AuditResult;
  details: Record<string, string>;
  request_id: string;
  hash: string;
}

export interface AuditQuery {
  limit?: number;
  cursor?: string | null;
  action?: string;
  actor?: string;
  result?: AuditResult | '';
}

export interface AuditPage {
  items: AuditEntry[];
  next_cursor: string | null;
}

export interface AuditReport {
  intact: boolean;
  checked: number;
  head_seq: number;
  head_hash: string;
  first_bad_seq: number | null;
  problem: string | null;
}

export interface FieldError {
  field: string;
  code: string;
  params?: Record<string, string>;
}

export interface ApiErrorBody {
  error: {
    code: string;
    reason: string;
    message_key: string;
    message: string;
    request_id: string;
    retryable: boolean;
    params?: Record<string, string>;
    details?: FieldError[];
  };
}

export type LicensePhase = 'evaluation' | 'evaluation_expired' | 'active' | 'grace' | 'locked';
export type BannerSeverity = 'info' | 'warning' | 'caution' | 'danger';

export interface LicenseBanner {
  kind: string;
  severity: BannerSeverity;
  params: Record<string, string>;
}

export interface LicenseStatus {
  expired: boolean;
  phase?: LicensePhase; // Administrators and Auditors only
  banners: LicenseBanner[];
}

export interface LicenseInfo {
  license_id: string;
  customer: string;
  issued_at: string;
  valid_from: string;
  valid_until: string;
  max_targets: number;
  features: string[];
  replaces: string;
  key_id: string;
}

export interface LicenseFileEntry {
  status: 'current' | 'pending' | 'superseded' | 'invalid';
  uploaded_at: string;
  license: LicenseInfo | null;
}

export interface LicenseHistoryEntry {
  at: string;
  event: 'installed' | 'renewed' | 'state_change' | 'clock_anomaly' | 'rejected' | 'notice';
  license_id: string;
  from_state: string;
  to_state: string;
  notice: string | null;
}

export interface LicenseDetail {
  installation_id: string;
  installed_at: string;
  phase: LicensePhase;
  effective_time: string;
  current: LicenseInfo | null;
  pending: LicenseInfo | null;
  max_targets: number;
  targets_used: number;
  ends_at: string;
  locks_at: string;
  days_left: number;
  grace_day: number;
  tampered: boolean;
  files: LicenseFileEntry[];
  history: LicenseHistoryEntry[];
}

export interface LicenseUploadResult {
  license: LicenseInfo;
  pending: boolean;
  already_expired: boolean;
  correction: boolean;
  duplicate: boolean;
  phase: LicensePhase;
}

// Phase 3: servers (targets), host keys, SSH key inventory, jobs (api/openapi.yaml).

export type TargetStatus = 'pending_host_key' | 'checking' | 'ok' | 'unreachable' | 'host_key_changed' | 'auth_failed' | 'disabled';
export type TargetType = 'linux' | 'nginx' | 'azure_key_vault';

// Warning is a stable code (translated as warnings.<code>) and its parameters.
export interface Warning {
  code: string;
  params: Record<string, string>;
}

export interface OSRelease {
  id: string;
  version_id: string;
  pretty_name: string;
}

export interface DiscoveredHostKey {
  key_type: string;
  bits: number;
  fingerprint: string;
  weak: boolean;
}

export interface UnreadableLine {
  os_user: string;
  file_path: string;
  line_no: number;
}

// SSHDSettings mirrors the API's sshd facts: the effective settings of the server's SSH daemon.
// The whole object is null until the first scan; the strings are the values sshd reports.
export interface SSHDSettings {
  read: boolean;
  pubkey_authentication: string;
  password_authentication: string;
  permit_root_login: string;
  authorized_keys_file: string[];
  authorized_keys_command: string;
  keys_managed_elsewhere: boolean;
  certificates_in_use: boolean;
}

export interface TargetFacts {
  os: OSRelease;
  helper_version: string;
  helper_protocol: number;
  sshd: SSHDSettings | null;
  host_keys: DiscoveredHostKey[];
  warnings: Warning[];
  unreadable: UnreadableLine[];
}

export interface Target {
  id: string;
  name: string;
  type: TargetType;
  host: string;
  port: number;
  username: string;
  status: TargetStatus;
  last_error: { code: string; reason: string } | null;
  last_success_at: string | null;
  last_discovery_at: string | null;
  discovery_interval_hours: number;
  keys_managed_elsewhere: boolean;
  capabilities: string[];
  facts: TargetFacts;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface TargetCreateRequest {
  name: string;
  type: 'linux';
  host: string;
  port: number;
  username: string;
}

export interface JobAccepted {
  job_id: string;
  status_url: string;
}

export interface TargetCreated extends JobAccepted {
  target: Target;
}

export type HostKeyStatus = 'observed' | 'pinned' | 'superseded' | 'rejected';

export interface HostKey {
  id: string;
  key_type: string;
  fingerprint: string;
  status: HostKeyStatus;
  observed_at: string;
  confirmed_at: string | null;
  confirmed_by_name: string;
  superseded_at: string | null;
  verify_command: string;
}

export type KeyFlag = 'weak' | 'command' | 'root_without_from' | 'duplicate' | 'cert_authority' | 'security_key';

export interface KeyLocation {
  id: string;
  ssh_key_id: string;
  fingerprint: string;
  key_type: string;
  target_id: string;
  target_name: string;
  os_user: string;
  file_path: string;
  line_no: number;
  options: string;
  comment: string;
  flags: KeyFlag[];
  first_seen_at: string;
  last_seen_at: string;
  missing_since: string | null;
  removed_at: string | null;
  is_alice_connection_key: boolean;
}

export interface SSHKey {
  id: string;
  fingerprint: string;
  key_type: string;
  bits: number;
  public_key: string;
  managed: boolean;
  is_platform_key: boolean;
  weak: boolean;
  comment: string;
  location_count: number;
  target_count: number;
  missing: boolean;
  first_seen_at: string;
  locations?: KeyLocation[];
}

export interface SSHKeyPage {
  items: SSHKey[];
  next_cursor: string | null;
}

export interface SSHKeyQuery {
  target_id?: string;
  os_user?: string;
  q?: string;
  flag?: KeyFlag | '';
  missing?: boolean;
  cursor?: string | null;
  limit?: number;
}

export interface SetupSnippet {
  sudoers: string;
  script: string;
}

export interface PlatformKeyInfo {
  public_key: string;
  fingerprint: string;
  authorized_keys_line: string;
  helper_path: string;
  helper_protocol: number;
  profiles: { linux: SetupSnippet; nginx: SetupSnippet };
}

export type JobStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled' | 'dead' | 'blocked_license';

export interface JobError {
  code: string;
  reason: string;
  params?: Record<string, string>;
}

export interface Job {
  id: string;
  type: string;
  kind: 'user' | 'scheduled' | 'system';
  status: JobStatus;
  target_id: string | null;
  attempts: number;
  max_attempts: number;
  error: JobError | null;
  result: Record<string, unknown>;
  created_at: string;
  run_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface JobPage {
  items: Job[];
  next_cursor: string | null;
}

export interface JobQuery {
  status?: JobStatus;
  target_id?: string;
  cursor?: string | null;
}
