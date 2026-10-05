// Wire types for the Alice REST API (snake_case, see api/openapi.yaml).

import type { Vault } from './keyvault';

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

export type TargetStatus = 'pending_host_key' | 'checking' | 'ok' | 'degraded' | 'unreachable' | 'host_key_changed' | 'auth_failed' | 'disabled';
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

// NginxFacts are what the last scan or test learned about Nginx on an Nginx server (absent on other
// servers and before the first scan). config_error and config_error_reason are codes (see
// CONFIG_ERRORS and CONFIG_REASONS); config_error_file is text from the server.
export interface NginxFacts {
  version: string;
  conf_path: string;
  config_valid: boolean;
  config_error: string;
  config_error_reason: string;
  config_error_file: string;
  found: boolean;
}

export interface TargetFacts {
  os: OSRelease;
  helper_version: string;
  helper_protocol: number;
  sshd: SSHDSettings | null;
  host_keys: DiscoveredHostKey[];
  warnings: Warning[];
  unreadable: UnreadableLine[];
  nginx?: NginxFacts;
}

export interface Target {
  id: string;
  name: string;
  type: TargetType;
  host: string;
  port: number;
  username: string;
  status: TargetStatus;
  last_error: { code: string; reason: string; params?: Record<string, string> } | null;
  last_success_at: string | null;
  last_discovery_at: string | null;
  discovery_interval_hours: number;
  keys_managed_elsewhere: boolean;
  capabilities: string[];
  facts: TargetFacts;
  // vault is present on a Key Vault (type azure_key_vault) and never holds a secret.
  vault?: Vault;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface TargetCreateRequest {
  name: string;
  type: 'linux' | 'nginx';
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
  // deployment_id and import_id are not in the API yet (Needs API change); a screen uses them when present.
  deployment_id?: string | null;
  import_id?: string | null;
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

// --- Phase 4: TLS certificates, signing requests, Nginx locations and deployments ---
// Shapes follow api/openapi.yaml (the source of truth); fields the API documents with "known
// values" are typed as unions plus string where "a newer server may add others".

// 'azure_kv' is reserved by the inventory (a later phase); the API lists the other three today.
export type CertificateSource = 'discovered' | 'uploaded' | 'csr' | 'azure_kv';
// CertificateSourceFilter is what GET /certificates accepts for source (azure_kv would be a 422);
// azure_kv is only ever displayed.
export type CertificateSourceFilter = Exclude<CertificateSource, 'azure_kv'>;
export type KeyAlgorithm = 'rsa' | 'ecdsa' | 'ed25519' | 'other';
export type CSRStatus = 'pending' | 'completed' | 'cancelled';
export type CSRKeyType = 'ecdsa-p256' | 'rsa-3072' | 'rsa-4096';
export type ExpiryFilter = '' | 'expired' | '30' | '60';

export interface Certificate {
  id: string;
  fingerprint: string;
  subject_cn: string;
  subject: string;
  issuer: string;
  serial: string;
  sans: string[];
  not_before: string;
  not_after: string;
  key_algorithm: KeyAlgorithm;
  key_bits: number;
  source: CertificateSource;
  label: string;
  has_private_key: boolean;
  chain_complete: boolean;
  self_signed: boolean;
  location_count: number;
  first_seen_at: string;
  last_seen_at: string;
}

// CertificateDetail is GET /certificates/{id} and the certificate of an upload or a completion.
export interface CertificateDetail extends Certificate {
  pem_chain: string;
  locations: CertificateLocation[];
  locations_truncated: boolean;
}

export interface CertificateRef {
  id: string;
  subject_cn: string;
  label: string;
  fingerprint: string;
  not_after: string;
}

export interface CertListen {
  addr: string;
  port: number;
  default_server: boolean;
}

export interface CertServer {
  names: string[];
  listens: CertListen[];
  file: string;
  line: number;
}

export interface CertificateLocation {
  id: string;
  target_id: string;
  target_name: string;
  cert_path: string;
  key_path: string;
  resolved_cert_path: string;
  key_type: '' | 'rsa' | 'ecdsa';
  certificate: CertificateRef | null;
  servers: CertServer[];
  supported: boolean;
  unsupported_reason: string;
  problem: string;
  key_problem: string;
  inherited: boolean;
  custom_location: boolean;
  symlinked: boolean;
  key_exists: boolean;
  key_mode: string;
  key_owner: string;
  key_group: string;
  warnings: string[];
  deployed_fingerprint: string;
  changed_outside_at: string | null;
  verify_port: number | null;
  verify_sni: string;
  skip_verify: boolean;
  first_seen_at: string;
  last_seen_at: string;
  missing_since: string | null;
  version: number;
  active_deployment_id: string | null;
}

export interface CertificateLocationList {
  items: CertificateLocation[];
  // truncated is true when missing locations were left out (at most 1000 are returned).
  truncated: boolean;
}

export type DeploymentStatus = 'pending' | 'running' | 'succeeded' | 'unchanged' | 'failed' | 'rolled_back' | 'rollback_failed' | 'needs_attention';
// The API shows '' for a code it does not recognise (codeOrBlank), so state and status can be ''.
export type DeploymentState = '' | 'queued' | 'precheck' | 'deploying' | 'recovering' | 'done';
export type StepStatus = '' | 'started' | 'ok' | 'failed' | 'skipped';

export interface DeploymentStep {
  n: number;
  // name is a code from the server; a newer server may add names (see DEPLOYMENT_STEP_NAMES).
  name: string;
  status: StepStatus;
  at: string;
  params: Record<string, string>;
}

export interface ErrorRef {
  code: string;
  reason: string;
  params?: Record<string, string>;
}

export interface Deployment {
  id: string;
  certificate_id: string;
  certificate_name: string;
  location_id: string;
  target_id: string;
  target_name: string;
  cert_path: string;
  key_path: string;
  job_id: string | null;
  job_status: string;
  trigger: string;
  state: DeploymentState;
  status: DeploymentStatus | '';
  result: '' | 'committed' | 'unchanged' | 'no_change' | 'rolled_back' | 'rollback_failed' | 'uncertain';
  phase: '' | 'none' | 'prepared' | 'writing' | 'committed' | 'unchanged' | 'restoring' | 'restored' | 'restore_failed';
  new_fingerprint: string;
  previous_fingerprint: string;
  confirm_incomplete_chain: boolean;
  verified: '' | 'remote' | 'local' | 'skipped';
  // source key_vault: the certificate came from a vault version; binding_id, kv_version and vault_name are set.
  source: 'upload' | 'key_vault';
  binding_id: string | null;
  kv_version: string;
  vault_name: string;
  verify_failed: ErrorRef | null;
  error: ErrorRef | null;
  failed_step: string;
  cause_step: string;
  helper_error: string;
  backup_dir: string;
  requested_by: string | null;
  requested_by_name: string;
  recovery_attempts: number;
  recover_after: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface DeploymentDetail extends Deployment {
  steps: DeploymentStep[];
}

export interface CSR {
  id: string;
  common_name: string;
  sans: string[];
  key_algorithm: 'rsa' | 'ecdsa';
  key_bits: number;
  csr_pem: string;
  status: CSRStatus;
  certificate_id: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface CertificateQuery {
  target_id?: string;
  source?: CertificateSourceFilter | '';
  q?: string;
  expiry?: ExpiryFilter;
  cursor?: string | null;
  limit?: number;
}

export interface DeploymentQuery {
  target_id?: string;
  certificate_id?: string;
  location_id?: string;
  cursor?: string | null;
  limit?: number;
}

// UploadRequest holds secrets (private key, PFX bytes, PFX password): it exists only in the upload
// dialog's component state and in the one request body.
export interface UploadRequest {
  label?: string;
  certificate_pem?: string;
  private_key_pem?: string;
  pfx_base64?: string;
  pfx_password?: string;
}

export interface UploadResult {
  certificate: CertificateDetail;
  // warnings: not_yet_valid, chain_incomplete, chain_certificate_expired, csr_name_mismatch (see UPLOAD_WARNINGS).
  warnings: string[];
}

export interface DeployResult {
  deployments: { id: string; job_id: string; location_id: string; status_url: string; deployment_url: string; warnings: string[] }[];
}

export interface CSRCreateRequest {
  common_name: string;
  sans: string[];
  key_type: CSRKeyType;
}

export interface LocationPatch {
  verify_port?: number;
  verify_sni?: string;
  skip_verify?: boolean;
}
