// Wire types for the Alice REST API (snake_case, see api/openapi.yaml).

import type { Vault } from './keyvault';
import type { LocationObservation } from './drift';
import type { WebServerType } from './webServer';

export type Role = 'admin' | 'operator' | 'auditor';

// Permission is a route's x-permission (internal/rbac, docs/authz-matrix.md) as the session's access names it.
export type Permission =
  | 'read'
  | 'audit.read'
  | 'users.read'
  | 'users.manage'
  | 'settings.manage'
  | 'license.read'
  | 'license.manage'
  | 'targets.manage'
  | 'hostkeys.confirm'
  | 'hostkeys.repin'
  | 'inventory.operate'
  | 'jobs.confirm'
  | 'certificates.operate'
  | 'credentials.manage'
  | 'sshkeys.download'
  | 'rotation.manage'
  | 'rotation.operate'
  | 'sso.manage'
  | 'backup.manage'
  | 'acme.view'
  | 'acme.operate'
  | 'acme.manage'
  | 'acme.preview'
  | 'discovery.view'
  | 'discovery.operate'
  | 'discovery.manage'
  | 'certificates.incident'
  | 'services.manage'
  | 'services.assign'
  | 'services.trust'
  | 'access.manage'
  | 'services.policy';
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
  // null: no global role (the person reaches only the services of their role bindings, R49 Phase 2).
  role: Role | null;
  locale: string;
  disabled: boolean;
  mfa_enrolled: boolean;
  last_login_at: string | null;
  created_at: string;
  // How the person signs in: a local account, single sign-on (no Alice password or authenticator; the role comes from groups)
  // or a directory (LDAP or Active Directory: no Alice password, the role comes from groups, Alice's authenticator stays).
  auth_source: AuthSource;
  sso_provider_id: string | null;
  // The directory of a directory user; null for every other user.
  ldap_directory_id: string | null;
  // Only in the user administration's answers: when a directory user's directory sign-in lockout ends (three failed
  // directory passwords lock it for 45 minutes); absent when it is not locked.
  directory_sign_in_locked_until?: string;
}

export type AuthSource = 'local' | 'oidc' | 'ldap';

export interface SessionInfo {
  user: User;
  csrf_token: string;
  expires_at: string;
  idle_expires_at: string;
  stepup_until: string | null;
  // What the person may reach (R49 Phase 2); absent from an older server (auth/permissions.ts then reads the role).
  access?: SessionAccess;
}

// A service the signed-in person holds a role on, with those roles.
export interface SessionService extends ServiceRef {
  roles: Role[];
}

export interface SessionAccess {
  global_role: Role | null;
  services: SessionService[];
  // Held on at least one service or globally (navigation, lists, create buttons).
  permissions_anywhere: Permission[];
  // Held with a global grant (the platform pages: people, settings, audit, license, ...).
  platform_permissions: Permission[];
}

export interface SessionWithCodes extends SessionInfo {
  recovery_codes?: string[];
}

// signed_in comes only from a directory that does not ask for MFA: the session is full at once.
export interface LoginResponse {
  status: 'mfa_required' | 'mfa_enrollment_required' | 'signed_in';
  csrf_token: string;
}

export interface MfaEnrollment {
  secret: string;
  otpauth_uri: string;
  qr_png: string;
}

export type MfaInput = { code: string } | { recovery_code: string };

export interface SetupStatus {
  // admin_exists, recovery_passphrase_set and license_chosen are absent from the anonymous answer after completion
  // (S-18): read whether an administrator exists through adminExists (auth/setupStatus.ts).
  admin_exists?: boolean;
  recovery_passphrase_set?: boolean;
  license_chosen?: boolean;
  completed: boolean;
  default_locale: string;
  // Phase 8 (C11, C12): present while setup is open or for a signed-in session; after completion an anonymous caller gets
  // only completed and default_locale (S-18).
  https_chosen?: boolean;
  mail_chosen?: boolean;
  next_step?: SetupNextStep;
}

export type SetupNextStep = 'passphrase' | 'https' | 'mail' | 'license' | 'platform' | 'done';

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
  // null: no global role.
  role: Role | null;
  password: string;
}

export interface UserUpdateRequest {
  display_name?: string;
  email?: string;
  // null removes the global role.
  role?: Role | null;
  disabled?: boolean;
}

export interface ApiToken {
  id: string;
  user_id: string;
  name: string;
  prefix: string;
  scope: TokenScope;
  // The services the token is limited to (R54); null: its owner's whole reach.
  service_ids?: string[] | null;
  expires_at: string;
  last_used_at: string | null;
  created_at: string;
}

export interface TokenCreateRequest {
  name: string;
  scope: TokenScope;
  expires_in_days: number;
  // Limit the token to these services (each one its owner holds a role on); absent: no limit.
  service_ids?: string[];
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
  // The continuity window of a licensed lock (locks_at + 45 days): until then certificates already managed keep
  // renewing and deploying automatically. null during the evaluation (it has no window).
  continuity_ends_at: string | null;
  // Whole days left in the window while locked inside it; 0 otherwise.
  continuity_days_left: number;
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
export type TargetType = 'linux' | WebServerType | 'windows' | 'azure_key_vault';

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

// WebServerFacts are what the last scan or test learned about the web server software on a web server
// (absent on other servers and before the first scan). software equals the target type (iis on a Windows server); config_error
// and config_error_reason are codes (see CONFIG_ERRORS and CONFIG_REASONS); config_error_file is text
// from the server.
export interface WebServerFacts {
  software: WebServerType | 'iis';
  version: string;
  conf_path: string;
  config_valid: boolean;
  config_error: string;
  config_error_reason: string;
  config_error_file: string;
  found: boolean;
}

// WindowsFacts are what the last connection test learned about a Windows server (absent on other servers and
// before the first test). elevated false fails the test with ALC-WIN-0003.
export interface WindowsFacts {
  build: string;
  product: string;
  installation_type: string;
  elevated: boolean;
  iis_installed: boolean;
  iis_version: string;
  stores: string[];
  openssh_version: string;
}

export interface TargetFacts {
  os: OSRelease;
  helper_version: string;
  helper_protocol: number;
  sshd: SSHDSettings | null;
  host_keys: DiscoveredHostKey[];
  warnings: Warning[];
  unreadable: UnreadableLine[];
  web_server?: WebServerFacts;
  windows?: WindowsFacts;
}

// The service that owns a row (R49): its id, name and environment (null for none).
export interface EnvironmentRef {
  id: string;
  key: string;
  name: string;
}

export interface ServiceRef {
  id: string;
  name: string;
  environment: EnvironmentRef | null;
}

// OutsideService is the owning service of a row outside the caller's services: the server says so, never which one.
export interface OutsideService {
  outside: true;
  id?: undefined;
  name?: undefined;
  environment?: undefined;
}

// OwnerService is a row's owning service as the server shows it to the caller.
export type OwnerService = ServiceRef | OutsideService;

// isOutside reports whether a row's service is outside the caller's services.
export function isOutside(service: OwnerService | null | undefined): service is OutsideService {
  return !!service && 'outside' in service && service.outside === true;
}

export interface Target {
  service?: OwnerService;
  // What the caller may do with the row: the permissions held on its owning service (omitted when none).
  allowed_actions?: string[];
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
  // certificate_cleanup (R62): the switch "remove certificates Alice imported once nothing uses them"; present only on a
  // server whose capabilities include cleanup_certificates. Changed with PATCH /targets/{id}.
  certificate_cleanup?: boolean;
  // vault is present on a Key Vault (type azure_key_vault) and never holds a secret.
  vault?: Vault;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface TargetCreateRequest {
  name: string;
  type: 'linux' | WebServerType | 'windows';
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
  service?: OwnerService;
  // What the caller may do with the row: the permissions held on its owning service (omitted when none).
  allowed_actions?: string[];
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
  service_id?: string;
  environment_id?: string;
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
  profiles: { linux: SetupSnippet; nginx: SetupSnippet; apache: SetupSnippet; haproxy: SetupSnippet; windows: SetupSnippet };
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
  // The deployment of a certificate.deploy or certificate.deploy_recover job and the import of a kv.import job; null otherwise
  // (optional only so that older fixtures stay valid).
  deployment_id?: string | null;
  import_id?: string | null;
  // The SSH key of an sshkey.add job and the rotation run of a rotation.location job; null otherwise.
  ssh_key_id?: string | null;
  rotation_id?: string | null;
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

// 'azure_kv' is a Key Vault certificate and 'acme' one Alice ordered from a certificate authority; the list and the export accept it as a filter since Phase 7.
export type CertificateSource = 'discovered' | 'uploaded' | 'csr' | 'azure_kv' | 'acme';
// CertificateSourceFilter is what GET /certificates accepts for source: every source (Phase 7 added azure_kv).
export type CertificateSourceFilter = CertificateSource;
export type KeyAlgorithm = 'rsa' | 'ecdsa' | 'ed25519' | 'other';
export type CSRStatus = 'pending' | 'completed' | 'cancelled';
export type CSRKeyType = 'ecdsa-p256' | 'rsa-3072' | 'rsa-4096';
export type ExpiryFilter = '' | 'expired' | '7' | '14' | '30' | '60' | '90';

export interface Certificate {
  service?: OwnerService;
  // What the caller may do with the row: the permissions held on its owning service (omitted when none).
  allowed_actions?: string[];
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
  // Revocation, key compromise and the per-source capability matrix (2026-10-20).
  public_key_sha256: string;
  revoked_at: string | null;
  revocation_reason: RevocationReasonOrEmpty;
  revoked_by_name: string;
  compromised_at: string | null;
  acme_certificate_id: string | null;
  capabilities: SourceCapability[];
  // R64: the authority revoked it and Alice learned it by the revocation check (not at her request).
  revoked_by_authority: boolean;
}

// RevocationCheck is the last revocation check of a certificate (R64, D5); error names why it gave no answer.
export type RevocationCheckStatus = 'good' | 'revoked' | 'on_hold' | 'unknown' | 'unavailable' | 'not_checkable';
export interface RevocationCheck {
  status: RevocationCheckStatus;
  method: '' | 'ocsp' | 'crl';
  reason: string;
  revoked_at: string | null;
  checked_at: string;
  next_check_at: string;
  error: ErrorRef | null;
}

// SourceCapability is one thing Alice can do with a certificate of a source (internal/inventory/source_capabilities.go;
// a test keeps the lists equal).
export type SourceCapability = 'discover' | 'obtain' | 'renew' | 'deploy' | 'verify' | 'revoke' | 'recovery';
export const SOURCE_CAPABILITIES: readonly SourceCapability[] = ['discover', 'obtain', 'renew', 'deploy', 'verify', 'revoke', 'recovery'];

// RevocationReason is an RFC 5280 reason a certificate owner gives (internal/acme/revoke.go).
export type RevocationReason = 'unspecified' | 'keyCompromise' | 'affiliationChanged' | 'superseded' | 'cessationOfOperation';
// The final reasons only an authority reports (R64): a certificate revoked by its authority may carry them.
export type RevocationReasonOrEmpty = '' | RevocationReason | 'cACompromise' | 'privilegeWithdrawn' | 'aACompromise';
export const REVOCATION_REASONS: readonly RevocationReason[] = ['unspecified', 'keyCompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation'];

// CertificateDetail is GET /certificates/{id} and the certificate of an upload or a completion.
export interface CertificateDetail extends Certificate {
  pem_chain: string;
  locations: CertificateLocation[];
  locations_truncated: boolean;
  // Locations on servers outside the reader's services, left out of locations (R49 Phase 2; absent from older answers).
  hidden_count?: number;
  // The last revocation check (R64); null before the first.
  revocation_check: RevocationCheck | null;
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
  section?: string;
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
  target_type: WebServerType | 'windows';
  // deployable: the server's software deploys certificates (its deploy_certificate capability).
  deployable: boolean;
  // R52: what the location should have, what Alice last deployed and what is observed today; null when it follows
  // no binding.
  observation: LocationObservation | null;
  // R59: the location's kind (a certificate file, or an http.sys binding, a BIG-IP profile entry, a TLS Secret), the
  // identity of a location that is not a file (null for a file), the kind's facts and the probe address ("" when not set).
  kind?: LocationKind;
  locator?: Record<string, string | number | boolean> | null;
  details?: Record<string, unknown>;
  verify_address?: string;
}

export type LocationKind = 'server_file' | 'win_sslbinding' | 'f5_clientssl' | 'k8s_tls_secret';

export interface CertificateLocationList {
  items: CertificateLocation[];
  // truncated is true when missing locations were left out (at most 1000 are returned).
  truncated: boolean;
}

export type DeploymentStatus = 'pending' | 'running' | 'succeeded' | 'unchanged' | 'failed' | 'rolled_back' | 'rollback_failed' | 'needs_attention';
// The API shows '' for a code it does not recognise (codeOrBlank), so state and status can be ''.
export type DeploymentState = '' | 'queued' | 'precheck' | 'deploying' | 'holding' | 'recovering' | 'done';
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
  phase: '' | 'none' | 'prepared' | 'writing' | 'committed' | 'unchanged' | 'restoring' | 'restored' | 'restore_failed' | 'restore_forbidden';
  new_fingerprint: string;
  previous_fingerprint: string;
  confirm_incomplete_chain: boolean;
  verified: '' | 'remote' | 'local' | 'skipped';
  // source key_vault: the certificate came from a vault version; binding_id, kv_version and vault_name are set.
  // acme: the certificate was ordered from a certificate authority.
  source: 'upload' | 'key_vault' | 'acme';
  binding_id: string | null;
  kv_version: string;
  vault_name: string;
  verify_failed: ErrorRef | null;
  error: ErrorRef | null;
  failed_step: string;
  cause_step: string;
  helper_error: string;
  // backup_dir is "" for a Windows binding; its previous certificate is backup_store (My or WebHosting) and
  // backup_sha1 (its SHA-1 thumbprint), both absent for any other deployment (R61).
  backup_dir: string;
  // location_kind (R62): what the deployment's location is; always present (server_file for a certificate file).
  location_kind: LocationKind;
  backup_store?: string;
  backup_sha1?: string;
  requested_by: string | null;
  requested_by_name: string;
  recovery_attempts: number;
  recover_after: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  verification: DeploymentVerification;
  // R65: the canary rollout the deployment belongs to (null outside one).
  rollout?: DeploymentRolloutRef | null;
}

export interface DeploymentRolloutRef {
  id: string;
  wave: 1 | 2;
  state: RolloutState;
}

export type RolloutState = 'wave1' | 'hold' | 'wave2' | 'completed' | 'failed' | 'aborted' | 'stopped' | 'preempted';

// CanaryCheck is the latest observation of a wave-1 hold (R65).
export interface CanaryCheck {
  rounds: number;
  passes: number;
  consecutive_failures: number;
  last_at: string | null;
  last_result: '' | 'pass' | 'fail' | 'unknown';
  last_reason: string;
  last_tls: '' | 'pass' | 'fail' | 'skipped' | 'unknown';
  last_http_status: number | null;
  last_latency_ms: number | null;
  next_check_at: string;
}

export interface RolloutSettings {
  count: number;
  percent: number;
  hold: string;
  interval: string;
  failures: number;
  check: { path: string; host: string; port: number; expect_status: number[]; timeout: string } | null;
  override_allowed: boolean;
}

export interface RolloutLocation {
  location_id: string;
  target_id: string;
  target_name: string;
  site: string;
  deployment_id: string | null;
  deployment_state: string | null;
  deployment_status: string | null;
  canary: CanaryCheck | null;
}

// Rollout is a canary deployment (R65): wave 1 observed for the hold, then wave 2.
export interface Rollout {
  id: string;
  state: RolloutState;
  reason: string;
  reason_params: Record<string, string>;
  origin: 'manual' | 'acme' | 'key_vault';
  certificate: { id: string; name: string };
  service: { id?: string; name?: string; outside?: boolean } | null;
  policy_version: number;
  settings: RolloutSettings;
  hold_started_at: string | null;
  hold_until: string | null;
  now: string;
  waves: { wave: 1 | 2; locations: RolloutLocation[] }[];
  skipped: { location_id: string; reason: string }[];
  allowed_actions: ('continue' | 'abort')[];
  hidden_count: number;
  created_at: string;
  finished_at: string | null;
}

// DeploymentVerification is what the verification of the new certificate proved and found (R51): level 0 none (not
// succeeded), 1 installed (the check was skipped), 2 served, 3 trusted (4 is reserved for a service health check);
// trust is null when the served chain was not measured; failure names the kind of a failed verification.
export interface DeploymentVerification {
  level: number;
  trust: DeploymentTrust | null;
  failure: '' | 'network' | 'certificate' | 'trust';
}

// DeploymentTrust: unchecked means an older alice-helper answered without the chain; enforced means Alice knew the
// anchor, so an untrusted chain (other than a name mismatch) failed the deployment.
export interface DeploymentTrust {
  status: 'trusted' | 'untrusted' | 'unchecked';
  error: string;
  port: number | null;
  store: '' | 'system' | 'acme_bundle' | 'uploaded_root';
  enforced: boolean;
}

export interface DeploymentDetail extends Deployment {
  steps: DeploymentStep[];
  // R65: the latest observation of a wave-1 hold (null when it never held).
  canary?: CanaryCheck | null;
}

export interface CSR {
  service?: OwnerService;
  // What the caller may do with the row: the permissions held on its owning service (omitted when none).
  allowed_actions?: string[];
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
  service_id?: string;
  environment_id?: string;
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
  // R65: the canary rollout the request became (deployments is then wave 1 only); null when none.
  rollout?: { id: string; state: RolloutState; wave1: string[]; wave2: string[]; settings: RolloutSettings } | null;
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
  // R59: not for a certificate file.
  verify_address?: string;
}

// Phase 8 (contract C12). Backups: the list, the state and the schedule.
// check is "ok", "missing checksum", "checksum mismatch", "unreadable header" or "unreadable"; code says why a file is
// unreadable ("permission_denied" or "io") and is empty otherwise.
export interface Backup {
  name: string;
  kind: string;
  size: number;
  created_at: string;
  alice_version: string;
  check: string;
  code?: string;
}

export interface BackupState {
  last_success_at: string | null;
  last_success_name: string;
  age_hours: number | null;
  failing: boolean;
  alarm: boolean;
  configured: boolean;
  free_bytes: number;
}

// version is the If-Match validator, as for the Phase 7 settings.
export interface BackupSchedule {
  time: string;
  zone: string;
  retention: number;
  next_at: string | null;
  version: number;
}

export interface BackupList {
  items: Backup[];
  state: BackupState;
  schedule: BackupSchedule;
}

// The certificate Alice serves. warnings: name_mismatch, chain_incomplete, expires_soon (after an upload).
export interface HTTPSInfo {
  subject: string;
  dns_names: string[];
  ip_addresses: string[];
  not_before: string;
  not_after: string;
  fingerprint_sha256: string;
  temporary: boolean;
  warnings?: string[];
}

// An upload is either the PEM pair or a PFX with its password; it is a mutation input only, never cached.
export type HTTPSUpload = { cert_pem: string; key_pem: string } | { pfx_base64: string; pfx_password: string };

export type ForwardingTransport = 'tls' | 'tcp' | 'udp';

// The CA certificate is write-only: ca_pem in a request, ca_set in an answer.
export interface Forwarding {
  enabled: boolean;
  host: string;
  port: number;
  transport: ForwardingTransport;
  ca_set: boolean;
  backlog: number;
  cursor_seq: number;
  last_sent_at: string | null;
  last_error_code: string;
  last_error_at: string | null;
  version: number;
}

export interface ForwardingInput {
  enabled: boolean;
  host: string;
  port: number;
  transport: ForwardingTransport;
  ca_pem?: string;
}

// The dashboard's backup part (Administrators and Auditors) and the setup checklist (Administrators).
export type BackupSummary = Omit<BackupState, 'free_bytes'> & { free_bytes?: number };
export type ChecklistItemName = 'passphrase' | 'https' | 'mail' | 'license' | 'target';
export interface ChecklistItem {
  item: ChecklistItemName;
  done: boolean;
  required: boolean;
}
