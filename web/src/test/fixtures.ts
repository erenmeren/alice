import { http, HttpResponse } from 'msw';
import type { RoleBinding } from '../api/access';
import { ROLE_PERMISSIONS } from '../auth/permissions';
import type { ACMEAccount, ACMEBinding, ACMECertificate, ACMEDNSSettings, ACMEHook, ACMEOrder, ACMEProvider } from '../api/acme';
import type { CertificateImpact, Incident } from '../api/incidents';
import type { AssignResult, Environment, Service, ServicePolicy, ServiceTrust } from '../api/services';
import type { LocationObservation } from '../api/drift';
import type { DashboardSummary } from '../api/phase7';
import type { DiscoveredCertificate, DiscoveredEndpoint, DiscoveryPreview, DiscoveryScan, DiscoveryScope, DiscoverySettings } from '../api/discovery';
import type { Provider } from '../api/sso';
import type { Directory } from '../api/ldap';
import type { Policy, Preview, PreviewAction, Run, RunLocation } from '../api/rotation';
import type { ManagedKeyInfo } from '../api/sshkeys';
import type { Backup, BackupList, BackupSchedule, BackupState, Forwarding, HTTPSInfo } from '../api/types';
import type {
  AccessCheckRow,
  Binding,
  BindingLocation,
  DeployableLocation,
  KVCertificate,
  KVCertificateDetail,
  KVImport,
  KVKey,
  KVSecret,
  KVVersion,
  Vault,
  VaultAccess,
} from '../api/keyvault';
import type {
  Certificate,
  CertificateDetail,
  CertificateLocation,
  CSR,
  Deployment,
  DeploymentDetail,
  DeploymentStep,
  HostKey,
  Job,
  KeyLocation,
  LicenseBanner,
  LicenseDetail,
  LicenseStatus,
  WebServerFacts,
  PlatformKeyInfo,
  Role,
  SessionInfo,
  SetupStatus,
  SSHKey,
  Target,
  User,
} from '../api/types';

export function userFor(role: Role, locale = 'en'): User {
  return {
    id: `00000000-0000-7000-8000-00000000000${role === 'admin' ? 1 : role === 'operator' ? 2 : 3}`,
    username: role,
    display_name: { admin: 'Ayşe Yılmaz', operator: 'Olcay Öztürk', auditor: 'Ilgın Işık' }[role],
    email: `${role}@example.com`,
    role,
    locale,
    disabled: false,
    mfa_enrolled: true,
    last_login_at: null,
    created_at: '2026-09-30T08:00:00Z',
    auth_source: 'local',
    sso_provider_id: null,
    ldap_directory_id: null,
  };
}

export function sessionFor(role: Role, locale = 'en'): SessionInfo {
  return {
    user: userFor(role, locale),
    csrf_token: `csrf-${role}`,
    expires_at: '2026-09-30T20:00:00Z',
    idle_expires_at: '2026-09-30T08:30:00Z',
    stepup_until: null,
  };
}

// ssoSessionFor is a session of a single sign-on user of the provider ssoProviderFixture.
export function ssoSessionFor(role: Role, locale = 'en'): SessionInfo {
  const s = sessionFor(role, locale);
  return { ...s, user: { ...s.user, username: 'ayse@corp.example', auth_source: 'oidc', sso_provider_id: 'p1' } };
}

// ldapSessionFor is a session of a directory user of the directory directoryFixture (Alice user name deniz).
export function ldapSessionFor(role: Role, locale = 'en', mfaEnrolled = true): SessionInfo {
  const s = sessionFor(role, locale);
  return { ...s, user: { ...s.user, username: 'deniz', auth_source: 'ldap', ldap_directory_id: DIRECTORY_ID, mfa_enrolled: mfaEnrolled } };
}

export const adminSession = sessionFor('admin');
export const operatorSession = sessionFor('operator');
export const auditorSession = sessionFor('auditor');

export const installedStatus: SetupStatus = {
  admin_exists: true,
  recovery_passphrase_set: true,
  license_chosen: true,
  completed: true,
  default_locale: 'en',
};

// completedAnonymousStatus is what GET /setup/status answers an anonymous caller once setup is complete: exactly
// {completed, default_locale} (S-18, R43 row 47).
export const completedAnonymousStatus: SetupStatus = { completed: true, default_locale: 'en' };

export const freshStatus: SetupStatus = {
  admin_exists: false,
  recovery_passphrase_set: false,
  license_chosen: false,
  completed: false,
  default_locale: 'en',
};

// errorResponse builds an error body shaped like the server's (spec §9.3).
export function errorResponse(
  status: number,
  code: string,
  reason: string,
  extra: { retryable?: boolean; params?: Record<string, string>; details?: { field: string; code: string; params?: Record<string, string> }[] } = {},
) {
  return HttpResponse.json(
    {
      error: {
        code,
        reason,
        message_key: `errors.${reason}`,
        message: `server text for ${reason}`,
        request_id: 'req-1',
        retryable: status === 429,
        ...extra,
      },
    },
    { status },
  );
}

// sessionHandlers installs handlers for a signed-in user (or none) and the setup status.
export function sessionHandlers(session: SessionInfo | null, status: SetupStatus = installedStatus) {
  return [
    http.get('/api/v1/setup/status', () => HttpResponse.json(status)),
    http.get('/api/v1/auth/session', () =>
      session ? HttpResponse.json(session) : errorResponse(401, 'ALC-AUTH-0001', 'auth.unauthenticated'),
    ),
  ];
}

export const licenseInfoFixture = {
  license_id: 'LIC-2026-000123',
  customer: 'Örnek Bankası A.Ş.',
  issued_at: '2026-10-01T00:00:00Z',
  valid_from: '2026-10-01T00:00:00Z',
  valid_until: '2027-10-01T00:00:00Z',
  max_targets: 10,
  features: [],
  replaces: '',
  key_id: 'vk-2026-01',
};

export const licenseDetailFixture: LicenseDetail = {
  installation_id: 'ALICE-7F3K-9Q2M-XD41-B8TC',
  installed_at: '2026-10-01T08:00:00Z',
  phase: 'active',
  effective_time: '2026-10-02T08:00:00Z',
  current: licenseInfoFixture,
  pending: null,
  max_targets: 10,
  targets_used: 3,
  ends_at: '2027-10-01T00:00:00Z',
  locks_at: '2027-10-08T00:00:00Z',
  days_left: 364,
  grace_day: 0,
  continuity_ends_at: '2027-11-22T00:00:00Z',
  continuity_days_left: 0,
  tampered: false,
  files: [{ status: 'current', uploaded_at: '2026-10-01T09:00:00Z', license: licenseInfoFixture }],
  history: [
    { at: '2026-10-01T09:00:00Z', event: 'installed', license_id: 'LIC-2026-000123', from_state: 'evaluation', to_state: 'active', notice: null },
  ],
};

// statusWith builds a license status with the given banners (no banner = nothing to show).
export function statusWith(...banners: LicenseBanner[]): LicenseStatus {
  return { expired: banners.some((b) => ['grace', 'locked', 'locked_continuity', 'evaluation_ended'].includes(b.kind)), banners };
}

// Phase 3 fixtures: one connected Linux server with three keys, Alice's own key and a finished job.
export const targetFixture: Target = {
  id: '0192b000-0000-7000-8000-0000000000a1',
  name: 'web-01',
  type: 'linux',
  host: 'web-01.example.com',
  port: 22,
  username: 'alice-svc',
  status: 'ok',
  last_error: null,
  last_success_at: '2026-10-01T08:00:00Z',
  last_discovery_at: '2026-10-01T08:01:00Z',
  discovery_interval_hours: 24,
  keys_managed_elsewhere: false,
  capabilities: ['authorized_keys', 'discover_ssh_keys', 'test_connection'],
  facts: {
    os: { id: 'ubuntu', version_id: '22.04', pretty_name: 'Ubuntu 22.04.4 LTS' },
    helper_version: '1.0.0',
    helper_protocol: 1,
    sshd: null,
    host_keys: [],
    warnings: [],
    unreadable: [],
  },
  version: 3,
  created_at: '2026-10-01T07:59:00Z',
  updated_at: '2026-10-01T08:01:00Z',
};

export function targetWith(o: Partial<Target>): Target {
  return { ...targetFixture, ...o };
}

export function hostKeyFixture(o: Partial<HostKey> = {}): HostKey {
  return {
    id: '0192b000-0000-7000-8000-0000000000h1',
    key_type: 'ssh-ed25519',
    fingerprint: 'SHA256:pinnedPinnedPinnedPinnedPinnedPinnedPinned0',
    status: 'pinned',
    observed_at: '2026-10-01T07:59:30Z',
    confirmed_at: '2026-10-01T07:59:40Z',
    confirmed_by_name: 'admin',
    superseded_at: null,
    verify_command: 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub',
    ...o,
  };
}

export function keyLocationFixture(o: Partial<KeyLocation> = {}): KeyLocation {
  return {
    id: '0192b000-0000-7000-8000-0000000000l1',
    ssh_key_id: '0192b000-0000-7000-8000-0000000000k1',
    fingerprint: 'SHA256:deployDeployDeployDeployDeployDeployDeploy0',
    key_type: 'ssh-ed25519',
    target_id: targetFixture.id,
    target_name: targetFixture.name,
    os_user: 'deploy',
    file_path: '/home/deploy/.ssh/authorized_keys',
    line_no: 1,
    options: '',
    comment: 'deploy@laptop',
    flags: [],
    first_seen_at: '2026-10-01T08:01:00Z',
    last_seen_at: '2026-10-01T08:01:00Z',
    missing_since: null,
    removed_at: null,
    is_alice_connection_key: false,
    ...o,
  };
}

export const aliceKeyLocation: KeyLocation = keyLocationFixture({
  id: '0192b000-0000-7000-8000-0000000000l9',
  ssh_key_id: '0192b000-0000-7000-8000-0000000000k9',
  fingerprint: 'SHA256:aliceAliceAliceAliceAliceAliceAliceAlice00',
  os_user: 'alice-svc',
  file_path: '/var/lib/alice-svc/.ssh/authorized_keys',
  comment: 'alice-platform',
  options: 'no-agent-forwarding,no-port-forwarding,no-X11-forwarding',
  is_alice_connection_key: true,
});

export const platformKeyFixture: PlatformKeyInfo = {
  public_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExample alice-platform',
  fingerprint: 'SHA256:aliceAliceAliceAliceAliceAliceAliceAlice00',
  authorized_keys_line:
    'no-agent-forwarding,no-port-forwarding,no-X11-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExample alice-platform',
  helper_path: '/usr/local/libexec/alice-helper',
  helper_protocol: 1,
  profiles: {
    linux: { sudoers: '# linux profile', script: '# linux setup script\nset -eu\n' },
    nginx: { sudoers: '# nginx profile', script: '# nginx setup script\nset -eu\n' },
    apache: { sudoers: '# apache profile', script: '# apache setup script\nset -eu\n' },
    haproxy: { sudoers: '# haproxy profile', script: '# haproxy setup script\nset -eu\n' },
  },
};

export function jobFixture(o: Partial<Job> = {}): Job {
  return {
    id: '0192b000-0000-7000-8000-0000000000j1',
    type: 'target.test_connection',
    kind: 'user',
    status: 'succeeded',
    target_id: targetFixture.id,
    attempts: 1,
    max_attempts: 1,
    error: null,
    result: {},
    created_at: '2026-10-01T08:00:00Z',
    run_at: '2026-10-01T08:00:00Z',
    started_at: '2026-10-01T08:00:01Z',
    finished_at: '2026-10-01T08:00:02Z',
    ...o,
  };
}

export function sshKeyFixture(o: Partial<SSHKey> = {}): SSHKey {
  return {
    id: '0192b000-0000-7000-8000-0000000000k1',
    fingerprint: 'SHA256:deployDeployDeployDeployDeployDeployDeploy0',
    key_type: 'ssh-ed25519',
    bits: 256,
    public_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDeployDeployDeployDeployDeployDeployDep',
    managed: false,
    is_platform_key: false,
    weak: false,
    comment: 'deploy@laptop',
    location_count: 2,
    target_count: 2,
    missing: false,
    first_seen_at: '2026-10-01T08:01:00Z',
    ...o,
  };
}

// managedKeyFixture is what the detail route adds for a key Alice generated (Phase 6). There is no key material here.
export function managedKeyFixture(o: Partial<ManagedKeyInfo> = {}): ManagedKeyInfo {
  return {
    label: 'Deploy Key',
    comment: 'alice:deploy-key:2026-10-05',
    key_type: 'ed25519',
    created_by: 'admin',
    created_at: '2026-10-05T08:00:00Z',
    retired_at: null,
    destroyed_at: null,
    rotated_from: null,
    download_count: 0,
    last_downloaded_at: null,
    policy_id: null,
    open_rotation_id: null,
    ...o,
  };
}

// Phase 6 rotation fixtures. The lines are public key material shaped text, never a private key.
export const POLICY_ID = '0192e000-0000-7000-8000-0000000000p1';
export const RUN_ID = '0192e000-0000-7000-8000-0000000000r1';

export function policyFixture(o: Partial<Policy> = {}): Policy {
  return {
    id: POLICY_ID,
    ssh_key_id: '0192b000-0000-7000-8000-0000000000k1',
    name: 'Quarterly',
    enabled: false,
    interval_days: 90,
    overlap_days: 7,
    overlap_minutes: 10080,
    notify_before_hours: 24,
    new_key_type: 'same',
    next_run_at: null,
    open_rotation_id: null,
    last_run_id: null,
    last_run_status: null,
    last_run_result: null,
    version: 1,
    created_at: '2026-10-05T08:00:00Z',
    updated_at: '2026-10-05T08:00:00Z',
    ...o,
  };
}

export function previewActionFixture(o: Partial<PreviewAction> = {}): PreviewAction {
  return {
    n: 1,
    location_id: '0192b000-0000-7000-8000-0000000000l1',
    target_id: targetFixture.id,
    target_name: 'web-01',
    os_user: 'deploy',
    file_path: '/home/deploy/.ssh/authorized_keys',
    options: '',
    skip_reason: '',
    verify: true,
    verify_note: '',
    remove_line: 'ssh-ed25519 AAAAOLDOLDOLD deploy-key',
    add_line: 'ssh-ed25519 AAAANEWNEWNEW deploy-key',
    ...o,
  };
}

export function previewFixture(o: Partial<Preview> = {}): Preview {
  return {
    policy_id: POLICY_ID,
    ssh_key_id: '0192b000-0000-7000-8000-0000000000k1',
    fingerprint: 'SHA256:deployDeployDeployDeployDeployDeployDeploy0',
    plan_digest: 'ab'.repeat(32),
    planned_for: '2026-10-06T08:00:00Z',
    new_key_type: 'ed25519',
    overlap_minutes: 10080,
    change_count: 1,
    skip_count: 1,
    emailed: true,
    actions: [
      previewActionFixture(),
      previewActionFixture({ n: 2, location_id: 'l2', target_name: 'db-01', os_user: 'ops', file_path: '/home/ops/.ssh/authorized_keys', skip_reason: 'target_not_connected', verify: false, add_line: '', remove_line: '' }),
    ],
    ...o,
  };
}

export function runLocationFixture(o: Partial<RunLocation> = {}): RunLocation {
  return {
    id: 'rl1',
    n: 1,
    target_id: targetFixture.id,
    target_name: 'web-01',
    os_user: 'deploy',
    file_path: '/home/deploy/.ssh/authorized_keys',
    options: '',
    state: 'verified',
    skip_reason: '',
    verify_note: '',
    error: null,
    backup: '',
    verified_at: '2026-10-06T08:05:00Z',
    reverified_at: null,
    removed_at: null,
    new_location_id: 'nl1',
    add_resend_count: 0,
    add_resent_at: null,
    ...o,
  };
}

export function runFixture(o: Partial<Run> = {}): Run {
  return {
    id: RUN_ID,
    policy_id: POLICY_ID,
    old_ssh_key_id: '0192b000-0000-7000-8000-0000000000k1',
    new_ssh_key_id: '0192b000-0000-7000-8000-0000000000k2',
    old_fingerprint: 'SHA256:oldOldOldOldOldOldOldOldOldOldOldOldOld0',
    new_fingerprint: 'SHA256:newNewNewNewNewNewNewNewNewNewNewNewNew0',
    trigger: 'manual',
    status: 'overlap',
    paused_license: false,
    awaiting_decision: false,
    decision_due_at: null,
    planned_for: '2026-10-06T08:00:00Z',
    notified_at: '2026-10-06T07:50:00Z',
    started_at: '2026-10-06T08:00:00Z',
    verified_at: '2026-10-06T08:05:00Z',
    overlap_until: '2026-10-13T08:05:00Z',
    finished_at: null,
    result: null,
    plan_digest: 'ab'.repeat(32),
    new_key_type: 'ed25519',
    overlap_minutes: 10080,
    change_count: 1,
    skip_count: 0,
    kept_count: 0,
    actions_allowed: [],
    location_counts: { total: 1, verified: 1, removed: 0, skipped: 0, kept: 0, failed: 0, undone: 0, cancelled: 0, in_flight: 0 },
    locations: [runLocationFixture()],
    steps: [],
    version: 1,
    ...o,
  };
}

// Phase 4 fixtures: a certificate Alice holds with its key, a pending signing request, one Nginx
// location and one finished deployment.
export function certificateFixture(o: Partial<Certificate> = {}): Certificate {
  return {
    id: '0192c000-0000-7000-8000-0000000000c1',
    fingerprint: 'ab12'.repeat(16),
    subject_cn: 'www.example.test',
    subject: 'CN=www.example.test',
    issuer: 'CN=Example Test CA',
    serial: '0a1b2c',
    sans: ['www.example.test', 'example.test'],
    not_before: '2026-09-01T00:00:00Z',
    not_after: '2027-09-01T00:00:00Z',
    key_algorithm: 'ecdsa',
    key_bits: 256,
    source: 'uploaded',
    label: '',
    has_private_key: true,
    chain_complete: true,
    self_signed: false,
    location_count: 1,
    first_seen_at: '2026-10-01T08:00:00Z',
    last_seen_at: '2026-10-01T08:00:00Z',
    public_key_sha256: 'cd34'.repeat(16),
    revoked_at: null,
    revocation_reason: '',
    revoked_by_name: '',
    compromised_at: null,
    acme_certificate_id: null,
    capabilities: ['discover', 'deploy', 'verify'],
    ...o,
  };
}

export function locationFixture(o: Partial<CertificateLocation> = {}): CertificateLocation {
  return {
    id: '0192c000-0000-7000-8000-0000000000e1',
    target_id: targetFixture.id,
    target_name: targetFixture.name,
    cert_path: '/etc/nginx/ssl/www.crt',
    key_path: '/etc/nginx/ssl/www.key',
    resolved_cert_path: '',
    key_type: 'ecdsa',
    certificate: null,
    servers: [{ names: ['www.example.test'], listens: [{ addr: '*', port: 443, default_server: false }], file: '/etc/nginx/conf.d/www.conf', line: 4 }],
    supported: true,
    unsupported_reason: '',
    problem: '',
    key_problem: '',
    inherited: false,
    custom_location: false,
    symlinked: false,
    key_exists: true,
    key_mode: '0600',
    key_owner: 'root',
    key_group: 'root',
    warnings: [],
    deployed_fingerprint: '',
    changed_outside_at: null,
    verify_port: null,
    verify_sni: '',
    skip_verify: false,
    first_seen_at: '2026-10-01T08:01:00Z',
    last_seen_at: '2026-10-01T08:01:00Z',
    missing_since: null,
    version: 1,
    active_deployment_id: null,
    target_type: 'nginx',
    deployable: true,
    observation: null,
    ...o,
  };
}

export function certificateDetailFixture(o: Partial<CertificateDetail> = {}): CertificateDetail {
  return {
    ...certificateFixture(),
    pem_chain: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
    locations: [locationFixture()],
    locations_truncated: false,
    ...o,
  };
}

export function csrFixture(o: Partial<CSR> = {}): CSR {
  return {
    id: '0192c000-0000-7000-8000-0000000000r1',
    common_name: 'www.example.test',
    sans: ['www.example.test', 'example.test'],
    key_algorithm: 'ecdsa',
    key_bits: 256,
    csr_pem: '-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n',
    status: 'pending',
    certificate_id: null,
    created_at: '2026-10-02T09:00:00Z',
    finished_at: null,
    ...o,
  };
}

export function deploymentFixture(o: Partial<Deployment> = {}): Deployment {
  return {
    id: '0192c000-0000-7000-8000-0000000000d1',
    certificate_id: certificateFixture().id,
    certificate_name: 'www.example.test',
    location_id: locationFixture().id,
    target_id: targetFixture.id,
    target_name: targetFixture.name,
    cert_path: '/etc/nginx/ssl/www.crt',
    key_path: '/etc/nginx/ssl/www.key',
    job_id: null,
    job_status: 'succeeded',
    trigger: 'manual',
    state: 'done',
    status: 'succeeded',
    result: 'committed',
    phase: 'committed',
    new_fingerprint: 'ab12'.repeat(16),
    previous_fingerprint: 'cd34'.repeat(16),
    confirm_incomplete_chain: false,
    source: 'upload',
    binding_id: null,
    kv_version: '',
    vault_name: '',
    verified: 'remote',
    verify_failed: null,
    error: null,
    failed_step: '',
    cause_step: '',
    helper_error: '',
    backup_dir: '',
    requested_by: userFor('operator').id,
    requested_by_name: 'Olcay Öztürk',
    recovery_attempts: 0,
    recover_after: null,
    created_at: '2026-10-02T10:00:00Z',
    started_at: '2026-10-02T10:00:01Z',
    finished_at: '2026-10-02T10:00:09Z',
    verification: { level: 2, trust: null, failure: '' },
    ...o,
  };
}

// stepFixture is one deployment event (the API reports one record per event: started, ok, failed).
export function stepFixture(n: number, name: string, status: DeploymentStep['status'] = 'ok', params: Record<string, string> = {}): DeploymentStep {
  return { n, name, status, at: `2026-10-02T10:00:${String(n).padStart(2, '0')}Z`, params };
}

export function deploymentDetailFixture(o: Partial<DeploymentDetail> = {}): DeploymentDetail {
  return { ...deploymentFixture(), steps: [], ...o };
}

// nginxTargetFixture is an Nginx server whose last scan was fine; webServerFacts builds its facts.
export function webServerFacts(o: Partial<WebServerFacts> = {}): WebServerFacts {
  return { software: 'nginx', version: '1.24.0', conf_path: '/etc/nginx/nginx.conf', config_valid: true, config_error: '', config_error_reason: '', config_error_file: '', found: true, ...o };
}

export const nginxTargetFixture: Target = {
  ...targetFixture,
  id: '0192b000-0000-7000-8000-0000000000a2',
  name: 'web-nginx',
  type: 'nginx',
  host: 'nginx-01.example.com',
  capabilities: ['authorized_keys', 'deploy_certificate', 'discover_certificates', 'discover_ssh_keys', 'http01_challenge', 'key_login', 'test_connection', 'verify_deployment'],
  facts: { ...targetFixture.facts, web_server: webServerFacts() },
};

// apacheTargetFixture is an Apache server (discovery only: no deploy_certificate) whose last scan was fine.
export const apacheTargetFixture: Target = {
  ...targetFixture,
  id: '0192b000-0000-7000-8000-0000000000a3',
  name: 'web-apache',
  type: 'apache',
  host: 'apache-01.example.com',
  capabilities: ['authorized_keys', 'discover_certificates', 'discover_ssh_keys', 'key_login', 'test_connection'],
  facts: {
    ...targetFixture.facts,
    web_server: webServerFacts({ software: 'apache', version: '2.4.57', conf_path: '/etc/apache2/apache2.conf' }),
  },
};

// haproxyTargetFixture is an HAProxy server (discovery only: no deploy_certificate) whose last scan was fine.
export const haproxyTargetFixture: Target = {
  ...apacheTargetFixture,
  id: '0192b000-0000-7000-8000-0000000000a4',
  name: 'web-haproxy',
  type: 'haproxy',
  host: 'haproxy-01.example.com',
  facts: {
    ...targetFixture.facts,
    web_server: webServerFacts({ software: 'haproxy', version: '2.6.12-1+deb12u3', conf_path: '/etc/haproxy/haproxy.cfg' }),
  },
};

export function nginxTargetWith(o: Partial<Target>, facts: Partial<Target['facts']> = {}): Target {
  return { ...nginxTargetFixture, ...o, facts: { ...nginxTargetFixture.facts, ...facts } };
}

// Phase 5: Key Vaults. The IDs and thumbprints are made up; there is no key material here.
export const VAULT_ID = '0192d000-0000-7000-8000-0000000000a1';
export const OBJECT_ID = '11111111-2222-4333-8444-555555555555';
export const TENANT_ID = '6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60';
export const CLIENT_ID = '0f1e2d3c-4b5a-4968-8776-655443322110';

export function accessRow(name: AccessCheckRow['name'], result: AccessCheckRow['result'], role: AccessCheckRow['role'] = '', error: AccessCheckRow['error'] = null): AccessCheckRow {
  return { name, result, role, error };
}

export function accessFixture(o: Partial<VaultAccess> = {}): VaultAccess {
  return {
    object_id: OBJECT_ID,
    tenant_id: TENANT_ID,
    permission_model: 'rbac',
    checks: [
      accessRow('sign_in', 'ok'),
      accessRow('list_certificates', 'ok'),
      accessRow('list_keys', 'ok'),
      accessRow('list_secrets', 'ok'),
      accessRow('read_secret', 'not_checked'),
      accessRow('import', 'not_checked'),
    ],
    checked_at: '2026-10-05T08:00:00Z',
    ...o,
  };
}

export function vaultInfo(o: Partial<Vault> = {}): Vault {
  return {
    url: 'https://contoso-prod.vault.azure.net',
    name: 'contoso-prod',
    auth: 'client_secret',
    tenant_id: TENANT_ID,
    client_id: CLIENT_ID,
    poll_interval_minutes: 15,
    secret_expires_on: null,
    cert_thumbprint: '',
    cert_not_after: null,
    access: accessFixture(),
    ...o,
  };
}

export const vaultFixture: Target = {
  ...targetFixture,
  id: VAULT_ID,
  name: 'Prod vault',
  type: 'azure_key_vault',
  host: 'contoso-prod.vault.azure.net',
  port: 443,
  username: '',
  status: 'ok',
  last_error: null,
  last_success_at: '2026-10-05T08:00:00Z',
  last_discovery_at: '2026-10-05T08:00:00Z',
  discovery_interval_hours: 0,
  capabilities: ['test_connection', 'discover_certificates'],
  vault: vaultInfo(),
  version: 4,
};

export function vaultWith(o: Partial<Target>, v: Partial<Vault> = {}): Target {
  return { ...vaultFixture, ...o, vault: vaultInfo({ ...vaultFixture.vault, ...v }) };
}

export const KV_CERT_ID = '0192d000-0000-7000-8000-0000000000c1';
export const KV_VERSION_ID = '0192d000-0000-7000-8000-0000000000e1';
export const BINDING_ID = '0192d000-0000-7000-8000-0000000000b1';
export const LOCATION_ID = '0192d000-0000-7000-8000-0000000000f1';

export function kvCertificateFixture(o: Partial<KVCertificate> = {}): KVCertificate {
  return {
    id: KV_CERT_ID,
    target_id: VAULT_ID,
    name: 'web-cert',
    current_version: '0123456789abcdef0123456789abcdef',
    current_thumbprint: 'aa'.repeat(20),
    enabled: true,
    not_before: '2026-09-01T00:00:00Z',
    expires: '2027-09-01T00:00:00Z',
    kv_created_at: '2026-09-01T00:00:00Z',
    kv_updated_at: '2026-09-01T00:00:00Z',
    exportable: true,
    key_type: 'rsa',
    key_size: 2048,
    content_type: 'application/x-pkcs12',
    issuer_name: 'Self',
    auto_renew: true,
    details_pending: false,
    first_seen_at: '2026-09-02T00:00:00Z',
    last_seen_at: '2026-10-05T08:00:00Z',
    missing_since: null,
    bound: false,
    current_held: false,
    current_held_reason: '',
    ...o,
  };
}

export function kvVersionFixture(o: Partial<KVVersion> = {}): KVVersion {
  return {
    id: KV_VERSION_ID,
    version: '0123456789abcdef0123456789abcdef',
    thumbprint: 'aa'.repeat(20),
    certificate_id: certificateFixture().id,
    enabled: true,
    not_before: '2026-09-01T00:00:00Z',
    expires: '2027-09-01T00:00:00Z',
    kv_created_at: '2026-09-01T00:00:00Z',
    exportable: true,
    key_type: 'rsa',
    content_type: 'application/x-pkcs12',
    detected_at: '2026-09-02T00:00:00Z',
    held: false,
    held_reason: '',
    chain_incomplete: false,
    ...o,
  };
}

export function kvCertificateDetailFixture(o: Partial<KVCertificateDetail> = {}): KVCertificateDetail {
  return { ...kvCertificateFixture(), versions: [kvVersionFixture()], binding: null, deploy_access: 'not_checked', ...o };
}

export function bindingLocationFixture(o: Partial<BindingLocation> = {}): BindingLocation {
  return {
    location_id: LOCATION_ID,
    target_id: targetFixture.id,
    target_name: 'web-01',
    cert_path: '/etc/nginx/ssl/www.crt',
    state: 'not_deployed',
    version: '',
    deployment_id: null,
    ...o,
  };
}

export function bindingFixture(o: Partial<Binding> = {}): Binding {
  return {
    id: BINDING_ID,
    kv_certificate_id: KV_CERT_ID,
    vault_id: VAULT_ID,
    certificate_name: 'web-cert',
    vault_name: 'Prod vault',
    auto_deploy: false,
    auto_since: null,
    stopped_version: '',
    location_count: 1,
    version: 2,
    created_at: '2026-10-03T08:00:00Z',
    created_by: userFor('operator').id,
    locations: [bindingLocationFixture()],
    ...o,
  };
}

export function deployableLocationFixture(o: Partial<DeployableLocation> = {}): DeployableLocation {
  return {
    id: LOCATION_ID,
    target_id: targetFixture.id,
    target_name: 'web-01',
    cert_path: '/etc/nginx/ssl/www.crt',
    key_path: '/etc/nginx/ssl/www.key',
    key_type: 'rsa',
    server_names: ['www.example.test'],
    binding_id: null,
    ...o,
  };
}

export function kvKeyFixture(o: Partial<KVKey> = {}): KVKey {
  return {
    id: '0192d000-0000-7000-8000-0000000000d2',
    target_id: VAULT_ID,
    name: 'signing-key',
    version: 'fedcba9876543210fedcba9876543210',
    key_type: 'RSA',
    curve: '',
    key_size: 2048,
    hsm: false,
    managed: false,
    enabled: true,
    details_updated_at: '2026-10-05T08:00:00Z',
    details_problem: '',
    not_before: null,
    expires: '2027-01-01T00:00:00Z',
    kv_created_at: '2026-09-01T00:00:00Z',
    kv_updated_at: '2026-09-01T00:00:00Z',
    first_seen_at: '2026-09-02T00:00:00Z',
    last_seen_at: '2026-10-05T08:00:00Z',
    missing_since: null,
    ...o,
  };
}

export function kvSecretFixture(o: Partial<KVSecret> = {}): KVSecret {
  return {
    id: '0192d000-0000-7000-8000-0000000000d3',
    target_id: VAULT_ID,
    name: 'db-password',
    content_type: 'text/plain',
    managed: false,
    enabled: true,
    not_before: null,
    expires: null,
    kv_created_at: '2026-09-01T00:00:00Z',
    kv_updated_at: '2026-09-01T00:00:00Z',
    first_seen_at: '2026-09-02T00:00:00Z',
    last_seen_at: '2026-10-05T08:00:00Z',
    missing_since: null,
    ...o,
  };
}

export function kvImportFixture(o: Partial<KVImport> = {}): KVImport {
  return {
    id: '0192d000-0000-7000-8000-0000000000i1',
    certificate_id: certificateFixture().id,
    target_id: VAULT_ID,
    name: 'www-example-test',
    new_version: false,
    state: 'succeeded',
    version: '0123456789abcdef0123456789abcdef',
    thumbprint: 'bb'.repeat(20),
    error: null,
    can_retry: false,
    job_id: '0192d000-0000-7000-8000-0000000000j9',
    requested_by: userFor('admin').id,
    created_at: '2026-10-05T09:00:00Z',
    sent_at: '2026-10-05T09:00:05Z',
    finished_at: '2026-10-05T09:00:09Z',
    ...o,
  };
}

// emptyDashboardSummary is the all-zero DashboardSummary the default handler answers.
export const emptyDashboardSummary: DashboardSummary = {
  generated_at: '2026-10-07T09:00:00Z',
  certificates: { monitored: 0, expired: 0, within_7: 0, within_30: 0, within_60: 0, kv_expired: 0, kv_within_30: 0 },
  deployments: { failed_7d: 0, recent: [] },
  targets: { total: 0, by_status: {} },
  license: { expired: false, phase: 'active', ends_at: null, days_left: null },
  rotation: { upcoming: [], running: 0, needs_attention: 0 },
  notifications: null,
  audit: null,
  attention: 0,
};

// providerFixture is a configured identity provider (id p1, named Corp IdP).
export function providerFixture(o: Partial<Provider> = {}): Provider {
  return {
    id: 'p1',
    name: 'Corp IdP',
    issuer_url: 'https://idp.example.com',
    client_id: 'alice-client',
    has_client_secret: true,
    scopes: ['openid', 'profile', 'email', 'groups'],
    groups_claim: 'groups',
    ca_pem: '',
    endpoints: { authorization: 'https://idp.example.com/authorize', token: 'https://idp.example.com/token', jwks: 'https://idp.example.com/jwks' },
    enabled: true,
    redirect_uri: 'https://alice.example.com/api/v1/auth/oidc/p1/callback',
    version: 1,
    created_at: '2026-10-07T09:00:00Z',
    updated_at: '2026-10-07T09:00:00Z',
    ...o,
  };
}

// directoryFixture is a configured directory (named Corp AD).
export const DIRECTORY_ID = '0192f100-0000-7000-8000-0000000000d1';
export function directoryFixture(o: Partial<Directory> = {}): Directory {
  return {
    id: DIRECTORY_ID,
    name: 'Corp AD',
    addresses: ['ldaps://dc1.corp.example:636', 'ldaps://dc2.corp.example'],
    user_base_dn: 'ou=people,dc=corp,dc=example',
    user_filter: '(&(objectClass=user)(sAMAccountName={login}))',
    login_attribute: 'sAMAccountName',
    unique_id_attribute: 'objectGUID',
    display_name_attribute: 'displayName',
    email_attribute: 'mail',
    bind_dn: 'cn=alice-svc,ou=services,dc=corp,dc=example',
    bind_password_set: true,
    group_base_dn: 'ou=groups,dc=corp,dc=example',
    group_filter: '(member:1.2.840.113556.1.4.1941:={dn})',
    group_name_attribute: 'cn',
    ca_pem: '',
    mfa_required: true,
    enabled: true,
    version: 3,
    created_at: '2026-10-15T09:00:00Z',
    updated_at: '2026-10-15T09:00:00Z',
    ...o,
  };
}

// Phase 8 (contract C12): backups, the backup schedule, the HTTPS certificate and the audit forwarding.
export const BACKUP_NAME = 'alice-backup-7F3K92QD-20261010T023000Z-auto.alicebak';
export function backupFixture(o: Partial<Backup> = {}): Backup {
  return { name: BACKUP_NAME, kind: 'auto', size: 52_400_000, created_at: '2026-10-10T02:30:00Z', alice_version: '1.0.0', check: 'ok', code: '', ...o };
}

export function backupStateFixture(o: Partial<BackupState> = {}): BackupState {
  return {
    last_success_at: '2026-10-10T02:30:00Z',
    last_success_name: BACKUP_NAME,
    age_hours: 6,
    failing: false,
    alarm: false,
    configured: true,
    free_bytes: 41_200_000_000,
    ...o,
  };
}

export function backupScheduleFixture(o: Partial<BackupSchedule> = {}): BackupSchedule {
  return { time: '02:30', zone: 'Europe/Istanbul', retention: 14, next_at: '2026-10-10T23:30:00Z', version: 3, ...o };
}

export function backupListFixture(o: Partial<BackupList> = {}): BackupList {
  return { items: [backupFixture()], state: backupStateFixture(), schedule: backupScheduleFixture(), ...o };
}

export function httpsInfoFixture(o: Partial<HTTPSInfo> = {}): HTTPSInfo {
  return {
    subject: 'CN=alice.example.test',
    dns_names: ['alice.example.test'],
    ip_addresses: ['10.0.0.5'],
    not_before: '2026-10-01T00:00:00Z',
    not_after: '2027-10-01T00:00:00Z',
    fingerprint_sha256: 'ab'.repeat(32),
    temporary: true,
    ...o,
  };
}

export function forwardingFixture(o: Partial<Forwarding> = {}): Forwarding {
  return {
    enabled: false,
    host: '',
    port: 6514,
    transport: 'tls',
    ca_set: false,
    backlog: 0,
    cursor_seq: 0,
    last_sent_at: null,
    last_error_code: '',
    last_error_at: null,
    version: 0,
    ...o,
  };
}

// smtpFixture is the mail settings of an installation without a mail server.
export const smtpFixture = {
  configured: false,
  host: '',
  port: 587,
  tls_mode: 'starttls',
  from: '',
  username: '',
  has_password: false,
  ca_pem: '',
  trusted_certificate: null,
  version: 0,
  updated_at: null,
};

// ACME issuance: a certificate authority (Let's Encrypt staging, with an active account), its account, a DNS hook and an
// ACME certificate. The ids are fixed UUIDs, so the tests can address them.
export const ACME_PROVIDER_ID = '0192f000-0000-7000-8000-0000000000a1';
export const ACME_ACCOUNT_ID = '0192f000-0000-7000-8000-0000000000a2';
export const ACME_HOOK_ID = '0192f000-0000-7000-8000-0000000000a3';
export const ACME_CERT_ID = '0192f000-0000-7000-8000-0000000000a4';

export function acmeAccountFixture(o: Partial<ACMEAccount> = {}): ACMEAccount {
  return {
    id: ACME_ACCOUNT_ID,
    provider_id: ACME_PROVIDER_ID,
    contact_email: 'ops@example.com',
    account_url: 'https://acme-staging-v02.api.letsencrypt.org/acme/acct/123',
    tos_url: 'https://letsencrypt.org/documents/LE-SA-v1.5.pdf',
    tos_accepted_at: '2026-10-13T09:00:00Z',
    state: 'active',
    created_at: '2026-10-13T09:00:00Z',
    updated_at: '2026-10-13T09:00:00Z',
    ...o,
  };
}

export function acmeProviderFixture(o: Partial<ACMEProvider> = {}): ACMEProvider {
  return {
    id: ACME_PROVIDER_ID,
    name: 'LE staging',
    directory_url: 'https://acme-staging-v02.api.letsencrypt.org/directory',
    preset: 'letsencrypt_staging',
    ca_bundle_pem: '',
    eab_kid: '',
    eab_configured: false,
    allowed_suffixes: ['example.com'],
    active_account_id: ACME_ACCOUNT_ID,
    pending_rollover: false,
    created_at: '2026-10-13T08:00:00Z',
    updated_at: '2026-10-13T08:00:00Z',
    ...o,
  };
}

// emptyDNSSettings are a hook's settings (a built-in DNS provider's are filled in).
export const emptyDNSSettings: ACMEDNSSettings = {
  auth: '',
  tenant_id: '',
  client_id: '',
  subscription_id: '',
  resource_group: '',
  cert_thumbprint: '',
  cert_not_after: null,
  access_key_id: '',
  role_arn: '',
  external_id: '',
};

export function acmeHookFixture(o: Partial<ACMEHook> = {}): ACMEHook {
  return {
    id: ACME_HOOK_ID,
    kind: 'webhook',
    settings: emptyDNSSettings,
    name: 'Internal DNS',
    url: 'https://dns-hook.example.com/acme',
    ca_bundle_pem: '',
    secret_configured: true,
    allowed_suffixes: ['example.com'],
    propagation_wait_seconds: 5,
    poll_timeout_seconds: 60,
    created_at: '2026-10-13T08:00:00Z',
    updated_at: '2026-10-13T08:00:00Z',
    ...o,
  };
}

export function acmeCertificateFixture(o: Partial<ACMECertificate> = {}): ACMECertificate {
  return {
    id: ACME_CERT_ID,
    provider_id: ACME_PROVIDER_ID,
    account_id: ACME_ACCOUNT_ID,
    names: ['www.example.com'],
    key_type: 'ecdsa_p256',
    challenge: 'dns01',
    hook_id: ACME_HOOK_ID,
    http_target_id: null,
    renew_before_days: 30,
    auto_renew: true,
    auto_deploy: false,
    state: 'active',
    stopped_reason: '',
    failures: 0,
    last_failure_class: '',
    permanent_failures: 0,
    recovering: false,
    next_attempt_at: null,
    ca_not_before: null,
    ca_wait_critical: false,
    last_attempt_at: null,
    last_error: null,
    running_order_id: null,
    current: null,
    ari_window: null,
    renew_at: null,
    renew_at_source: '',
    deploy_held_reason: '',
    deploy_stopped: false,
    bindings_count: 0,
    created_at: '2026-10-13T08:00:00Z',
    updated_at: '2026-10-13T08:00:00Z',
    ...o,
  };
}

// Issued certificates: an order of the ACME certificate, its current certificate and a website bound to it.
export const ACME_ORDER_ID = '0192f000-0000-7000-8000-0000000000a5';
export const ACME_CURRENT_ID = '0192f000-0000-7000-8000-0000000000a6';

export function acmeOrderFixture(o: Partial<ACMEOrder> = {}): ACMEOrder {
  return {
    id: ACME_ORDER_ID,
    acme_certificate_id: ACME_CERT_ID,
    kind: 'issue',
    state: 'succeeded',
    trigger: 'manual',
    started_at: '2026-10-13T09:00:00Z',
    finished_at: '2026-10-13T09:01:00Z',
    error: null,
    certificate_id: ACME_CURRENT_ID,
    requested_by: null,
    presented: 0,
    cleanup_at: null,
    cleanup_error: null,
    revoked_at: null,
    revocation_reason: '',
    compromised: false,
    replaces: '',
    replaces_outcome: '',
    ...o,
  };
}

export const acmeCurrentFixture = (o: Partial<NonNullable<ACMECertificate['current']>> = {}): NonNullable<ACMECertificate['current']> => ({
  id: ACME_CURRENT_ID,
  fingerprint_sha256: '0123456789abcdef'.repeat(4),
  not_before: '2026-10-13T09:00:00Z',
  not_after: '2099-01-11T09:00:00Z',
  chain_complete: true,
  revoked_at: null,
  revocation_reason: '',
  compromised: false,
  ...o,
});

export function acmeBindingFixture(o: Partial<ACMEBinding> = {}): ACMEBinding {
  return {
    acme_certificate_id: ACME_CERT_ID,
    location_id: LOCATION_ID,
    target_id: nginxTargetFixture.id,
    target_name: 'web-nginx',
    cert_path: '/etc/nginx/ssl/www.crt',
    auto_deploy: false,
    state: 'current',
    attention_at: null,
    attention: null,
    served_certificate_id: ACME_CURRENT_ID,
    created_at: '2026-10-13T09:05:00Z',
    observation: null,
    ...o,
  };
}

// The observation of a bound location (R52): Alice deployed the current certificate, the file and the website agree.
export const DESIRED_FP = '0123456789abcdef'.repeat(4);
export const OLD_FP = 'fedcba9876543210'.repeat(4);
export function observationFixture(o: Partial<LocationObservation> = {}): LocationObservation {
  return {
    health: 'in_sync',
    source: 'acme',
    source_id: ACME_CERT_ID,
    desired: { certificate_id: ACME_CURRENT_ID, fingerprint: DESIRED_FP, not_after: '2099-01-11T09:00:00Z' },
    last_deployment: { deployment_id: '0192c000-0000-7000-8000-0000000000d9', fingerprint: DESIRED_FP, finished_at: '2026-10-13T09:10:00Z', level: 3 },
    file: { certificate_id: ACME_CURRENT_ID, fingerprint: DESIRED_FP, not_after: '2099-01-11T09:00:00Z', observed_at: '2026-10-20T06:00:00Z', changed_outside_at: null },
    tls: {
      certificate_id: ACME_CURRENT_ID,
      fingerprint: DESIRED_FP,
      not_after: '2099-01-11T09:00:00Z',
      observed_at: '2026-10-20T06:00:05Z',
      probe: 'alice',
      level: 3,
      trust: 'trusted',
      trust_error: '',
    },
    tls_attempted_at: '2026-10-20T06:00:05Z',
    tls_error: null,
    mode: 'auto',
    mode_setting: 'default',
    default_mode: 'auto',
    drift_since: null,
    drift_fingerprint: '',
    drift_source: '',
    backoff_reason: '',
    backed_off_at: null,
    active_deployment_id: null,
    next_observe_at: '2026-10-20T12:00:00Z',
    repair_available: false,
    ...o,
  };
}

// A drifted observation: another tool put an older certificate back (it ends soon).
export function driftedObservationFixture(o: Partial<LocationObservation> = {}): LocationObservation {
  const old = { certificate_id: null, fingerprint: OLD_FP, not_after: '2026-10-21T06:00:00Z' };
  return observationFixture({
    health: 'drifted',
    file: { ...old, observed_at: '2026-10-20T12:00:00Z', changed_outside_at: '2026-10-20T12:00:00Z' },
    tls: { ...old, observed_at: '2026-10-20T12:00:05Z', probe: 'helper', level: 0, trust: '', trust_error: '' },
    drift_since: '2026-10-20T12:00:05Z',
    drift_fingerprint: OLD_FP,
    drift_source: 'tls',
    repair_available: true,
    ...o,
  });
}

// Network discovery.
export const SCOPE_ID = '0192f100-0000-7000-8000-0000000000d1';
export const SCAN_ID = '0192f100-0000-7000-8000-0000000000e1';
export const DISCOVERED_FP = 'a1'.repeat(32);

export function discoveryScanFixture(o: Partial<DiscoveryScan> = {}): DiscoveryScan {
  return {
    id: SCAN_ID,
    scope_id: SCOPE_ID,
    scope_name: 'Data centre',
    trigger: 'manual',
    state: 'done',
    cancel_requested: false,
    endpoints_total: 512,
    endpoints_answered: 40,
    endpoints_failed: 472,
    endpoints_excluded: 0,
    certificates_new: 3,
    cert_churn: 0,
    requested_by: null,
    queued_at: '2026-10-13T09:00:00Z',
    started_at: '2026-10-13T09:00:01Z',
    finished_at: '2026-10-13T09:03:13Z',
    error_code: null,
    error_reason: null,
    ...o,
  };
}

export function discoveryScopeFixture(o: Partial<DiscoveryScope> = {}): DiscoveryScope {
  return {
    id: SCOPE_ID,
    name: 'Data centre',
    entries: ['10.0.1.0/24', 'intranet.example.test'],
    ports: [443, 8443],
    sni_names: [],
    exclusions: [],
    enabled: true,
    schedule_hours: 0,
    window_start: '',
    window_end: '',
    window_tz: 'UTC',
    alert_on_expiry: false,
    rate_per_sec: 0,
    concurrency: 0,
    version: 3,
    created_by: null,
    created_at: '2026-10-12T09:00:00Z',
    updated_at: '2026-10-12T09:00:00Z',
    last_scheduled_at: null,
    active_scan_id: null,
    last_scan: discoveryScanFixture(),
    ...o,
  };
}

export function discoverySettingsFixture(o: Partial<DiscoverySettings> = {}): DiscoverySettings {
  return {
    allowed_networks: ['10.0.0.0/16'],
    global_exclusions: ['10.0.9.0/24'],
    retention_days: 90,
    scanning_enabled: true,
    builtin_exclusions: ['127.0.0.0/8', '169.254.0.0/16'],
    ...o,
  };
}

export function discoveredEndpointFixture(o: Partial<DiscoveredEndpoint> = {}): DiscoveredEndpoint {
  return {
    id: '0192f100-0000-7000-8000-0000000000f1',
    scope_id: SCOPE_ID,
    address: '10.0.1.20',
    port: 443,
    sni: '',
    host: '',
    fingerprint_sha256: DISCOVERED_FP,
    previous_fingerprints: [],
    chain_length: 2,
    tls_version: 'TLS 1.3',
    cipher: 'TLS_AES_128_GCM_SHA256',
    state: 'present',
    last_error_code: '',
    missed_scans: 0,
    first_seen: '2026-10-12T09:01:00Z',
    last_seen: '2026-10-13T09:02:00Z',
    last_scanned_at: '2026-10-13T09:02:00Z',
    gone_since: null,
    target: null,
    ...o,
  };
}

export function discoveredCertificateFixture(o: Partial<DiscoveredCertificate> = {}): DiscoveredCertificate {
  return {
    fingerprint_sha256: DISCOVERED_FP,
    subject_cn: 'legacy.example.test',
    sans: ['legacy.example.test', 'old.example.test'],
    issuer_cn: 'Example Issuing CA',
    not_before: '2026-01-01T00:00:00Z',
    not_after: '2099-01-01T00:00:00Z',
    days_left: 26000,
    expired: false,
    key_algorithm: 'rsa',
    self_signed: false,
    status: 'unmanaged',
    managed_certificate_id: null,
    endpoint_count: 2,
    seen_on_count: 2,
    first_seen: '2026-10-12T09:01:00Z',
    last_seen: '2026-10-13T09:02:00Z',
    ...o,
  };
}

export function discoveryPreviewFixture(o: Partial<DiscoveryPreview> = {}): DiscoveryPreview {
  return { addresses: 1024, excluded_addresses: 0, hostnames: 0, ports: 2, sni_names: 0, endpoints: 2048, builtin_exclusions: [], ...o };
}

// Revocation and key-compromise incidents (2026-10-20): the impact of the Phase 4 certificate (two files on a server, one
// with another certificate made with the same key, and one endpoint network discovery found) and an incident of it.
export const INCIDENT_ID = '0192f100-0000-7000-8000-0000000000b1';

export function certificateImpactFixture(o: Partial<CertificateImpact> = {}): CertificateImpact {
  const c = certificateFixture();
  return {
    certificate: c,
    certificates: [
      { id: c.id, fingerprint: c.fingerprint, subject_cn: c.subject_cn, label: '', source: c.source, not_after: c.not_after, revoked_at: null, compromised_at: null, match: 'certificate' },
      { id: '0192c000-0000-7000-8000-0000000000c7', fingerprint: 'ef56'.repeat(16), subject_cn: 'other.example.test', label: '', source: 'discovered', not_after: c.not_after, revoked_at: null, compromised_at: null, match: 'key' },
    ],
    locations: [
      { location_id: locationFixture().id, target_id: targetFixture.id, target_name: targetFixture.name, target_type: 'nginx', cert_path: '/etc/nginx/ssl/www.crt', certificate_id: c.id, fingerprint: c.fingerprint, match: 'certificate', deployable: true, acme_certificate_id: null, kv_bound: false },
      { location_id: '0192c000-0000-7000-8000-0000000000e7', target_id: targetFixture.id, target_name: targetFixture.name, target_type: 'nginx', cert_path: '/etc/nginx/ssl/other.crt', certificate_id: '0192c000-0000-7000-8000-0000000000c7', fingerprint: 'ef56'.repeat(16), match: 'key', deployable: true, acme_certificate_id: null, kv_bound: false },
    ],
    vaults: [],
    endpoints: [
      { endpoint_id: '0192c000-0000-7000-8000-0000000000f7', scope_id: '0192c000-0000-7000-8000-0000000000f8', scope_name: 'Office LAN', address: '10.0.0.9', port: 443, sni: '', host: '', fingerprint: c.fingerprint, state: 'present', last_seen: '2026-10-19T08:00:00Z', match: 'certificate' },
    ],
    endpoints_hidden: false,
    truncated: false,
    open_incident_id: null,
    ...o,
  };
}

export function incidentFixture(o: Partial<Incident> = {}): Incident {
  const c = certificateFixture();
  return {
    id: INCIDENT_ID,
    certificate_id: c.id,
    certificate_name: c.subject_cn,
    fingerprint: c.fingerprint,
    source: 'acme',
    public_key_sha256: c.public_key_sha256,
    acme_certificate_id: ACME_CERT_ID,
    state: 'needs_attention',
    revoke_mode: 'after_verified',
    revocation: 'pending',
    order_id: ACME_ORDER_ID,
    order_state: 'succeeded',
    replacement_certificate_id: ACME_CURRENT_ID,
    replacement_fingerprint: '0123456789abcdef'.repeat(4),
    attention: { code: 'ALC-INC-0010', reason: 'incident.deployments_failed' },
    revoke_attempts: 0,
    next_attempt_at: null,
    revoked_at: null,
    started_by: '0192a000-0000-7000-8000-0000000000u1',
    started_by_name: 'Ada',
    closed_by: null,
    created_at: '2026-10-20T08:00:00Z',
    updated_at: '2026-10-20T08:05:00Z',
    finished_at: null,
    counts: { verified: 1, failed: 1 },
    locations: [
      { location_id: locationFixture().id, target_id: targetFixture.id, target_name: targetFixture.name, cert_path: '/etc/nginx/ssl/www.crt', status: 'verified', deployment_id: '0192c000-0000-7000-8000-0000000000d1', error: null, attempts: 1, updated_at: '2026-10-20T08:04:00Z', outcome_uncertain: false },
      { location_id: '0192c000-0000-7000-8000-0000000000e7', target_id: targetFixture.id, target_name: targetFixture.name, cert_path: '/etc/nginx/ssl/api.crt', status: 'failed', deployment_id: '0192c000-0000-7000-8000-0000000000d2', error: { code: 'ALC-DEP-0006', reason: 'deployment.reload_failed' }, attempts: 1, updated_at: '2026-10-20T08:04:00Z', outcome_uncertain: false },
    ],
    ...o,
  };
}

// Services and environments (R49): Production with one service owning a server and a certificate, the Default service,
// and a trust from the Default service.
export const SERVICE_ID = '0192f200-0000-7000-8000-0000000000a1';
export const DEFAULT_SERVICE_ID = '0192f200-0000-7000-8000-000000000001';
export const PRODUCTION_ID = '0192f200-0000-7000-8000-0000000000e1';

export function environmentFixture(o: Partial<Environment> = {}): Environment {
  return { id: PRODUCTION_ID, key: 'production', name: 'Production', sort: 10, version: 1, services: 1, created_at: '2026-10-20T08:00:00Z', updated_at: '2026-10-20T08:00:00Z', ...o };
}

export function serviceFixture(o: Partial<Service> = {}): Service {
  return {
    id: SERVICE_ID,
    name: 'Payments',
    description: 'Card payments and the checkout website.',
    environment: { id: PRODUCTION_ID, key: 'production', name: 'Production' },
    is_default: false,
    policy_version: 1,
    version: 1,
    counts: { servers: 1, key_vaults: 0, certificates: 1, signing_requests: 0, acme_certificates: 0, ssh_keys: 0, discovery_scopes: 0 },
    created_at: '2026-10-20T08:00:00Z',
    updated_at: '2026-10-20T08:00:00Z',
    ...o,
  };
}

export const defaultServiceFixture = serviceFixture({
  id: DEFAULT_SERVICE_ID,
  name: 'Default',
  description: '',
  environment: null,
  is_default: true,
  counts: { servers: 2, key_vaults: 1, certificates: 3, signing_requests: 0, acme_certificates: 1, ssh_keys: 2, discovery_scopes: 1 },
});

export const serviceRef = { id: SERVICE_ID, name: 'Payments', environment: { id: PRODUCTION_ID, key: 'production', name: 'Production' } };
export const defaultServiceRef = { id: DEFAULT_SERVICE_ID, name: 'Default', environment: null };

export function servicePolicyFixture(o: Partial<ServicePolicy> = {}): ServicePolicy {
  return { version: 1, body: { schema: 1 }, created_by: null, created_by_name: '', created_at: '2026-10-20T08:00:00Z', ...o };
}

export function serviceTrustFixture(o: Partial<ServiceTrust> = {}): ServiceTrust {
  return { id: '0192f200-0000-7000-8000-0000000000f1', source: defaultServiceRef, target: serviceRef, created_by_name: 'Ada Admin', created_at: '2026-10-20T08:00:00Z', ...o };
}

export function assignResultFixture(o: Partial<AssignResult> = {}): AssignResult {
  return {
    dry_run: true,
    destination: serviceRef,
    moves: [{ type: 'target', id: targetFixture.id, name: targetFixture.name, from: defaultServiceRef, changed: true }],
    untrusted: [
      {
        kind: 'key_vault',
        source_id: '0192f200-0000-7000-8000-0000000000b1',
        source_name: 'www-cert',
        location_id: '0192f200-0000-7000-8000-0000000000b2',
        target_id: targetFixture.id,
        target_name: targetFixture.name,
        source_service: defaultServiceRef,
        target_service: serviceRef,
      },
    ],
    ...o,
  };
}

// Scoped access (R49 Phase 2). scopedSession is a person without a global role who holds the given roles on the Payments
// service (none: a person with no access at all); globalSession is a global role as the server sends it with access.
export function scopedSession(roles: Role[], locale = 'en'): SessionInfo {
  const s = sessionFor(roles[0] ?? 'operator', locale);
  const perms = [...new Set(roles.flatMap((r) => ROLE_PERMISSIONS[r]))];
  return {
    ...s,
    user: { ...s.user, id: '00000000-0000-7000-8000-000000000009', username: 'deniz', display_name: 'Deniz Kaya', role: null },
    access: { global_role: null, services: roles.length > 0 ? [{ ...serviceRef, roles }] : [], permissions_anywhere: perms, platform_permissions: [] },
  };
}

export function globalSession(role: Role, locale = 'en'): SessionInfo {
  const s = sessionFor(role, locale);
  const perms = [...ROLE_PERMISSIONS[role]];
  return { ...s, access: { global_role: role, services: [], permissions_anywhere: perms, platform_permissions: perms } };
}

export const ROLE_BINDING_ID = '0192f200-0000-7000-8000-0000000000c1';
export const ENV_BINDING_ID = '0192f200-0000-7000-8000-0000000000c2';

export function roleBindingFixture(o: Partial<RoleBinding> = {}): RoleBinding {
  return {
    id: ROLE_BINDING_ID,
    user_id: userFor('operator').id,
    username: 'operator',
    display_name: 'Olcay Öztürk',
    directory_group_id: null,
    role: 'operator',
    service: serviceRef,
    environment: null,
    services: [serviceRef],
    created_by: userFor('admin').id,
    created_by_name: 'Ayşe Yılmaz',
    created_at: '2026-10-21T08:00:00Z',
    ...o,
  };
}

export const environmentBindingFixture = roleBindingFixture({
  id: ENV_BINDING_ID,
  role: 'auditor',
  service: null,
  environment: { id: PRODUCTION_ID, key: 'production', name: 'Production' },
  services: [serviceRef],
});
