import { http, HttpResponse } from 'msw';
import type { DashboardSummary } from '../api/phase7';
import type { Provider } from '../api/sso';
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
  NginxFacts,
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
  tampered: false,
  files: [{ status: 'current', uploaded_at: '2026-10-01T09:00:00Z', license: licenseInfoFixture }],
  history: [
    { at: '2026-10-01T09:00:00Z', event: 'installed', license_id: 'LIC-2026-000123', from_state: 'evaluation', to_state: 'active', notice: null },
  ],
};

// statusWith builds a license status with the given banners (no banner = nothing to show).
export function statusWith(...banners: LicenseBanner[]): LicenseStatus {
  return { expired: banners.some((b) => ['grace', 'locked', 'evaluation_ended'].includes(b.kind)), banners };
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

// nginxTargetFixture is an Nginx server whose last scan was fine; nginxFacts builds its facts.
export function nginxFacts(o: Partial<NginxFacts> = {}): NginxFacts {
  return { version: '1.24.0', conf_path: '/etc/nginx/nginx.conf', config_valid: true, config_error: '', config_error_reason: '', config_error_file: '', found: true, ...o };
}

export const nginxTargetFixture: Target = {
  ...targetFixture,
  id: '0192b000-0000-7000-8000-0000000000a2',
  name: 'web-nginx',
  type: 'nginx',
  host: 'nginx-01.example.com',
  capabilities: ['discover_certs', 'deploy_certs', 'test_connection'],
  facts: { ...targetFixture.facts, nginx: nginxFacts() },
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
