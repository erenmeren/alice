import { http, HttpResponse } from 'msw';
import type {
  Certificate,
  CertificateDetail,
  CertificateLocation,
  CSR,
  Deployment,
  HostKey,
  Job,
  KeyLocation,
  LicenseBanner,
  LicenseDetail,
  LicenseStatus,
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
