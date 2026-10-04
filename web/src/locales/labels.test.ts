import en from './en.json';
import tr from './tr.json';

function lookup(bundle: unknown, key: string): unknown {
  return key.split('.').reduce<unknown>((o, k) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[k] : undefined), bundle);
}

// AUDIT_ACTIONS are the audit actions the Phase 4 backend emits for certificates, signing requests,
// locations and deployments (the Action strings in internal/inventory: uploads.go, csr.go,
// location_settings.go, locations.go, deployments.go, deployment_records.go). AuditPage looks a
// label up as audit.actions.<action with dots as underscores>.
const AUDIT_ACTIONS = [
  'certificate.uploaded',
  'certificate.upload_rejected',
  'certificate.key_attached',
  'csr.created',
  'csr.completed',
  'csr.cancelled',
  'location.updated',
  'location.changed_outside',
  'deployment.requested',
  'deployment.denied',
  'deployment.precheck_started',
  'deployment.started',
  'deployment.recovering',
  'deployment.recovery_started',
  'deployment.succeeded',
  'deployment.unchanged',
  'deployment.failed',
  'deployment.rolled_back',
  'deployment.rollback_failed',
  'deployment.needs_attention',
];

// JOB_TYPES are the job types of Phase 4 (internal/inventory/jobs.go). BlockedJobsPanel looks a type
// up as jobs.types.<type>, a nested path, so "certificate.deploy" is jobs.types.certificate.deploy.
const JOB_TYPES = ['certificate.deploy', 'certificate.deploy_recover'];

describe.each([
  ['en', en],
  ['tr', tr],
] as const)('%s labels', (_lang, bundle) => {
  it.each(AUDIT_ACTIONS)('has an audit label for %s', (action) => {
    expect(typeof lookup(bundle, `audit.actions.${action.replace(/\./g, '_')}`)).toBe('string');
  });

  it.each(JOB_TYPES)('has a job label for %s that the nested lookup finds', (type) => {
    expect(typeof lookup(bundle, `jobs.types.${type}`)).toBe('string');
    // The flat form the contract first named is not a key (D33).
    expect(lookup(bundle, `jobs.types.${type.replace('.', '_')}`)).toBeUndefined();
  });

  it('keeps the upload button and the upload dialog texts apart (D35)', () => {
    expect(typeof lookup(bundle, 'certificates.uploadButton')).toBe('string');
    expect(typeof lookup(bundle, 'certificates.upload.title')).toBe('string');
  });
});
