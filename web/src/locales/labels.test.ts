import { auditActionsIn, backendAuditActions, backendJobTypes, jobTypesIn } from '../test/goSources';
import en from './en.json';
import tr from './tr.json';

function lookup(bundle: unknown, key: string): unknown {
  return key.split('.').reduce<unknown>((o, k) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[k] : undefined), bundle);
}

// AuditPage looks a label up as audit.actions.<action with dots as underscores>; BlockedJobsPanel
// looks a job type up as jobs.types.<type>, a nested path ("certificate.deploy" is
// jobs.types.certificate.deploy).
const auditKey = (action: string) => `audit.actions.${action.replace(/\./g, '_')}`;
const jobKey = (type: string) => `jobs.types.${type}`;

function missingLabels(bundle: unknown, names: string[], keyOf: (n: string) => string): string[] {
  return names.filter((n) => typeof lookup(bundle, keyOf(n)) !== 'string');
}

describe('the Go source readers', () => {
  it('find every way an audit action is written', () => {
    const src = `
      s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "csr.created", ObjectType: "csr"})
      ev.Action = "certificate.key_attached"
      return s.appendAudit(ctx, tx, "deployment.started", audit.Success, id, nil)
      r.jobEvent("job.blocked_license", audit.Denied, h.id, nil)
      events = []ev{{"deployment.succeeded", audit.Success, nil}, {"deployment.failed", audit.Failure, nil}}
      reason := "deployment.interrupted"`;
    expect(auditActionsIn(src)).toEqual([
      'certificate.key_attached',
      'csr.created',
      'deployment.failed',
      'deployment.started',
      'deployment.succeeded',
      'job.blocked_license',
    ]);
  });

  it('find job type constants', () => {
    expect(jobTypesIn('const (\n\tJobDiscover = "target.discover"\n\t// JobX is documented\n\tJobCertificateDeploy = "certificate.deploy"\n)')).toEqual([
      'certificate.deploy',
      'target.discover',
    ]);
  });

  it('read the real sources', () => {
    expect(backendAuditActions()).toEqual(expect.arrayContaining(['certificate.uploaded', 'csr.completed', 'deployment.recovery_started', 'location.updated']));
    expect(backendJobTypes()).toEqual(expect.arrayContaining(['certificate.deploy', 'certificate.deploy_recover']));
  });

  it('make the completeness check fail for an action or a job type without a label', () => {
    const fakeAction = auditActionsIn('Action: "certificate.fake_new"');
    expect(missingLabels(en, [...backendAuditActions(), ...fakeAction], auditKey)).toEqual(['certificate.fake_new']);
    const fakeJob = jobTypesIn('Job = "certificate.fake_job"');
    expect(missingLabels(tr, [...backendJobTypes(), ...fakeJob], jobKey)).toEqual(['certificate.fake_job']);
  });
});

describe.each([
  ['en', en],
  ['tr', tr],
] as const)('%s labels', (_lang, bundle) => {
  it('has an audit label for every audit action the backend writes', () => {
    expect(missingLabels(bundle, backendAuditActions(), auditKey)).toEqual([]);
  });

  it('has a job label for every job type, found by the nested lookup', () => {
    expect(missingLabels(bundle, backendJobTypes(), jobKey)).toEqual([]);
    // The flat form the contract first named is not a key (D33).
    expect(lookup(bundle, 'jobs.types.certificate_deploy')).toBeUndefined();
  });

  it('keeps the upload button and the upload dialog texts apart (D35)', () => {
    expect(typeof lookup(bundle, 'certificates.uploadButton')).toBe('string');
    expect(typeof lookup(bundle, 'certificates.upload.title')).toBe('string');
  });
});
