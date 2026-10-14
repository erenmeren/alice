import { auditActionsIn, backendAuditActions, backendJobTypes, jobTypesIn, registeredJobTypes, rejectReasonsIn } from '../test/goSources';
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

  it('find the actions passed to the audit helpers and chosen in assignments (AUD-25 d)', () => {
    const src = `
      return s.adminChange(ctx, actor, id, "user.password_reset", details, func(tx pgx.Tx) error {
      return s.auditFailure(ctx, tx, actor, "auth.mfa_verify", p.UserID.String(), reason)
      return s.recordFailure(ctx, tx, actor, p.UserID, "auth.stepup", "bad_totp")
      if aerr := s.adminFailure(ctx, p, m, "user.created", "", "username_taken"); aerr != nil {
      r.terminate(ctx, c, "job.unknown_type", "job.dead")
      action, result := "job.recovered", audit.Success
      event, action := "renewed", "license.renewed"
      problem, action = "jump_cleared", "clock.jump_cleared"
      action = "license.expired"
      h.recordFailure(jobCtx, j.TargetID, providers.NewError("ssh.timeout", true, err, nil))
      return action == "license.installation_tampered", n, legacy, nil
      Action: "license.upload." + reason,`;
    expect(auditActionsIn(src)).toEqual([
      'auth.mfa_verify',
      'auth.stepup',
      'clock.jump_cleared',
      'job.dead',
      'job.recovered',
      'license.expired',
      'license.renewed',
      'user.created',
      'user.password_reset',
    ]);
  });

  it('find the reasons of a refused license upload', () => {
    const src = 'func RejectReason(err error) string {\n\tswitch {\n\tcase x:\n\t\treturn "invalid_signature"\n\tdefault:\n\t\treturn "error"\n\t}\n}\n\nfunc other() string {\n\treturn "nope"\n}';
    expect(rejectReasonsIn(src)).toEqual(['error', 'invalid_signature']);
  });

  it('find job type constants', () => {
    expect(jobTypesIn('const (\n\tJobDiscover = "target.discover"\n\t// JobX is documented\n\tJobCertificateDeploy = "certificate.deploy"\n)')).toEqual([
      'certificate.deploy',
      'target.discover',
    ]);
  });

  it('find job types registered with a literal name', () => {
    expect(registeredJobTypes('A = Register("license.evaluate", license.ClassAlways)\nB = Register(inventory.JobX, c)\nC = Register("notify.send", c)')).toEqual([
      'license.evaluate',
      'notify.send',
    ]);
  });

  it('read the real sources', () => {
    expect(backendAuditActions()).toEqual(
      expect.arrayContaining([
        'certificate.uploaded',
        'csr.completed',
        'deployment.recovery_started',
        'location.updated',
        // written by internal/auth, internal/license and internal/setup, through helpers and assignments
        'auth.login',
        'user.mfa_reset',
        'user.sessions_revoked',
        'token.revoked',
        'license.activated',
        'license.state_changed',
        'license.upload.invalid_signature',
        'license.upload.older_than_installed',
        'clock.jump_cleared',
        'setup.completed',
        'job.recovered',
        'job.tampered',
      ]),
    );
    // "license.upload." + RejectReason(err) is expanded, never kept as a bare prefix.
    expect(backendAuditActions().filter((a) => a.endsWith('.'))).toEqual([]);
    expect(backendJobTypes()).toEqual(expect.arrayContaining(['certificate.deploy', 'certificate.deploy_recover', 'license.evaluate', 'discovery.schedule', 'deployment.recovery_sweep']));
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

  it('words the discovery job so it is true for Linux and Nginx servers', () => {
    expect(lookup(bundle, 'jobs.types.target.discover')).not.toMatch(/SSH/);
  });

  // Network discovery (A1): the netdisco.* job types are declared in internal/jobs/types.go and registered with their
  // handlers later, so the guard above cannot see them yet; their labels exist already and stay apart from the SSH-key
  // discovery task (discovery.schedule).
  it('labels the network discovery job types before they are registered', () => {
    expect(missingLabels(bundle, ['netdisco.scan', 'netdisco.schedule', 'netdisco.retention'], jobKey)).toEqual([]);
    expect(lookup(bundle, 'jobs.types.netdisco.schedule')).not.toBe(lookup(bundle, 'jobs.types.discovery.schedule'));
  });

  it('keeps the upload button and the upload dialog texts apart (D35)', () => {
    expect(typeof lookup(bundle, 'certificates.uploadButton')).toBe('string');
    expect(typeof lookup(bundle, 'certificates.upload.title')).toBe('string');
  });
});
