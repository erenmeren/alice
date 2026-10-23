import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import en from '../locales/en.json';
import tr from '../locales/tr.json';
import { callArgsIn, goConsts, goFiles, readRepoFile } from '../test/goSources';
import {
  CERTIFICATE_SOURCES,
  CONFIG_ERRORS,
  CONFIG_REASONS,
  CSR_STATUSES,
  DEPLOYMENT_STATES,
  DEPLOYMENT_STATUSES,
  DEPLOYMENT_STEP_NAMES,
  FILE_PROBLEMS,
  KEY_ALGORITHMS,
  STEP_STATUSES,
  UNSUPPORTED_REASONS,
  UPLOAD_WARNING_KEYS,
  VERIFIED_MODES,
  WINDOWS_STEP_ERRORS,
  configErrorKey,
  configReasonKey,
  deploymentStateKey,
  fileProblemKey,
  stepErrorKey,
  stepNameKey,
  stepStatusKey,
  unsupportedReasonKey,
  verifiedKey,
} from './enums';
import { CAPABILITIES } from './capabilities';
import { WEB_SERVER_TYPES } from './webServer';
import { LOCATION_WARNINGS, WARNING_PARAMS, locationWarningKey, warningKey } from './warnings';

// The enums are read from api/openapi.yaml, so a value the API gains without a label fails here.
const spec = readFileSync(resolve(process.cwd(), '../api/openapi.yaml'), 'utf8');

// schemaProp returns the text of one property (its flow-style line plus its block description).
function schemaProp(schema: string, prop: string): string {
  const start = spec.indexOf(`\n    ${schema}:\n`);
  if (start < 0) throw new Error(`schema ${schema} not found`);
  const rest = spec.slice(start + 1);
  const end = rest.slice(1).search(/\n {4}\S/);
  const block = end < 0 ? rest : rest.slice(0, end + 1);
  const at = block.indexOf(`\n        ${prop}:`);
  if (at < 0) throw new Error(`${schema}.${prop} not found`);
  const tail = block.slice(at + 1);
  const next = tail.slice(1).search(/\n {8}\S/);
  return next < 0 ? tail : tail.slice(0, next + 1);
}

function enumOf(schema: string, prop: string): string[] {
  const m = /enum: \[([^\]]*)\]/.exec(schemaProp(schema, prop));
  if (!m) throw new Error(`${schema}.${prop} has no enum`);
  return m[1].split(',').map((v) => v.trim().replace(/^"|"$/g, ''));
}

// knownList reads the list after "Known values: " up to a ';', '"' or '}' outside parentheses: a value
// may carry an explanation in parentheses, which can hold commas and semicolons of its own and is
// dropped ("chain_completed (an upload completed …; answered with 200)").
function knownList(text: string): string[] | null {
  const at = text.indexOf('Known values: ');
  if (at < 0) return null;
  const values: string[] = [];
  let depth = 0;
  let current = '';
  for (const ch of text.slice(at + 'Known values: '.length)) {
    if (ch === '(') depth += 1;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    else if (depth === 0 && (ch === ';' || ch === '"' || ch === '}')) break;
    else if (depth === 0 && ch === ',') {
      values.push(current);
      current = '';
    } else if (depth === 0) current += ch;
  }
  values.push(current);
  return values.map((v) => v.trim().replace(/\.$/, '')).filter((v) => v !== '');
}

function knownValues(schema: string, prop: string): string[] {
  const list = knownList(schemaProp(schema, prop).replace(/\s+/g, ' '));
  if (!list) throw new Error(`${schema}.${prop} has no known values`);
  return list;
}

function lookup(bundle: unknown, key: string): unknown {
  return key.split('.').reduce<unknown>((o, k) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[k] : undefined), bundle);
}

const bundles = { en, tr } as const;

describe('enum labels cover every value of api/openapi.yaml', () => {
  it('reads sane values from the specification', () => {
    expect(enumOf('CSR', 'status')).toEqual(['pending', 'completed', 'cancelled']);
    expect(knownValues('Certificate', 'source')).toContain('uploaded');
    // A value explained in parentheses (with commas and a semicolon inside) is read as the value alone.
    expect(knownList('Known values: a, b_c (x, y; z), d; a newer server may add others.')).toEqual(['a', 'b_c', 'd']);
    expect(knownValues('CertificateStored', 'warnings')).toContain('chain_completed');
  });

  const cases: { name: string; values: () => string[]; labelKey: (v: string) => string; known: readonly string[] }[] = [
    { name: 'certificate source', values: () => knownValues('Certificate', 'source'), labelKey: (v) => `enum.certificateSource.${v}`, known: CERTIFICATE_SOURCES },
    { name: 'key algorithm', values: () => knownValues('Certificate', 'key_algorithm'), labelKey: (v) => `enum.keyAlgorithm.${v}`, known: KEY_ALGORITHMS },
    { name: 'signing request status', values: () => enumOf('CSR', 'status'), labelKey: (v) => `enum.csrStatus.${v}`, known: CSR_STATUSES },
    { name: 'deployment status', values: () => enumOf('Deployment', 'status'), labelKey: (v) => `enum.deploymentStatus.${v}`, known: DEPLOYMENT_STATUSES },
    { name: 'upload warning', values: () => knownValues('CertificateStored', 'warnings'), labelKey: (v) => UPLOAD_WARNING_KEYS[v] ?? `missing.${v}`, known: Object.keys(UPLOAD_WARNING_KEYS) },
  ];

  describe.each(cases)('$name', ({ values, labelKey, known }) => {
    it.each(['en', 'tr'] as const)('has a %s label for every API value', (lang) => {
      for (const v of values()) {
        expect(typeof lookup(bundles[lang], labelKey(v)), `${lang}: ${labelKey(v)}`).toBe('string');
      }
    });
    it('lists every API value in the code table', () => {
      for (const v of values()) expect(known, v).toContain(v);
    });
  });

  it('has a label for every value in the code tables, in both languages', () => {
    for (const lang of ['en', 'tr'] as const) {
      for (const v of CERTIFICATE_SOURCES) expect(typeof lookup(bundles[lang], `enum.certificateSource.${v}`)).toBe('string');
      for (const v of KEY_ALGORITHMS) expect(typeof lookup(bundles[lang], `enum.keyAlgorithm.${v}`)).toBe('string');
      for (const key of Object.values(UPLOAD_WARNING_KEYS)) expect(typeof lookup(bundles[lang], key)).toBe('string');
    }
  });
});

// --- Task 22: deployments, websites and Nginx facts, from the specification and the Go sources ---

// topLevelText returns the description of a schema that is a plain string (FileProblem).
function topLevelText(schema: string): string {
  const start = spec.indexOf(`\n    ${schema}:\n`);
  if (start < 0) throw new Error(`schema ${schema} not found`);
  const rest = spec.slice(start + 1);
  const end = rest.slice(1).search(/\n {4}\S/);
  return (end < 0 ? rest : rest.slice(0, end + 1)).replace(/\s+/g, ' ');
}

function knownIn(text: string): string[] {
  const list = knownList(text);
  if (!list) throw new Error('no known values');
  return list;
}

const t = (lang: 'en' | 'tr', key: string) => lookup(bundles[lang], key);
const eq = (a: readonly string[], b: readonly string[]) => expect([...a].sort()).toEqual([...b].sort());

describe('Nginx deployment, website and fact labels cover the specification and the Go sources', () => {
  it('reads sane values from the Go sources', () => {
    expect(goConsts('internal/providers/types.go', /^StepName/)).toContain('verify_old');
    expect(goConsts('internal/providers/types.go', /^Warn/)).toContain('stream_tls');
  });

  const stepNames = [
    ...goConsts('internal/providers/types.go', /^StepName/),
    // R59: the steps of the Windows, BIG-IP and Kubernetes targets.
    ...goConsts('internal/providers/groundwork.go', /^StepName/),
    ...goConsts('internal/providers/linuxssh/helperproto/helperproto.go', /^Step(?!s)[A-Z]\w*$/),
    // The engine's own steps: the pre-check (stepPrecheck) and every other step* constant of the
    // package (stepRecoverPending, W1 fix round 1).
    ...goFiles('internal/jobs/deployjobs').flatMap((f) => goConsts(f, /^step[A-Z]\w*$/)),
  ];
  const typesWarnings = goConsts('internal/providers/types.go', /^Warn/);
  // The SSH helper's warnings and the ones Alice makes from its unlisted accounts (protocol 6).
  const helperWarnings = goConsts('internal/providers/linuxssh/helperproto/helperproto.go', /^Warn/);
  const inventoryWarnings = goConsts('internal/inventory/locations.go', /^Warn/);
  // R60: the Windows helper's warnings; win_ctl is a location warning, the others are server warnings.
  const winAllWarnings = goConsts('internal/providers/windows/winproto/winproto.go', /^Warn/);
  // W3: warnings of the helper's `iis-cleanup --plan` answer. Only Alice's cleanup job consumes them; they are
  // never a location or a server warning, so the SPA has no label for them. A new Warn* constant of winproto
  // is a dump warning unless it is named here (the assertion below pins this list against the Go source).
  const cleanupPlanWarnings = ['journal_unreadable', 'binding_record_unreadable'];
  const winWarnings = winAllWarnings.filter((w) => !cleanupPlanWarnings.includes(w));
  // The web-server providers' own warning(...) literals (the shared layer and the providers built on it).
  const webServerWarnings = ['internal/providers/nginx', 'internal/providers/apache', 'internal/providers/haproxy', 'internal/providers/webserver']
    .flatMap((dir) => goFiles(dir))
    .flatMap((f) => callArgsIn(readRepoFile(f), 'warning'));
  // haproxyconf's own warning constants (WarnConfigFileNotRead), passed through the dump as server warnings.
  const haproxyconfWarnings = goFiles('internal/providers/haproxyconf').flatMap((f) => goConsts(f, /^Warn/));
  const openapiTargetWarnings = [...topLevelTargetWarningText().matchAll(/\b(web_server_[a-z_]+|[a-z]+_[a-z_]+)\b/g)].map((m) => m[1]);

  function topLevelTargetWarningText(): string {
    const m = /Phase 4 values for web servers include ([^;]*?); a newer/.exec(schemaProp('TargetFacts', 'warnings').replace(/\s+/g, ' '));
    if (!m) throw new Error('target warning list not found');
    return m[1].replace(/\(params\.path\)/g, '').replace(/ and /g, ', ');
  }

  it('lists every deployment step the engine, the helper and the pre-check report, and every one the API names', () => {
    expect(stepNames).toEqual(expect.arrayContaining(['verify_current', 'recover_pending']));
    eq([...new Set(stepNames)], DEPLOYMENT_STEP_NAMES);
    eq(knownValues('DeploymentStep', 'name'), DEPLOYMENT_STEP_NAMES);
  });

  it('lists the deployment states, step statuses and verification modes of the specification', () => {
    eq(enumOf('Deployment', 'state'), DEPLOYMENT_STATES);
    eq(enumOf('DeploymentStep', 'status'), STEP_STATUSES);
    eq(enumOf('Deployment', 'verified').filter((v) => v !== ''), VERIFIED_MODES);
  });

  it('lists the unsupported reasons and file problems of the Go sources and the specification', () => {
    // R60: the Windows provider's own reasons and problems (internal/providers/windows/convert.go).
    const winReasons = goConsts('internal/providers/windows/convert.go', /^Unsupported[A-Z]/);
    const winProblems = goConsts('internal/providers/windows/convert.go', /^Problem[A-Z]/);
    expect(winReasons).toEqual(expect.arrayContaining(['win_foreign_app', 'win_ccs', 'win_store_unsupported']));
    expect(winProblems).toEqual(expect.arrayContaining(['cert_missing', 'key_missing', 'key_inaccessible']));
    eq(goConsts('internal/providers/types.go', /^Unsupported[A-Z]/), UNSUPPORTED_REASONS.filter((r) => !winReasons.includes(r)));
    eq(knownValues('CertificateLocation', 'unsupported_reason').map((v) => v.replace(/ \(.*\)$/, '')).filter((r) => !winReasons.includes(r)), UNSUPPORTED_REASONS.filter((r) => !winReasons.includes(r)));
    for (const r of winReasons) expect(UNSUPPORTED_REASONS, r).toContain(r);
    eq(goConsts('internal/providers/types.go', /^CertProblem/), FILE_PROBLEMS.filter((p) => !winProblems.includes(p)));
    eq(knownIn(topLevelText('FileProblem')).filter((p) => !winProblems.includes(p)), FILE_PROBLEMS.filter((p) => !winProblems.includes(p)));
    for (const p of winProblems) expect(FILE_PROBLEMS, p).toContain(p);
  });

  // R61: the Windows helper's step error classes (winproto Err*), except file_changed (a configuration error class
  // already) and forbidden (the rollback guard's, shown by the phase restore_forbidden).
  it('lists the step error classes of the Windows helper', () => {
    eq(goConsts('internal/providers/windows/winproto/winproto.go', /^Err[A-Z]/).filter((e) => e !== 'file_changed' && e !== 'forbidden'), WINDOWS_STEP_ERRORS);
    expect(WINDOWS_STEP_ERRORS).toEqual(expect.arrayContaining(['key_unusable', 'read_back', 'store_error', 'backup_missing']));
  });

  it('lists the configuration error classes and reasons', () => {
    eq(goConsts('internal/providers/types.go', /^ConfigErr/), CONFIG_ERRORS.filter((e) => e !== 'file_changed'));
    expect(goConsts('internal/providers/types.go', /^DeployErrFileChanged$/)).toEqual(['file_changed']);
    eq(knownValues('WebServerFacts', 'config_error'), CONFIG_ERRORS.filter((e) => e !== 'file_changed'));
    eq(goConsts('internal/providers/types.go', /^ConfigReason/), CONFIG_REASONS);
    eq(knownValues('WebServerFacts', 'config_error_reason'), CONFIG_REASONS);
    // 'iis' is the software of a Windows server (R60); the three web servers are the SSH ones.
    eq(enumOf('WebServerFacts', 'software'), [...WEB_SERVER_TYPES, 'iis']);
  });

  it('knows every location warning of the specification and the inventory, and every provider warning at one level', () => {
    for (const w of knownValues('CertificateLocation', 'warnings')) expect(Object.keys(LOCATION_WARNINGS), w).toContain(w);
    for (const w of inventoryWarnings) expect(Object.keys(LOCATION_WARNINGS), w).toContain(w);
    for (const w of typesWarnings) expect([...Object.keys(LOCATION_WARNINGS), ...Object.keys(WARNING_PARAMS)], w).toContain(w);
    for (const w of winWarnings) expect([...Object.keys(LOCATION_WARNINGS), ...Object.keys(WARNING_PARAMS)], w).toContain(w);
  });

  it('classifies the cleanup plan warnings of the Windows helper apart from the dump warnings', () => {
    // Every winproto Warn* constant is a dump warning or one of the cleanup plan's; none is both.
    expect(winAllWarnings.filter((w) => cleanupPlanWarnings.includes(w))).toEqual([...cleanupPlanWarnings].sort());
    expect(winAllWarnings).toEqual([...winWarnings, ...cleanupPlanWarnings].sort());
    for (const w of cleanupPlanWarnings) expect([...Object.keys(LOCATION_WARNINGS), ...Object.keys(WARNING_PARAMS)], w).not.toContain(w);
  });

  it('has no location warning, and no server-level Nginx warning, that no source reports', () => {
    const sources = new Set([...knownValues('CertificateLocation', 'warnings'), ...inventoryWarnings, ...typesWarnings, ...winWarnings]);
    for (const w of Object.keys(LOCATION_WARNINGS)) expect(sources.has(w), `location warning ${w} has no source`).toBe(true);
    const server = new Set([...typesWarnings, ...webServerWarnings, ...haproxyconfWarnings, ...openapiTargetWarnings, ...winWarnings]);
    const windowsOnly = ['win_shared_config', 'win_autocertrebind', 'win_ccs_enabled', 'win_expired_in_store'];
    expect(winWarnings).toEqual(expect.arrayContaining([...windowsOnly, 'win_ctl']));
    expect(Object.keys(LOCATION_WARNINGS)).toContain('win_ctl');
    expect(haproxyconfWarnings).toContain('config_file_not_read');
    const webServerOnly = ['web_server_not_found', 'web_server_profile_missing', 'web_server_helper_too_old', 'web_server_config_invalid', 'locations_dropped', 'list_truncated', 'too_many_files', 'config_dir_not_read', 'config_file_not_read', 'stream_tls', 'mail_tls', 'config_file_writable', 'key_mode_open', 'symlinked', 'custom_location', 'key_group_open', 'certificate_block_dropped'];
    for (const w of webServerOnly) expect(server.has(w), `server warning ${w} has no source`).toBe(true);
    // every Nginx entry of the table is one of those (the rest are the SSH warnings of Phase 3)
    const ssh = new Set(['keys_managed_elsewhere', 'keys_managed_elsewhere_user', 'certificates_in_use', 'pubkey_disabled', 'sshd_unreadable', 'sshd_unreadable_user', 'strict_modes', 'unsupported_path', 'unsupported_path_unnamed', 'file_unreadable', 'file_unparseable', 'file_too_large', 'directory_users_not_listed', 'too_many_users', 'account_name_unsupported', 'account_home_unsupported', 'account_id_unsupported', 'accounts_nul_byte', 'list_truncated_uid']);
    const keyVault = ['kv_item_unreadable', 'kv_version_conflict', 'kv_listing_empty']; // Phase 5: what a vault poll could not use or doubted (internal/providers/types.go, internal/inventory/kv_prepare.go)
    for (const w of Object.keys(WARNING_PARAMS)) expect(ssh.has(w) || webServerOnly.includes(w) || keyVault.includes(w) || windowsOnly.includes(w), `warning ${w} is in no group`).toBe(true);
  });

  it('knows every warning of the SSH helper and of its unlisted accounts (protocol 6, AUD-03)', () => {
    expect(helperWarnings).toEqual(expect.arrayContaining(['account_name_unsupported', 'account_home_unsupported', 'account_id_unsupported', 'accounts_nul_byte']));
    for (const w of helperWarnings) expect(Object.keys(WARNING_PARAMS), w).toContain(w);
    for (const code of ['account_name_unsupported', 'account_home_unsupported', 'account_id_unsupported']) {
      expect(warningKey({ code, params: { uid: '1001' } })).toBe(`warnings.${code}`);
      // Only a broken helper sends one without its uid: a neutral text, never a {{uid}} placeholder.
      expect(warningKey({ code, params: {} })).toBe('warnings.incomplete');
    }
    expect(warningKey({ code: 'accounts_nul_byte', params: {} })).toBe('warnings.accounts_nul_byte');
    // A cut SSH listing names the account it stopped at; other cut lists name nothing.
    expect(warningKey({ code: 'list_truncated', params: { uid: '1500' } })).toBe('warnings.list_truncated_uid');
    expect(warningKey({ code: 'list_truncated', params: {} })).toBe('warnings.list_truncated');
    for (const lang of ['en', 'tr'] as const) {
      expect(t(lang, 'warnings.account_id_unsupported')).toContain('getent passwd {{uid}}');
      expect(t(lang, 'warnings.list_truncated_uid')).toContain('{{uid}}');
    }
  });

  it('knows the warnings of a deploy answer, as the specification and the inventory list them', () => {
    const start = spec.indexOf('\n    DeployAccepted:');
    const block = spec.slice(start, spec.indexOf('\n    DeploymentStep:', start)).replace(/\s+/g, ' ');
    const m = /Known values: ([^;"]*)/.exec(block);
    expect(m).not.toBeNull();
    const known = m![1].split(',').map((v) => v.trim());
    expect(known).toEqual(['san_mismatch']);
    expect(inventoryWarnings).toEqual(expect.arrayContaining(known));
    for (const w of known) {
      expect(Object.keys(LOCATION_WARNINGS), w).toContain(w);
      for (const lang of ['en', 'tr'] as const) expect(typeof lookup(bundles[lang], locationWarningKey(w)), `${lang} ${w}`).toBe('string');
    }
  });

  it('knows every server-level warning of the Nginx provider, the scan job and the specification', () => {
    for (const w of [...typesWarnings, ...webServerWarnings, ...openapiTargetWarnings]) expect(Object.keys(WARNING_PARAMS), w).toContain(w);
    for (const w of winWarnings.filter((x) => x !== 'win_ctl')) expect(Object.keys(WARNING_PARAMS), w).toContain(w);
    expect(warningKey({ code: 'win_expired_in_store', params: { count: '3' } })).toBe('warnings.win_expired_in_store');
    expect(warningKey({ code: 'win_expired_in_store', params: {} })).toBe('warnings.incomplete');
    expect(openapiTargetWarnings).toEqual(expect.arrayContaining(['web_server_profile_missing', 'stream_tls', 'config_file_writable']));
  });

  describe.each(['en', 'tr'] as const)('%s', (lang) => {
    it('labels every step name, step status, state and verification mode', () => {
      for (const n of DEPLOYMENT_STEP_NAMES) expect(typeof t(lang, stepNameKey(n)), n).toBe('string');
      expect(typeof t(lang, 'deployments.steps.write')).toBe('string');
      for (const s of STEP_STATUSES) expect(typeof t(lang, stepStatusKey(s)), s).toBe('string');
      for (const k of ['waiting', 'notRun', 'unknown']) expect(typeof t(lang, `deployments.stepStatus.${k}`), k).toBe('string');
      for (const s of DEPLOYMENT_STATES) expect(typeof t(lang, deploymentStateKey(s)), s).toBe('string');
      for (const v of [...VERIFIED_MODES, 'none']) expect(typeof t(lang, verifiedKey(v)), v).toBe('string');
    });

    it('labels every unsupported reason, file problem, configuration error and reason', () => {
      for (const r of UNSUPPORTED_REASONS) expect(typeof t(lang, unsupportedReasonKey(r)), r).toBe('string');
      for (const r of FILE_PROBLEMS) expect(typeof t(lang, fileProblemKey(r)), r).toBe('string');
      for (const r of CONFIG_ERRORS) expect(typeof t(lang, configErrorKey(r)), r).toBe('string');
      for (const r of CONFIG_REASONS) expect(typeof t(lang, configReasonKey(r)), r).toBe('string');
      for (const r of WINDOWS_STEP_ERRORS) expect(t(lang, stepErrorKey(r)), r).toBe(t(lang, `deployments.stepError.${r}`));
      for (const r of WINDOWS_STEP_ERRORS) expect(typeof t(lang, stepErrorKey(r)), r).toBe('string');
      expect(typeof t(lang, stepErrorKey('file_changed', true))).toBe('string');
      expect(stepErrorKey('file_changed', true)).toBe('deployments.stepError.file_changed_windows');
      expect(stepErrorKey('file_changed')).toBe(configErrorKey('file_changed'));
      expect(stepErrorKey('key_mismatch', true)).toBe(configErrorKey('key_mismatch'));
    });

    it('gives a value it does not know, and an empty one, a neutral text', () => {
      expect(t(lang, stepNameKey('brand_new'))).toBe(t(lang, 'deployments.steps.unknown'));
      expect(t(lang, stepStatusKey(''))).toBe(t(lang, 'deployments.stepStatus.unknown'));
      expect(t(lang, deploymentStateKey(''))).toBe(t(lang, 'enum.unknown'));
      expect(t(lang, unsupportedReasonKey('brand_new'))).toBe(t(lang, 'locations.unsupported.unknown'));
      expect(t(lang, fileProblemKey(''))).toBe(t(lang, 'locations.problems.unknown'));
      expect(t(lang, configErrorKey('brand_new'))).toBe(t(lang, 'locations.configError.unknown'));
      expect(t(lang, stepErrorKey('brand_new', true))).toBe(t(lang, 'locations.configError.unknown'));
      expect(t(lang, locationWarningKey('brand_new'))).toBe(t(lang, 'locations.warnings.unknown'));
    });

    it('words every location warning and every server-level warning', () => {
      for (const w of Object.keys(LOCATION_WARNINGS)) expect(typeof t(lang, locationWarningKey(w)), w).toBe('string');
      for (const [code, params] of Object.entries(WARNING_PARAMS)) {
        if (code === 'unsupported_path_unnamed' || code.endsWith('_user') || code.endsWith('_uid')) continue;
        const key = warningKey({ code, params: Object.fromEntries(params.map((p) => [p, 'x'])) });
        expect(key, code).toBe(`warnings.${code}`);
        expect(typeof t(lang, key), code).toBe('string');
      }
    });
  });
});

describe('capabilities', () => {
  it('lists every Go capability', () => {
    eq(goConsts('internal/providers/capability.go', /^Cap/), CAPABILITIES);
  });
});
