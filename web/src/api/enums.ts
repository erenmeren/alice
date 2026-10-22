import type { CertificateSource, CSRStatus, DeploymentState, DeploymentStatus, KeyAlgorithm, StepStatus } from './types';

// Every enum the certificate API returns, with the label key the SPA shows for it. The lists are
// checked against api/openapi.yaml by enums.test.ts, which fails when the API gains a value that
// has no label in both languages.

export const CERTIFICATE_SOURCES: readonly CertificateSource[] = ['discovered', 'uploaded', 'csr', 'azure_kv', 'acme'];
export const KEY_ALGORITHMS: readonly KeyAlgorithm[] = ['rsa', 'ecdsa', 'ed25519', 'other'];
export const CSR_STATUSES: readonly CSRStatus[] = ['pending', 'completed', 'cancelled'];
export const DEPLOYMENT_STATUSES: readonly DeploymentStatus[] = [
  'pending',
  'running',
  'succeeded',
  'unchanged',
  'failed',
  'rolled_back',
  'rollback_failed',
  'needs_attention',
];

// UPLOAD_WARNING_KEYS maps a warning code of an upload or a signing request's completion to its text.
// Source: internal/certs/upload.go (not_yet_valid, chain_incomplete, chain_certificate_expired),
// internal/inventory/csr.go (csr_name_mismatch) and the inventory's chain completion (chain_completed).
export const UPLOAD_WARNING_KEYS: Readonly<Record<string, string>> = {
  chain_incomplete: 'certificates.upload.chainWarning',
  chain_certificate_expired: 'certificates.upload.chainExpiredWarning',
  not_yet_valid: 'certificates.upload.notYetValid',
  csr_name_mismatch: 'certificates.upload.nameMismatchWarning',
  // Not a problem: the upload completed the chain of a certificate Alice already held (HTTP 200
  // instead of 201). The dialogs show it as the result itself, not as a warning.
  chain_completed: 'certificates.upload.chainCompleted',
};

// CHAIN_COMPLETED is the upload warning that says the upload completed a stored certificate's chain.
export const CHAIN_COMPLETED = 'chain_completed';

// uploadWarningKey is the text for a warning code; a code from a newer server gets a generic text.
export function uploadWarningKey(code: string): string {
  return UPLOAD_WARNING_KEYS[code] ?? 'certificates.upload.otherWarning';
}

// keyAlgorithmKey is the label of a key algorithm code (ALC-CRT-0010 params carry raw codes).
export function keyAlgorithmKey(code: string): string {
  return `enum.keyAlgorithm.${KEY_ALGORITHMS.includes(code as KeyAlgorithm) ? code : 'other'}`;
}

// deploymentStatusKey is the label of a deployment status; '' (a status the server did not
// recognise) or a value from a newer server gets the neutral "Unknown".
export function deploymentStatusKey(status: string): string {
  return DEPLOYMENT_STATUSES.includes(status as DeploymentStatus) ? `enum.deploymentStatus.${status}` : 'enum.unknown';
}

// --- Nginx deployments, websites and facts (Task 22) ---
// Each list is checked against api/openapi.yaml and the Go sources by enums.test.ts. A value a newer
// server adds (or '') gets the neutral text of its kind, never a raw code in a sentence.

export const DEPLOYMENT_STATES: readonly DeploymentState[] = ['queued', 'precheck', 'deploying', 'recovering', 'done'];
export const STEP_STATUSES: readonly StepStatus[] = ['started', 'ok', 'failed', 'skipped'];

// DEPLOYMENT_STEP_NAMES are the steps a deployment reports: the helper's (helperproto.Step*), the
// provider's (providers.StepName*) and the engine's own in internal/jobs/deployjobs: the pre-check
// and recover_pending (Alice puts back the files of an unfinished earlier change it no longer follows
// before it deploys; param operation_id) and kv_secret (a Key Vault deployment reads its certificate
// secret from the vault before anything is sent to the server; param reason on an incomplete chain).
export const DEPLOYMENT_STEP_NAMES: readonly string[] = [
  'verify_current',
  'kv_secret',
  'backup',
  'write_key',
  'write_cert',
  'config_test',
  'reload',
  'journal',
  'restore',
  'rollback_config_test',
  'rollback_reload',
  'verify',
  'verify_old',
  'recover_pending',
  // R59: the Windows server (import into the stores, re-point the binding), BIG-IP (upload, install, one transaction,
  // device-group sync, save) and Kubernetes (write the Secret) steps.
  'import_chain',
  'import_certificate',
  'bind',
  'upload',
  'install',
  'commit',
  'sync',
  'save',
  'write_secret',
];

// UNSUPPORTED_REASONS: CertificateLocation.unsupported_reason (providers.Unsupported*).
export const UNSUPPORTED_REASONS: readonly string[] = [
  'variable',
  'data_value',
  'engine_key',
  'key_missing',
  'password_file',
  'path_not_allowed',
  'stream',
  'combined_file',
  'config_file_writable',
  'conditional',
  'unknown_keyword',
  'key_conflict',
  'file_problem',
  'unsupported_key',
  // R60: a Windows server's http.sys bindings (internal/providers/windows/convert.go).
  'win_foreign_app',
  'win_ccs',
  'win_store_unsupported',
  'unknown',
];

// FILE_PROBLEMS: CertificateLocation.problem and key_problem (providers.CertProblem*).
export const FILE_PROBLEMS: readonly string[] = [
  'missing',
  'not_root_controlled',
  'not_regular',
  'hard_linked',
  'too_large',
  'not_a_certificate',
  'leaf_unreadable',
  'unreadable',
  'bad_name',
  'name_not_allowed',
  'special_filesystem',
  // R60: a Windows binding's certificate and key (the store holds no such certificate, no key, or SYSTEM cannot use it).
  'cert_missing',
  'key_missing',
  'key_inaccessible',
  'unknown',
];

// CONFIG_ERRORS: WebServerFacts.config_error (providers.ConfigErr*) and a deployment's helper_error,
// which adds file_changed.
export const CONFIG_ERRORS: readonly string[] = ['key_mismatch', 'file_missing', 'cert_load', 'key_load', 'syntax', 'untrusted', 'unsupported', 'file_changed'];

// CONFIG_REASONS: WebServerFacts.config_error_reason (providers.ConfigReason*).
export const CONFIG_REASONS: readonly string[] = [
  'not_root_controlled',
  'special_filesystem',
  'missing',
  'not_regular',
  'changed',
  'name_not_allowed',
  'unexpected_text',
  'wrong_first_file',
  'duplicate_file',
  'no_conf_path',
  'too_large',
  'too_complex',
  'include_loop',
  'nul_byte',
];

export const VERIFIED_MODES: readonly string[] = ['remote', 'local', 'skipped'];

const known = (list: readonly string[], v: string) => list.includes(v);

export const deploymentStateKey = (state: string) => (known(DEPLOYMENT_STATES, state) ? `enum.deploymentState.${state}` : 'enum.unknown');
export const stepStatusKey = (status: string) => (known(STEP_STATUSES, status) ? `deployments.stepStatus.${status}` : 'deployments.stepStatus.unknown');
export const stepNameKey = (name: string) => (known(DEPLOYMENT_STEP_NAMES, name) ? `deployments.steps.${name}` : 'deployments.steps.unknown');
export const unsupportedReasonKey = (r: string) => `locations.unsupported.${known(UNSUPPORTED_REASONS, r) ? r : 'unknown'}`;
export const fileProblemKey = (p: string) => `locations.problems.${known(FILE_PROBLEMS, p) ? p : 'unknown'}`;
export const configErrorKey = (e: string) => `locations.configError.${known(CONFIG_ERRORS, e) ? e : 'unknown'}`;
export const configReasonKey = (r: string) => `locations.configReason.${known(CONFIG_REASONS, r) ? r : 'unknown'}`;
export const verifiedKey = (v: string) => `deployments.verified.${known(VERIFIED_MODES, v) ? v : 'none'}`;

// R51: the verification levels a deployment reports (index = level; 4, a service health check, is reserved), the
// trust statuses, the reasons a served chain does not verify (providers.TrustErrors), the trust stores and the kinds of
// a failed verification.
export const VERIFICATION_LEVELS: readonly string[] = ['none', 'installed', 'served', 'trusted'];
export const TRUST_STATUSES: readonly string[] = ['trusted', 'untrusted', 'unchecked'];
export const TRUST_ERRORS: readonly string[] = [
  'unknown_authority',
  'wrong_intermediate',
  'incomplete_chain',
  'chain_order',
  'name_mismatch',
  'expired',
  'not_yet_valid',
  'invalid_chain',
];
export const TRUST_STORES: readonly string[] = ['system', 'acme_bundle', 'uploaded_root'];
export const VERIFY_FAILURES: readonly string[] = ['network', 'certificate', 'trust'];

export const verificationLevelKey = (level: number) => `deployments.level.${VERIFICATION_LEVELS[level] ?? 'unknown'}`;
export const trustStatusKey = (s: string) => `deployments.trust.status.${known(TRUST_STATUSES, s) ? s : 'unknown'}`;
export const trustErrorKey = (e: string) => `deployments.trust.error.${known(TRUST_ERRORS, e) ? e : 'unknown'}`;
export const trustStoreKey = (s: string) => `deployments.trust.store.${known(TRUST_STORES, s) ? s : 'unknown'}`;
export const verifyFailureKey = (f: string) => (known(VERIFY_FAILURES, f) ? `deployments.failure.${f}` : '');
