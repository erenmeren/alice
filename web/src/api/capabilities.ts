import type { Target } from './types';

// Capability is one thing a provider can do (internal/providers/capability.go; a test keeps the lists equal).
export type Capability =
  | 'test_connection'
  | 'discover_certificates'
  | 'discover_ssh_keys'
  | 'discover_kv_keys'
  | 'discover_kv_secret_metadata'
  | 'deploy_certificate'
  | 'import_certificate'
  | 'authorized_keys'
  | 'verify_deployment'
  | 'read_certificate_secret'
  | 'key_login'
  | 'http01_challenge';

export const CAPABILITIES: readonly Capability[] = [
  'test_connection',
  'discover_certificates',
  'discover_ssh_keys',
  'discover_kv_keys',
  'discover_kv_secret_metadata',
  'deploy_certificate',
  'import_certificate',
  'authorized_keys',
  'verify_deployment',
  'read_certificate_secret',
  'key_login',
  'http01_challenge',
];

// can: whether the target's stored capability set has the capability. The server rewrites the set from the registered
// provider at every startup (spec §8.1), so this always agrees with its own checks, which it still makes.
export function can(target: Pick<Target, 'capabilities'>, capability: Capability): boolean {
  return target.capabilities.includes(capability);
}
