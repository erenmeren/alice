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

// DISCOVERY_ONLY_TEXTS: the texts that mention deployment, with the key of the text a server that cannot
// deploy_certificate shows instead (spec §8.4).
export const DISCOVERY_ONLY_TEXTS: Readonly<Record<string, string>> = {
  'warnings.web_server_config_invalid': 'warnings.web_server_config_invalid_discovery',
  'locations.configInvalid': 'locations.configInvalidDiscovery',
  'locations.intro': 'locations.introDiscovery',
  'targets.page.operationsText': 'targets.page.operationsTextDiscovery',
  'locations.ready': 'locations.readyDiscovery',
  'locations.unsupported.unsupported_key': 'locations.unsupportedKeyDiscovery',
  'locations.warnings.key_group_open': 'locations.keyGroupOpenDiscovery',
};

// capabilityText: the key of the text to show for the target: the discovery-only one when it cannot deploy.
export function capabilityText(target: Pick<Target, 'capabilities'>, key: string): string {
  return !can(target, 'deploy_certificate') && Object.hasOwn(DISCOVERY_ONLY_TEXTS, key) ? DISCOVERY_ONLY_TEXTS[key] : key;
}
