import type { CertificateLocation, Target } from './types';

// Why Alice cannot deploy to an Nginx server right now, in the order it is shown. The facts and
// websites of the last successful scan stay visible but are stale for every reason except
// 'checking' (a connection test is under way).
export type DeployBlock = 'status' | 'profile_missing' | 'nginx_not_found' | 'config_invalid' | 'last_error' | 'discovery_failed';

export interface NginxState {
  block: DeployBlock | null;
  // stale: the facts and websites shown are from an earlier scan and may no longer be true.
  stale: boolean;
  // configInvalid: Nginx reports an error in its configuration (facts.web_server or the scan's warning).
  configInvalid: boolean;
}

// nginxState reads the server's status, its scan warnings and its Nginx facts. discoveryFailed is
// true when a scan this screen started just failed (the API keeps no record of a failed scan except
// for connection problems, which are the target's status and last_error).
export function nginxState(target: Target, discoveryFailed = false): NginxState {
  const codes = new Set(target.facts.warnings.map((w) => w.code));
  const nginx = target.facts.web_server;
  const configInvalid = (nginx?.found === true && !nginx.config_valid) || codes.has('web_server_config_invalid');
  let block: DeployBlock | null = null;
  if (target.status !== 'ok') block = 'status';
  else if (codes.has('web_server_profile_missing')) block = 'profile_missing';
  else if (codes.has('web_server_not_found') || (nginx !== undefined && !nginx.found && nginx.version === '')) block = 'nginx_not_found';
  else if (configInvalid) block = 'config_invalid';
  else if (target.last_error) block = 'last_error';
  else if (discoveryFailed) block = 'discovery_failed';
  return { block, configInvalid, stale: block !== null && !(block === 'status' && target.status === 'checking') };
}

// firstServerName is the website's name: the first server name of its first server that has one
// ('_' is the catch-all default server; '' when the location has no server name).
export function firstServerName(loc: CertificateLocation): string {
  for (const s of loc.servers) if (s.names.length > 0) return s.names[0];
  return '';
}

// serverNames lists every distinct server name of a location, in order.
export function serverNames(loc: CertificateLocation): string[] {
  return [...new Set(loc.servers.flatMap((s) => s.names))];
}

// listenAddrs lists every distinct listen address with its port, in order.
export function listenAddrs(loc: CertificateLocation): string[] {
  return [...new Set(loc.servers.flatMap((s) => s.listens.map((l) => `${l.addr}:${l.port}`)))];
}

// canDeployTo: a supported place that is still found and has no deployment running.
export function canDeployTo(loc: CertificateLocation): boolean {
  return loc.supported && loc.missing_since === null && loc.active_deployment_id === null;
}
