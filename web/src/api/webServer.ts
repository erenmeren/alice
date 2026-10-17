import type { CertificateLocation, Target } from './types';

// The single list of web-server target types. Phases B and C extend only this list.
export const WEB_SERVER_TYPES = ['nginx'] as const;
export type WebServerType = (typeof WEB_SERVER_TYPES)[number];

export function isWebServer(type: string): type is WebServerType {
  return (WEB_SERVER_TYPES as readonly string[]).includes(type);
}

// isServerType: a server Alice signs in to over SSH (Linux or a web server).
export function isServerType(type: string): boolean {
  return type === 'linux' || isWebServer(type);
}

// Why Alice cannot deploy to a web server right now, in the order it is shown. The facts and
// websites of the last successful scan stay visible but are stale for every reason except
// 'checking' (a connection test is under way).
export type DeployBlock = 'status' | 'profile_missing' | 'server_not_found' | 'config_invalid' | 'last_error' | 'discovery_failed';

export interface WebServerState {
  block: DeployBlock | null;
  // stale: the facts and websites shown are from an earlier scan and may no longer be true.
  stale: boolean;
  // configInvalid: the web server reports an error in its configuration (facts.web_server or the scan's warning).
  configInvalid: boolean;
}

// webServerState reads the server's status, its scan warnings and its web-server facts. discoveryFailed is
// true when a scan this screen started just failed (the API keeps no record of a failed scan except
// for connection problems, which are the target's status and last_error).
export function webServerState(target: Target, discoveryFailed = false): WebServerState {
  const codes = new Set(target.facts.warnings.map((w) => w.code));
  const ws = target.facts.web_server;
  const configInvalid = (ws?.found === true && !ws.config_valid) || codes.has('web_server_config_invalid');
  let block: DeployBlock | null = null;
  if (target.status !== 'ok') block = 'status';
  else if (codes.has('web_server_profile_missing')) block = 'profile_missing';
  else if (codes.has('web_server_not_found') || (ws !== undefined && !ws.found && ws.version === '')) block = 'server_not_found';
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
