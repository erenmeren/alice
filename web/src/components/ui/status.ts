import { isCancelled } from '../../api/deployments';
import type { Deployment, TargetStatus } from '../../api/types';
import type { IconName } from '../../design/Icon';
import type { Tone } from '../../theme';
import type { ExpiryState } from '../Expiry';

// The tone (color family) and icon of each status the product shows. Status is always text + icon + color; these maps
// pick the color and icon, the caller writes the text.

export const TARGET_TONE: Record<TargetStatus, Tone> = {
  ok: 'success',
  checking: 'info',
  degraded: 'warning',
  pending_host_key: 'warning',
  unreachable: 'warning',
  host_key_changed: 'danger',
  auth_failed: 'danger',
  disabled: 'neutral',
};

export const TARGET_ICON: Partial<Record<TargetStatus, IconName>> = {
  host_key_changed: 'Fingerprint',
  unreachable: 'Unplug',
  auth_failed: 'ShieldAlert',
  checking: 'RefreshCw',
  ok: 'CircleCheck',
};

const DEPLOYMENT_TONE: Record<Exclude<Deployment['status'], ''>, Tone> = {
  succeeded: 'success',
  unchanged: 'neutral',
  pending: 'info',
  running: 'info',
  rolled_back: 'warning',
  needs_attention: 'warning',
  failed: 'danger',
  rollback_failed: 'danger',
};

// deploymentTone: a deployment an Administrator cancelled before anything was sent is a failure by status but not a
// problem, so it is neutral. A status this version does not know ('') is neutral too.
export function deploymentTone(d: Pick<Deployment, 'status' | 'error'>): Tone {
  if (isCancelled(d)) return 'neutral';
  return d.status === '' ? 'neutral' : DEPLOYMENT_TONE[d.status];
}

const EXPIRY_TONE: Record<ExpiryState, Tone> = { expired: 'danger', within30: 'warning', within60: 'info', ok: 'success' };

export function expiryTone(state: ExpiryState): Tone {
  return EXPIRY_TONE[state];
}

export function expiryIcon(state: ExpiryState): IconName {
  return state === 'expired' ? 'CircleAlert' : 'Clock3';
}
