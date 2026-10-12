import type { DeploymentStatus, TargetStatus } from '../../api/types';
import type { ExpiryState } from '../Expiry';
import { deploymentTone, expiryIcon, expiryTone, TARGET_ICON, TARGET_TONE } from './status';

describe('status tones', () => {
  it('gives every server status a tone', () => {
    const expected: Record<TargetStatus, string> = {
      ok: 'success',
      checking: 'info',
      degraded: 'warning',
      pending_host_key: 'warning',
      unreachable: 'warning',
      host_key_changed: 'danger',
      auth_failed: 'danger',
      disabled: 'neutral',
    };
    expect(TARGET_TONE).toEqual(expected);
    expect(TARGET_ICON).toEqual({ host_key_changed: 'Fingerprint', unreachable: 'Unplug', auth_failed: 'ShieldAlert', checking: 'RefreshCw', ok: 'CircleCheck' });
  });

  it('gives every deployment status a tone, and a cancelled failure is neutral, not danger', () => {
    const expected: Record<DeploymentStatus, string> = {
      succeeded: 'success',
      unchanged: 'neutral',
      pending: 'info',
      running: 'info',
      rolled_back: 'warning',
      needs_attention: 'warning',
      failed: 'danger',
      rollback_failed: 'danger',
    };
    for (const [status, tone] of Object.entries(expected)) expect(deploymentTone({ status: status as DeploymentStatus, error: null })).toBe(tone);
    expect(deploymentTone({ status: 'failed', error: { code: 'ALC-DEP-0022', reason: 'deployment.cancelled' } })).toBe('neutral');
    expect(deploymentTone({ status: 'failed', error: { code: 'ALC-DEP-0006', reason: 'deployment.reload_failed' } })).toBe('danger');
    expect(deploymentTone({ status: '', error: null })).toBe('neutral');
  });

  it('gives every expiry state a tone and an icon', () => {
    const tones: Record<ExpiryState, string> = { expired: 'danger', within30: 'warning', within60: 'info', ok: 'success' };
    for (const [state, tone] of Object.entries(tones)) expect(expiryTone(state as ExpiryState)).toBe(tone);
    expect(expiryIcon('expired')).toBe('CircleAlert');
    for (const s of ['within30', 'within60', 'ok'] as const) expect(expiryIcon(s)).toBe('Clock3');
  });
});
