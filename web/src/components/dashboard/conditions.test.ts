import type { Condition } from '../../api/phase7';
import { CONDITION_ICON, conditionLabel, conditionTarget, conditionTone } from './conditions';

const cond = (kind: string, id = 'x-1'): Condition => ({ kind, object_id: id, name: 'n', since: '2026-10-06T09:00:00Z', error_code: '' });
const t = (k: string) => `T(${k})`;
const KINDS = ['host_key_changed', 'auth_failed', 'deployment_failed', 'audit_broken', 'notifications_failing'];

describe('conditions', () => {
  it('sends each kind to the page where it is dealt with', () => {
    const vaults = new Set(['v-1']);
    expect(conditionTarget(cond('auth_failed', 'v-1'), vaults)).toBe('/key-vaults/v-1');
    expect(conditionTarget(cond('auth_failed', 's-1'), vaults)).toBe('/servers/s-1');
    expect(conditionTarget(cond('host_key_changed', 'v-1'), vaults)).toBe('/servers/v-1');
    expect(conditionTarget(cond('deployment_failed', 'd/1'), vaults)).toBe('/deployments/d%2F1');
    expect(conditionTarget(cond('audit_broken'), vaults)).toBe('/audit');
    expect(conditionTarget(cond('notifications_failing'), vaults)).toBe('/settings?tab=mail');
    expect(conditionTarget(cond('something_new'), vaults)).toBeNull();
  });

  it('labels the known kinds from the catalog and never an unknown one', () => {
    expect(conditionLabel(cond('host_key_changed'), t)).toBe('T(enum.targetStatus.host_key_changed)');
    expect(conditionLabel(cond('auth_failed'), t)).toBe('T(enum.targetStatus.auth_failed)');
    expect(conditionLabel(cond('deployment_failed'), t)).toBe('T(enum.deploymentStatus.failed)');
    expect(conditionLabel(cond('audit_broken'), t)).toBe('T(dashboard.auditBroken)');
    expect(conditionLabel(cond('notifications_failing'), t)).toBe('T(notifications.failingTitle)');
    expect(conditionLabel(cond('something_new'), t)).toBeNull();
  });

  it('gives every known kind an icon and a tone', () => {
    expect(Object.keys(CONDITION_ICON).sort()).toEqual([...KINDS].sort());
    expect(KINDS.map((k) => conditionTone(cond(k)))).toEqual(['danger', 'danger', 'warning', 'danger', 'warning']);
  });
});
