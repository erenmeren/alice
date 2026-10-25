import { canaryFirstWave } from './CanaryChoice';

// The deploy dialogs' note counts the first wave as the server does (authz.CanaryWaves): a count or the ceiling of the
// percentage, at least 1, never all, and at most 19 (final review C2, R65).
describe('canaryFirstWave', () => {
  it('counts as the server does, capped at 19', () => {
    expect(canaryFirstWave({ enabled: true }, 2)).toBe(1);
    expect(canaryFirstWave({ enabled: true, subset: { count: 5 } }, 3)).toBe(2);
    expect(canaryFirstWave({ enabled: true, subset: { percent: 50 } }, 38)).toBe(19);
    expect(canaryFirstWave({ enabled: true, subset: { percent: 50 } }, 39)).toBe(19);
    expect(canaryFirstWave({ enabled: true, subset: { percent: 10 } }, 200)).toBe(19);
  });
});
