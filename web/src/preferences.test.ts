import { act, renderHook } from '@testing-library/react';
import { DENSITY_KEY, applyDensity, readDensity, saveDensity, useDensity } from './preferences';

describe('density preference', () => {
  it('defaults to comfortable and remembers compact on this device', () => {
    expect(readDensity()).toBe('comfortable');
    saveDensity('compact');
    expect(localStorage.getItem(DENSITY_KEY)).toBe('compact');
    expect(document.documentElement.dataset.density).toBe('compact');
    expect(readDensity()).toBe('compact');
  });
  it('ignores an unknown stored value', () => {
    localStorage.setItem(DENSITY_KEY, 'tiny');
    expect(readDensity()).toBe('comfortable');
  });
  it('still applies the choice when storage is blocked (private window, policy)', () => {
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new DOMException('blocked'); });
    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new DOMException('blocked'); });
    expect(readDensity()).toBe('comfortable');
    expect(() => saveDensity('compact')).not.toThrow();
    expect(document.documentElement.dataset.density).toBe('compact');
    set.mockRestore();
    get.mockRestore();
  });
  it('useDensity updates the page and the hook state', () => {
    applyDensity('comfortable');
    const { result } = renderHook(() => useDensity());
    act(() => result.current[1]('compact'));
    expect(result.current[0]).toBe('compact');
    expect(document.documentElement.dataset.density).toBe('compact');
  });
});
