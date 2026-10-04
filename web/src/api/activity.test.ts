import { installActivityListeners, noteInput, resetActivity, returnActivity, takeActivity } from './activity';

// A trusted event cannot be created in jsdom (dispatchEvent always gives isTrusted false), so the
// listener's decision is tested through noteInput with plain objects.
const input = (type: string, isTrusted = true) => ({ type, isTrusted }) as unknown as Event;

describe('activity marking (AUD-01)', () => {
  beforeEach(() => resetActivity(false));

  it('a page load counts as activity once', async () => {
    vi.resetModules();
    const fresh = await import('./activity');
    expect(fresh.takeActivity()).toBe(true);
    expect(fresh.takeActivity()).toBe(false);
  });

  it.each(['pointerdown', 'click', 'keydown', 'wheel', 'touchstart'])('a trusted %s marks the next request only', (type) => {
    noteInput(input(type));
    expect(takeActivity()).toBe(true);
    expect(takeActivity()).toBe(false);
  });

  it.each(['pointermove', 'mousemove', 'pointerover', 'focus', 'focusin', 'blur', 'visibilitychange', 'scroll', 'resize'])(
    '%s is not a person acting',
    (type) => {
      noteInput(input(type));
      expect(takeActivity()).toBe(false);
    },
  );

  it.each(['pointerdown', 'click', 'keydown', 'wheel', 'touchstart'])('a %s dispatched by a script does not count', (type) => {
    noteInput(input(type, false));
    expect(takeActivity()).toBe(false);
  });

  it('many inputs before a request still mark only that one request', () => {
    for (let i = 0; i < 50; i++) noteInput(input('keydown'));
    expect(takeActivity()).toBe(true);
    expect(takeActivity()).toBe(false);
  });

  it('a mark whose request failed is given back', () => {
    noteInput(input('wheel'));
    expect(takeActivity()).toBe(true);
    returnActivity();
    expect(takeActivity()).toBe(true);
    expect(takeActivity()).toBe(false);
  });

  it('listens on the page, passively and in the capture phase, and removes every listener', () => {
    const add = vi.spyOn(window, 'addEventListener');
    const remove = vi.spyOn(window, 'removeEventListener');
    const uninstall = installActivityListeners(window);
    const added = add.mock.calls.map(([type, fn, opts]) => ({ type, fn, opts }));
    expect(added.map((a) => a.type).sort()).toEqual(['click', 'keydown', 'pointerdown', 'touchstart', 'wheel']);
    for (const a of added) {
      expect(a.fn).toBe(noteInput);
      expect(a.opts).toEqual({ capture: true, passive: true });
    }
    uninstall();
    const removed = remove.mock.calls.map(([type, fn, opts]) => ({ type, fn, opts }));
    expect(removed).toEqual(added);
    add.mockRestore();
    remove.mockRestore();
  });

  it('a synthetic event on the page reaches the listener and is ignored', () => {
    const uninstall = installActivityListeners(window);
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'a' }));
    document.body.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(takeActivity()).toBe(false);
    uninstall();
  });
});
