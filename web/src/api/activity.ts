// Activity marking (AUD-01, Decisions 1 and 2, R39). The server extends a session's idle timeout
// only for state-changing requests and for same-origin reads that carry X-Alice-Activity: 1. A read
// is marked when a person gave input since the last marked request; background polls after that go
// out unmarked, so a tab left open is signed out 30 minutes after the last input although it keeps
// polling.
//
// What counts: a press of a pointer or a key, a click, the wheel and a touch, as the browser
// reports them (event.isTrusted). Pointer movement, focus and visibility changes, timers and events
// a script dispatches do not: browsers fire mouse moves when content shifts under a resting
// pointer, and a script (ours or an extension's) must not keep a session alive. Input sent by
// automation through the browser's own input pipeline (a test driver, an accessibility tool, a
// remote desktop) is trusted and counts; no page can tell it apart from a person.
//
// The first request after a page load is also marked: loading or reloading a page is a person's
// action.
const INPUT_EVENTS = ['pointerdown', 'click', 'keydown', 'wheel', 'touchstart'] as const;
const INPUT_TYPES: ReadonlySet<string> = new Set(INPUT_EVENTS);

export const ACTIVITY_HEADER = 'X-Alice-Activity';

let pending = true;

// noteInput is the listener: it only sets a flag, so it costs nothing per event.
export function noteInput(e: Event): void {
  if (e.isTrusted && INPUT_TYPES.has(e.type)) pending = true;
}

// takeActivity reports whether a person gave input since the last marked request, and consumes
// the mark: the next request carries it, the ones after it do not.
export function takeActivity(): boolean {
  const p = pending;
  pending = false;
  return p;
}

// returnActivity puts back a mark whose request never reached Alice (the network failed, the
// request was cancelled, or the server refused it before recording anything), so the next request
// carries it instead.
export function returnActivity(): void {
  pending = true;
}

// resetActivity sets the flag (tests).
export function resetActivity(value: boolean): void {
  pending = value;
}

// installActivityListeners listens for input on the whole page (capture, passive: nothing can stop
// the event before it is seen, and scrolling is never delayed). It returns the function that
// removes the listeners again.
export function installActivityListeners(target: Window): () => void {
  const opts: AddEventListenerOptions = { capture: true, passive: true };
  for (const type of INPUT_EVENTS) target.addEventListener(type, noteInput, opts);
  return () => {
    for (const type of INPUT_EVENTS) target.removeEventListener(type, noteInput, opts);
  };
}
