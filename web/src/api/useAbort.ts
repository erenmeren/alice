import { useEffect, useState } from 'react';

interface Abort {
  signal: () => AbortSignal;
  abort: () => void;
  // mount and unmount are for the hook's effect only.
  mount: () => void;
  unmount: () => void;
}

function create(): Abort {
  let ctrl = new AbortController();
  return {
    signal: () => ctrl.signal,
    abort: () => {
      ctrl.abort();
      ctrl = new AbortController();
    },
    mount: () => {
      if (ctrl.signal.aborted) ctrl = new AbortController();
    },
    unmount: () => ctrl.abort(),
  };
}

// useAbort gives a component a cancellation signal for the waiting it starts (job polling). The
// signal is aborted when the component unmounts. The controller is renewed when the component
// mounts: React StrictMode runs mount, cleanup, mount in development, and a controller created
// once would stay aborted. abort() cancels what is pending now and installs a fresh controller
// for what starts later.
export function useAbort(): Pick<Abort, 'signal' | 'abort'> {
  const [a] = useState(create);
  useEffect(() => {
    a.mount();
    return () => a.unmount();
  }, [a]);
  return a;
}
