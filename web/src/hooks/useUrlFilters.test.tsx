import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider, useSearchParams } from 'react-router';
import { useDebouncedParam, useUrlFilters } from './useUrlFilters';

const KEYS = ['q', 'expiry'] as const;

function Probe() {
  const [values, set, clear] = useUrlFilters(KEYS);
  return (
    <div>
      <output data-testid="values">{JSON.stringify(values)}</output>
      <button onClick={() => set({ q: 'abc' })}>set q</button>
      <button onClick={() => set({ q: '' })}>empty q</button>
      <button onClick={() => set({ expiry: '7' })}>set expiry</button>
      <button onClick={clear}>clear</button>
    </div>
  );
}

function setup(path: string) {
  const router = createMemoryRouter([{ path: '*', element: <Probe /> }], { initialEntries: [path] });
  render(<RouterProvider router={router} />);
  return router;
}

describe('useUrlFilters', () => {
  it('reads only the allowed keys', () => {
    setup('/x?q=hello&other=1');
    expect(JSON.parse(screen.getByTestId('values').textContent ?? '')).toEqual({ q: 'hello', expiry: '' });
  });

  it('sets, removes on empty, keeps the other keys, and clears', async () => {
    const router = setup('/x?other=1');
    await userEvent.click(screen.getByText('set q'));
    await userEvent.click(screen.getByText('set expiry'));
    await waitFor(() => expect(router.state.location.search).toBe('?other=1&q=abc&expiry=7'));
    await userEvent.click(screen.getByText('empty q'));
    await waitFor(() => expect(router.state.location.search).toBe('?other=1&expiry=7'));
    await userEvent.click(screen.getByText('clear'));
    await waitFor(() => expect(router.state.location.search).toBe(''));
  });

  it('replaces the history entry', async () => {
    const router = setup('/x');
    await userEvent.click(screen.getByText('set q'));
    await waitFor(() => expect(router.state.location.search).toBe('?q=abc'));
    expect(router.state.historyAction).toBe('REPLACE');
  });
});

function Draft({ onWrite, delay }: { onWrite: (v: string) => void; delay: number }) {
  const [params] = useSearchParams();
  const [draft, change, reset] = useDebouncedParam(params.get('q') ?? '', onWrite, delay);
  return (
    <div>
      <input aria-label="q" value={draft} onChange={(e) => change(e.currentTarget.value)} />
      <button onClick={() => reset('fresh')}>reset</button>
    </div>
  );
}

describe('useDebouncedParam', () => {
  function setupDraft(path: string, onWrite: (v: string) => void, delay = 20) {
    const router = createMemoryRouter([{ path: '*', element: <Draft onWrite={onWrite} delay={delay} /> }], { initialEntries: [path] });
    render(<RouterProvider router={router} />);
    return router;
  }

  it('writes the trimmed text once, after the typing stops', async () => {
    const writes: string[] = [];
    setupDraft('/x?q=start', (v) => writes.push(v));
    expect(screen.getByLabelText('q')).toHaveValue('start');
    await userEvent.type(screen.getByLabelText('q'), ' ab ');
    await waitFor(() => expect(writes).toEqual(['start ab']));
  });

  it('follows the address when it changes from outside, and reset drops a pending write', async () => {
    const writes: string[] = [];
    const router = setupDraft('/x?q=one', (v) => writes.push(v), 400);
    await act(() => router.navigate('/x?q=two'));
    await waitFor(() => expect(screen.getByLabelText('q')).toHaveValue('two'));
    await userEvent.type(screen.getByLabelText('q'), 'z');
    await userEvent.click(screen.getByText('reset'));
    expect(screen.getByLabelText('q')).toHaveValue('fresh');
    await new Promise((r) => setTimeout(r, 500));
    expect(writes).toEqual([]);
  });
});
