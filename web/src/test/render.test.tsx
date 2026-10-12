import { useMantineColorScheme } from '@mantine/core';
import { fireEvent, screen } from '@testing-library/react';
import { COLOR_SCHEME_KEY } from '../preferences';
import { renderApp } from './render';

// The test providers keep the color mode as the app does (ThemeProvider): under alice.colorScheme, "auto" by default.
function Probe() {
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  return (
    <>
      <output>{colorScheme}</output>
      <button type="button" onClick={() => setColorScheme('dark')}>dark</button>
      <button type="button" onClick={() => setColorScheme('auto')}>auto</button>
    </>
  );
}

it('starts from the app default "auto" and stores the color mode under the app key', async () => {
  await renderApp(<Probe />);
  expect(screen.getByRole('status')).toHaveTextContent('auto');
  fireEvent.click(screen.getByRole('button', { name: 'dark' }));
  expect(localStorage.getItem(COLOR_SCHEME_KEY)).toBe('dark');
  expect(localStorage.getItem('mantine-color-scheme-value')).toBeNull();
  expect(screen.getByRole('status')).toHaveTextContent('dark');
  fireEvent.click(screen.getByRole('button', { name: 'auto' }));
  expect(localStorage.getItem(COLOR_SCHEME_KEY)).toBe('auto');
});
