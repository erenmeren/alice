import { MantineProvider, localStorageColorSchemeManager } from '@mantine/core';
import { useMemo, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { readCspNonce } from './csp';
import { COLOR_SCHEME_KEY } from './preferences';
import { appTheme, cssVariablesResolver } from './theme';

// The color mode is a per-device preference: light, dark or the system's ("auto", the default). public/theme-init.js
// applies the stored value before the app runs.
const schemeManager = localStorageColorSchemeManager({ key: COLOR_SCHEME_KEY });

// ThemeProvider is Mantine's provider with the app's theme in the current language: the theme names the
// scrolling part of a table, so it is made again when the language changes.
export function ThemeProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const label = t('ui.scrollRegion');
  const theme = useMemo(() => appTheme(label), [label]);
  return (
    <MantineProvider
      theme={theme}
      cssVariablesResolver={cssVariablesResolver}
      getStyleNonce={readCspNonce}
      colorSchemeManager={schemeManager}
      defaultColorScheme="auto"
    >
      {children}
    </MantineProvider>
  );
}
