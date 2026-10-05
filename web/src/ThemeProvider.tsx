import { MantineProvider } from '@mantine/core';
import { useMemo, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { readCspNonce } from './csp';
import { appTheme, cssVariablesResolver } from './theme';

// ThemeProvider is Mantine's provider with the app's theme in the current language: the theme names the
// scrolling part of a table, so it is made again when the language changes.
export function ThemeProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const label = t('ui.scrollRegion');
  const theme = useMemo(() => appTheme(label), [label]);
  return (
    <MantineProvider theme={theme} cssVariablesResolver={cssVariablesResolver} getStyleNonce={readCspNonce} defaultColorScheme="light">
      {children}
    </MantineProvider>
  );
}
