import { readFileSync } from 'node:fs';
import { DEFAULT_THEME, MantineProvider, Table, TextInput, defaultVariantColorsResolver, mergeMantineTheme } from '@mantine/core';
import { render, screen } from '@testing-library/react';
import { createElement } from 'react';
import { I18nextProvider } from 'react-i18next';
import { createI18n } from './i18n';
import { ThemeProvider } from './ThemeProvider';
import { DANGER_HOVER, SCROLL_REGION_CLASS, appTheme, cssVariablesResolver } from './theme';

const theme = appTheme('Table, scrolls sideways');

function scrollingTable() {
  return createElement(Table.ScrollContainer, { minWidth: 720 }, createElement(Table, null, createElement(Table.Tbody, null, createElement(Table.Tr, null, createElement(Table.Td, null, 'cell')))));
}

// The CSS Mantine's provider writes for its variables (a style tag with the light scheme's values).
function mantineVariables(): string {
  return [...document.querySelectorAll('style')].map((s) => s.textContent ?? '').join('\n');
}

// Mantine's own stylesheet (main.tsx loads it): the rules that draw an error read the one variable.
const mantineCss = readFileSync('node_modules/@mantine/core/styles.css', 'utf8');

// WCAG 2.x relative luminance of a #rrggbb color.
function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

describe('theme', () => {
  const full = mergeMantineTheme(DEFAULT_THEME, theme);

  it('keeps white text on the red confirm buttons above 4.5:1, also on hover', () => {
    const colors = full.variantColorResolver({ color: 'red.9', theme: full, variant: 'filled' });
    expect(colors.hover).toBe(DANGER_HOVER);
    expect(contrast('#ffffff', DANGER_HOVER)).toBeGreaterThanOrEqual(4.5);
    expect(contrast('#ffffff', full.colors.red[9])).toBeGreaterThanOrEqual(4.5);
  });

  it('needs the override: Mantine itself hovers red 9 with red 8, which has no safety margin', () => {
    const base = defaultVariantColorsResolver({ color: 'red.9', theme: full, variant: 'filled' });
    expect(base.hover).toBe('var(--mantine-color-red-8)'); // the variable resolves to full.colors.red[8]
    // Exact WCAG math gives 4.513:1 for #e03131, but axe measures 4.48:1 on the rendered hover,
    // which fails AA. That is why the override exists.
    expect(contrast('#ffffff', full.colors.red[8])).toBeLessThan(4.6);
  });

  it('leaves other filled buttons alone', () => {
    const colors = full.variantColorResolver({ color: 'indigo', theme: full, variant: 'filled' });
    expect(colors.hover).not.toBe(DANGER_HOVER);
  });

  it('draws everything that marks an error in red 9, which has the contrast red 6 lacks (axe, e2e)', () => {
    expect(contrast('#ffffff', full.colors.red[6])).toBeLessThan(4.5);
    expect(contrast('#ffffff', full.colors.red[9])).toBeGreaterThanOrEqual(4.5);
    // The light scheme's error color is red 9; the app has no dark scheme (defaultColorScheme="light").
    expect(cssVariablesResolver(full)).toEqual({ variables: {}, light: { '--mantine-color-error': 'var(--mantine-color-red-9)' }, dark: {} });
    render(createElement(MantineProvider, { theme, cssVariablesResolver }, createElement(TextInput, { label: 'Vault address', error: 'bad' })));
    expect(mantineVariables()).toMatch(/--mantine-color-error:\s*var\(--mantine-color-red-9\)/);
  });

  it('relies on Mantine drawing the field message, the typed text and the choice labels of an error from that variable', () => {
    for (const rule of [
      /--input-color:\s*var\(--mantine-color-error\)/, // the text typed into a field with an error
      /--input-placeholder-color:\s*var\(--mantine-color-error\)/,
      /\.m_8f816625\s*\{[^}]*color:\s*var\(--mantine-color-error\)/, // InputWrapper's error message
    ]) {
      expect(mantineCss).toMatch(rule);
    }
    // Checkbox, Radio and Switch draw their error label as an InputWrapper error too (the same class).
    expect(mantineCss.match(/var\(--mantine-color-error\)/g)?.length).toBeGreaterThanOrEqual(8);
  });

  it('makes the scrolling part of every table scroll container a named group (not a landmark) and a tab stop with its focus ring', () => {
    const { container } = render(createElement(MantineProvider, { theme }, scrollingTable()));
    const viewport = container.querySelector('.mantine-ScrollArea-viewport');
    expect(viewport).toHaveAttribute('tabindex', '0');
    expect(viewport).toHaveAttribute('role', 'group');
    expect(viewport).toHaveAttribute('aria-label', 'Table, scrolls sideways');
    expect(viewport).toHaveClass(SCROLL_REGION_CLASS);
  });

  it('draws the focus ring inside the region: the ScrollArea root clips anything outside it', () => {
    const css = readFileSync('src/theme.css', 'utf8');
    const rule = new RegExp(`\\.${SCROLL_REGION_CLASS}:focus-visible\\s*\\{([^}]*)\\}`).exec(css);
    expect(rule, 'a :focus-visible rule for the region').not.toBeNull();
    expect(rule![1]).toMatch(/outline:\s*2px solid var\(--mantine-primary-color-filled\)/);
    expect(rule![1]).toMatch(/outline-offset:\s*-2px/);
    expect(readFileSync('src/main.tsx', 'utf8')).toContain("import './theme.css';");
  });

  it('names the region in the language of the app', async () => {
    for (const [lang, label] of [
      ['en-US', 'Table, scrolls sideways'],
      ['tr-TR', 'Tablo, yana kaydırılır'],
    ] as const) {
      const i18n = await createI18n([lang]);
      const { unmount } = render(createElement(I18nextProvider, { i18n }, createElement(ThemeProvider, null, scrollingTable())));
      expect(screen.getByRole('group', { name: label })).toHaveAttribute('tabindex', '0');
      expect(screen.queryByRole('region', { name: label })).not.toBeInTheDocument();
      expect(mantineVariables()).toMatch(/--mantine-color-error:\s*var\(--mantine-color-red-9\)/);
      unmount();
    }
  });
});
