import { readFileSync } from 'node:fs';
import { Checkbox, DEFAULT_THEME, MantineProvider, Radio, Switch, Table, mergeMantineTheme } from '@mantine/core';
import { render, screen } from '@testing-library/react';
import { createElement } from 'react';
import { I18nextProvider } from 'react-i18next';
import { createI18n } from './i18n';
import { ThemeProvider } from './ThemeProvider';
import { renderApp } from './test/render';
import classes from './design/mantine.module.css';
import { SCROLL_REGION_CLASS, TONE_COLOR, appTheme, cssVariablesResolver, toneOf, variantColorResolver } from './theme';

const theme = appTheme('Table, scrolls sideways');
const full = mergeMantineTheme(DEFAULT_THEME, theme);

function scrollingTable() {
  return createElement(Table.ScrollContainer, { minWidth: 720 }, createElement(Table, null, createElement(Table.Tbody, null, createElement(Table.Tr, null, createElement(Table.Td, null, 'cell')))));
}

// The CSS Mantine's provider writes for its variables (a style tag with the scheme values).
function mantineVariables(): string {
  return [...document.querySelectorAll('style')].map((s) => s.textContent ?? '').join('\n');
}

// Mantine's own stylesheet (main.tsx loads it): the rules that draw an error read the one variable.
const mantineCss = readFileSync('node_modules/@mantine/core/styles.css', 'utf8');

describe('semantic colors', () => {
  it('maps Mantine colors, with or without a shade, to the design tones', () => {
    expect(toneOf('red.9')).toBe('danger');
    expect(toneOf('yellow')).toBe('warning');
    expect(toneOf('orange')).toBe('warning');
    expect(toneOf('green')).toBe('success');
    expect(toneOf('teal.9')).toBe('success');
    expect(toneOf('blue')).toBe('info');
    expect(toneOf('gray')).toBe('neutral');
    expect(toneOf('indigo')).toBe('brand');
    expect(toneOf(undefined)).toBe('brand');
    expect(TONE_COLOR.danger).toBe('red');
  });
  it('draws light and subtle variants with the tone on its soft background, never black text', () => {
    const light = variantColorResolver({ color: 'yellow', theme: full, variant: 'light' });
    expect(light.background).toBe('var(--alice-warning-soft)');
    expect(light.color).toBe('var(--alice-warning)');
    expect(JSON.stringify(light)).not.toContain('black');
    expect(variantColorResolver({ color: 'red', theme: full, variant: 'subtle' }).color).toBe('var(--alice-danger)');
  });
  it('fills buttons with the strong tone and its readable foreground, hovering the hover token', () => {
    const danger = variantColorResolver({ color: 'red.9', theme: full, variant: 'filled' });
    expect(danger).toMatchObject({ background: 'var(--alice-danger)', hover: 'var(--alice-danger-hover)', color: 'var(--alice-on-strong)' });
    const primary = variantColorResolver({ color: full.primaryColor, theme: full, variant: 'filled' });
    expect(primary).toMatchObject({ background: 'var(--alice-brand)', color: 'var(--alice-on-brand)' });
  });
  it('draws outline variants with the tone border and leaves other variants to Mantine', () => {
    expect(variantColorResolver({ color: 'blue', theme: full, variant: 'outline' })).toMatchObject({ border: '1px solid var(--alice-info)', color: 'var(--alice-info)' });
    expect(variantColorResolver({ color: 'red', theme: full, variant: 'default' }).background).toBe('var(--mantine-color-default)');
  });
  it('maps Mantine’s own variables onto the tokens in both schemes', () => {
    const vars = cssVariablesResolver(full);
    for (const scheme of [vars.light, vars.dark]) {
      expect(scheme['--mantine-color-body']).toBe('var(--alice-canvas)');
      expect(scheme['--mantine-color-text']).toBe('var(--alice-text)');
      expect(scheme['--mantine-color-dimmed']).toBe('var(--alice-text-secondary)');
      expect(scheme['--mantine-color-error']).toBe('var(--alice-danger)');
      expect(scheme['--mantine-primary-color-filled']).toBe('var(--alice-brand)');
      expect(scheme['--mantine-color-default-border']).toBe('var(--alice-border)');
    }
  });
  it('uses the bundled Geist fonts with system fallbacks', () => {
    expect(full.fontFamily).toMatch(/^Geist, /);
    expect(full.fontFamilyMonospace).toMatch(/^'Geist Mono', /);
    expect(full.headings.sizes.h1.fontSize).toBe('32px');
  });
});

describe('theme', () => {
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
    expect(rule![1]).toMatch(/outline:\s*2px solid var\(--alice-focus\)/);
    expect(rule![1]).toMatch(/outline-offset:\s*-2px/);
  });

  it('loads the tokens and the design rules after Mantine’s stylesheet', () => {
    const main = readFileSync('src/main.tsx', 'utf8');
    const at = (s: string) => main.indexOf(`import '${s}';`);
    expect(at('@mantine/core/styles.css')).toBeGreaterThanOrEqual(0);
    expect(at('./design/tokens.css')).toBeGreaterThan(at('@mantine/core/styles.css'));
    expect(at('./theme.css')).toBeGreaterThan(at('./design/tokens.css'));
    expect(at('./design/base.css')).toBeGreaterThan(at('./theme.css'));
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
      expect(mantineVariables()).toMatch(/--mantine-color-error:\s*var\(--alice-danger\)/);
      unmount();
    }
  });
});

describe('color mode', () => {
  afterEach(() => document.documentElement.removeAttribute('data-mantine-color-scheme'));

  async function renderProvider() {
    const i18n = await createI18n(['en-US']);
    return render(createElement(I18nextProvider, { i18n }, createElement(ThemeProvider, null, 'app')));
  }

  it('follows the system (light in the tests) when nothing is stored', async () => {
    await renderProvider();
    expect(document.documentElement).toHaveAttribute('data-mantine-color-scheme', 'light');
  });

  it('applies the color mode stored on this device', async () => {
    localStorage.setItem('alice.colorScheme', 'dark');
    await renderProvider();
    expect(document.documentElement).toHaveAttribute('data-mantine-color-scheme', 'dark');
  });
});

describe('design rules', () => {
  const moduleCss = readFileSync('src/design/mantine.module.css', 'utf8');

  it('styles fields through Mantine’s input variables, so the disabled and error states keep their own colors', () => {
    const rules = [...moduleCss.matchAll(/([^{}]*\.input\b[^{}]*)\{([^}]*)\}/g)];
    expect(rules.length).toBeGreaterThan(0);
    for (const [, , body] of rules) expect(body).not.toMatch(/(^|[;{\s])(background|background-color|color)\s*:/);
    expect(moduleCss).toMatch(/\.input\s*\{[^}]*--input-bg:\s*var\(--alice-surface\)/);
    expect(moduleCss).toMatch(/\.input:not\(\[data-error\]\)\s*\{[^}]*--input-color:\s*var\(--alice-text\)/);
  });

  it('draws checked Checkbox, Radio and Switch with the design classes in dark mode', async () => {
    await renderApp(
      createElement('div', null,
        createElement(Checkbox, { label: 'c', defaultChecked: true }),
        createElement(Radio, { label: 'r', defaultChecked: true }),
        createElement(Switch, { label: 's', defaultChecked: true })),
      ['en-US'], { colorScheme: 'dark' });
    expect(document.documentElement).toHaveAttribute('data-mantine-color-scheme', 'dark');
    expect(screen.getByRole('checkbox', { name: 'c' }).closest('.mantine-Checkbox-root')).toHaveClass(classes.checkbox);
    expect(screen.getByRole('radio', { name: 'r' }).closest('.mantine-Radio-root')).toHaveClass(classes.radio);
    const sw = screen.getByRole('switch', { name: 's' });
    expect(sw).toHaveClass(classes.switchInput);
    const root = sw.closest('.mantine-Switch-root')!;
    expect(root.querySelector('.mantine-Switch-track')).toHaveClass(classes.switchTrack);
    expect(root.querySelector('.mantine-Switch-thumb')).toHaveClass(classes.switchThumb);
  });
});
