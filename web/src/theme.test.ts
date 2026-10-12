import { readdirSync, readFileSync } from 'node:fs';
import { Alert, Checkbox, DEFAULT_THEME, MantineProvider, PasswordInput, Radio, Switch, Table, mergeMantineTheme } from '@mantine/core';
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
  // Checkbox, Radio, Tabs, Progress and Loader write the primary color into an inline variable
  // (--checkbox-color: var(--mantine-color-forest-filled)); it must be the brand token, not palette shade 3 or 7.
  it('draws the primary color’s own variables from the brand tokens in both schemes', () => {
    const vars = cssVariablesResolver(full);
    for (const scheme of [vars.light, vars.dark]) {
      expect(scheme['--mantine-color-forest-filled']).toBe('var(--alice-brand)');
      expect(scheme['--mantine-color-forest-filled-hover']).toBe('var(--alice-brand-hover)');
      expect(scheme['--mantine-color-forest-light']).toBe('var(--alice-brand-soft)');
      expect(scheme['--mantine-color-forest-light-color']).toBe('var(--alice-brand)');
      expect(scheme['--mantine-color-forest-outline']).toBe('var(--alice-brand)');
      expect(scheme['--mantine-color-forest-text']).toBe('var(--alice-brand)');
    }
  });
  it('draws disabled controls from the tokens in both schemes', () => {
    const vars = cssVariablesResolver(full);
    for (const scheme of [vars.light, vars.dark]) {
      expect(scheme['--mantine-color-disabled']).toBe('var(--alice-surface-subtle)');
      expect(scheme['--mantine-color-disabled-color']).toBe('var(--alice-text-muted)');
      expect(scheme['--mantine-color-disabled-border']).toBe('var(--alice-border)');
    }
  });
  // Mantine draws its dark scheme (popover and menu surfaces, hovers, borders, the select chevron, segmented controls,
  // the close button) from its neutral "dark" palette; mapped onto the tokens, those surfaces match the canvas.
  it('maps every shade of Mantine’s dark palette onto a token in the dark scheme only', () => {
    const vars = cssVariablesResolver(full);
    const tokens = readFileSync('src/design/tokens.css', 'utf8');
    const darkBlock = tokens.slice(tokens.indexOf(":root[data-mantine-color-scheme='dark']"));
    for (let n = 0; n <= 9; n++) {
      const value = vars.dark[`--mantine-color-dark-${n}`];
      expect(value).toMatch(/^var\(--alice-[a-z-]+\)$/);
      expect(darkBlock).toContain(`${value.slice(4, -1)}:`);
      expect(vars.light[`--mantine-color-dark-${n}`]).toBeUndefined();
    }
  });
  it('leaves no other palette shade in Mantine’s dark-scheme rules for a component the app uses', () => {
    const shades = new Set<string>();
    for (const [, sel, body] of mantineCss.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
      if (!/data-mantine-color-scheme='dark'/.test(sel) || sel.trim().startsWith(':root')) continue;
      for (const [, shade] of body.matchAll(/--mantine-color-([a-z]+-\d)\b/g)) if (!shade.startsWith('dark-')) shades.add(shade);
    }
    // Tooltip (gray-2) and the typography styles' <mark> (yellow-5): components the app does not use.
    expect([...shades].sort()).toEqual(['gray-2', 'yellow-5']);
    const sources = (readdirSync('src', { recursive: true }) as string[]).filter((f) => /\.tsx?$/.test(f) && !/\.test\.tsx?$/.test(f));
    const users = sources.filter((f) => /\b(Tooltip|TypographyStylesProvider|Typography)\b/.test(readFileSync(`src/${f}`, 'utf8')));
    expect(users).toEqual([]);
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

  // Found by the Phase 9 focus scan (e2e/phase9.spec.ts): Mantine's alert message clips its overflow, which cut off the
  // 3 px ring (3 px outside) of a link in a banner such as "Open the License page".
  it('lets a link inside an alert show its whole focus ring: the message does not clip, the body may still shrink', async () => {
    await renderApp(createElement(Alert, { title: 't' }, createElement('a', { href: '/license' }, 'Open the License page')), ['en-US']);
    const link = screen.getByRole('link', { name: 'Open the License page' });
    expect(link.closest('.mantine-Alert-message')).toHaveClass(classes.alertMessage);
    expect(link.closest('.mantine-Alert-body')).toHaveClass(classes.alertBody);
    expect(moduleCss).toMatch(/\.alertMessage\s*\{[^}]*overflow:\s*visible/);
    expect(moduleCss).toMatch(/\.alertBody\s*\{[^}]*min-width:\s*0/);
  });

  // Found by the Phase 9 focus scan: a password field's real input fills a wrapper that clips its overflow, so the
  // global ring (outside the input) was never visible on password fields. The wrapper draws it instead.
  it('draws the focus ring of a password field on its wrapper, which cannot clip it', async () => {
    await renderApp(createElement(PasswordInput, { label: 'p' }), ['en-US']);
    const input = screen.getByLabelText('p');
    expect(input).toHaveClass(classes.passwordInnerInput);
    expect(input.parentElement).toHaveClass(classes.input);
    expect(moduleCss).toMatch(/\.input:has\(\.passwordInnerInput:focus-visible\)\s*\{[^}]*outline:\s*3px solid var\(--alice-focus\);\s*outline-offset:\s*3px/);
    expect(moduleCss).toMatch(/\.passwordInnerInput:focus-visible\s*\{\s*outline:\s*0/);
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
