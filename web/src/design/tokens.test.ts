import { readFileSync } from 'node:fs';

const css = readFileSync('src/design/tokens.css', 'utf8');

// tokensOf reads the custom properties of the first rule whose selector list contains selector.
function tokensOf(selector: string): Record<string, string> {
  const rule = [...css.matchAll(/([^{}]+)\{([^}]*)\}/g)].find(([, sel]) => sel.split(',').map((s) => s.trim()).includes(selector));
  if (!rule) throw new Error(`no rule for ${selector}`);
  return Object.fromEntries([...rule[2].matchAll(/--alice-([a-z-]+):\s*(#[0-9a-f]{6})\b/g)].map(([, k, v]) => [k, v]));
}

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
// mix is CSS color-mix(in srgb, a p%, b): the light variants' hover background (theme.ts).
function mix(a: string, b: string, p: number): string {
  const ch = (h: string, i: number) => parseInt(h.slice(i, i + 2), 16);
  return '#' + [1, 3, 5].map((i) => Math.round(ch(a, i) * p + ch(b, i) * (1 - p)).toString(16).padStart(2, '0')).join('');
}

const TONES = ['success', 'warning', 'danger', 'info', 'neutral'] as const;
const TEXT_PAIRS: [string, string][] = [
  ['text', 'canvas'], ['text', 'surface'], ['text', 'surface-hover'],
  ['text-secondary', 'surface'], ['text-secondary', 'canvas'], ['text-secondary', 'surface-subtle'],
  ['text-muted', 'canvas'], ['text-muted', 'surface'], ['text-muted', 'surface-subtle'],
  ['on-brand', 'brand'], ['on-brand', 'brand-hover'], ['brand', 'brand-soft'], ['brand', 'surface'], ['brand', 'canvas'], ['brand', 'surface-hover'],
  ...TONES.flatMap((t): [string, string][] => [[t, `${t}-soft`], ['on-strong', t], ['on-strong', `${t}-hover`], [t, 'surface']]),
];

describe.each([
  ['light', ':root[data-mantine-color-scheme=\'light\']'],
  ['dark', ':root[data-mantine-color-scheme=\'dark\']'],
])('the %s scheme', (_name, selector) => {
  const light = tokensOf(':root[data-mantine-color-scheme=\'light\']');
  const tokens = { ...light, ...tokensOf(selector) };

  it.each(TEXT_PAIRS)('%s on %s reaches 4.5:1', (fg, bg) => {
    expect(contrast(tokens[fg], tokens[bg])).toBeGreaterThanOrEqual(4.5);
  });

  it.each(TONES)('%s text stays at 4.5:1 on its hovered light variant', (t) => {
    expect(contrast(tokens[t], mix(tokens[t], tokens[`${t}-soft`], 0.1))).toBeGreaterThanOrEqual(4.5);
  });

  it('draws field borders and the focus ring at 3:1 (non-text contrast)', () => {
    for (const bg of ['surface', 'canvas']) {
      expect(contrast(tokens['border-strong'], tokens[bg])).toBeGreaterThanOrEqual(3);
      expect(contrast(tokens.focus, tokens[bg])).toBeGreaterThanOrEqual(3);
    }
  });
});

it('has the same token names in both schemes and a compact density row', () => {
  const light = Object.keys(tokensOf(':root[data-mantine-color-scheme=\'light\']')).sort();
  const dark = Object.keys(tokensOf(':root[data-mantine-color-scheme=\'dark\']'));
  for (const k of dark) expect(light).toContain(k);
  for (const k of ['canvas', 'surface', 'text', 'brand', 'danger', 'focus', 'on-strong']) expect(dark).toContain(k);
  expect(css).toMatch(/:root\[data-density='compact'\]\s*\{\s*--alice-row-height:\s*48px;/);
  expect(css).not.toMatch(/https?:\/\//); // fonts are local (CSP font-src 'self', offline installations)
});

// Mantine draws the check of a checked Checkbox, the dot of a Radio and the thumb of a Switch on the brand color; the
// design rules (mantine.module.css) give them the design's colors, which reach 3:1 (non-text contrast) in both schemes.
describe('checked controls', () => {
  const moduleCss = readFileSync('src/design/mantine.module.css', 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
  // tokenOf finds the --alice-* token the design rule for selector (in both schemes) assigns to variable.
  function tokenOf(selector: string, variable: string): string {
    const part = `[data-mantine-color-scheme] ${selector}`;
    for (const [, sel, body] of moduleCss.matchAll(/([^{}]+)\{([^}]*)\}/g)) {
      if (!sel.split(',').map((x) => x.trim()).includes(part)) continue;
      const m = body.match(new RegExp(`${variable}:\\s*var\\(--alice-([a-z-]+)\\)`));
      if (m) return m[1];
    }
    throw new Error(`no ${variable} under ${part}`);
  }
  const PAIRS: [string, string, string, string][] = [
    ['the check', ".checkbox:where([data-variant='filled'])", '--checkbox-icon-color', 'brand'],
    ['the radio dot', '.radio', '--radio-icon-color', 'brand'],
    ['the switch thumb when on', '.switchInput:checked + * > .switchThumb', '--switch-thumb-bg', 'brand'],
  ];
  describe.each(['light', 'dark'])('%s', (scheme) => {
    const tokens = { ...tokensOf(':root[data-mantine-color-scheme=\'light\']'), ...tokensOf(`:root[data-mantine-color-scheme='${scheme}']`) };
    it.each(PAIRS)('%s reaches 3:1 on its background', (_what, part, variable, bg) => {
      const fg = tokenOf(part, variable);
      expect(fg).toBe('on-brand');
      expect(contrast(tokens[fg], tokens[bg])).toBeGreaterThanOrEqual(3);
    });
    it('the switch thumb when off reaches 3:1 on its track', () => {
      const thumb = tokenOf('.switchThumb', '--switch-thumb-bg');
      const track = tokenOf('.switchTrack', '--switch-bg');
      expect(contrast(tokens[thumb], tokens[track])).toBeGreaterThanOrEqual(3);
    });
  });
});

it('gives the page the design canvas before the app mounts (Mantine’s body and text variables in both schemes)', () => {
  for (const selector of [':root,\n:root[data-mantine-color-scheme=\'light\']', ':root[data-mantine-color-scheme=\'dark\']']) {
    const rule = css.slice(css.indexOf(`${selector} {`));
    const body = rule.slice(0, rule.indexOf('}'));
    expect(body).toMatch(/--mantine-color-body:\s*var\(--alice-canvas\);/);
    expect(body).toMatch(/--mantine-color-text:\s*var\(--alice-text\);/);
  }
});
