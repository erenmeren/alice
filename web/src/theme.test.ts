import { DEFAULT_THEME, MantineProvider, TextInput, defaultVariantColorsResolver, mergeMantineTheme } from '@mantine/core';
import { render, screen } from '@testing-library/react';
import { createElement } from 'react';
import { DANGER_HOVER, theme } from './theme';

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

  it('draws a field error in red 9, which has the contrast red 6 lacks (axe, e2e)', () => {
    expect(contrast('#ffffff', full.colors.red[6])).toBeLessThan(4.5);
    expect(contrast('#ffffff', full.colors.red[9])).toBeGreaterThanOrEqual(4.5);
    const message = 'This value contains characters that are not allowed.';
    render(createElement(MantineProvider, { theme }, createElement(TextInput, { label: 'Vault address', error: message })));
    expect(screen.getByText(message)).toHaveStyle({ color: 'var(--mantine-color-red-9)' });
  });
});
