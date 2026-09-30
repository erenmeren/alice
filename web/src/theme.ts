import { InputWrapper, createTheme, defaultVariantColorsResolver, type VariantColorsResolver } from '@mantine/core';

// Mantine hovers a filled button of shade 9 with the lighter shade 8; for red that is #e03131,
// and white text on it has no safety margin (exact math 4.513:1, but axe measures 4.48:1 on the
// rendered hover, which fails WCAG AA 4.5:1). That is why the override exists: the danger buttons
// (color "red.9") hover a darker red instead, #a51d1d at 7.5:1.
export const DANGER_HOVER = '#a51d1d';

// Mantine's "light" and "subtle" variants draw shade-6 text on a pale tint of the
// same color (for example green 2.2:1, indigo 3.8:1), below WCAG AA (4.5:1).
// Keep the tint as the color cue and use black text instead.
const variantColorResolver: VariantColorsResolver = (input) => {
  const colors = defaultVariantColorsResolver(input);
  if (input.variant === 'filled' && input.color === 'red.9') {
    return { ...colors, hover: DANGER_HOVER };
  }
  if (input.variant === 'light' || input.variant === 'subtle') {
    return { ...colors, color: 'var(--mantine-color-black)', hoverColor: 'var(--mantine-color-black)' };
  }
  return colors;
};

export const theme = createTheme({
  primaryColor: 'indigo',
  // Shade 7 keeps white text on filled buttons and the active nav item above 4.5:1 (5.0:1).
  primaryShade: 7,
  defaultRadius: 'md',
  variantColorResolver,
  components: {
    // Field help texts default to the "dimmed" gray (3.3:1); gray 7 is 8.2:1.
    InputWrapper: InputWrapper.extend({ styles: { description: { color: 'var(--mantine-color-gray-7)' } } }),
  },
});
