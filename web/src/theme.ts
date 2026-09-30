import { InputWrapper, createTheme, defaultVariantColorsResolver, type VariantColorsResolver } from '@mantine/core';

// Mantine's "light" and "subtle" variants draw shade-6 text on a pale tint of the
// same color (for example green 2.2:1, indigo 3.8:1), below WCAG AA (4.5:1).
// Keep the tint as the color cue and use black text instead.
const variantColorResolver: VariantColorsResolver = (input) => {
  const colors = defaultVariantColorsResolver(input);
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
