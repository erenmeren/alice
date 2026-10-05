import { InputWrapper, TableScrollContainer, createTheme, defaultVariantColorsResolver, type CSSVariablesResolver, type MantineThemeOverride, type VariantColorsResolver } from '@mantine/core';

// Mantine hovers a filled button of shade 9 with the lighter shade 8; for red that is #e03131,
// and white text on it has no safety margin (exact math 4.513:1, but axe measures 4.48:1 on the
// rendered hover, which fails WCAG AA 4.5:1). That is why the override exists: the danger buttons
// (color "red.9") hover a darker red instead, #a51d1d at 7.5:1.
export const DANGER_HOVER = '#a51d1d';

// SCROLL_REGION_CLASS marks the scrolling part of every table scroll container; theme.css draws its
// keyboard focus ring inside it (the ScrollArea root clips anything drawn outside, overflow: hidden).
export const SCROLL_REGION_CLASS = 'alice-scroll-region';

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

// cssVariablesResolver goes to the MantineProvider (it is not part of the theme). Mantine draws
// everything that marks an error from one variable, --mantine-color-error: the message under a field,
// the text, placeholder, sections, asterisk and border of a field with an error, and the error labels of
// Checkbox, Radio and Switch. Its default in the light scheme is red 6 (3.1:1 on white); red 9 is 6.1:1.
// The app is light only (defaultColorScheme="light"), so the dark scheme keeps Mantine's value.
export const cssVariablesResolver: CSSVariablesResolver = () => ({
  variables: {},
  light: { '--mantine-color-error': 'var(--mantine-color-red-9)' },
  dark: {},
});

// appTheme is the app's theme. scrollRegionLabel names the scrolling part of a table (the caller's
// translated "ui.scrollRegion"), so the theme is made again when the language changes.
export function appTheme(scrollRegionLabel: string): MantineThemeOverride {
  return createTheme({
    primaryColor: 'indigo',
    // Shade 7 keeps white text on filled buttons and the active nav item above 4.5:1 (5.0:1).
    primaryShade: 7,
    defaultRadius: 'md',
    variantColorResolver,
    components: {
      // Field help texts default to the "dimmed" gray (3.3:1); gray 7 is 8.2:1. (Field errors: see
      // cssVariablesResolver.)
      InputWrapper: InputWrapper.extend({ styles: { description: { color: 'var(--mantine-color-gray-7)' } } }),
      // A table that scrolls sideways on a narrow screen must be reachable with the keyboard (axe
      // scrollable-region-focusable); a table without a link or button in it has nothing else to focus.
      // The stop is a named group (a screen reader says what it is; a group is no landmark, so pages with
      // several tables do not fill the landmark list with one repeated name) with a focus ring drawn inside it.
      TableScrollContainer: TableScrollContainer.extend({
        defaultProps: {
          scrollAreaProps: {
            classNames: { viewport: SCROLL_REGION_CLASS },
            viewportProps: { tabIndex: 0, role: 'group', 'aria-label': scrollRegionLabel },
          },
        },
      }),
    },
  });
}
