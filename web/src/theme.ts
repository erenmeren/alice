import {
  Alert, Badge, Button, Card, Checkbox, Code, Input, InputWrapper, Modal, Paper, PasswordInput, Radio, SegmentedControl, Switch, Table, TableScrollContainer, TableTh, Tabs, Title,
  createTheme, defaultVariantColorsResolver,
  type CSSVariablesResolver, type MantineColorsTuple, type MantineThemeOverride, type VariantColorsResolver,
} from '@mantine/core';
import classes from './design/mantine.module.css';

// SCROLL_REGION_CLASS marks the scrolling part of every table scroll container; theme.css draws its keyboard focus ring
// inside it (the ScrollArea root clips anything drawn outside, overflow: hidden).
export const SCROLL_REGION_CLASS = 'alice-scroll-region';

// The design's forest accent as a palette; shade 7 is the light brand. Components that read a palette shade directly
// (Loader, Progress, Switch, Checkbox) get the brand; everything scheme-dependent comes from the variables below.
const forest: MantineColorsTuple = ['#e9f2ed', '#d3e6db', '#a7c9b9', '#83bb9c', '#5a9479', '#3d7d64', '#24695a', '#145f50', '#104c40', '#0b3a31'];

export type Tone = 'brand' | 'success' | 'warning' | 'danger' | 'info' | 'neutral';

// The Mantine color a component passes, by the design's semantic tone it stands for. Pages keep saying color="red" or
// color="yellow"; the resolver turns that into the tone's tokens, in both schemes.
const TONE_OF: Record<string, Tone> = {
  forest: 'brand', indigo: 'brand', violet: 'brand', grape: 'brand',
  green: 'success', teal: 'success', lime: 'success',
  yellow: 'warning', orange: 'warning',
  red: 'danger', pink: 'danger',
  blue: 'info', cyan: 'info',
  gray: 'neutral', dark: 'neutral',
};

export const TONE_COLOR: Record<Tone, string> = { brand: 'forest', success: 'green', warning: 'yellow', danger: 'red', info: 'blue', neutral: 'gray' };

// toneOf maps "red", "red.9" or a missing color (the primary color) to its tone; anything unknown is neutral.
export function toneOf(color: string | undefined): Tone {
  if (!color) return 'brand';
  return TONE_OF[color.split('.')[0]] ?? 'neutral';
}

const strong = (t: Tone) => `var(--alice-${t})`;
const onStrong = (t: Tone) => (t === 'brand' ? 'var(--alice-on-brand)' : 'var(--alice-on-strong)');

// variantColorResolver replaces the light-only overrides of earlier phases (black text on light variants, a darker red
// hover): every variant draws from the semantic tokens, whose pairs tokens.test.ts holds at 4.5:1 in both schemes.
export const variantColorResolver: VariantColorsResolver = (input) => {
  const tone = toneOf(input.color ?? input.theme.primaryColor);
  const soft = `var(--alice-${tone}-soft)`;
  switch (input.variant) {
    case 'filled':
      return { background: strong(tone), hover: `var(--alice-${tone}-hover)`, color: onStrong(tone), hoverColor: onStrong(tone), border: '1px solid transparent' };
    case 'light':
      return {
        background: soft,
        hover: `color-mix(in srgb, ${strong(tone)} 10%, ${soft})`,
        color: strong(tone),
        hoverColor: strong(tone),
        border: `1px solid color-mix(in srgb, ${strong(tone)} 30%, transparent)`,
      };
    case 'subtle':
      return { background: 'transparent', hover: soft, color: strong(tone), hoverColor: strong(tone), border: '1px solid transparent' };
    case 'outline':
      return { background: 'transparent', hover: soft, color: strong(tone), hoverColor: strong(tone), border: `1px solid ${strong(tone)}` };
    default:
      return defaultVariantColorsResolver(input);
  }
};

// Mantine's own variables, mapped onto the tokens. The tokens change with data-mantine-color-scheme, so both schemes
// use the same mapping. Mantine draws everything that marks an error (field message, typed text, placeholder, border,
// the error labels of Checkbox, Radio and Switch) from --mantine-color-error.
const SCHEME: Record<string, string> = {
  '--mantine-color-body': 'var(--alice-canvas)',
  '--mantine-color-text': 'var(--alice-text)',
  '--mantine-color-dimmed': 'var(--alice-text-secondary)',
  '--mantine-color-placeholder': 'var(--alice-text-muted)',
  '--mantine-color-anchor': 'var(--alice-brand)',
  '--mantine-color-default': 'var(--alice-surface)',
  '--mantine-color-default-hover': 'var(--alice-surface-hover)',
  '--mantine-color-default-color': 'var(--alice-text)',
  '--mantine-color-default-border': 'var(--alice-border)',
  '--mantine-color-error': 'var(--alice-danger)',
  '--mantine-primary-color-filled': 'var(--alice-brand)',
  '--mantine-primary-color-filled-hover': 'var(--alice-brand-hover)',
  '--mantine-primary-color-light': 'var(--alice-brand-soft)',
  '--mantine-primary-color-light-hover': 'var(--alice-surface-hover)',
  '--mantine-primary-color-light-color': 'var(--alice-brand)',
  '--mantine-primary-color-contrast': 'var(--alice-on-brand)',
  // The primary color by name: Checkbox, Radio, Tabs, Progress and Loader write var(--mantine-color-forest-filled)
  // into their inline variables; it is the brand token, not the palette's shade 7 (light) or 3 (dark).
  '--mantine-color-forest-filled': 'var(--alice-brand)',
  '--mantine-color-forest-filled-hover': 'var(--alice-brand-hover)',
  '--mantine-color-forest-light': 'var(--alice-brand-soft)',
  '--mantine-color-forest-light-hover': 'var(--alice-surface-hover)',
  '--mantine-color-forest-light-color': 'var(--alice-brand)',
  '--mantine-color-forest-outline': 'var(--alice-brand)',
  '--mantine-color-forest-outline-hover': 'var(--alice-brand-soft)',
  '--mantine-color-forest-text': 'var(--alice-brand)',
  '--mantine-color-disabled': 'var(--alice-surface-subtle)',
  '--mantine-color-disabled-color': 'var(--alice-text-muted)',
  '--mantine-color-disabled-border': 'var(--alice-border)',
};

// Mantine's dark-scheme rules draw surfaces, hovers, borders and secondary text (popovers, menus, segmented
// controls, the select chevron, the close button) from its neutral "dark" palette. In the dark scheme each shade is the
// token it stands for, so those parts sit on the design's green-grey canvas; tokens.test.ts holds the text pairs.
const DARK_PALETTE: Record<string, string> = {
  '--mantine-color-dark-0': 'var(--alice-text)',
  '--mantine-color-dark-1': 'var(--alice-text-secondary)',
  '--mantine-color-dark-2': 'var(--alice-text-muted)',
  '--mantine-color-dark-3': 'var(--alice-border-strong)',
  '--mantine-color-dark-4': 'var(--alice-border)',
  '--mantine-color-dark-5': 'var(--alice-surface-hover)',
  '--mantine-color-dark-6': 'var(--alice-surface-raised)',
  '--mantine-color-dark-7': 'var(--alice-surface)',
  '--mantine-color-dark-8': 'var(--alice-canvas)',
  '--mantine-color-dark-9': 'var(--alice-canvas)',
};

// cssVariablesResolver goes to the MantineProvider (it is not part of the theme).
export const cssVariablesResolver: CSSVariablesResolver = () => ({ variables: {}, light: SCHEME, dark: { ...SCHEME, ...DARK_PALETTE } });

const SANS = "Geist, system-ui, -apple-system, 'Segoe UI', Arial, sans-serif";
const MONO = "'Geist Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

// appTheme is the app's theme. scrollRegionLabel names the scrolling part of a table (the caller's translated
// "ui.scrollRegion"), so the theme is made again when the language changes.
export function appTheme(scrollRegionLabel: string): MantineThemeOverride {
  return createTheme({
    colors: { forest },
    primaryColor: 'forest',
    primaryShade: { light: 7, dark: 3 },
    variantColorResolver,
    fontFamily: SANS,
    fontFamilyMonospace: MONO,
    headings: {
      fontFamily: SANS,
      fontWeight: '600',
      sizes: {
        h1: { fontSize: '32px', lineHeight: '1.2', fontWeight: '590' },
        h2: { fontSize: '16px', lineHeight: '1.5', fontWeight: '600' },
        h3: { fontSize: '14px', lineHeight: '1.5', fontWeight: '600' },
        h4: { fontSize: '13px', lineHeight: '1.5', fontWeight: '600' },
        h5: { fontSize: '12px', lineHeight: '1.5', fontWeight: '600' },
        h6: { fontSize: '11px', lineHeight: '1.5', fontWeight: '600' },
      },
    },
    fontSizes: { xs: '11px', sm: '12px', md: '14px', lg: '16px', xl: '20px' },
    radius: { xs: '4px', sm: '6px', md: '10px', lg: '14px', xl: '20px' },
    defaultRadius: 'sm',
    spacing: { xs: '8px', sm: '12px', md: '16px', lg: '24px', xl: '32px' },
    cursorType: 'pointer',
    components: {
      Alert: Alert.extend({ defaultProps: { variant: 'light', radius: 'md' }, classNames: { root: classes.alert, body: classes.alertBody, title: classes.alertTitle, message: classes.alertMessage } }),
      Badge: Badge.extend({ defaultProps: { radius: 'sm', tt: 'none', variant: 'light' }, classNames: { root: classes.badge, label: classes.badgeLabel } }),
      Button: Button.extend({ defaultProps: { radius: 'sm' }, classNames: { root: classes.button } }),
      Card: Card.extend({ defaultProps: { radius: 'md' }, classNames: { root: classes.panel } }),
      Paper: Paper.extend({ defaultProps: { radius: 'md' }, classNames: { root: classes.panel } }),
      Code: Code.extend({ classNames: { root: classes.code } }),
      Modal: Modal.extend({
        defaultProps: { radius: 'lg', overlayProps: { blur: 3 } },
        classNames: { content: classes.dialog, header: classes.dialogHeader, title: classes.dialogTitle, body: classes.dialogBody, overlay: classes.dialogOverlay },
      }),
      Table: Table.extend({ classNames: { table: classes.table } }),
      // The design's tables mark header cells as column headers; a row header passes scope="row" itself.
      TableTh: TableTh.extend({ defaultProps: { scope: 'col' } }),
      Tabs: Tabs.extend({ classNames: { list: classes.tabsList, tab: classes.tab } }),
      Title: Title.extend({ classNames: { root: classes.title } }),
      Input: Input.extend({ classNames: { input: classes.input } }),
      // The real input of a password field fills a wrapper that clips its overflow; the wrapper draws the focus ring.
      PasswordInput: PasswordInput.extend({ classNames: { innerInput: classes.passwordInnerInput } }),
      InputWrapper: InputWrapper.extend({ classNames: { label: classes.inputLabel, description: classes.inputDescription } }),
      // Checked choices draw their check, dot and thumb in the design's colors (mantine.module.css), in both schemes.
      Checkbox: Checkbox.extend({ classNames: { root: classes.checkbox, input: classes.checkboxInput } }),
      Radio: Radio.extend({ classNames: { root: classes.radio, radio: classes.radioInput } }),
      // The design's .segmented: a subtle track with a border, the active segment on the surface.
      SegmentedControl: SegmentedControl.extend({ classNames: { root: classes.segmented, indicator: classes.segmentedIndicator, label: classes.segmentedLabel } }),
      Switch: Switch.extend({ classNames: { input: classes.switchInput, track: classes.switchTrack, thumb: classes.switchThumb } }),
      // A table that scrolls sideways on a narrow screen must be reachable with the keyboard (axe
      // scrollable-region-focusable); a table without a link or button in it has nothing else to focus.
      // The stop is a named group (not a landmark) with a focus ring drawn inside it (theme.css).
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
