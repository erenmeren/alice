import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';

export default tseslint.config(
  { ignores: ['node_modules', 'playwright-report', 'test-results'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { files: ['**/*.cjs'], languageOptions: { sourceType: 'commonjs', globals: globals.node } },
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'no-restricted-syntax': [
        'error',
        { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: 'dangerouslySetInnerHTML is forbidden (XSS, SEC-035).' },
        { selector: "CallExpression[callee.property.name=/^to(Upper|Lower)Case$/]", message: 'Use toLocaleUpperCase/toLocaleLowerCase with the active locale for user-visible text (Turkish dotted/dotless i).' },
        { selector: "JSXAttribute[name.name='c'][value.value=/^(black|white|[a-z]+\\.[0-9])$/]", message: 'Use a semantic color (c="dimmed", c="var(--alice-…)"): a palette shade fails in the dark scheme (Phase 9).' },
        { selector: "JSXAttribute[name.name='color'][value.value=/^[a-z]+\\.[0-9]$/]", message: 'Use the tone\'s color name (color="red") or a token: the theme maps names, not palette shades, onto both schemes (Phase 9).' },
        { selector: "JSXAttribute[name.name='style'] Property[key.name=/^(color|background|backgroundColor|border|borderColor|borderTop|borderRight|borderBottom|borderLeft|outline|outlineColor|fill|stroke)$/] Literal[value=/#|var\\(|rgb|hsl|\\b(black|white)\\b/]", message: 'Put colors in a CSS module that reads the --alice-* tokens, not in an inline style (Phase 9, colorRules.test.ts).' },
      ],
    },
  },
);
