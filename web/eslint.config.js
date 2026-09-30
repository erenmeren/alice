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
      ],
    },
  },
);
