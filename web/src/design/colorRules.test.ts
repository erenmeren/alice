import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

// Both color schemes draw from the semantic tokens (tokens.css, mapped onto Mantine by theme.ts). This guard keeps the
// colors that look right in one scheme only (a palette shade, black or white text, a literal color) out of the
// components; the ESLint rule in eslint.config.js catches the c="…" cases while editing.

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : [path];
  });
}

const SOURCES = files('src').filter((f) => /\.(tsx?|css)$/.test(f) && !/\.test\.tsx?$/.test(f) && !f.startsWith(join('src', 'test')));

// The only places that may hold a literal color, each limited to the lines that need it:
const LITERAL_ALLOWED: { file: string; line: RegExp; why: string }[] = [
  { file: 'src/design/tokens.css', line: /./, why: 'the tokens themselves, light and dark' },
  { file: 'src/theme.ts', line: /^const forest: MantineColorsTuple = /, why: "the design's forest accent as Mantine's palette" },
  { file: 'src/design/mantine.module.css', line: /^\[data-mantine-color-scheme\] \.dialog \{/, why: "the design's dialog shadow" },
  { file: 'src/components/ui/ui.module.css', line: /^\.miniApp\b/, why: 'the appearance previews draw each mode as it looks, whatever the active scheme' },
  { file: 'src/components/auth/auth.module.css', line: /^\.qrTile \{/, why: 'authenticator apps scan dark on light: the TOTP QR tile stays white in both schemes' },
].map((a) => ({ ...a, file: join(...a.file.split('/')) }));

const literalAllowed = (f: string, line: string) => LITERAL_ALLOWED.some((a) => a.file === f && a.line.test(line));

const HEX = /(?<![\w&-])#[0-9a-fA-F]{6}(?:[0-9a-fA-F]{2})?\b|(?<![\w&-])#[0-9a-fA-F]{3}\b(?![\w-])/;

// [name, pattern, literal: true if LITERAL_ALLOWED applies]
const RULES: [string, RegExp, boolean][] = [
  ['c="black" or c="white"', /\bc=["'{]+(black|white)["'}]/, false],
  ['a palette shade as a text color (c="gray.7")', /\bc=["'{]+[a-z]+\.\d["'}]/, false],
  ['a palette shade as a component color (color="red.9")', /\bcolor=["'{]+[a-z]+\.\d["'}]/, false],
  ['a palette shade variable', /var\(--mantine-color-(?:[a-z]+-\d|white|black)\)/, false],
  ['a color in an inline style', /style=\{[^}]*\b(?:color|background|backgroundColor|border(?:Top|Bottom|Left|Right)?(?:Color)?|outlineColor|fill|stroke)\s*:[^}]*(?:#|var\(|rgb|hsl|\b(?:black|white|red|gray)\b)/, false],
  ['a literal hex color', HEX, true],
  ['an rgb() or hsl() color', /\b(?:rgba?|hsla?)\(/, true],
  ['a named black or white in CSS', /(?:color|background(?:-color)?|border(?:-[a-z]+)?|fill|stroke)\s*:[^;]*\b(?:black|white)\b/, true],
];

// isComment skips comment lines: the rules are about what is drawn, not what is explained.
const isComment = (line: string) => /^\s*(\/\/|\*|\/\*)/.test(line);

function hits(re: RegExp, literal: boolean): string[] {
  return SOURCES.flatMap((f) => readFileSync(f, 'utf8').split('\n').map((line, i) => ({ f, n: i + 1, line })))
    .filter(({ f, line }) => re.test(line) && !isComment(line) && !(literal && literalAllowed(f, line)))
    .map(({ f, n, line }) => `${f}:${n}: ${line.trim()}`);
}

describe('no hard-coded colors (both schemes draw from the tokens)', () => {
  it.each(RULES)('has no %s', (_name, re, literal) => {
    expect(hits(re, literal)).toEqual([]);
  });

  it('keeps every allowance in use, so the list cannot hide new colors behind a stale entry', () => {
    for (const a of LITERAL_ALLOWED) {
      const lines = readFileSync(a.file, 'utf8').split('\n').filter((l) => a.line.test(l));
      expect(lines.some((l) => HEX.test(l)), `${a.file}: ${a.why}`).toBe(true);
    }
  });

  it('keeps the QR tile white in both schemes', () => {
    const auth = readFileSync(join('src', 'components', 'auth', 'auth.module.css'), 'utf8');
    expect(auth).toMatch(/^\.qrTile \{[^}]*background: #ffffff;/m);
  });

  // The guard itself: each rule catches what it is for, so a broken pattern cannot pass silently.
  it.each([
    ['<Text c="gray.7">', 1],
    ['<Anchor c="black" fw={600}>', 0],
    ["<Progress color='red.9' />", 2],
    ['border: 1px solid var(--mantine-color-gray-4);', 3],
    ["<p style={{ color: 'var(--alice-danger)' }}>", 4],
    ["<Box style={{ borderTop: '1px solid var(--alice-border)' }}>", 4],
    ["<Box style={bad ? { border: '2px solid var(--alice-danger)' } : undefined}>", 4],
    ['.x { background: #1b2b27; }', 5],
    ['.x { color: rgb(0 0 0); }', 6],
    ['.x { color: white; }', 7],
  ] as const)('catches %s', (line, rule) => {
    expect(RULES[rule][1].test(line)).toBe(true);
  });

  it.each([
    '<Text c="dimmed">',
    '<Text c="var(--alice-danger)">',
    '<Anchor c="inherit" fw={600}>',
    '<Alert color="red">',
    "<Box style={{ overflowWrap: 'anywhere' }}>",
    '.x { color: var(--alice-text); }',
    '<a href="#main">',
    '&#x2192;',
  ])('lets %s through', (line) => {
    expect(RULES.filter(([, re]) => re.test(line)).map(([name]) => name)).toEqual([]);
  });
});
