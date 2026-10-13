import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { expect, test, type Page } from '@playwright/test';
import { ADMIN, apiAs, browserLocale, resetInstall, runWizard, seedDashboard, signOut, type Lang } from './helpers';

// Visual evidence for the owner's review of the Clarity design (Phase 9, Task 19): screenshots of every primary route
// and every wizard screen in light and dark, English and Turkish, at 1440/1024/768/390 px, written to
// bin/design-evidence (git-ignored, never committed) with an index.html contact sheet. Opt-in: make e2e-design-evidence.
test.skip(!process.env.ALICE_DESIGN_EVIDENCE, 'set ALICE_DESIGN_EVIDENCE=1 (make e2e-design-evidence)');

const OUT = resolve(process.cwd(), '../bin/design-evidence');
const WIDTHS = [1440, 1024, 768, 390] as const;
const ROUTES: [string, string][] = [
  ['overview', '/'], ['assurance', '/?view=assurance'], ['certificates', '/certificates'], ['issued-certificates', '/acme'], ['ssh-keys', '/ssh-keys'],
  ['servers', '/servers'], ['key-vaults', '/key-vaults'], ['deployments', '/deployments'], ['rotations', '/rotations'],
  ['audit', '/audit'], ['people', '/users'], ['license', '/license'], ['account', '/account'], ['tokens', '/tokens'],
  ...(['mail', 'recipients', 'alerts', 'general', 'backups', 'https', 'acme', 'forwarding', 'sso'] as const).map((tab): [string, string] => [`settings-${tab}`, `/settings?tab=${tab}`]),
];
const shots: string[] = [];

// A screenshot never carries a secret: the authenticator seed and QR code, the recovery codes and any one-time value
// are painted over (the instance is a throw-away e2e install, but the pictures are shared for review).
const SECRET = '[data-testid="totp-secret"], [data-testid="recovery-codes"], img[src^="data:image/png"], [data-testid*="token"], [data-testid*="secret"]';

async function shoot(page: Page, dir: string, name: string): Promise<void> {
  const original = page.viewportSize();
  for (const width of WIDTHS) {
    await page.setViewportSize({ width, height: 900 });
    await page.evaluate(() => document.fonts.ready);
    const file = join(OUT, dir, String(width), `${name}.png`);
    mkdirSync(dirname(file), { recursive: true });
    await page.screenshot({ path: file, fullPage: true, animations: 'disabled', mask: [page.locator(SECRET)] });
    shots.push(relative(OUT, file));
  }
  if (original) await page.setViewportSize(original);
}

async function scheme(page: Page, s: 'light' | 'dark'): Promise<void> {
  await page.emulateMedia({ colorScheme: s });
  await page.addInitScript((v) => localStorage.setItem('alice.colorScheme', v), s);
}

test.afterAll(() => {
  if (shots.length === 0) return;
  mkdirSync(OUT, { recursive: true });
  const rows = shots.map((s) => `<figure><img loading="lazy" src="${s}" alt=""><figcaption>${s}</figcaption></figure>`).join('\n');
  writeFileSync(join(OUT, 'index.html'), `<!doctype html><meta charset="utf-8"><title>Alice design evidence</title><style>body{font:13px system-ui;margin:24px}figure{display:inline-block;margin:8px;width:360px;vertical-align:top}img{width:100%;border:1px solid #ccc}</style>\n${rows}\n`);
});

for (const lang of ['en', 'tr'] as Lang[]) {
  for (const s of ['light', 'dark'] as const) {
    test.describe(`${lang} ${s}`, () => {
    test.use({ locale: browserLocale(lang) });
    test(`evidence ${lang} ${s}`, async ({ page, request }) => {
      test.setTimeout(45 * 60_000);
      const dir = `${lang}-${s}`;
      await scheme(page, s);
      await resetInstall(request);
      const { totpSecret } = await runWizard(page, request, lang, ADMIN, { onScreen: (name) => shoot(page, dir, name.replace(/\s+/g, '-')) });
      await seedDashboard(request);
      await (await apiAs(page)).stepUp(totpSecret);
      for (const [name, path] of ROUTES) {
        await page.goto(path);
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
        await shoot(page, dir, name);
      }
      for (const [list, prefix, name] of [['/certificates', '/certificates/', 'certificate-detail'], ['/servers', '/servers/', 'server-detail'], ['/deployments', '/deployments/', 'deployment-detail']] as const) {
        await page.goto(list);
        const link = page.getByRole('main').locator(`a[href^="${prefix}"]`).first();
        await link.waitFor({ timeout: 10_000 }).catch(() => undefined); // the list loads after the heading
        if ((await link.count()) === 0) continue;
        await page.goto((await link.getAttribute('href'))!);
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
        await shoot(page, dir, name);
      }
      await signOut(page);
      await shoot(page, dir, 'sign-in');
    });
    });
  }
}
