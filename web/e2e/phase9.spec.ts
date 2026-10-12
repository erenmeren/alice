import type { APIRequestContext, Page } from '@playwright/test';
import {
  ADMIN,
  apiAs,
  azureReset,
  browserLocale,
  drainJobs,
  expect,
  expectAccessibleAt,
  resetInstall,
  runWizard,
  seedDashboard,
  signIn,
  signOut,
  test,
  translator,
  type Lang,
} from './helpers';

// Phase 9 (the Clarity design): every primary route at the design's four widths, in both color schemes and both
// languages (alice-design/IMPLEMENTATION.md acceptance checks 1-3 and 7): no serious or critical axe finding, no
// horizontal page scroll, no status badge cut off and no focus ring cut off by a clipping container. Soft assertions
// list every finding of a run instead of stopping at the first.
const WIDTHS = [390, 768, 1024, 1440] as const;
const ROUTES = [
  '/', '/?view=assurance', '/certificates', '/ssh-keys', '/servers', '/key-vaults', '/deployments', '/rotations',
  '/audit', '/users', '/license', '/account', '/tokens',
] as const;
const SETTINGS = ['mail', 'recipients', 'alerts', 'general', 'backups', 'https', 'forwarding', 'sso'] as const;

async function applyScheme(page: Page, scheme: 'light' | 'dark'): Promise<void> {
  await page.emulateMedia({ colorScheme: scheme });
  await page.evaluate((s) => localStorage.setItem('alice.colorScheme', s), scheme);
}

// saveLanguage saves the account's language, which the app applies at the next page load.
async function saveLanguage(page: Page, lang: Lang): Promise<void> {
  const api = await apiAs(page);
  const res = await api.put('/api/v1/auth/locale', { locale: lang });
  expect(res.ok(), await res.text()).toBe(true);
}

async function firstDetail(page: Page, list: string, prefix: string): Promise<string | null> {
  await page.goto(list);
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  const link = page.getByRole('main').locator(`a[href^="${prefix}"]`).first();
  return (await link.count()) > 0 ? link.getAttribute('href') : null;
}

// clippedFocusRings focuses every visible, enabled, keyboard-reachable control (after a Tab press, so the browser is
// in keyboard modality and :focus-visible applies) and reports the controls whose focus outline would be cut off by
// an ancestor that clips its overflow. A control that is itself partly outside such an ancestor (scrolled out of a
// table's scroll region, an off-canvas menu) is not judged: its ring is not the problem there.
async function clippedFocusRings(page: Page): Promise<string[]> {
  await page.keyboard.press('Tab');
  const found = await page.evaluate(() => {
    const selector =
      'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    const describe = (el: Element): string => {
      const name = (el.getAttribute('aria-label') ?? el.textContent ?? '').trim().replace(/\s+/g, ' ').slice(0, 40);
      const cls = typeof el.className === 'string' ? el.className.split(' ').filter(Boolean).slice(0, 2).join('.') : '';
      return `${el.tagName.toLocaleLowerCase('en')}${cls ? `.${cls}` : ''} "${name}"`;
    };
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(selector))) {
      if (el.closest('[inert], [aria-hidden="true"]')) continue;
      const box = el.getBoundingClientRect();
      if (box.width === 0 || box.height === 0) continue;
      const own = getComputedStyle(el);
      if (own.visibility === 'hidden' || own.display === 'none' || Number(own.opacity) === 0) continue;
      el.focus({ preventScroll: true });
      if (document.activeElement !== el) continue;
      const style = getComputedStyle(el);
      const width = style.outlineStyle === 'none' ? 0 : parseFloat(style.outlineWidth) || 0;
      const reach = width + (parseFloat(style.outlineOffset) || 0);
      if (width === 0 || reach <= 0) continue; // no ring, or a ring drawn inside the control
      for (let a = el.parentElement; a && a !== document.body; a = a.parentElement) {
        const s = getComputedStyle(a);
        if (s.overflowX === 'visible' && s.overflowY === 'visible') continue;
        const r = a.getBoundingClientRect();
        const clip = {
          left: r.left + a.clientLeft,
          top: r.top + a.clientTop,
          right: r.left + a.clientLeft + a.clientWidth,
          bottom: r.top + a.clientTop + a.clientHeight,
        };
        const inside = box.left >= clip.left - 0.5 && box.right <= clip.right + 0.5 && box.top >= clip.top - 0.5 && box.bottom <= clip.bottom + 0.5;
        if (!inside) break; // the control itself is cut off (scrolled away or off-canvas): not a ring problem
        // Along an axis the ancestor really scrolls, a control next to the edge is a question of the scroll position
        // (the sidebar's last link at the bottom of a short window), not of the layout: only fixed clipping counts.
        const scrollsX = /auto|scroll/.test(s.overflowX) && a.scrollWidth > a.clientWidth;
        const scrollsY = /auto|scroll/.test(s.overflowY) && a.scrollHeight > a.clientHeight;
        const cut =
          (s.overflowX !== 'visible' && !scrollsX && (box.left - reach < clip.left - 0.5 || box.right + reach > clip.right + 0.5)) ||
          (s.overflowY !== 'visible' && !scrollsY && (box.top - reach < clip.top - 0.5 || box.bottom + reach > clip.bottom + 0.5));
        if (cut) {
          const at = (b: { left: number; top: number; right: number; bottom: number }) => [b.left, b.top, b.right, b.bottom].map(Math.round).join(',');
          out.push(`${describe(el)} [${at(box)}] in ${describe(a).split(' "')[0]} [${at(clip)}] reach ${reach}`);
          break;
        }
      }
    }
    (document.activeElement as HTMLElement | null)?.blur();
    return out;
  });
  return [...new Set(found)];
}

// truncatedBadges lists the status badges whose text is cut off (Mantine's badge label is one line with an
// ellipsis): a long Turkish state such as "Dağıtıldı: sürüm …" must stay readable at every width.
async function truncatedBadges(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLElement>('.mantine-Badge-label'))
      .filter((l) => l.getClientRects().length > 0 && l.scrollWidth > l.clientWidth + 1)
      .map((l) => `"${(l.textContent ?? '').trim()}" (${l.clientWidth} of ${l.scrollWidth} px)`),
  );
}

// scanLayout checks, at every width, the geometry axe does not judge: no badge text cut off and no focus ring cut
// off by a clipping container. Both are independent of the color scheme.
async function scanLayout(page: Page, label: string): Promise<void> {
  const original = page.viewportSize();
  try {
    for (const width of WIDTHS) {
      await page.setViewportSize({ width, height: original?.height ?? 720 });
      expect.soft(await truncatedBadges(page), `truncated badge: ${label} at ${width} px`).toEqual([]);
      expect.soft(await clippedFocusRings(page), `clipped focus ring: ${label} at ${width} px`).toEqual([]);
    }
  } finally {
    if (original) await page.setViewportSize(original);
  }
}

// scanRoute opens a route and checks it at every width. The scheme and language are asserted first, so a scan can
// never pass in the wrong scheme or language.
async function scanRoute(page: Page, path: string, label: string, expected: { scheme: 'light' | 'dark'; lang: Lang; layout: boolean }): Promise<void> {
  await page.goto(path);
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('data-mantine-color-scheme', expected.scheme);
  await expect(page.locator('html')).toHaveAttribute('lang', expected.lang);
  await expectAccessibleAt(page, label, WIDTHS, { soft: true });
  if (expected.layout) await scanLayout(page, label);
}

// scanOverlays checks the shell's two overlays: the attention bell's popover and the page palette.
async function scanOverlays(page: Page, lang: Lang, label: string): Promise<void> {
  const t = translator(lang);
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await page.getByRole('button', { name: t('shell.attention.open'), exact: true }).click();
  await expect(page.getByText(t('shell.attention.overview'), { exact: true })).toBeVisible();
  await expectAccessibleAt(page, `attention popover ${label}`, WIDTHS, { soft: true });
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: t('shell.search.open'), exact: true }).click();
  const palette = page.getByRole('dialog', { name: t('shell.search.title') });
  await expectAccessibleAt(page, `page palette ${label}`, WIDTHS, { soft: true, dialog: palette });
  await page.keyboard.press('Escape');
  await expect(palette).toHaveCount(0);
}

// install sets Alice up with the dashboard's seeded data set (servers, certificates, deployments) plus the fake Azure
// service's Key Vault (first poll drained), so the vault and Key Vault certificate pages have content too.
async function install(page: Page, request: APIRequestContext, lang: Lang): Promise<string> {
  await resetInstall(request);
  const { totpSecret } = await runWizard(page, request, lang);
  await seedDashboard(request);
  const creds = azureReset();
  const api = await apiAs(page);
  await api.stepUp(totpSecret);
  const res = await api.post('/api/v1/key-vaults', {
    name: 'phase9-vault',
    vault_url: creds.vault_url,
    auth: 'client_secret',
    tenant_id: creds.tenant_id,
    client_id: creds.client_id,
    client_secret: creds.client_secret,
  });
  expect(res.status(), await res.text()).toBe(201);
  await drainJobs(request);
  await page.reload();
  return totpSecret;
}

for (const lang of ['en', 'tr'] as Lang[]) {
  test.describe(`Phase 9 design (${lang})`, () => {
    test.use({ locale: browserLocale(lang) });

    test(`every route in light and dark at 390/768/1024/1440 px (${lang})`, async ({ page, request }) => {
      test.setTimeout(30 * 60_000);
      const totpSecret = await install(page, request, lang);
      await saveLanguage(page, lang);
      const details = [
        await firstDetail(page, '/certificates', '/certificates/'),
        await firstDetail(page, '/servers', '/servers/'),
        await firstDetail(page, '/deployments', '/deployments/'),
        await firstDetail(page, '/ssh-keys', '/ssh-keys/'),
        await firstDetail(page, '/rotations', '/rotation/runs/'),
      ].filter((p): p is string => p !== null);
      const vault = await firstDetail(page, '/key-vaults', '/key-vaults/');
      expect(vault, 'the Key Vault added by install').not.toBeNull();
      details.push(vault!);
      const kvCertificate = await firstDetail(page, vault!, `${vault}/certificates/`);
      if (kvCertificate) details.push(kvCertificate);
      test.info().annotations.push({ type: 'detail pages scanned', description: details.join(' ') });
      console.log(`detail pages scanned (${lang}): ${details.join(' ')}`);
      for (const scheme of ['light', 'dark'] as const) {
        await applyScheme(page, scheme);
        // Badge widths and focus-ring geometry do not depend on the color scheme: checked once, in the light scheme.
        const layout = scheme === 'light';
        for (const path of [...ROUTES, ...details]) await scanRoute(page, path, `${path} ${scheme} ${lang}`, { scheme, lang, layout });
        await scanOverlays(page, lang, `${scheme} ${lang}`);
        // Settings reads need a fresh step-up (5 minutes): renew it right before the tabs.
        await (await apiAs(page)).stepUp(totpSecret);
        for (const tab of SETTINGS) await scanRoute(page, `/settings?tab=${tab}`, `settings ${tab} ${scheme} ${lang}`, { scheme, lang, layout });
      }
    });

    test(`sign-in and the wizard in the dark scheme (${lang})`, async ({ page, request }) => {
      test.setTimeout(15 * 60_000);
      await page.addInitScript(() => localStorage.setItem('alice.colorScheme', 'dark'));
      await page.emulateMedia({ colorScheme: 'dark' });
      await resetInstall(request);
      const { totpSecret } = await runWizard(page, request, lang, ADMIN, { a11y: true });
      await signOut(page);
      await expect(page.getByRole('heading', { level: 1, name: translator(lang)('login.title') })).toBeVisible();
      await expect(page.locator('html')).toHaveAttribute('data-mantine-color-scheme', 'dark');
      await expectAccessibleAt(page, `login dark ${lang}`, WIDTHS, { soft: true });
      await scanLayout(page, `login ${lang}`);
      await signIn(page, request, ADMIN, totpSecret);
    });
  });
}
