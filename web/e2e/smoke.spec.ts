import type { Page } from '@playwright/test';
import { COPY, expect, resetInstall, test } from './helpers';

function collectProblems(page: Page): string[] {
  const problems: string[] = [];
  page.on('console', (m) => {
    if (m.type() !== 'error') return;
    // A signed-out app gets 401 from /api/v1/auth/session; Chromium logs exactly that as a failed resource.
    const expected401 =
      m.text().startsWith('Failed to load resource') && m.text().includes('401') && m.location().url.endsWith('/api/v1/auth/session');
    if (!expected401) problems.push(`${m.text()} (${m.location().url})`);
  });
  page.on('pageerror', (e) => problems.push(e.message));
  return problems;
}

test.beforeEach(async ({ request }) => {
  await resetInstall(request);
});

test('a fresh install lands on the setup wizard without CSP or script errors', async ({ page }) => {
  const problems = collectProblems(page);
  await page.goto('/');
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByRole('heading', { name: COPY.en.wizardHeading })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  expect(problems.filter((p) => /Content Security Policy/i.test(p))).toEqual([]);
  expect(problems).toEqual([]);
});

test.describe('Turkish browser', () => {
  test.use({ locale: 'tr-TR' });
  test('first visit is in Turkish', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: COPY.tr.wizardHeading })).toBeVisible();
    await expect(page.locator('html')).toHaveAttribute('lang', 'tr');
  });
});

test('deep links (also with a dot) load the app and unknown API paths return JSON errors', async ({ page, request }) => {
  // The server answers with the SPA (200), not a 404, even with a dot in the last segment;
  // /users/a.b is not a client route, so the app itself shows its "Page not found" screen.
  const deep = await page.goto('/users/a.b');
  expect(deep?.status()).toBe(200);
  await expect(page.getByRole('heading', { name: 'Page not found' })).toBeVisible();

  const res = await request.get('/api/v1/nope', { headers: { 'Accept-Language': 'tr' } });
  expect(res.status()).toBe(404);
  const body = await res.json();
  expect(body.error.code).toBe('ALC-SYS-0001');
  expect(body.error.message).toContain('bulunamadı');
});

test('security headers are present', async ({ request }) => {
  const res = await request.get('/');
  const h = res.headers();
  expect(h['content-security-policy']).toMatch(/style-src 'self' 'nonce-[A-Za-z0-9+/=]+'/);
  expect(h['strict-transport-security']).toBe('max-age=31536000; includeSubDomains');
  expect(h['x-frame-options']).toBe('DENY');
});

test('the session cookie is never readable by scripts', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: COPY.en.wizardHeading })).toBeVisible();
  expect(await page.evaluate(() => document.cookie)).not.toContain('alice');
});

test('the test clock only moves forward', async ({ request }) => {
  const back = await request.post('/test/clock', { data: { advance_seconds: -1 } });
  expect(back.status()).toBe(422);
  const tooFar = await request.post('/test/clock', { data: { advance_seconds: 10 * 365 * 24 * 3600 + 1 } });
  expect(tooFar.status()).toBe(422);
});
