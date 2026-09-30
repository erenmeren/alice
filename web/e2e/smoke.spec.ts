import AxeBuilder from '@axe-core/playwright';
import { test, expect, type Page } from '@playwright/test';

const EN_HEADING = 'Welcome to Alice';
const TR_HEADING = "Alice'e hoş geldiniz";

function collectProblems(page: Page): string[] {
  const problems: string[] = [];
  page.on('console', (m) => {
    if (m.type() === 'error') problems.push(m.text());
  });
  page.on('pageerror', (e) => problems.push(e.message));
  return problems;
}

async function seriousViolations(page: Page) {
  const results = await new AxeBuilder({ page }).analyze();
  return results.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => `${v.impact}: ${v.id} (${v.nodes.map((n) => n.target.join(' ')).join(', ')})`);
}

test('home page loads in English, switches to Turkish, and violates no CSP rule', async ({ page }) => {
  const problems = collectProblems(page);
  await page.goto('/');
  await expect(page.getByRole('heading', { name: EN_HEADING })).toBeVisible();
  await expect(page.getByTestId('server-status')).toContainText('Server version');

  await page.getByText('Türkçe').click();
  await expect(page.getByRole('heading', { name: TR_HEADING })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'tr');
  await expect(page.getByTestId('server-status')).toContainText('Sunucu sürümü');

  await page.reload();
  await expect(page.getByRole('heading', { name: TR_HEADING })).toBeVisible();

  expect(problems.filter((p) => /Content Security Policy/i.test(p))).toEqual([]);
  expect(problems).toEqual([]);
});

test('switching back to English after Turkish works and persists', async ({ page }) => {
  await page.goto('/');
  await page.getByText('Türkçe').click();
  await expect(page.getByRole('heading', { name: TR_HEADING })).toBeVisible();

  await page.getByText('English').click();
  await expect(page.getByRole('heading', { name: EN_HEADING })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.getByTestId('server-status')).toContainText('Server version');

  await page.reload();
  await expect(page.getByRole('heading', { name: EN_HEADING })).toBeVisible();
});

test.describe('Turkish browser', () => {
  test.use({ locale: 'tr-TR' });
  test('first visit is in Turkish', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: TR_HEADING })).toBeVisible();
  });
});

test('deep links load the app and unknown API paths return JSON errors', async ({ page, request }) => {
  await page.goto('/users/5');
  await expect(page.getByRole('heading', { name: EN_HEADING })).toBeVisible();

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

test.describe('accessibility', () => {
  test('home page has no serious or critical violations in English', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByTestId('server-status')).toContainText('Server version');
    expect(await seriousViolations(page)).toEqual([]);
  });

  test('home page has no serious or critical violations in Turkish', async ({ page }) => {
    await page.goto('/');
    await page.getByText('Türkçe').click();
    await expect(page.getByTestId('server-status')).toContainText('Sunucu sürümü');
    expect(await seriousViolations(page)).toEqual([]);
  });
});
