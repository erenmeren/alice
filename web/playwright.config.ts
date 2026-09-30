import { defineConfig, devices } from '@playwright/test';

// The host port is ALICE_PORT (deploy/.env); ALICE_BASE_URL overrides everything.
const port = process.env.ALICE_PORT ?? '443';
const baseURL = process.env.ALICE_BASE_URL ?? (port === '443' ? 'https://localhost' : `https://localhost:${port}`);

export default defineConfig({
  testDir: './e2e',
  // Every test resets the one shared server (POST /test/reset), so tests must never overlap.
  workers: 1,
  fullyParallel: false,
  timeout: 180_000,
  expect: { timeout: 15_000 },
  retries: process.env.CI ? 1 : 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL,
    ignoreHTTPSErrors: true, // the stack uses a temporary self-signed certificate
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
