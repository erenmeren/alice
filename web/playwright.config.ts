import { defineConfig, devices } from '@playwright/test';

// The host port is ALICE_PORT (deploy/.env); ALICE_BASE_URL overrides everything.
const port = process.env.ALICE_PORT ?? '443';
const baseURL = process.env.ALICE_BASE_URL ?? (port === '443' ? 'https://localhost' : `https://localhost:${port}`);

export default defineConfig({
  testDir: './e2e',
  retries: process.env.CI ? 1 : 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL,
    ignoreHTTPSErrors: true, // the Phase 0 stack uses a temporary self-signed certificate
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
