import { defineConfig, devices } from '@playwright/test';

// The e2e stack (project alice-e2e) publishes ALICE_E2E_PORT (default 9443, deploy/docker-compose.e2e.yml),
// never ALICE_PORT, so it runs beside the make up stack. ALICE_BASE_URL overrides everything.
const port = process.env.ALICE_E2E_PORT || '9443';
const baseURL = process.env.ALICE_BASE_URL ?? `https://localhost:${port}`;

export default defineConfig({
  testDir: './e2e',
  // Every test resets the one shared server (POST /test/reset), so tests must never overlap.
  workers: 1,
  fullyParallel: false,
  timeout: 180_000,
  expect: { timeout: 15_000 },
  // One retry, locally and in CI, that the networkChangeGuard fixture in e2e/helpers.ts lets run only
  // when the failed attempt saw Chromium abort requests with net::ERR_NETWORK_CHANGED (a host network
  // change; docs/dev/getting-started.md); any other failure fails its retry at once with that reason,
  // so a real flake is never hidden.
  retries: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL,
    ignoreHTTPSErrors: true, // the stack uses a temporary self-signed certificate
    trace: 'retain-on-failure',
  },
  // make e2e runs Chromium only (--project=chromium); make e2e-browsers runs every spec on all three
  // (nightly and release, spec §22.7; WebKit needs its system libraries: npx playwright install --with-deps).
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
