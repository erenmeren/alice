/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

const locales = fileURLToPath(new URL('../locales', import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@locales': locales } },
  server: { fs: { allow: ['..'] } },
  build: {
    outDir: '../internal/webui/dist/app',
    emptyOutDir: true,
    assetsInlineLimit: 0, // CSP: no data: fonts or inline assets
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    // A few page tests render a long form and take about 5 s under `make coverage` with 144 test
    // files running in parallel (AcmeCertificatePage 'deploys now' took 5.1-6.8 s): the default
    // 5 s test timeout made `make ci` flaky. Passing tests are not slower; only hangs wait longer.
    testTimeout: 20_000,
    // make web-coverage (npm run coverage) enforces the thresholds (AUD-23). Spec §22.7 asks for
    // 70 %; they are the values measured when they were set (2026-10-16: statements 96.21, branches
    // 92.61, functions 95.82, lines 97.33), rounded down; branches one point lower, because
    // one timing-dependent branch is not taken in every run. Raise them, never lower them.
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.test.{ts,tsx}', 'src/test/**'],
      reporter: ['text-summary'],
      thresholds: { statements: 96, branches: 91, functions: 95, lines: 97 },
    },
  },
});
