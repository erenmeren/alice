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
    // make web-coverage (npm run coverage) enforces the thresholds (AUD-23). Spec §22.7 asks for
    // 70 %; they are the values measured when they were set (2026-10-04: statements 93.99, branches
    // 90.98-91.03, functions 93.96, lines 95.55), rounded down; branches one point lower, because
    // one timing-dependent branch is not taken in every run. Raise them, never lower them.
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.test.{ts,tsx}', 'src/test/**'],
      reporter: ['text-summary'],
      thresholds: { statements: 93, branches: 90, functions: 93, lines: 95 },
    },
  },
});
