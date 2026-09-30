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
  },
});
