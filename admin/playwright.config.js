import { defineConfig } from '@playwright/test';
// Chromium cannot be given the acceptance CA, so E2E accepts the local certificate;
// strict chain and hostname verification is covered by tls.test.js.
export default defineConfig({ testDir: './e2e', workers: 1, use: { baseURL: 'https://localhost:18866', ignoreHTTPSErrors: true }, reporter: 'list' });
