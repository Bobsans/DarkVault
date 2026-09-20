import { defineConfig } from '@playwright/test';
export default defineConfig({ testDir: './e2e', workers: 1, use: { baseURL: 'https://127.0.0.1:18866', ignoreHTTPSErrors: true }, reporter: 'list' });
