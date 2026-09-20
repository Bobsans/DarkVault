import { defineConfig } from '@playwright/test';
export default defineConfig({ testDir: './e2e', workers: 1, use: { baseURL: 'https://localhost:18866', ignoreHTTPSErrors: true }, reporter: 'list' });
