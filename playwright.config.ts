import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: 'tests',
  timeout: 60_000,
  fullyParallel: true,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
    video: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: [
    {
      command: 'cd apps/mock-idp && npm run dev',
      port: 4000,
      timeout: 120_000,
      reuseExistingServer: !process.env.CI,
    },
    {
      command: 'cd apps/gw && npm run dev',
      port: 3000,
      timeout: 120_000,
      reuseExistingServer: !process.env.CI,
      env: {
        GW_BASE_URL: 'http://localhost:3000',
        LOCAL_USER: 'admin',
        LOCAL_PASSWORD: 'secret',
        UPSTREAM_AUTHORIZATION_ENDPOINT: 'http://localhost:4000/authorize',
        UPSTREAM_TOKEN_ENDPOINT: 'http://localhost:4000/token',
        UPSTREAM_CLIENT_ID: 'gw-local',
        UPSTREAM_CLIENT_SECRET: '',
        UPSTREAM_SCOPES: 'openid profile',
        REDIRECT_URI: 'http://localhost:3000/oauth/callback',
        SESSION_SECRET: 'dev-session-secret-change-me',
        TOKEN_ENCRYPTION_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'.slice(0,64),
        UPSTREAM_API_BASE: 'http://localhost:4000',
        SSE_HEARTBEAT_MS: '12000'
      },
    },
  ],
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } }
  ],
});

