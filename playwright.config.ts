import { defineConfig, devices } from '@playwright/test';
import { CERT_FILE, KEY_FILE, SITE_DIR, ensureCert, ensureSite } from './tests/e2e/global-setup';

// Playwright starts `webServer` BEFORE running globalSetup, and the server needs
// both the self-signed cert and the staged _site to exist (its health check
// hits /index.html).  So prepare them eagerly here, at config-module load time,
// which runs before everything.  Both are idempotent.
ensureCert();
ensureSite();

// Port for the local HTTPS static server.  The page origin is
// https://wklm.online:PORT — Chromium maps wklm.online -> 127.0.0.1 (see
// --host-resolver-rules below) so the WebAuthn RP id `wklm.online` matches and
// the origin is a secure context (HTTPS), which WebCrypto/WebAuthn require.
const PORT = Number(process.env.PORT || 8443);
const RP_HOST = 'wklm.online';
const BASE_URL = `https://${RP_HOST}:${PORT}`;

export default defineConfig({
  testDir: './tests/e2e',
  // The round-trip drives Docker (encrypt + re-render) mid-test; give it room.
  timeout: 180_000,
  expect: { timeout: 30_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never', outputFolder: 'tests/e2e/playwright-report' }]],
  // Cert + _site are prepared eagerly at config-module load (above) because
  // webServer starts before globalSetup; no separate globalSetup hook needed.
  outputDir: 'tests/e2e/test-results',

  use: {
    baseURL: BASE_URL,
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // Use the Playwright-bundled chromium (chromium-1223) already on fuji.
        channel: undefined,
        launchOptions: {
          args: [
            // Map the RP host to loopback so the page loads from our local
            // HTTPS server while keeping origin == https://wklm.online.
            `--host-resolver-rules=MAP ${RP_HOST} 127.0.0.1`,
            '--ignore-certificate-errors',
          ],
        },
      },
    },
  ],

  webServer: {
    command: 'node tests/e2e/serve.mjs',
    url: `https://127.0.0.1:${PORT}/index.html`,
    ignoreHTTPSErrors: true,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    env: {
      SITE_DIR,
      CERT_FILE,
      KEY_FILE,
      PORT: String(PORT),
    },
  },
});
