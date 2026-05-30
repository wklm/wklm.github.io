import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..');

export const CERT_DIR = join(here, '.certs');
export const CERT_FILE = join(CERT_DIR, 'cert.pem');
export const KEY_FILE = join(CERT_DIR, 'key.pem');
export const SITE_DIR = join(repoRoot, '_site');

/**
 * Generate a self-signed cert for CN=wklm.online (with a SAN) so the page can be
 * served over HTTPS at https://wklm.online — WebCrypto/WebAuthn require a secure
 * origin, and the enroll WebAuthn RP id is `wklm.online`.  Chromium is launched
 * with --host-resolver-rules mapping wklm.online -> 127.0.0.1 and Playwright with
 * ignoreHTTPSErrors, so the self-signed cert is accepted and the origin matches.
 */
export function ensureCert(): void {
  if (existsSync(CERT_FILE) && existsSync(KEY_FILE)) return;
  rmSync(CERT_DIR, { recursive: true, force: true });
  mkdirSync(CERT_DIR, { recursive: true });
  // openssl 3.x one-shot self-signed cert with SAN.
  execFileSync(
    'openssl',
    [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', KEY_FILE,
      '-out', CERT_FILE,
      '-days', '7',
      '-subj', '/CN=wklm.online',
      '-addext', 'subjectAltName=DNS:wklm.online,DNS:localhost,IP:127.0.0.1',
    ],
    { stdio: 'ignore' },
  );
  if (!existsSync(CERT_FILE) || !existsSync(KEY_FILE)) {
    throw new Error('global-setup: failed to generate self-signed cert');
  }
}

/**
 * Stage _site (extract WASM artifacts into static/, build the generator image,
 * render _site).  Skipped when CRANE_BLOG_SKIP_STAGE=1 (CI stages the site in a
 * dedicated step before invoking Playwright, and avoids a redundant rebuild).
 */
export function ensureSite(): void {
  if (process.env.CRANE_BLOG_SKIP_STAGE === '1') {
    if (!existsSync(SITE_DIR)) {
      throw new Error(
        'global-setup: CRANE_BLOG_SKIP_STAGE=1 but _site does not exist; ' +
          'stage it first with tests/e2e/stage-site.sh',
      );
    }
    return;
  }
  execFileSync('bash', [join(here, 'stage-site.sh')], {
    cwd: repoRoot,
    stdio: 'inherit',
  });
}

export default function globalSetup(): void {
  ensureCert();
  ensureSite();
}
