import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { BrowserContext, CDPSession, Page } from '@playwright/test';

const here = dirname(fileURLToPath(import.meta.url));
export const repoRoot = join(here, '..', '..');

// The runtime generator image carries the native Crane-extracted encrypt_post
// (and blog_generator) at /usr/local/bin — usable without the heavy Coq/Crane
// toolchain.  We run it with the worktree mounted at /site; encrypt_post is
// CWD-relative (reads posts/ + keys/, writes posts-encrypted/).
const GEN_IMAGE = process.env.CRANE_BLOG_GEN_IMAGE || 'crane-blog-gen';

/**
 * Capability profile of a CDP virtual authenticator.  Parameterized so the e2e
 * can run the round-trip across a MATRIX of realistic authenticators — crucially
 * a NON-resident-key one (hasResidentKey:false), which is exactly what the old
 * hard-coded residentKey:'required' enroll policy silently failed on.  With the
 * policy lifted to BrowserPolicy.rk_discouraged, enroll must now succeed here.
 */
export interface AuthenticatorProfile {
  hasResidentKey: boolean;
  hasUserVerification: boolean;
  isUserVerified: boolean;
}

/**
 * Attach a CTAP2 internal virtual authenticator with the given capability
 * profile to the page via CDP (auto presence simulation).  This is the enabler:
 * navigator.credentials.create/get then resolve headlessly.  Returns the CDP
 * session so the caller can keep it alive across the whole flow (the passkey
 * created during enroll must remain available for the decrypt gate).
 *
 * Defaults preserve the original full-capability authenticator
 * (resident keys + UV) for callers that don't care about the matrix.
 */
export async function addVirtualAuthenticator(
  context: BrowserContext,
  page: Page,
  profile: AuthenticatorProfile = {
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
  },
): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: profile.hasResidentKey,
      hasUserVerification: profile.hasUserVerification,
      automaticPresenceSimulation: true,
      isUserVerified: profile.isUserVerified,
    },
  });
  return { cdp, authenticatorId };
}

/** A WebCrypto EC P-256 JWK (the fields we rely on). */
export interface EcJwk {
  kty: string;
  crv: string;
  x: string;
  y: string;
  d?: string;
}

/**
 * Records stored in IndexedDB store `reader-keys` by the WASM EnrollApp.
 * NOTE: the WASM build (json_object4 marshalling) stores `privkeyJwk` as a JSON
 * *string*, not a nested object — DecryptApp reads it back via json_array_field
 * and hands the string straight to ecdh_p256_agree (which JSON.parses it).  So
 * here it is `string`; use parseJwk() to read its coordinates.
 */
export interface ReaderKeyRecord {
  id: string;
  pubkey: string; // compressed (33-byte) hex
  privkeyJwk: string; // JSON-stringified EcJwk
  created: string;
}

/** Parse the JSON-stringified privkeyJwk field of a reader-keys record. */
export function parseJwk(privkeyJwk: string): EcJwk {
  return JSON.parse(privkeyJwk) as EcJwk;
}

/** Read every record from an IndexedDB object store, in the page's origin. */
export async function readIdbStore(page: Page, store: string): Promise<any[]> {
  return page.evaluate(async (storeName) => {
    return await new Promise<any[]>((resolve, reject) => {
      const req = indexedDB.open('crane-blog-v2', 1);
      req.onsuccess = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(storeName)) {
          db.close();
          resolve([]);
          return;
        }
        const tx = db.transaction(storeName, 'readonly');
        const all = tx.objectStore(storeName).getAll();
        all.onsuccess = () => {
          db.close();
          resolve(all.result || []);
        };
        all.onerror = () => {
          db.close();
          reject(all.error);
        };
      };
      req.onerror = () => reject(req.error);
    });
  }, store);
}

/** base64url -> hex (no padding required). */
function b64urlToHex(b64url: string): string {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(b64, 'base64').toString('hex');
}

/**
 * Reconstruct the 65-byte SEC1 *uncompressed* public key (0x04 || x || y) hex
 * from a WebCrypto EC P-256 JWK.  encrypt_post / crypto_helpers.h require the
 * uncompressed form (ec_point_from_uncompressed rejects anything but 65 bytes);
 * the enroll page only renders the compressed form, so we derive the full key
 * from the stored JWK coordinates instead.
 */
export function uncompressedPubHexFromJwk(jwk: { x: string; y: string }): string {
  const xHex = b64urlToHex(jwk.x).padStart(64, '0');
  const yHex = b64urlToHex(jwk.y).padStart(64, '0');
  if (xHex.length !== 64 || yHex.length !== 64) {
    throw new Error(`bad JWK coords: x=${xHex.length} y=${yHex.length} hex chars`);
  }
  return '04' + xHex + yHex;
}

/**
 * Encrypt a fixture markdown post to a single recipient (the just-enrolled
 * reader) using the Crane-extracted encrypt_post inside the builder image.
 * Writes keys/<kid>.pub (uncompressed hex) + posts/<slug>.md, runs encrypt_post
 * with CRANE_BLOG_AUTHOR_KEY_ID=<kid>, and produces posts-encrypted/<slug>.eml.
 * Returns the eml path (relative to repoRoot).  Runs as the host uid so the
 * bind-mounted outputs stay host-owned.
 */
export function encryptFixturePost(args: {
  kid: string;
  uncompressedPubHex: string;
  slug: string;
  markdown: string;
}): string {
  const { kid, uncompressedPubHex, slug, markdown } = args;

  const keysDir = join(repoRoot, 'keys');
  const postsDir = join(repoRoot, 'posts');
  mkdirSync(keysDir, { recursive: true });
  mkdirSync(postsDir, { recursive: true });
  writeFileSync(join(keysDir, `${kid}.pub`), uncompressedPubHex);
  writeFileSync(join(postsDir, `${slug}.md`), markdown);

  const uid = process.getuid?.() ?? 1000;
  const gid = process.getgid?.() ?? 1000;

  // Run the native encrypt_post from the runtime image with the worktree mounted
  // at /site (its WORKDIR).  Mounting the worktree over the builder's /home would
  // shadow its pre-built _build/; the runtime image keeps the binary on PATH.
  execFileSync(
    'docker',
    [
      'run', '--rm',
      '--user', `${uid}:${gid}`,
      '-v', `${repoRoot}:/site`,
      '-w', '/site',
      '-e', `CRANE_BLOG_AUTHOR_KEY_ID=${kid}`,
      '-e', 'CRANE_BLOG_AUTHOR_EMAIL=e2e@wklm.online',
      '--entrypoint', '/usr/local/bin/encrypt_post',
      GEN_IMAGE,
      `posts/${slug}.md`,
    ],
    { stdio: 'inherit' },
  );

  const eml = join(repoRoot, 'posts-encrypted', `${slug}.eml`);
  if (!existsSync(eml)) {
    throw new Error(`encrypt_post did not produce ${eml}`);
  }
  return eml;
}

// NOTE: render_eml_page emits only the multipart body into #ciphertext (no outer
// Content-Type/boundary header).  src/DecryptApp.v parse_envelope now recovers the
// boundary from the first "--" delimiter line (scan_boundary), so the e2e serves the
// real render_eml_page output unmodified — no harness-side envelope rewriting.

/**
 * Re-render _site from the current posts-encrypted/ + static/ using the
 * already-built generator image (no rebuild).  Used after encryptFixturePost so
 * the new fixture post page exists; the browser context keeps the enrolled
 * privkey in IndexedDB (origin-scoped, unaffected by the disk re-render).
 */
export function reRenderSite(): void {
  const uid = process.getuid?.() ?? 1000;
  const gid = process.getgid?.() ?? 1000;
  const siteDir = join(repoRoot, '_site');
  mkdirSync(siteDir, { recursive: true });
  execFileSync(
    'docker',
    [
      'run', '--rm',
      '--user', `${uid}:${gid}`,
      '-v', `${join(repoRoot, 'posts-encrypted')}:/site/posts-encrypted:ro`,
      '-v', `${join(repoRoot, 'static')}:/site/static:ro`,
      '-v', `${siteDir}:/site/_site`,
      GEN_IMAGE,
    ],
    { stdio: 'inherit' },
  );
}
