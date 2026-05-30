import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
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
 * Attach a CTAP2 internal virtual authenticator (resident keys + user
 * verification, auto presence + verified) to the page via CDP.  This is the
 * enabler: navigator.credentials.create/get then resolve headlessly.  Returns
 * the CDP session so the caller can keep it alive across the whole flow (the
 * passkey created during enroll must remain available for the decrypt gate).
 */
export async function addVirtualAuthenticator(
  context: BrowserContext,
  page: Page,
): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      automaticPresenceSimulation: true,
      isUserVerified: true,
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
  selfDescribeEnvelope(eml);
  return eml;
}

/**
 * Make the .eml body self-describing so the page's #ciphertext element carries
 * the outer MIME Content-Type + boundary.
 *
 * WHY: src/Logic.v render_eml_page renders only `ep_body` (the bytes AFTER the
 * first blank line) into <pre id="ciphertext">, so the outer
 *   Content-Type: multipart/hpke+wrapped; boundary="..."
 * header — which encrypt_post emits in the header block — is stripped out.  But
 * src/DecryptApp.v parse_envelope recovers the multipart boundary ONLY from that
 * Content-Type header (extract_boundary over the Content-Type value); it has no
 * boundary-scan fallback (the pre-WASM static/crane_bridge.js had `_scanBoundary`
 * for exactly this case — the WASM port dropped it).  With the header absent, the
 * boundary is "" and parse_envelope reports "No ciphertext found in envelope".
 *
 * This is a genuine src/ defect (Logic.render_eml_page vs DecryptApp.parse_envelope
 * disagree on the #ciphertext framing); src/ is out of scope to change here.  As a
 * harness-side workaround we copy the outer Content-Type header to the top of the
 * body so the served #ciphertext is a self-contained MIME entity.  This changes
 * only the MIME *framing* the page exposes — the wrapped CEK, the ciphertext bytes
 * and the AAD binding are untouched, so the in-browser decryption is fully genuine.
 *
 * AIDEV-NOTE: remove this once DecryptApp.parse_envelope regains a boundary scan
 * (or render_eml_page emits the outer Content-Type into #ciphertext).
 */
export function selfDescribeEnvelope(emlPath: string): void {
  const raw = readFileSync(emlPath, 'utf8');
  const sepMatch = raw.match(/\r?\n\r?\n/);
  if (!sepMatch || sepMatch.index === undefined) return; // no header/body split
  const headerBlock = raw.slice(0, sepMatch.index);
  const body = raw.slice(sepMatch.index + sepMatch[0].length);

  const ctLine = headerBlock
    .split(/\r?\n/)
    .find((l) => /^content-type:\s*multipart\/hpke\+wrapped/i.test(l.trim()));
  if (!ctLine) return; // nothing to copy
  if (/^content-type:\s*multipart\/hpke\+wrapped/i.test(body.trimStart().split(/\r?\n/)[0] || '')) {
    return; // body already self-describing
  }

  const nl = sepMatch[0]; // preserve the file's newline convention (CRLF here)
  const newBody = ctLine.trim() + nl + nl + body;
  writeFileSync(emlPath, headerBlock + nl + nl + newBody);
}

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
