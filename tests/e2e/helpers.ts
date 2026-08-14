import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, existsSync, rmSync, readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
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
 * Generate a P-256 recipient UNRELATED to anything enrolled in the browser, for
 * the "not a recipient" decrypt-failure test.  Returns the 65-byte uncompressed
 * pubkey hex plus the key id derived EXACTLY as the app does
 * (BrowserCrypto.browser_key_id = first 12 hex chars of SHA-256(compressed
 * pubkey)), so encrypt_post produces a well-formed envelope addressed to a kid
 * the enrolled reader does not hold — DecryptApp.try_keys_aux then finds no
 * matching wrap and surfaces the "not a recipient" error.
 */
export async function generateForeignRecipient(): Promise<{
  kid: string;
  uncompressedPubHex: string;
}> {
  const kp = await webcrypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const raw = new Uint8Array(await webcrypto.subtle.exportKey('raw', kp.publicKey)); // 0x04||x||y
  // Compress (0x02/0x03 || x) to match browser_key_id's input.
  const x = raw.slice(1, 33);
  const y = raw.slice(33, 65);
  const compressed = new Uint8Array(33);
  compressed[0] = (y[31] & 1) === 1 ? 0x03 : 0x02;
  compressed.set(x, 1);
  const digest = new Uint8Array(await webcrypto.subtle.digest('SHA-256', compressed));
  const kid = Buffer.from(digest).toString('hex').slice(0, 12);
  const uncompressedPubHex = '04' + Buffer.from(raw.slice(1)).toString('hex');
  return { kid, uncompressedPubHex };
}

/**
 * Resolve the author ECDSA P-256 signing keypair for the fixture envelope.
 *
 * encrypt_post REQUIRES CRANE_BLOG_SIGNING_KEY_ID + CRANE_BLOG_SIGNING_KEY and
 * reads the public half back from keys/<kid>.sign.pub in the worktree; the
 * browser then verifies the envelope's Signature against the Signing-Key header
 * via WebCrypto.  Strategy (hermetic by default):
 *
 *  1. If both CRANE_BLOG_SIGNING_KEY_ID and CRANE_BLOG_SIGNING_KEY are set in
 *     the environment (e.g. a real deployment key is exported on the host),
 *     reuse that key: write keys/<kid>.sign.pub ONLY when it does not already
 *     exist (an existing .sign.pub is never overwritten), deriving the 65-byte
 *     uncompressed public key from the private scalar via openssl if needed.
 *  2. Otherwise generate an ephemeral P-256 keypair at test time with openssl,
 *     using the same extraction pipeline as scripts/test-roundtrip.sh
 *     (65-byte uncompressed pub hex, 32-byte scalar, key_id = sha256(pub)[:12]),
 *     and write keys/<kid>.sign.pub with NO trailing newline.  Existing
 *     .sign.pub files are left untouched.
 *
 * keys/ is gitignored, so no key material is ever committed.  Returns the key
 * id (for the env) + the private scalar hex.
 */
function resolveSigningKey(keysDir: string): { signKid: string; signPrivHex: string } {
  const envKid = process.env.CRANE_BLOG_SIGNING_KEY_ID;
  const envPriv = process.env.CRANE_BLOG_SIGNING_KEY;
  if (envKid && envPriv) {
    if (!/^[0-9a-f]{12}$/.test(envKid.trim())) {
      throw new Error(`CRANE_BLOG_SIGNING_KEY_ID must be 12 hex chars, got '${envKid}'`);
    }
    if (!/^[0-9a-f]{64}$/.test(envPriv.trim())) {
      throw new Error(`CRANE_BLOG_SIGNING_KEY must be a 32-byte hex scalar, got ${envPriv.trim().length} hex chars`);
    }
    const signKid = envKid.trim();
    const signPrivHex = envPriv.trim();
    const pubPath = join(keysDir, `${signKid}.sign.pub`);
    if (!existsSync(pubPath)) {
      // Reuse the env-designated key, but its public half is missing from the
      // worktree — rebuild the 65-byte uncompressed point from the scalar
      // (SEC1 EC PRIVATE KEY DER: 0x30 0x77 0x02 0x01 0x01 0x04 0x20 <scalar>
      // a0 0a 06 08 2a 86 48 ce 3d 03 01 07), never overwriting if it exists.
      const pubHex = execFileSync('bash', ['-c', [
        'set -euo pipefail',
        'scratch="$(mktemp -d)"',
        'trap \'rm -rf "$scratch"\' EXIT',
        'printf \'%s\' "$1" | perl -e \'print pack "H*", <STDIN>\' > "$scratch/scalar.bin"',
        'printf \'\x30\x77\x02\x01\x01\x04\x20\' > "$scratch/prefix.bin"',
        'printf \'\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\' > "$scratch/suffix.bin"',
        'cat "$scratch/prefix.bin" "$scratch/scalar.bin" "$scratch/suffix.bin" > "$scratch/key.der"',
        'openssl ec -inform DER -in "$scratch/key.der" -pubout -conv_form uncompressed 2>/dev/null |',
        '  openssl pkey -pubin -outform DER 2>/dev/null |',
        '  tail -c 65 | od -An -tx1 -v | tr -d \' \n\'',
      ].join('\n'), 'bash', signPrivHex], { encoding: 'utf8' }).trim();
      if (!/^04[0-9a-f]{128}$/.test(pubHex)) {
        throw new Error(`could not derive public key for signing key ${signKid} (got ${pubHex.length} hex chars)`);
      }
      writeFileSync(pubPath, pubHex); // no trailing newline
    }
    return { signKid, signPrivHex };
  }

  // Hermetic default: ephemeral P-256 keypair, generated at test time with the
  // exact extraction pipeline of scripts/generate-signing-key.sh.  An existing
  // keys/<kid>.sign.pub is never overwritten — a fresh key simply gets a fresh
  // (sha256-derived) id.  The private scalar lives only in process memory and
  // is passed straight into the encrypt_post container.
  const script = [
    'set -euo pipefail',
    'scratch="$(mktemp -d)"',
    'trap \'rm -rf "$scratch"\' EXIT',
    'openssl ecparam -name prime256v1 -genkey -noout -out "$scratch/sign.pem" 2>/dev/null',
    'pub_hex=$(openssl ec -in "$scratch/sign.pem" -pubout -conv_form uncompressed 2>/dev/null |',
    '  openssl pkey -pubin -outform DER 2>/dev/null |',
    '  tail -c 65 | od -An -tx1 -v | tr -d \' \n\')',
    'priv_hex=$(openssl ec -in "$scratch/sign.pem" -text -noout 2>/dev/null |',
    '  awk \'/priv:/{f=1;next}/pub:/{f=0}f\' | tr -d \' :\n\')',
    'if [ ${#priv_hex} -eq 66 ]; then priv_hex=${priv_hex#00}; fi',
    'if [ ${#priv_hex} -ne 64 ] || [ ${#pub_hex} -ne 130 ]; then',
    '  echo "signing key extraction failed (priv_len=${#priv_hex} want 64, pub_len=${#pub_hex} want 130)" >&2',
    '  exit 1',
    'fi',
    'key_id=$(printf \'%s\' "$pub_hex" | od -An -tx1 -v | tr -d \' \n\' | shasum -a 256 | cut -c 1-12)',
    'printf \'%s %s %s\' "$key_id" "$pub_hex" "$priv_hex"',
  ].join('\n');
  const out = execFileSync('bash', ['-c', script], { encoding: 'utf8' }).trim();
  const [signKid, pubHex, signPrivHex] = out.split(/\s+/);
  if (!/^[0-9a-f]{12}$/.test(signKid) || !/^04[0-9a-f]{128}$/.test(pubHex) || !/^[0-9a-f]{64}$/.test(signPrivHex)) {
    throw new Error(`ephemeral signing key generation produced invalid output: '${out}'`);
  }
  writeFileSync(join(keysDir, `${signKid}.sign.pub`), pubHex); // no trailing newline
  return { signKid, signPrivHex };
}

/**
 * Encrypt a fixture markdown post to a single recipient (the just-enrolled
 * reader) using the Crane-extracted encrypt_post inside the builder image.
 * Writes keys/<kid>.pub (uncompressed hex) + posts/<slug>.md, resolves (or
 * generates) an ephemeral author ECDSA signing keypair, writes
 * keys/<signKid>.sign.pub, runs encrypt_post with CRANE_BLOG_AUTHOR_KEY_ID=<kid>
 * + CRANE_BLOG_SIGNING_KEY_ID/CRANE_BLOG_SIGNING_KEY, and produces
 * posts-encrypted/<slug>.eml with a verifiable Signature/Signing-Key header
 * pair.  Returns the eml path (relative to repoRoot).  Runs as the host uid so
 * the bind-mounted outputs stay host-owned.
 */
export function encryptFixturePost(args: {
  kid: string;
  uncompressedPubHex?: string;
  slug: string;
  markdown: string;
  public?: boolean;
}): string {
  const { kid, uncompressedPubHex, slug, markdown, public: isPublic } = args;

  const keysDir = join(repoRoot, 'keys');
  const postsDir = join(repoRoot, 'posts');
  mkdirSync(keysDir, { recursive: true });
  mkdirSync(postsDir, { recursive: true });
  writeFileSync(join(postsDir, `${slug}.md`), markdown);
  if (isPublic) {
    // Feature 2: PUBLIC posts (frontmatter `recipients: *`) need no recipient
    // key at all — the keyless branch never reads keys/<kid>.pub.  The author
    // ECDSA signing key below is still required (public posts are signed).
  } else {
    if (!uncompressedPubHex) {
      throw new Error('uncompressedPubHex is required for encrypted (non-public) fixtures');
    }
    writeFileSync(join(keysDir, `${kid}.pub`), uncompressedPubHex);
  }

  // The fixture envelope must be signed: encrypt_post fails without the signing
  // env, and the browser decrypt gate rejects an unsigned envelope.
  const { signKid, signPrivHex } = resolveSigningKey(keysDir);
  if (isPublic) {
    // G4/D-C5: the generator emits the trust-anchor meta from
    // keys/author-signing.pub (NOT the envelope's own Signing-Key).  Pin the
    // ephemeral signing key so the browser verifies the public post against an
    // INDEPENDENT build-time constant — the caller restores the committed pin
    // in its afterEach.
    const pin = readFileSync(join(keysDir, `${signKid}.sign.pub`), 'utf8').trim();
    writeFileSync(join(keysDir, 'author-signing.pub'), pin); // no trailing newline
  }

  // Run the native encrypt_post from the runtime image.  DinD-safe: the
  // self-hosted runner mounts only docker.sock, so -v bind mounts resolve
  // against the HOST daemon and $PWD/... is an empty dir.  Create a container
  // with the encrypt_post entrypoint + env + args, copy inputs in, start -a to
  // run it, copy the produced .eml back out.  (No --user: docker cp reads the
  // output back as root; the host-uid flag only mattered for bind mounts.)
  const emlDir = join(repoRoot, 'posts-encrypted');
  mkdirSync(emlDir, { recursive: true });
  const cid = execFileSync(
    'docker',
    [
      'create',
      '-w', '/site',
      '-e', `CRANE_BLOG_AUTHOR_KEY_ID=${kid}`,
      '-e', 'CRANE_BLOG_AUTHOR_EMAIL=e2e@wklm.online',
      '-e', `CRANE_BLOG_SIGNING_KEY_ID=${signKid}`,
      '-e', `CRANE_BLOG_SIGNING_KEY=${signPrivHex}`,
      '--entrypoint', '/usr/local/bin/encrypt_post',
      GEN_IMAGE,
      `posts/${slug}.md`,
    ],
    { encoding: 'utf8' },
  ).trim();
  try {
    execFileSync('docker', ['cp', keysDir, `${cid}:/site/keys`], { stdio: 'ignore' });
    execFileSync('docker', ['cp', postsDir, `${cid}:/site/posts`], { stdio: 'ignore' });
    execFileSync('docker', ['start', '-a', cid], { stdio: 'inherit' });
    const tmpEml = join(repoRoot, 'posts-encrypted', '.e2e-tmp');
    rmSync(tmpEml, { recursive: true, force: true });
    execFileSync('docker', ['cp', `${cid}:/site/posts-encrypted`, tmpEml], { stdio: 'ignore' });
    // docker cp of a dir into a new dir nests it: posts-encrypted/.e2e-tmp/<slug>.eml
    const nestedEml = join(tmpEml, `${slug}.eml`);
    if (!existsSync(nestedEml)) {
      throw new Error(`encrypt_post produced no ${slug}.eml in the container`);
    }
    execFileSync('mv', [nestedEml, join(emlDir, `${slug}.eml`)]);
    rmSync(tmpEml, { recursive: true, force: true });
  } finally {
    execFileSync('docker', ['rm', '-f', cid], { stdio: 'ignore' });
  }

  const eml = join(repoRoot, 'posts-encrypted', `${slug}.eml`);
  if (!existsSync(eml)) {
    throw new Error(`encrypt_post did not produce ${eml}`);
  }
  return eml;
}

// NOTE: render_eml_page emits the FULL outer envelope (public headers + multipart
// body) into #ciphertext, so the browser parses exactly the same bytes the native
// decrypt_post parses.  src/DecryptApp.v parse_envelope reads the Signature /
// Signing-Key headers and the Content-Type boundary from that header block, so
// the e2e serves the real render_eml_page output unmodified — no harness-side
// envelope rewriting.

/**
 * Re-render _site from the current posts-encrypted/ + static/ using the
 * already-built generator image (no rebuild).  Used after encryptFixturePost so
 * the new fixture post page exists; the browser context keeps the enrolled
 * privkey in IndexedDB (origin-scoped, unaffected by the disk re-render).
 */
export function reRenderSite(): void {
  const siteDir = join(repoRoot, '_site');
  mkdirSync(siteDir, { recursive: true });
  // DinD-safe: copy the whole inputs dirs in (the runtime CMD mkdir -p's
  // posts-encrypted + _site before generating), start -a to generate, then
  // copy _site back out through a temp dir (docker cp of a dir into an
  // existing dir nests it, so copy into a fresh tmp and move the contents).
  const cid = execFileSync('docker', ['create', GEN_IMAGE], { encoding: 'utf8' }).trim();
  try {
    execFileSync('docker', ['cp', join(repoRoot, 'posts-encrypted'), `${cid}:/site/posts-encrypted`], { stdio: 'ignore' });
    execFileSync('docker', ['cp', join(repoRoot, 'static'), `${cid}:/site/static`], { stdio: 'ignore' });
    if (existsSync(join(repoRoot, 'keys', 'author-signing.pub'))) {
      execFileSync('docker', ['cp', join(repoRoot, 'keys'), `${cid}:/site/keys`], { stdio: 'ignore' });
    }
    execFileSync('docker', ['start', '-a', cid], { stdio: 'inherit' });
    // Copy from a SIBLING temp dir.  (A plain `mv dir` onto an existing dir
    // silently MERGES and keeps stale files, so a second re-render would serve
    // a previous test's envelope; rsync is not in the DinD job image, so wipe
    // the destination and cp -a instead — cp is universally present.)
    const tmpSite = join(repoRoot, '.e2e-tmp-site');
    rmSync(tmpSite, { recursive: true, force: true });
    execFileSync('docker', ['cp', `${cid}:/site/_site`, tmpSite], { stdio: 'ignore' });
    execFileSync('bash', ['-c', `rm -rf ${siteDir}/* ${siteDir}/.[!.]* ${siteDir}/..?* 2>/dev/null || true; cp -a ${tmpSite}/. ${siteDir}/`], { stdio: 'ignore' });
    rmSync(tmpSite, { recursive: true, force: true });
  } finally {
    execFileSync('docker', ['rm', '-f', cid], { stdio: 'ignore' });
  }
}
