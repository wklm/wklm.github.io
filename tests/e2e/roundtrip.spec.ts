import { test, expect } from '@playwright/test';
import type { CDPSession } from '@playwright/test';
import { rmSync } from 'node:fs';
import { join } from 'node:path';
import {
  addVirtualAuthenticator,
  readIdbStore,
  parseJwk,
  uncompressedPubHexFromJwk,
  encryptFixturePost,
  reRenderSite,
  repoRoot,
  type ReaderKeyRecord,
} from './helpers';

// The Facet A acceptance gate: prove the ROCQ->C++->WASM browser runtime works
// in a real headless Chromium.  Full round-trip in a single page/context so the
// WebAuthn virtual authenticator (created at enroll) and the enrolled privkey in
// IndexedDB both survive into the decrypt step.
//
//   1. /enroll/  -> click Enroll -> a key id + compressed pubkey render, and the
//      ECDH keypair + passkey land in IndexedDB (reader-keys / passkeys).
//   2. Mid-test: reconstruct the uncompressed pubkey from the stored JWK,
//      encrypt a fixture markdown post to that key with the Crane-extracted
//      encrypt_post, and re-render _site.
//   3. /<slug>/  -> click Decrypt -> the decrypted markdown renders in #real-body
//      with NO plaintext / <img> leaking into the public encrypted shell.

const SLUG = 'e2e-fixture';
const PLAINTEXT_MARKER = 'crane-wasm-roundtrip-plaintext-marker';
const SECRET_PARA = `This secret paragraph is ${PLAINTEXT_MARKER} and proves in-browser decrypt.`;
// A deliberately long (>40-word) paragraph.  The Verified-Reader's original
// O(n^3) Knuth-Plass breaker would hang the WASM module on a paragraph this size
// and exceed the decrypt timeout below; the Wave-2b prefix-sum O(n^2) fix +
// paragraph chunking must render it in well under a second.  This makes the gate
// a real regression test for both, end to end in headless Chromium.
const LONG_PARA = `The verified typesetter must lay out a paragraph considerably longer than forty words in order to exercise the Knuth and Plass optimal line breaking dynamic program inside the WebAssembly module under realistic conditions, because the original cubic time implementation that shipped with the first Verified Reader spike would effectively hang the browser tab on any genuine article length body and silently exceed the decryption timeout; the surrounding clauses, the deliberately winding subordinate structure, and this closing stretch of prose together push the total word count well beyond that critical threshold, so the prefix sum performance fix and the paragraph chunking renderer are both genuinely tested from end to end inside a real headless Chromium render rather than merely in an isolated native microbenchmark that never touches the canvas drawing path.`;
const FIXTURE_TITLE = 'E2E WASM Round-Trip Fixture';
const FIXTURE_MD = `---
title: ${FIXTURE_TITLE}
date: 2026-05-30
slug: ${SLUG}
---
${SECRET_PARA}

${LONG_PARA}

A short closing paragraph to exercise the multi-paragraph chunked renderer.
`;

// Recipient key ids created in-browser during the run (for cleanup).
const createdKids = new Set<string>();

// The test writes a fixture post + recipient key into the worktree (keys/ and
// posts/ are gitignored; posts-encrypted/ is tracked, so the .eml must be
// removed).  Clean them up so the repo stays pristine across runs.
test.afterEach(() => {
  const paths = [
    join(repoRoot, 'posts-encrypted', `${SLUG}.eml`),
    join(repoRoot, 'posts', `${SLUG}.md`),
  ];
  for (const kid of createdKids) paths.push(join(repoRoot, 'keys', `${kid}.pub`));
  for (const p of paths) rmSync(p, { force: true });
  createdKids.clear();
});

/** Wait until the WASM module has run on-load and armed [buttonId]. */
async function waitForArmed(page: import('@playwright/test').Page, buttonId: string) {
  await page.locator(`#${buttonId}`).waitFor({ state: 'attached' });
  await expect
    .poll(
      async () =>
        page.evaluate((id) => {
          const el = document.getElementById(id) as (HTMLElement & { __craneBound?: boolean }) | null;
          return !!(el && el.__craneBound === true);
        }, buttonId),
      { timeout: 60_000, message: `WASM module never armed #${buttonId}` },
    )
    .toBe(true);
}

test('Facet A WASM: in-browser enroll + decrypt round-trip', async ({ context, page }) => {
  // Capture uncaught page errors (WASM aborts: Asyncify state violations, the
  // "Maximum call stack size exceeded" we hit pre-fix, etc.).  Ignore unrelated
  // console noise (e.g. favicon 404); a real WASM failure surfaces as a pageerror
  // AND would fail the functional assertions below anyway.
  const fatalErrors: string[] = [];
  page.on('pageerror', (err) => fatalErrors.push(`pageerror: ${err.message}`));

  // The enabler: a virtual authenticator so navigator.credentials.* resolve.
  // Kept alive for the whole test (passkey from enroll is reused at decrypt).
  let cdp: CDPSession | undefined;
  ({ cdp } = await addVirtualAuthenticator(context, page));

  // ---- 1. ENROLL ----------------------------------------------------------
  await page.goto('/enroll/', { waitUntil: 'domcontentloaded' });
  await waitForArmed(page, 'enroll-button');

  await page.locator('#enroll-button').click();

  // The WASM enroll reveals #enroll-result and fills the key id + pubkey hex.
  await expect(page.locator('#enroll-result')).toBeVisible({ timeout: 60_000 });
  const renderedKid = (await page.locator('#reader-key-id').textContent())?.trim() || '';
  const renderedPubHex = (await page.locator('#reader-pubkey-hex').textContent())?.trim() || '';

  // key id is 12 hex chars; compressed pubkey is 33 bytes = 66 hex chars (0x02/0x03 prefix).
  expect(renderedKid).toMatch(/^[0-9a-f]{12}$/);
  expect(renderedPubHex).toMatch(/^0[23][0-9a-f]{64}$/);
  createdKids.add(renderedKid); // for afterEach cleanup of keys/<kid>.pub

  // The keypair + passkey are persisted in IndexedDB (EnrollApp.v schema).
  const readerKeys = (await readIdbStore(page, 'reader-keys')) as ReaderKeyRecord[];
  expect(readerKeys.length).toBe(1);
  const rk = readerKeys[0];
  expect(rk.id).toBe(renderedKid);
  expect(rk.pubkey).toBe(renderedPubHex);
  // privkeyJwk is stored as a JSON string by the WASM EnrollApp marshalling.
  const jwk = parseJwk(rk.privkeyJwk);
  expect(jwk.crv).toBe('P-256');
  expect(typeof jwk.d).toBe('string'); // private scalar present (extractable JWK)

  const passkeys = await readIdbStore(page, 'passkeys');
  expect(passkeys.length).toBe(1);
  expect(passkeys[0].keyId).toBe(renderedKid);
  expect(passkeys[0].credentialId).toMatch(/^[0-9a-f]+$/);

  // ---- 2. ENCRYPT A FIXTURE TO THE ENROLLED KEY, RE-RENDER ----------------
  // encrypt_post needs the 65-byte uncompressed pubkey; the enroll page renders
  // only the compressed form, so reconstruct it from the stored JWK coords.
  const uncompressedPubHex = uncompressedPubHexFromJwk(jwk);
  expect(uncompressedPubHex).toMatch(/^04[0-9a-f]{128}$/);

  encryptFixturePost({
    kid: renderedKid,
    uncompressedPubHex,
    slug: SLUG,
    markdown: FIXTURE_MD,
  });
  reRenderSite();

  // ---- 3. DECRYPT IN-BROWSER ----------------------------------------------
  await page.goto(`/${SLUG}/`, { waitUntil: 'domcontentloaded' });
  await waitForArmed(page, 'decrypt-button');

  // The public shell shows only the ciphertext + placeholder subject pre-decrypt.
  await expect(page.locator('#encrypted-shell')).toBeVisible();
  await expect(page.locator('#decrypted-content')).toBeHidden();
  // No plaintext leak in the server-rendered HTML shell.
  const shellHtml = await page.content();
  expect(shellHtml).not.toContain(PLAINTEXT_MARKER);
  expect(shellHtml).not.toContain(FIXTURE_TITLE);

  await page.locator('#decrypt-button').click();

  // Decryption succeeds: the inner content is revealed and rendered.
  await expect(page.locator('#decrypted-content')).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#decrypt-error')).toHaveText('');
  await expect(page.locator('#real-title')).toHaveText(FIXTURE_TITLE);
  // #real-body is the accessible text alternative: kept in the DOM (so this
  // assertion + screen readers see the plaintext) but visually subordinate
  // (.sr-only) to the Verified-Reader canvas.  textContent works on sr-only.
  await expect(page.locator('#real-body')).toContainText(PLAINTEXT_MARKER);
  await expect(page.locator('#real-body')).toContainText('closing paragraph');
  // The long middle paragraph (>40 words) decrypted + rendered without the WASM
  // module hanging or timing out — the Wave-2b DP perf fix + chunking working
  // end to end (the old O(n^3) breaker would not have finished in time).
  await expect(page.locator('#real-body')).toContainText('Knuth and Plass');

  // ---- Verified-Reader canvas: the ROCQ Typeset engine painted the body. ----
  // The decrypted body is rendered onto #reader-canvas via reader_begin/
  // reader_glyph (BrowserEffect.v).  Assert the canvas exists, is the visible
  // surface, and that its 2D context actually has painted (non-blank) pixels —
  // i.e. some pixel has a non-zero alpha.  A blank canvas (reader_begin/_glyph
  // silently no-op'd, or DCE'd) would have all-zero alpha and fail here.
  await expect(page.locator('#reader-canvas')).toBeVisible();
  const canvasPainted = await page.evaluate(() => {
    const c = document.getElementById('reader-canvas') as HTMLCanvasElement | null;
    if (!c) return { ok: false, reason: 'no #reader-canvas element' };
    if (c.width === 0 || c.height === 0)
      return { ok: false, reason: `canvas backing store is ${c.width}x${c.height}` };
    const cx = c.getContext('2d');
    if (!cx) return { ok: false, reason: 'no 2d context' };
    const { data } = cx.getImageData(0, 0, c.width, c.height);
    let nonZeroAlpha = 0;
    for (let i = 3; i < data.length; i += 4) if (data[i] !== 0) nonZeroAlpha++;
    return { ok: nonZeroAlpha > 0, reason: `painted alpha px: ${nonZeroAlpha}`, nonZeroAlpha };
  });
  expect(canvasPainted.ok, `reader-canvas not painted: ${canvasPainted.reason}`).toBe(true);

  // Wave 3 a11y: the pure-CSS "Comfortable spacing" toggle hides the bitmap
  // canvas and reveals #real-body as full-flow text with Zorzi letter/word
  // spacing (better accessibility than spacing a canvas would be).
  await page.locator('.reader-a11y-label').click();
  await expect(page.locator('#reader-canvas')).toBeHidden();
  const spaced = await page.locator('#real-body').evaluate((el) => {
    const s = getComputedStyle(el);
    return { ls: s.letterSpacing, pos: s.position };
  });
  expect(spaced.ls, 'a11y mode should apply letter-spacing').not.toBe('normal');
  expect(spaced.pos, 'a11y mode should un-clip #real-body').toBe('static');
  await page.locator('.reader-a11y-label').click(); // restore the canvas view
  await expect(page.locator('#reader-canvas')).toBeVisible();

  // The encrypted shell + decrypt UI are hidden post-decrypt; no <img> rendered
  // (the fixture has no images, and the public shell must never embed one).
  await expect(page.locator('#encrypted-shell')).toBeHidden();
  await expect(page.locator('#decrypt-ui')).toBeHidden();
  expect(await page.locator('#real-body img').count()).toBe(0);
  expect(await page.locator('#decrypted-content img').count()).toBe(0);

  // The decrypted plaintext exists ONLY inside #real-body (client-side), never
  // in the originally-served ciphertext element.
  const cipherText = (await page.locator('#ciphertext').textContent()) || '';
  expect(cipherText).not.toContain(PLAINTEXT_MARKER);
  expect(cipherText).toContain('application/aes-gcm');

  // No uncaught WASM aborts during the whole flow.
  expect(fatalErrors, `uncaught page errors:\n${fatalErrors.join('\n')}`).toEqual([]);

  if (cdp) await cdp.detach().catch(() => {});
});
