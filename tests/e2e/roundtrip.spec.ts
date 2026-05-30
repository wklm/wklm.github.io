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
const FIXTURE_TITLE = 'E2E WASM Round-Trip Fixture';
const FIXTURE_MD = `---
title: ${FIXTURE_TITLE}
date: 2026-05-30
slug: ${SLUG}
---
${SECRET_PARA}

A second paragraph to exercise the markdown-to-paragraphs renderer.
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
  await expect(page.locator('#real-body')).toContainText(PLAINTEXT_MARKER);
  await expect(page.locator('#real-body')).toContainText('second paragraph');

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
