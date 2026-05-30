import { test, expect } from '@playwright/test';
import type { CDPSession, Page } from '@playwright/test';
import { rmSync } from 'node:fs';
import { join } from 'node:path';
import {
  addVirtualAuthenticator,
  readIdbStore,
  parseJwk,
  uncompressedPubHexFromJwk,
  encryptFixturePost,
  generateForeignRecipient,
  reRenderSite,
  repoRoot,
  type AuthenticatorProfile,
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
//
// HARDENED GATE.  The round-trip runs across a MATRIX of realistic virtual
// authenticators — including a NON-resident-key one and a no-UV one — and a
// separate "no authenticator" row asserts enroll FAILS VISIBLY.  These turn the
// original residentKey:'required' bug red: that policy made create() reject on a
// non-resident authenticator, so the non-resident row would never enroll.  The
// gate also asserts ZERO console.error / unhandled-rejection across the whole
// flow (the swallowed-failure + Asyncify-hang classes surface as console errors
// or rejections even when a functional assertion might not catch them).

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

/**
 * Capture console.error + unhandled page errors + unhandled promise rejections.
 * The swallowed-storage-failure and Asyncify-hang bug classes surface as console
 * errors / rejections even when a functional assertion might not catch them, so
 * the hardened gate asserts NONE occur (modulo a tiny benign allowlist).
 */
const BENIGN = [
  /favicon/i, // favicon.ico 404 on the test server — unrelated to the app
  /Failed to load resource:.*favicon/i,
];
function isBenign(msg: string): boolean {
  return BENIGN.some((re) => re.test(msg));
}
interface ErrorSink {
  fatal: string[];
}
function attachErrorCapture(page: Page): ErrorSink {
  const sink: ErrorSink = { fatal: [] };
  // WASM aborts: Asyncify state violations, "Maximum call stack size exceeded".
  page.on('pageerror', (err) => sink.fatal.push(`pageerror: ${err.message}`));
  // Any console.error the app emits (e.g. the shim's 'WebAuthn create failed').
  page.on('console', (msg) => {
    if (msg.type() !== 'error') return;
    const text = msg.text();
    if (!isBenign(text)) sink.fatal.push(`console.error: ${text}`);
  });
  // Unhandled promise rejections (an un-try/catch'd async shim would surface
  // here as the WASM stack is abandoned).
  page.on('console', (msg) => {
    const text = msg.text();
    if (/unhandled (promise )?rejection/i.test(text) && !isBenign(text)) {
      sink.fatal.push(`unhandledrejection: ${text}`);
    }
  });
  return sink;
}

/** Wait until the WASM module has run on-load and armed [buttonId]. */
async function waitForArmed(page: Page, buttonId: string) {
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

/**
 * The full in-browser enroll -> encrypt -> decrypt -> render round-trip, run
 * against an already-attached virtual authenticator.  Shared by every matrix
 * row so each authenticator profile exercises the identical flow + assertions.
 */
async function runRoundTrip(page: Page, sink: ErrorSink) {
  // ---- 1. ENROLL ----------------------------------------------------------
  await page.goto('/enroll/', { waitUntil: 'domcontentloaded' });
  await waitForArmed(page, 'enroll-button');

  await page.locator('#enroll-button').click();

  // The WASM enroll reveals #enroll-result and fills the key id + pubkey hex.
  // (With the residentKey policy fixed this now holds even for a non-resident
  // authenticator — the row that used to fail.)
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

  // Decryption succeeds: the inner content is revealed and rendered.  (A hung
  // Asyncify shim would never reveal #decrypted-content and this would time
  // out — the "Decrypting never finishes" regression, now caught here.)
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

  // No uncaught WASM aborts / console errors / unhandled rejections in the flow.
  expect(sink.fatal, `unexpected console errors / page errors:\n${sink.fatal.join('\n')}`).toEqual([]);
}

// The authenticator MATRIX.  Each row runs the identical round-trip.  The
// non-resident + no-UV rows are the ones the original residentKey:'required' /
// over-strict UV policy would have failed; with the policy lifted into
// BrowserPolicy (rk_discouraged / uv_preferred) every row must pass.
const MATRIX: Array<{ name: string; profile: AuthenticatorProfile }> = [
  {
    name: 'resident + UV (baseline platform authenticator)',
    profile: { hasResidentKey: true, hasUserVerification: true, isUserVerified: true },
  },
  {
    name: 'NON-resident key (residentKey:required would have failed enroll here)',
    profile: { hasResidentKey: false, hasUserVerification: true, isUserVerified: true },
  },
  {
    name: 'no user-verification (UV-incapable authenticator)',
    profile: { hasResidentKey: false, hasUserVerification: false, isUserVerified: false },
  },
];

for (const row of MATRIX) {
  test(`Facet A WASM round-trip — ${row.name}`, async ({ context, page }) => {
    const sink = attachErrorCapture(page);
    let cdp: CDPSession | undefined;
    ({ cdp } = await addVirtualAuthenticator(context, page, row.profile));
    try {
      await runRoundTrip(page, sink);
    } finally {
      if (cdp) await cdp.detach().catch(() => {});
    }
  });
}

// The "no usable authenticator" row: WebAuthn create() rejects (the realistic
// case where the reader has no authenticator, or declines/cancels the prompt).
// Enrollment MUST fail VISIBLY (a status error in the DOM) rather than silently
// appearing to succeed — the swallowed-failure class.  This asserts the failure
// is surfaced AND that nothing was persisted.
//
// We make create() reject DETERMINISTICALLY (and promptly) by intercepting it in
// an init script: with the CDP virtual environment but no authenticator,
// create() instead parks for the full ceremony timeout (BrowserPolicy
// wa_create_timeout = 120 s), which would make this a slow, flaky test.  A
// NotAllowedError is exactly what an absent/declining authenticator yields, so
// this faithfully exercises the APP's failure path (EnrollApp surfacing the
// empty cred_id + the shim's fail-closed catch), which is the behavior under
// test — not WebAuthn's timeout timing.
test('Facet A WASM enroll — no usable authenticator: enroll fails VISIBLY', async ({ page }) => {
  // A WebAuthn create rejection legitimately produces the shim's
  // console.error('WebAuthn create failed', ...) — the *expected* signal of a
  // surfaced failure, so allow that one message for this row only.
  const sink = attachErrorCapture(page);
  const ALLOW_WEBAUTHN_FAIL = /WebAuthn create failed/i;

  // Reject navigator.credentials.create immediately, before any navigation.
  await page.addInitScript(() => {
    if (navigator.credentials) {
      navigator.credentials.create = () =>
        Promise.reject(new DOMException('No usable authenticator', 'NotAllowedError'));
    }
  });

  await page.goto('/enroll/', { waitUntil: 'domcontentloaded' });
  await waitForArmed(page, 'enroll-button');

  await page.locator('#enroll-button').click();

  // The enroll status surfaces a failure message; the success panel stays hidden.
  await expect(page.locator('#enroll-status')).toContainText(/fail/i, { timeout: 30_000 });
  await expect(page.locator('#enroll-result')).toBeHidden();

  // CRITICAL: nothing was persisted — no half-written reader key / passkey that
  // a reader would mistake for a usable enrollment (the swallowed-failure class:
  // do_enroll must NOT reach the idb_put / success-reveal branch on failure).
  const readerKeys = await readIdbStore(page, 'reader-keys');
  expect(readerKeys.length, 'no reader key should be stored when enroll fails').toBe(0);
  const passkeys = await readIdbStore(page, 'passkeys');
  expect(passkeys.length, 'no passkey should be stored when enroll fails').toBe(0);

  // Only the expected WebAuthn-failure console.error is tolerated; any OTHER
  // console error / pageerror / unhandled rejection is still a gate failure.
  const unexpected = sink.fatal.filter((m) => !ALLOW_WEBAUTHN_FAIL.test(m));
  expect(unexpected, `unexpected errors (beyond the surfaced WebAuthn failure):\n${unexpected.join('\n')}`).toEqual([]);
});

// ===========================================================================
// INBOX coherence (/).  The inbox was only ever exercised happy-path on other
// pages; its enroll affordance vanished in the has-key state because it ran
// crane_enroll against a DOM missing #enroll-existing/#enroll-result.  The fix
// makes the inbox enroll affordance a LINK to /enroll/ and drops crane_enroll
// from the inbox (crane_decrypt still loads for the per-post status).  These two
// rows assert the inbox loads with NO console error AND the enroll affordance is
// present + usable in BOTH the no-key and has-key states — no vanished control.
// ===========================================================================

/**
 * The inbox must load cleanly and present a usable enroll affordance, in BOTH
 * the no-key and has-key states.  The affordance is a static link to /enroll/
 * (the inbox no longer runs crane_enroll, so nothing can hide it).  "Usable"
 * means: the link is present + visible, targets /enroll/, and following it lands
 * on a COHERENT enroll page — which, depending on enrollment state, is EITHER
 * the armed #enroll-ui (no key on the device) OR the "Already Enrolled"
 * #enroll-existing panel (a key is present).  EnrollApp.on_load only arms
 * #enroll-button in the no-key branch, so we must accept either coherent end
 * state, not unconditionally wait for the button to arm.
 */
async function assertInboxEnrollAffordance(page: Page) {
  // No in-page enroll button on the inbox anymore (it would vanish on has-key).
  expect(await page.locator('#enroll-button').count(), 'inbox must not host an in-page enroll button').toBe(0);
  // A static link to /enroll/ is present and points at the dedicated page.
  const link = page.locator('a.enroll-link');
  await expect(link, 'inbox must show an enroll link').toBeVisible();
  const href = await link.getAttribute('href');
  expect(href, 'enroll link must target the /enroll/ page').toMatch(/enroll\/?$/);
  // It is usable: following it lands on the working, coherent enroll page.
  await link.click();
  await page.waitForURL(/\/enroll\/?$/, { timeout: 30_000 });
  // Coherent in EITHER state: armed enroll UI (no key) OR the already-enrolled
  // panel (has key).  Poll until exactly one of the two coherent panels shows.
  await expect
    .poll(
      async () => {
        const armed = await page.evaluate(() => {
          const b = document.getElementById('enroll-button') as
            | (HTMLElement & { __craneBound?: boolean })
            | null;
          const ui = document.getElementById('enroll-ui');
          return !!(b && b.__craneBound === true && ui && getComputedStyle(ui).display !== 'none');
        });
        const existing = await page.locator('#enroll-existing').isVisible().catch(() => false);
        if (armed) return 'armed';
        if (existing) return 'existing';
        return 'pending';
      },
      { timeout: 60_000, message: 'enroll page never reached a coherent state (armed UI or already-enrolled panel)' },
    )
    .not.toBe('pending');
}

test('Facet A inbox — NO-KEY state: loads clean, enroll affordance present + usable', async ({ page }) => {
  const sink = attachErrorCapture(page);
  // Fresh origin: no reader key enrolled.
  await page.goto('/', { waitUntil: 'domcontentloaded' });
  // crane_decrypt runs on the inbox (per-post status); its inbox branch only
  // touches #inbox-status-msg and reads the absent #ciphertext — it must not
  // error.  Give the module a moment to run on-load before asserting clean.
  await page.locator('#main').waitFor({ state: 'attached' });
  await assertInboxEnrollAffordance(page);
  expect(sink.fatal, `unexpected console/page errors on the inbox (no-key):\n${sink.fatal.join('\n')}`).toEqual([]);
});

test('Facet A inbox — HAS-KEY state: after enrolling, the inbox stays coherent (button NOT vanished)', async ({ context, page }) => {
  const sink = attachErrorCapture(page);
  let cdp: CDPSession | undefined;
  ({ cdp } = await addVirtualAuthenticator(context, page, {
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
  }));
  try {
    // Enroll a reader key first (so the inbox is now in the has-key state).
    await page.goto('/enroll/', { waitUntil: 'domcontentloaded' });
    await waitForArmed(page, 'enroll-button');
    await page.locator('#enroll-button').click();
    await expect(page.locator('#enroll-result')).toBeVisible({ timeout: 60_000 });
    const kid = (await page.locator('#reader-key-id').textContent())?.trim() || '';
    expect(kid).toMatch(/^[0-9a-f]{12}$/);
    createdKids.add(kid);
    const readerKeys = await readIdbStore(page, 'reader-keys');
    expect(readerKeys.length, 'a reader key is enrolled for the has-key inbox state').toBe(1);

    // Now the inbox: with a key present, the OLD code hid #enroll-ui and showed
    // nothing (the absent #enroll-existing) — the button vanished with no
    // replacement.  The link affordance must instead be present + usable, and
    // crane_decrypt's "readable with your key" status may appear.
    await page.goto('/', { waitUntil: 'domcontentloaded' });
    await page.locator('#main').waitFor({ state: 'attached' });
    // crane_decrypt's inbox branch sets #inbox-status-msg when a key is saved in
    // sessionStorage; with a key only in IndexedDB the message may be empty —
    // either way the element must exist and the affordance must be coherent.
    await expect(page.locator('#inbox-status-msg')).toBeAttached();
    await assertInboxEnrollAffordance(page);
    expect(sink.fatal, `unexpected console/page errors on the inbox (has-key):\n${sink.fatal.join('\n')}`).toEqual([]);
  } finally {
    if (cdp) await cdp.detach().catch(() => {});
  }
});

// ===========================================================================
// DECRYPT FAILURE (not a recipient).  Enroll key A, then decrypt a post that is
// encrypted to a DIFFERENT key B (a foreign recipient).  DecryptApp.try_keys_aux
// finds no wrap for A, so do_decrypt must surface a VISIBLE #decrypt-error
// ("not a recipient") AND clear #decrypt-status (no lingering "Decrypting...").
// This is the silent-decrypt bug class: the error text was set but the element
// was display:none, and the status never cleared, so a failed decrypt looked
// like a hang/no-op.
// ===========================================================================
test('Facet A decrypt FAILURE — not a recipient: #decrypt-error VISIBLE + #decrypt-status cleared', async ({ context, page }) => {
  const sink = attachErrorCapture(page);
  let cdp: CDPSession | undefined;
  ({ cdp } = await addVirtualAuthenticator(context, page, {
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
  }));
  try {
    // ---- Enroll key A in the browser. ----
    await page.goto('/enroll/', { waitUntil: 'domcontentloaded' });
    await waitForArmed(page, 'enroll-button');
    await page.locator('#enroll-button').click();
    await expect(page.locator('#enroll-result')).toBeVisible({ timeout: 60_000 });
    const kidA = (await page.locator('#reader-key-id').textContent())?.trim() || '';
    expect(kidA).toMatch(/^[0-9a-f]{12}$/);
    createdKids.add(kidA);

    // ---- Encrypt the fixture to a FOREIGN key B (not A), re-render. ----
    const foreign = await generateForeignRecipient();
    expect(foreign.kid).not.toBe(kidA); // genuinely a different recipient
    createdKids.add(foreign.kid); // cleanup keys/<foreignKid>.pub in afterEach
    encryptFixturePost({
      kid: foreign.kid,
      uncompressedPubHex: foreign.uncompressedPubHex,
      slug: SLUG,
      markdown: FIXTURE_MD,
    });
    reRenderSite();

    // ---- Attempt decrypt with key A -> must FAIL visibly. ----
    await page.goto(`/${SLUG}/`, { waitUntil: 'domcontentloaded' });
    await waitForArmed(page, 'decrypt-button');
    // Pre-click: error empty (hidden via :empty), content hidden.
    await expect(page.locator('#decrypt-error')).toHaveText('');
    await expect(page.locator('#decrypted-content')).toBeHidden();

    await page.locator('#decrypt-button').click();

    // The error becomes VISIBLE with a "not a recipient" message (the :empty CSS
    // rule reveals it the moment ROCQ sets its textContent), and #decrypt-status
    // is cleared — no lingering "Decrypting...".  A hung/silent failure would
    // leave the error hidden/empty and the status stuck, timing out here.
    const err = page.locator('#decrypt-error');
    await expect(err).toBeVisible({ timeout: 60_000 });
    await expect(err).toContainText(/not a recipient/i);
    await expect(page.locator('#decrypt-status')).toHaveText('', { timeout: 30_000 });
    // The decrypted content never reveals, and no plaintext leaks anywhere.
    await expect(page.locator('#decrypted-content')).toBeHidden();
    const bodyText = (await page.locator('#real-body').textContent()) || '';
    expect(bodyText).not.toContain(PLAINTEXT_MARKER);

    // No uncaught WASM aborts / console errors / unhandled rejections: a VISIBLE,
    // surfaced "not a recipient" is the app working as designed, not an error.
    expect(sink.fatal, `unexpected console/page errors on decrypt failure:\n${sink.fatal.join('\n')}`).toEqual([]);
  } finally {
    if (cdp) await cdp.detach().catch(() => {});
  }
});
