import { test, expect, type Page, type BrowserContext } from '@playwright/test';
import path from 'path';
import { seedAliceWithBob, depositContactUpdate, depositRawBlob } from './fixtures/deposit-contact-update';

// ─────────────────────────────────────────────────────────────────────────────────────
// svrnty 9/10 DEMO ARC (§9.7) — the whole story as one end-to-end journey.
//
// The §9.7 named deliverable. The arc is the demo-script v1:
// five beats, each bound to
// its HONEST wired-state — the demo shows only what ships (a false demo is a false claim).
//
//   Beat 1 · the gray sea    — your relationships live in someone else's DB → real vCard import.
//   Beat 2 · genesis         — an identity made from a piece of you, on-device.
//   Beat 3 · handshake bloom  — a card given by hand; the edge lights across two devices.
//   Beat 4 · the living edge  — Bob edits his card → Alice's entry self-updates.
//   Beat 5 · the candle       — what survives the fire: export the whole self (no second Alexandria).
//
// MOVING PARTS:
//   • ceremony/export testids (beats 3 & 5) + un-stubs beat 4 when the consume→apply
//     caller lands.
//   • return-channel relay-semantics (the mailbox/poll/ack HOW).
//   • the BroadcastChannel repaint / last_interaction-reset that makes beat 4 LIVE.
//   • Coexists with e2e/return-channel.spec.ts (self-skips until endpoints land).
//
// WIRE-STATE (verified on main, 2026-08-18):
//   Beats 1–2 : LIVE — wired here (mirror import.spec.ts / identity.spec.ts). This test PASSES.
//   Beat 3    : LIVE (2026-08-21) — a real two-context handshake through the client-side relay:
//               Alice's Grow join-link (key on the URL fragment) → Bob joins → the edge blooms.
//               Runs+passes in e2e-prod (2.9s), skips clean in dev.
//   Beat 4    : LIVE (2026-08-19) — the return-channel consume caller + the live-apply
//               subscription. RECEIVE side on the wire (a real signed deposit → Alice consumes/verifies/
//               applies → data-live="push"); SEND-from-UI still simulated (Bob's client caller unbuilt).
//   Beat 5    : PENDING TESTIDS — SecureExportDialog exists; test.fixme until export testids land.
//
// HARD EXCLUSIONS (never demoed — a falsely-promised safety feature is a HARM, not a UX gap):
//   summon/duress "burns when in danger" · cross-relay peer-reach · rebuilding-from-shards
//   (the tear is the GIVE side only). See the demo-script's load-bearing exclusions.
// ─────────────────────────────────────────────────────────────────────────────────────

const VCF = path.join(__dirname, 'fixtures', 'contacts.vcf'); // 3 grays: Grace / Ada / Alan

// Beat 2 — genesis, as a reusable helper (mirrors identity.spec.ts / import.spec.ts). Each call runs
// in a fresh context ⇒ empty IndexedDB, a real on-device identity built from scratch.
async function genesis(page: Page, name: string, email: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  // §1: genesis is name + passphrase ONLY — no email field, no verification.
  await expect(page.getByPlaceholder('your@email.com')).toHaveCount(0);
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
}

// Beat 1 — the gray sea: import a multi-contact vCard, see the dedup preview BEFORE any write
// (confirm-gate, never silent), confirm. Mirrors import.spec.ts (proven assertions only).
async function importGraySea(page: Page) {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await page.getByTestId('import-contacts-trigger').click();
  await expect(page.getByTestId('import-contacts-dialog')).toBeVisible();
  await page.getByTestId('vcf-input').setInputFiles(VCF);
  await expect(page.getByTestId('import-preview')).toBeVisible();
  await expect(page.getByTestId('fresh-count')).toHaveText('3');
  await page.getByTestId('import-confirm').click();
  await expect(page.getByTestId('import-done')).toBeVisible();
  await page.getByRole('button', { name: /^Done$/ }).click();
}

test.describe('svrnty 9/10 demo arc (§9.7)', () => {
  // ── Beats 1–2: the wired foundation ─────────────────────────────────────────────────
  // The emotional arc opens on the gray sea (the wound) then genesis (your own identity); functionally
  // the identity must exist before contacts can land, so genesis runs first here.
  test('beats 1–2 (wired): genesis, then the gray sea imports under the confirm-gate', async ({ page }) => {
    await genesis(page, 'Alice E2E', 'alice-e2e@example.test'); // Beat 2 — identity from a piece of you
    await importGraySea(page);                                 // Beat 1 — the gray sea, honestly deduped
  });

  // ── Beat 3: the handshake bloom (two devices, one relay) ─────────────────────────────
  // LIVE. Real shape: Alice opens Grow → the app auto-creates a
  // one-time relay handshake (QR + short link off one code); Bob, on his own device/context, opens the
  // /c/<code>#<key> link, receives her signed card, and the trust edge goes live in his book.
  // ACTIVATION SATISFIED: extractJoinPath confirmed in CI (the key rides the URL fragment; read off the
  // Copy-link clipboard).
  test('beat 3: a card given by hand blooms an edge across two devices', async ({ browser }) => {
    test.skip(!process.env.E2E_PROD, 'beat-3 needs a prod build — StrictMode breaks the joiner under next dev (gap#1)');
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alice = await aliceCtx.newPage();
    const bob = await bobCtx.newPage();

    await genesis(alice, 'Alice E2E', 'alice-e2e@example.test');
    await genesis(bob, 'Bob E2E', 'bob-e2e@example.test'); // the joiner needs an identity first

    // Alice: Grow → the handshake auto-creates the relay → grab the full join URL.
    await alice.getByRole('button', { name: /^Grow$/i }).click();
    const joinPath = await extractJoinPath(aliceCtx, alice);

    // Bob: open the link on his device → walk the joiner steps → the edge persists.
    await bob.goto(joinPath);
    await bob.getByRole('button', { name: /receive their card/i }).click();
    await bob.getByRole('button', { name: /add to my network/i }).click();
    // Joiner /c/ navigation drops the in-memory session key — persistEdge prompts
    // to unlock so the return-channel deposit can be signed (R1). Then lattice.
    await bob.getByPlaceholder('Your passphrase').fill('e2e-passphrase-1234');
    await bob.getByRole('button', { name: /^unlock/i }).click();
    await bob.getByRole('button', { name: /the facet is lit/i }).click();

    // The bloom: Alice now appears in Bob's constellation. The joiner is a standalone /c/<code> page with no
    // app tab-nav, and a fresh load re-locks Bob's identity → go home, unlock, then open Contacts.
    await bob.goto('/');
    await bob.getByPlaceholder('Enter passphrase').fill('e2e-passphrase-1234');
    await bob.getByRole('button', { name: /unlock/i }).click();
    await bob.getByRole('tab', { name: 'Contacts', exact: true }).click();
    await expect(bob.getByText('Alice E2E')).toBeVisible();

    await aliceCtx.close();
    await bobCtx.close();
  });

  // ── Beat 4: the living edge — Bob edits → Alice's entry self-updates LIVE ─────────────
  // WIRED (2026-08-19): the return-channel consume caller (poll→decrypt→verify→apply→persist→ack)
  // + the ContactManagement live-apply subscription (data-live="push" on reason:'live-apply'). THREE
  // honesty hinges are baked in: (1) LIVE-not-reload — data-live="push" fires ONLY on a real incoming apply,
  // so asserting it IS the proof the update arrived live (a reload or local edit can never set it). (2)
  // SEND-from-UI is NOT wired yet (Bob's client caller doesn't exist — only the endpoint); we SIMULATE his
  // send with a REAL signed+encrypted deposit (fixture). (3) SECURITY is CONSUME-side: the /api/relay/envelope
  // deposit is identity-blind by design (the anti-oracle); Alice verifies Bob's signature + only accepts
  // updates from a contact already in her book — never "the relay authenticated the sender." A garbage
  // deposit must be rejected on consume (negative test below).
  test('beat 4: Bob edits his card → Alice\'s entry self-updates LIVE (no reload)', async ({ page, request }) => {
    await genesis(page, 'Alice E2E', 'alice-e2e@example.test');   // Alice's key is unlocked IN MEMORY, poll running
    await page.getByRole('tab', { name: 'Contacts', exact: true }).click();    // ensure ContactManagement (live subscription) is mounted
    // Extract Alice's real pubkey from her genesis identity + seed Bob into her book @ epoch 0 (I-2 whitelist).
    // ⚠ NO RELOAD after this — a refresh would relock her key → the poll no-ops → silent red.
    const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);

    // Simulate Bob's send (his client caller isn't wired — only the endpoint): a REAL signed + encrypted
    // contact.update to Alice's mailbox. The blind relay just queues it; the security gate is Alice's consume.
    const status = await depositContactUpdate(request, {
      sender: bob,
      recipientFingerprint: aliceFp,
      recipientPublicKeyArmored: aliceArmoredPub,
      fields: { changedFields: ['display_name'], delta: { display_name: 'Bob (NEW name)' } },
    });
    expect(status).toBe(200);

    // Alice's caller polls (≤5s) → consumes → verifies Bob's sig + in-book whitelist → applies → her row
    // repaints LIVE. data-live="push" fires only on reason:'live-apply', so this assertion IS the honesty
    // hinge — a dim relationship coming back to life, live, on the same screen.
    await expect(
      page.getByTestId('contact-row').filter({ hasText: 'Bob (NEW name)' }),
    ).toHaveAttribute('data-live', 'push', { timeout: 10_000 });
  });

  // Beat 4 negative — the honest guard: an unauthorized / garbage deposit must NEVER repaint. The blind
  // relay 200s the deposit (identity-blind by design); Alice's CONSUME decrypt/verify rejects it → no push.
  test('beat 4 (negative): a garbage deposit does not surface as a live update', async ({ page, request }) => {
    await genesis(page, 'Alice E2E', 'alice-e2e@example.test');
    await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
    const { aliceFp } = await seedAliceWithBob(page);
    const status = await depositRawBlob(request, { recipientFingerprint: aliceFp, blob: 'garbage-not-a-signed-update' });
    expect(status).toBe(200);            // the blind relay queues it; the only gate is Alice's consume-verify
    await page.waitForTimeout(6_000);    // give the poll a couple of intervals to (correctly) do nothing
    await expect(page.locator('[data-testid="contact-row"][data-live="push"]')).toHaveCount(0);
  });

  // ── Beat 5: the candle — export the whole self ───────────────────────────────────────
  // The exit right made visible (§9.3). "What survives the fire" has two halves:
  //   • encrypted-vault export — CUR-4: auth gate → vault passphrase → fleet packVault (v4).
  //   • vCard-all export — Contacts → More → Export all as vCard (auth-gated).
  // Honesty gate: we test only what SHIPS. A green here means an encrypted .svrnty vault really leaves the
  // device (real download event) — no server, no second Alexandria.
  test('beat 5 (vault export): the candle — the whole encrypted vault survives the fire', async ({ page }) => {
    await genesis(page, 'Alice E2E', 'alice-e2e@example.test');
    await page.getByRole('tab', { name: 'Identity' }).click();
    await page.getByRole('button', { name: /full backup/i }).click();

    // CUR-4 export-behind-auth: re-enter unlock passphrase before the vault packer.
    await expect(page.getByRole('heading', { name: /confirm it/i })).toBeVisible();
    await page.getByPlaceholder('Your everyday unlock passphrase').fill('e2e-passphrase-1234');
    await page.getByRole('button', { name: /^Continue$/ }).click();

    // Fleet packVault floor: 12+ char vault passphrase (not the unlock passphrase).
    await expect(page.getByTestId('vault-export-dialog')).toBeVisible();
    await page.getByTestId('vault-export-passphrase').fill('vault-pass-e2e');
    await page.getByTestId('vault-export-confirm').fill('vault-pass-e2e');
    const downloadPromise = page.waitForEvent('download');
    await page.locator('#fullBackupBtn').click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/^vault-.*\.svrnty$/);
  });

  // Beat 5 (vCard-all) — portable plaintext of every relationship (auth-gated, not encrypted).
  test('beat 5 (vCard-all): export every relationship as a portable vCard', async ({ page }) => {
    await genesis(page, 'Alice E2E', 'alice-e2e@example.test');
    await importGraySea(page);
    await page.getByRole('button', { name: /more/i }).click();
    await page.getByRole('menuitem', { name: /export all as vcard/i }).click();
    await expect(page.getByRole('heading', { name: /confirm it/i })).toBeVisible();
    await page.getByPlaceholder('Your everyday unlock passphrase').fill('e2e-passphrase-1234');
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: /^Continue$/ }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/^svrnty-contacts-.*\.vcf$/);
  });
});

// Reads the full join URL (with the key fragment) off the clipboard and returns the /c/<code>#<key>
// path, so the joiner context can open it on the test's own origin (baseURL). The displayed short link
// omits the key fragment by design; the "Copy link" button copies the full relay.url.
async function extractJoinPath(ctx: BrowserContext, page: Page): Promise<string> {
  await ctx.grantPermissions(['clipboard-read', 'clipboard-write']);
  await expect(page.getByRole('button', { name: /copy link/i })).toBeVisible({ timeout: 15_000 });
  await page.getByRole('button', { name: /copy link/i }).click({ force: true });
  const fullUrl: string = await page.evaluate(() => navigator.clipboard.readText());
  const m = fullUrl.match(/\/c\/[^#\s"']+#[^\s"']+/);
  if (!m) throw new Error(`extractJoinPath: no /c/<code>#<key> found in clipboard: "${fullUrl}"`);
  return m[0];
}
