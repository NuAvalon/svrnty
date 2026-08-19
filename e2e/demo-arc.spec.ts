import { test, expect, type Page, type BrowserContext } from '@playwright/test';
import path from 'path';

// ─────────────────────────────────────────────────────────────────────────────────────
// svrnty 9/10 DEMO ARC (§9.7) — the whole story as one end-to-end journey.
//
// Fable's §9.7 named deliverable. The arc is Hypatia's demo-script v1
// (shared/outbox/hypatia/svrnty_015_demo_script_v1.md, KB #85999): five beats, each bound to
// its HONEST wired-state — the demo shows only what ships (a false demo is a false claim).
//
//   Beat 1 · the gray sea    — your relationships live in someone else's DB → real vCard import.
//   Beat 2 · genesis         — an identity made from a piece of you, on-device.
//   Beat 3 · handshake bloom  — a card given by hand; the edge lights across two devices.
//   Beat 4 · the living edge  — Bob edits his card → Alice's entry self-updates.
//   Beat 5 · the candle       — what survives the fire: export the whole self (no second Alexandria).
//
// OWNERSHIP / DIVISION (Archie #116268):
//   • Hypatia — this arc skeleton (owns the arc).
//   • Athena  — ceremony/export testids (beats 3 & 5) + un-stubs beat 4 when her consume→apply
//               caller lands (return_channel_caller_build_plan.md).
//   • Archie  — return-channel relay-semantics (the mailbox/poll/ack HOW).
//   • Apollo  — the BroadcastChannel repaint / last_interaction-reset that makes beat 4 LIVE.
//   • Coexists with e2e/return-channel.spec.ts (Flint's gate; self-skips until endpoints land).
//
// WIRE-STATE (verified on main, 2026-08-18 — see KB #86234):
//   Beats 1–2 : LIVE — wired here (mirror import.spec.ts / identity.spec.ts). This test PASSES.
//   Beat 3    : SCAFFOLDED — a real two-context handshake through the client-side relay; test.fixme
//               until the relay-URL extraction (the key rides the URL FRAGMENT, not the displayed
//               short link) is confirmed in CI, or Athena adds a testid exposing the full join URL.
//   Beat 4    : NOT WIRED — verify+apply primitives (foldLivingWins) exist but have ZERO callers and
//               the relay is a single-use dead-drop → Bob's edit reaches Alice neither live nor on
//               reload. test.fixme until Athena's caller + Apollo's repaint land.
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
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('your@email.com').fill(email);
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /begin anew/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts' })).toBeVisible({ timeout: 15_000 });
}

// Beat 1 — the gray sea: import a multi-contact vCard, see the dedup preview BEFORE any write
// (confirm-gate, never silent), confirm. Mirrors import.spec.ts (proven assertions only).
async function importGraySea(page: Page) {
  await page.getByRole('tab', { name: 'Contacts' }).click();
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
  // SCAFFOLDED + honestly skipped. Real shape: Alice opens the Ceremony tab → the app auto-creates a
  // one-time relay handshake (QR + short link off one code); Bob, on his own device/context, opens the
  // /c/<code>#<key> link, receives her signed card, and the trust edge goes live in his book.
  // ACTIVATION (Athena beat-3 lane): confirm extractJoinPath in CI — the decryption key rides the URL
  // FRAGMENT (#…), which the DISPLAYED short link omits; we read the full relay.url off the clipboard via
  // the "Copy link" button. If clipboard is flaky in CI, add a data-testid exposing the full join URL.
  test.fixme('beat 3 (scaffolded): a card given by hand blooms an edge across two devices', async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alice = await aliceCtx.newPage();
    const bob = await bobCtx.newPage();

    await genesis(alice, 'Alice E2E', 'alice-e2e@example.test');
    await genesis(bob, 'Bob E2E', 'bob-e2e@example.test'); // the joiner needs an identity first

    // Alice: enter the ceremony → the handshake step auto-creates the relay → grab the full join URL.
    await alice.getByRole('tab', { name: 'Ceremony' }).click();
    const joinPath = await extractJoinPath(aliceCtx, alice);

    // Bob: open the link on his device → walk the joiner steps → the edge persists.
    await bob.goto(joinPath);
    await bob.getByRole('button', { name: /receive their card/i }).click();
    await bob.getByRole('button', { name: /add to my network/i }).click();
    await bob.getByRole('button', { name: /the facet is lit/i }).click();

    // The bloom: Alice now appears in Bob's constellation (a persisted edge).
    await bob.getByRole('tab', { name: 'Contacts' }).click();
    await expect(bob.getByText('Alice E2E')).toBeVisible();

    await aliceCtx.close();
    await bobCtx.close();
  });

  // ── Beat 4: the living edge — Bob edits → Alice self-updates ──────────────────────────
  // NOT WIRED. The merge primitives (foldLivingWins / applyVerifiedContactUpdate) exist but have zero
  // callers, and the relay is a single-use dead-drop with no return channel — Bob's edit reaches Alice
  // neither live nor on reload. Un-stub when Athena's consume→apply caller lands + Apollo's BroadcastChannel
  // repaint / last_interaction-reset makes it live.
  test.fixme('beat 4 (pending caller): Bob edits his card → Alice\'s entry self-updates', async () => {
    // INTENDED (once wired):
    //   1. On the established edge, Bob edits his display name / adds a channel → contact.update to relay.
    //   2. Alice's client polls her mailbox → verifyIncomingContactUpdate → applyVerifiedContactUpdate
    //      (foldLivingWins: her attested fields win; his net-new fields merge in).
    //   3. Alice's entry repaints WITHOUT a reload (BroadcastChannel) → assert Bob's new value in her book.
    //   HONESTY: narrate "live" only if poll+repaint is wired; otherwise the honest beat is
    //   "pull to refresh — there it is". Never script a self-update the build can't perform.
  });

  // ── Beat 5: the candle — export the whole self ───────────────────────────────────────
  // The exit right made visible: vCard-all export + full encrypted-vault export/restore (Fable §9.3).
  // Un-stub when Athena adds export testids to SecureExportDialog (SecureImportExportDialogs.tsx).
  test.fixme('beat 5 (pending export testids): the candle — export the whole (vCard + encrypted vault)', async () => {
    // INTENDED: open export → trigger vCard-all + encrypted-vault export → assert a download for each
    //   (await page.waitForEvent('download')). What survives the fire — no second Alexandria.
  });
});

// Reads the full join URL (with the key fragment) off the clipboard and returns the /c/<code>#<key>
// path, so the joiner context can open it on the test's own origin (baseURL). The displayed short link
// omits the key fragment by design; the "Copy link" button copies the full relay.url.
async function extractJoinPath(ctx: BrowserContext, page: Page): Promise<string> {
  await ctx.grantPermissions(['clipboard-read', 'clipboard-write']);
  await expect(page.getByRole('button', { name: /copy link/i })).toBeVisible({ timeout: 15_000 });
  await page.getByRole('button', { name: /copy link/i }).click();
  const fullUrl: string = await page.evaluate(() => navigator.clipboard.readText());
  const m = fullUrl.match(/\/c\/[^#\s"']+#[^\s"']+/);
  if (!m) throw new Error(`extractJoinPath: no /c/<code>#<key> found in clipboard: "${fullUrl}"`);
  return m[0];
}
