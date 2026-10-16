import { test, expect, devices, type Page } from '@playwright/test';
import {
  makeE2EIdentity,
  seedAliceWithBob,
  depositNote,
  depositRawBlob,
} from './fixtures/deposit-note';

/**
 * CLASSICAL note roundtrip — the human-open-path the friends-launch actually ships.
 *
 * notes-inbox.spec.ts proves the tab MOUNTS with honest copy/status; this proves the thing a real
 * human depends on: a note another person sends you ARRIVES, DECRYPTS, and RENDERS — end to end,
 * through the REAL app-shell live-book poll (startLiveBookPolling in app/page.tsx) and the REAL
 * over-wire note seam (noteOpenpgpDecryptor → acceptInboundNote: verifyNoteSender authn → isAdmitted →
 * putNote). Nothing is mocked: the sender is a genuine §5 canonical identity, the note is a real
 * signed + sealed (Seal-v0 CLASSICAL openpgp — NOT hybrid; sealLivingBookHybrid/@afdccbd is not on
 * main) NoteWireV0, deposited to the same /api/relay/envelope mailbox the shell poll reads.
 *
 * HONEST DELIVERY FLOOR (Flint #169814 open-Q, grounded): there is NO delivery receipt wired —
 * notes-status.ts has only not-sent / sent-unconfirmed / inbound, and statusIsHonestFloor() FORBIDS
 * "Delivered"/"Read"/"Expired" as live statuses. So this e2e proves RECEIVE + RENDER (the honest
 * "Sent — no receipt yet" floor); a "Delivered" receipt is a SEPARATE graduation (a receipt-back
 * channel), asserted-absent here so nothing ever falsely claims arrival.
 *
 * BROWSER MATRIX ([[feedback_prove_in_playwright]], refined: the USER-RELEVANT matrix, centered on
 * hardened-mobile — Vanadium is hardened Chromium): the roundtrip runs on desktop Chromium AND a
 * mobile-Chromium (Pixel-7) viewport. WebKit/iOS-Safari is a second ENGINE that needs a webkit project
 * + `npx playwright install webkit`; it is NOT covered here (flagged, not silently dropped) — a small
 * playwright.config projects change to add later, coordinated since it affects every spec.
 */

// Genesis a receiver to an unlocked in-memory session. Mirrors the proven notes-inbox.spec.ts flow.
// ⚠ NO RELOAD after this (and after seedAliceWithBob): the session unlock lives in memory only.
async function genesisReceiver(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

// Open the Notes tab and wait for the inbox glass to mount. `.click()` auto-scrolls the tab into view,
// so this works on both desktop and the narrow mobile viewport (the tab row is separate from the
// collapsible top-nav — top-nav-mobile.spec.ts confirms the tabs stay visible at 375px).
async function openNotesTab(page: Page) {
  const notesTab = page.getByTestId('tab-notes');
  await expect(notesTab).toBeVisible({ timeout: 20_000 });
  await notesTab.click();
  await expect(page.getByTestId('notes-inbox')).toBeVisible();
}

// Strip defaultBrowserType from the device descriptor — it cannot be set in a describe-level test.use
// (it would force a new worker/engine). We stay on the configured chromium project and only adopt the
// device's VIEWPORT / userAgent / isMobile / hasTouch — which is exactly the mobile-Chromium surface
// (Vanadium's family) we want to prove the render on.
const { defaultBrowserType: _ignoredBrowserType, ...pixel7Mobile } = devices['Pixel 7'];

const MATRIX: Array<{ label: string; use: Record<string, unknown> }> = [
  { label: 'desktop-chromium', use: { viewport: { width: 1280, height: 800 } } },
  { label: 'mobile-chromium (Pixel 7 — hardened-mobile center)', use: pixel7Mobile },
];

for (const variant of MATRIX) {
  test.describe(`notes roundtrip · ${variant.label}`, () => {
    test.use(variant.use);

    test('an admitted contact\'s note is received, decrypted, and rendered — honest floor, no false Delivered', async ({ page, request }) => {
      test.setTimeout(90_000);

      await genesisReceiver(page, 'Alice Roundtrip');
      // Seed Bob (a fresh canonical identity) into Alice's book so the consume-side admit (I-2) passes,
      // and get Alice's REAL receiver keys straight from her genesis'd IndexedDB. No reload after this.
      const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);

      const body = 'hey alice — proving the classical note open-path 🌱';
      const { note_id, thread_id, status } = await depositNote(request, {
        sender: bob,
        recipientFingerprint: aliceFp,
        recipientPublicKeyArmored: aliceArmoredPub,
        fields: { body },
      });
      expect(status).toBe(200); // the blind relay queues the opaque blob (it can't read it)

      // The ALWAYS-ON shell poll (bursting at 350ms for 12s post-genesis) decrypts + admits + persists
      // the note into the notes store — independent of which tab is open. Then open Notes to read it.
      await openNotesTab(page);

      // The inbound thread surfaces in the thread list within a poll+reread cycle; open it.
      const threadBtn = page.getByTestId(`notes-thread-${thread_id}`);
      await expect(threadBtn).toBeVisible({ timeout: 25_000 });
      await threadBtn.click();

      // The note BODY renders as an INBOUND bubble — the actual human-visible proof of receive.
      const bubble = page.getByTestId(`notes-bubble-${note_id}`);
      await expect(bubble).toBeVisible({ timeout: 10_000 });
      await expect(bubble).toHaveAttribute('data-direction', 'inbound');
      await expect(bubble).toContainText(body);

      // HONEST FLOOR: an inbound note carries no delivery status, and the UI never shows a live
      // "Delivered"/"Read"/"Expired" (not wired — graduates with a receipt-back channel).
      const panel = page.getByTestId('notes-inbox');
      await expect(panel.getByText(/^Delivered$/)).toHaveCount(0);
      await expect(panel.getByText(/^Read$/)).toHaveCount(0);
      await expect(panel.getByText(/^Expired$/)).toHaveCount(0);
    });

    test('a forged note (impersonating an admitted contact) and an unopenable blob are never rendered — authn + crypto gates', async ({ page, request }) => {
      test.setTimeout(90_000);

      await genesisReceiver(page, 'Alice Gatekeeper');
      const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);
      const mallory = await makeE2EIdentity('mallory'); // NOT in Alice's book — the forger

      // FORGERY: claim from_fingerprint = Bob (an ADMITTED contact), but sign with Mallory's key and
      // carry Mallory's public_key/PQ. It seals to Alice fine (she can decrypt), but verifyNoteSender
      // recomputes the canonical fp from the CARRIED (Mallory's) key ≠ bob.fp → AUTHN drop (#55). An
      // attacker who knows Bob's public fingerprint + Alice's public key STILL cannot place a note "from Bob".
      const forged = await depositNote(request, {
        sender: mallory,
        recipientFingerprint: aliceFp,
        recipientPublicKeyArmored: aliceArmoredPub,
        fields: { body: 'FORGED — this is definitely bob, trust me', claimedFrom: bob.fingerprint },
      });
      expect(forged.status).toBe(200); // the blind relay still queues it — it cannot tell it's forged

      // UNOPENABLE: a non-PGP blob deposited to Alice's mailbox → noteOpenpgpDecryptor returns null →
      // (and the contact-update decryptor too) → terminal drop. A note Alice can't open never surfaces.
      await depositRawBlob(request, {
        recipientFingerprint: aliceFp,
        blob: 'this-is-not-a-pgp-message-at-all',
      });

      await openNotesTab(page);

      // Let the always-on poll run several cycles to process + silently ack-drop BOTH (terminal, by
      // design I-1/I-2 — this is NOT silent-loss: neither is an openable, authenticated, admitted note
      // for Alice; it's the correct anti-oracle drop). There is no arrival event to await on — so we
      // wait, then assert the ABSENCE held.
      await page.waitForTimeout(7_000);

      const panel = page.getByTestId('notes-inbox');
      // Neither deposit created a thread or a bubble, and the forged body never appears anywhere.
      await expect(page.getByTestId(`notes-thread-${forged.thread_id}`)).toHaveCount(0);
      await expect(page.getByTestId(`notes-bubble-${forged.note_id}`)).toHaveCount(0);
      await expect(panel.getByText('FORGED — this is definitely bob, trust me')).toHaveCount(0);
      // No thread persisted at all → the inbox stays honestly empty.
      await expect(panel.getByTestId('notes-inbox-empty')).toBeVisible();
      // And nothing falsely claims the dropped mail arrived.
      await expect(panel.getByText(/^Delivered$/)).toHaveCount(0);
      await expect(panel.getByText(/^Read$/)).toHaveCount(0);
    });
  });
}
