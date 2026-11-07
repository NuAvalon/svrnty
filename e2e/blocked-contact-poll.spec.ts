import { test, expect, type Page } from '@playwright/test';
import { seedAliceWithBob, depositNote } from './fixtures/deposit-note';
import { depositContactUpdate } from './fixtures/deposit-contact-update';

/**
 * BLOCKED-CONTACT POLL — the live-poll block semantics end to end (Archie's pre-launch ask).
 *
 * The block fix on dev (consume-mailbox.ts: a blocked contact's frames are TERMINAL — dropped + acked,
 * never held, never replayed on unblock) has unit coverage for every piece but nothing that drives the
 * REAL poll loop in a real browser. These four specs do: a genuine §5 canonical Bob seeded into Alice's
 * book, real signed+sealed contact.updates / NoteWireV0s deposited to the same /api/relay/envelope
 * mailbox the shell poll reads, and the block/unblock driven through the REAL UI path (detail dialog →
 * Actions → Block → trust-action-confirm) so the record's `blocked` flag lands exactly as it does for a
 * human — admitContact then gates every subsequent inbound frame from that sender.
 *
 * What this proves, per case:
 *   1. A blocks B, B renames → A's card keeps the old name (contact-update-blocked: terminal drop).
 *   2. Unblock → NOTHING replays: blocked-era frames were acked away, not held for later.
 *   3. B's NEXT update (fresh, post-unblock) applies live — the book heals forward only.
 *   4. A note from blocked B → NO inbox entry (note-blocked-sender: terminal drop, anti-oracle I-1).
 *
 * GROUND TRUTH = the rendered list, by design: contact records are encrypted at rest (enc_version/
 * iv/ciphertext rows) and "A's card keeps the old name" is a render claim anyway, so the specs assert
 * on the contact rows — the same surface a human sees — plus the notes-inbox testids for case 4.
 *
 * OCCLUSION FINDING (flagged in the PR, not fixed here): the trust-action confirm that opens from the
 * contact detail dialog's Actions menu is painted UNDER the still-mounted radix detail dialog — the
 * z-80 portal overlay loses elementFromPoint to the z-50 dialog, so no pointer click can land on the
 * confirm button (PR#221 class, resurfacing on this path). The specs therefore dispatchEvent the real
 * React handler chain (onConfirm → applyTrustAction → handleSetBlocked) — the same code a click runs —
 * and the occlusion itself is reported for the fleet to fix on the glass side.
 */

// Genesis a receiver to an unlocked in-memory session. Mirrors notes-roundtrip.spec.ts.
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

async function openContactsTab(page: Page) {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
}

async function openNotesTab(page: Page) {
  const notesTab = page.getByTestId('tab-notes');
  await expect(notesTab).toBeVisible({ timeout: 20_000 });
  await notesTab.click();
  await expect(page.getByTestId('notes-inbox')).toBeVisible();
}

/** The contact row carrying a display name — row buttons render the name, so hasText binds it. */
function contactRow(page: Page, name: string) {
  return page.getByTestId('contact-row').filter({ hasText: name });
}

/**
 * Click a contact row by name → detail dialog → Actions dropdown → Block/Unblock → confirm.
 * Mirrors remove-contact-confirm.spec.ts, plus the occlusion workaround above: the confirm button is
 * under the still-mounted detail dialog (verified via elementFromPoint), so dispatchEvent drives the
 * real handler chain — the click path and this path converge on applyTrustAction → handleSetBlocked.
 */
async function trustActionViaUi(page: Page, contactName: string, item: 'Block' | 'Unblock') {
  const row = contactRow(page, contactName);
  await expect(row).toBeVisible({ timeout: 10_000 });
  const card = page.getByTestId('contact-action-card');
  // The book card TOGGLES on row click, and an already-open card carries a STALE selectedContact
  // (confirmTarget reads it — a pre-block snapshot has blocked unset, so an unblock confirm would
  // silently no-op 'not-blocked'). Force a fresh open: toggle closed if open, then open.
  if (await card.isVisible().catch(() => false)) {
    await row.click(); // toggles the stale card closed
    await expect(card).toHaveCount(0);
  }
  await row.click();
  if (!(await card.isVisible().catch(() => false))) await row.click(); // it toggled shut — reopen
  await expect(card).toBeVisible({ timeout: 10_000 });
  await card.getByTestId('card-actions-toggle').click();
  // The card menu labels the item 'Block' for BOTH directions (the confirm kind toggles inside);
  // the detail dialog labels it by state. Match either.
  const menuName = item === 'Unblock' ? /^(un)?block$/i : /^block$/i;
  await page.getByRole('menuitem', { name: menuName }).first().click();
  const confirm = page.getByTestId('trust-action-confirm');
  await expect(confirm).toBeVisible();
  await expect(confirm).toHaveAttribute('data-action-kind', item.toLowerCase());
  const btn = confirm.getByTestId('trust-action-confirm-btn');
  const occluded = await btn.evaluate((el) => {
    const r = el.getBoundingClientRect();
    const top = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
    return top !== el && !el.contains(top);
  });
  if (occluded) console.log(`OCCLUSION: detail dialog covers ${item} confirm — dispatchEvent used (flagged in PR)`);
  await btn.dispatchEvent('click');
  await expect(confirm).toHaveCount(0);
  // The detail dialog may still be mounted after the confirm — Escape closes it (radix onOpenChange).
  await page.keyboard.press('Escape');
}

/** Show the blocked list: the book-options ⋯ menu → 'View blocked contacts'. */
async function showBlockedList(page: Page) {
  await page.getByLabel('Book options').click();
  await page.getByRole('menuitem', { name: /view blocked contacts/i }).click();
}

/** Back to the default list: the same menu → 'Hide blocked contacts'. */
async function hideBlockedList(page: Page) {
  await page.getByLabel('Book options').click();
  await page.getByRole('menuitem', { name: /hide blocked contacts/i }).click();
}

/** Wait for the always-on poll to run several cycles (deposit → consume → persist/drop). */
async function pollCycles(page: Page, ms = 10_000) {
  await page.waitForTimeout(ms);
}

test.describe('blocked-contact poll', () => {
  test('a blocked sender\'s rename never touches the card — the contact.update is dropped', async ({ page, request }) => {
    test.setTimeout(120_000);
    await genesisReceiver(page, 'Alice BlockRename');
    const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);

    await openContactsTab(page);
    await trustActionViaUi(page, 'Bob', 'Block');

    // A blocked contact is filtered out of the default list — that's the honest "the block landed"
    // (records are encrypted at rest; the filter IS the flag's visible effect).
    await expect(contactRow(page, 'Bob')).toHaveCount(0);
    await showBlockedList(page);
    await expect(contactRow(page, 'Bob')).toBeVisible();

    // Bob renames himself on the wire — a REAL signed+sealed contact.update to Alice's mailbox.
    const status = await depositContactUpdate(request, {
      sender: bob,
      recipientFingerprint: aliceFp,
      recipientPublicKeyArmored: aliceArmoredPub,
      fields: { changedFields: ['display_name'], delta: { display_name: 'Bob (NEW name)' }, version: 1 },
    });
    expect(status).toBe(200);

    await pollCycles(page);

    // The card still carries the old name — the update was terminal-dropped, not applied.
    await expect(contactRow(page, 'Bob')).toBeVisible();
    await expect(page.getByText('Bob (NEW name)')).toHaveCount(0);
  });

  test('unblocking replays nothing — blocked-era frames were acked away, not held', async ({ page, request }) => {
    test.setTimeout(120_000);
    await genesisReceiver(page, 'Alice NoReplay');
    const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);

    await openContactsTab(page);
    await trustActionViaUi(page, 'Bob', 'Block');

    // While blocked, Bob sends a rename AND a note — both must die at the admit gate.
    expect(
      await depositContactUpdate(request, {
        sender: bob,
        recipientFingerprint: aliceFp,
        recipientPublicKeyArmored: aliceArmoredPub,
        fields: { changedFields: ['display_name'], delta: { display_name: 'Bob (NEW name)' }, version: 1 },
      }),
    ).toBe(200);
    const note = await depositNote(request, {
      sender: bob,
      recipientFingerprint: aliceFp,
      recipientPublicKeyArmored: aliceArmoredPub,
      fields: { body: 'sent while blocked — must never surface' },
    });
    expect(note.status).toBe(200);
    await pollCycles(page);

    // Unblock — the honest UI path back (blocked list → Actions → Unblock → confirm).
    await showBlockedList(page);
    await trustActionViaUi(page, 'Bob', 'Unblock');
    // Back on the default list — still under the OLD name, nothing replayed.
    await hideBlockedList(page);
    await expect(contactRow(page, 'Bob')).toBeVisible({ timeout: 10_000 });

    // Several more cycles: if anything had been held, this is where it would replay.
    await pollCycles(page);

    await expect(page.getByText('Bob (NEW name)')).toHaveCount(0);
    await expect(page.getByTestId(`notes-thread-${note.thread_id}`)).toHaveCount(0);
    await expect(page.getByTestId(`notes-bubble-${note.note_id}`)).toHaveCount(0);
  });

  test('a contact\'s first update AFTER the unblock applies live — the book heals forward', async ({ page, request }) => {
    test.setTimeout(120_000);
    await genesisReceiver(page, 'Alice HealsForward');
    const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);

    await openContactsTab(page);
    await trustActionViaUi(page, 'Bob', 'Block');
    expect(
      await depositContactUpdate(request, {
        sender: bob,
        recipientFingerprint: aliceFp,
        recipientPublicKeyArmored: aliceArmoredPub,
        fields: { changedFields: ['display_name'], delta: { display_name: 'Bob (BLOCKED-era name)' }, version: 1 },
      }),
    ).toBe(200);
    await pollCycles(page);

    await showBlockedList(page);
    await trustActionViaUi(page, 'Bob', 'Unblock');
    await hideBlockedList(page);
    await expect(contactRow(page, 'Bob')).toBeVisible({ timeout: 10_000 });

    // Bob's NEXT rename — a fresh, signed, correctly-versioned update — must apply.
    expect(
      await depositContactUpdate(request, {
        sender: bob,
        recipientFingerprint: aliceFp,
        recipientPublicKeyArmored: aliceArmoredPub,
        fields: { changedFields: ['display_name'], delta: { display_name: 'Bob (post-unblock)' }, version: 2 },
      }),
    ).toBe(200);
    await pollCycles(page);

    // The row repaints with the post-unblock name (live-apply) — and never the blocked-era one.
    // The idle backoff ceiling is 15s; give the live-apply window well past it.
    await expect(contactRow(page, 'Bob (post-unblock)')).toBeVisible({ timeout: 45_000 });
    await expect(page.getByText('Bob (BLOCKED-era name)')).toHaveCount(0);
  });

  test('a note from a blocked sender never reaches the inbox — no thread, no badge', async ({ page, request }) => {
    test.setTimeout(120_000);
    await genesisReceiver(page, 'Alice BlockNote');
    const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);

    await openContactsTab(page);
    await trustActionViaUi(page, 'Bob', 'Block');

    const note = await depositNote(request, {
      sender: bob,
      recipientFingerprint: aliceFp,
      recipientPublicKeyArmored: aliceArmoredPub,
      fields: { body: 'blocked sender — this must not appear' },
    });
    expect(note.status).toBe(200); // blind relay still queues it — the admit gate is receiver-side

    await openNotesTab(page);
    await pollCycles(page, 7_000);

    const panel = page.getByTestId('notes-inbox');
    // No badge, no thread, no bubble, no body — the drop is silent by design (I-1).
    await expect(page.getByRole('tab', { name: 'Chat, new messages', exact: true })).toHaveCount(0);
    await expect(panel.getByTestId(`notes-thread-${note.thread_id}`)).toHaveCount(0);
    await expect(panel.getByTestId(`notes-bubble-${note.note_id}`)).toHaveCount(0);
    await expect(panel.getByText('blocked sender — this must not appear')).toHaveCount(0);
  });
});
