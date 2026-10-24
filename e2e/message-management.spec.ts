import { test, expect, type Page } from '@playwright/test';
import {
  seedAliceWithBob,
  depositNote,
} from './fixtures/deposit-note';

/**
 * #616 message management — REAL Playwright anchors (I9/I12c + friends).
 * Source-regex tests prove a Cancel button exists; this spec proves a
 * human driving the UI gets the contract: destructive ops arm a confirm
 * bar, Cancel is the default and deletes nothing, Confirm executes.
 *
 * Honest scope: every assert reads either rendered UI or the REAL
 * IndexedDB rows (via indexedDB.open in-page) — never source text.
 */

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

async function openNotesTab(page: Page) {
  const notesTab = page.getByTestId('tab-notes');
  await expect(notesTab).toBeVisible({ timeout: 20_000 });
  await notesTab.click();
  await expect(page.getByTestId('notes-inbox')).toBeVisible();
}

/** Raw IDB read inside the page — asserts on real store state, not UI claims. */
async function idbHasNote(page: Page, fp: string, store: string, noteId: string): Promise<boolean> {
  return page.evaluate(async ([dbName, storeName, id]) => {
    const db = await new Promise<IDBDatabase>((res, rej) => {
      const r = indexedDB.open(dbName as string);
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    if (!db.objectStoreNames.contains(storeName as string)) { db.close(); return false; }
    const rows: { note_id?: string }[] = await new Promise((res, rej) => {
      const q = db.transaction(storeName as string, 'readonly').objectStore(storeName as string).getAll();
      q.onsuccess = () => res(q.result);
      q.onerror = () => rej(q.error);
    });
    db.close();
    return rows.some((r) => r.note_id === id);
  }, [`svrnty-notes-${fp}`, store, noteId]);
}

async function depositAndOpen(page: Page, request: import('@playwright/test').APIRequestContext, name: string) {
  await genesisReceiver(page, name);
  const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);
  const { note_id, thread_id } = await depositNote(request, {
    sender: bob,
    recipientFingerprint: aliceFp,
    recipientPublicKeyArmored: aliceArmoredPub,
    fields: { body: `manage-me ${name}` },
  });
  await openNotesTab(page);
  await expect(page.getByTestId(`notes-thread-${thread_id}`)).toBeVisible({ timeout: 25_000 });
  await page.getByTestId(`notes-thread-${thread_id}`).click();
  await expect(page.getByTestId(`notes-bubble-${note_id}`)).toBeVisible({ timeout: 10_000 });
  return { aliceFp, note_id };
}

test('delete confirm: Cancel is default and deletes nothing; Confirm moves to bin', async ({ page, request }) => {
  test.setTimeout(90_000);
  const { aliceFp, note_id } = await depositAndOpen(page, request, 'Alice Manage');

  await page.getByRole('button', { name: 'Manage', exact: true }).click();
  await page.getByTestId(`notes-check-${note_id}`).check();

  // Arm → Cancel: the bar appears, Cancel is a real button, nothing moves.
  await page.getByTestId('notes-delete-btn').click();
  const bar = page.getByTestId('notes-confirm-bar');
  await expect(bar).toBeVisible();
  await expect(page.getByTestId('notes-confirm-copy')).toContainText(/device only|on this device|local/i);
  await expect(page.getByTestId('notes-confirm-cancel')).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(bar).toHaveCount(0);
  await expect(page.getByTestId(`notes-bubble-${note_id}`)).toBeVisible();
  expect(await idbHasNote(page, aliceFp, 'notes', note_id)).toBe(true);
  expect(await idbHasNote(page, aliceFp, 'recently_deleted', note_id)).toBe(false);

  // Arm → Confirm: the row moves live → bin (ciphertext, opaque move).
  await page.getByTestId(`notes-check-${note_id}`).check();
  await page.getByTestId('notes-delete-btn').click();
  await page.getByTestId('notes-confirm-ok').click();
  await expect(page.getByTestId(`notes-bubble-${note_id}`)).toHaveCount(0);
  await expect.poll(() => idbHasNote(page, aliceFp, 'recently_deleted', note_id)).toBe(true);
  expect(await idbHasNote(page, aliceFp, 'notes', note_id)).toBe(false);
});

test('empty bin confirm: Cancel keeps bin rows; Confirm empties the bin', async ({ page, request }) => {
  test.setTimeout(90_000);
  const { aliceFp, note_id } = await depositAndOpen(page, request, 'Alice Bin');

  await page.getByRole('button', { name: 'Manage', exact: true }).click();
  await page.getByTestId(`notes-check-${note_id}`).check();
  await page.getByTestId('notes-delete-btn').click();
  await page.getByTestId('notes-confirm-ok').click();
  await expect.poll(() => idbHasNote(page, aliceFp, 'recently_deleted', note_id)).toBe(true);

  // Switch to bin view — the binned row renders and is selectable.
  await page.getByTestId('notes-view-bin').click();
  await expect(page.getByTestId(`notes-binrow-${note_id}`)).toBeVisible();

  // Arm Empty bin → Cancel: rows stay.
  await page.getByTestId('notes-empty-bin-btn').click();
  const bar = page.getByTestId('notes-confirm-bar');
  await expect(bar).toBeVisible();
  await expect(page.getByTestId('notes-confirm-cancel')).toBeFocused();
  await page.keyboard.press('Enter');
  expect(await idbHasNote(page, aliceFp, 'recently_deleted', note_id)).toBe(true);

  // Arm → Confirm: bin empties.
  await page.getByTestId('notes-empty-bin-btn').click();
  await page.getByTestId('notes-confirm-ok').click();
  await expect.poll(() => idbHasNote(page, aliceFp, 'recently_deleted', note_id)).toBe(false);
});

test('archive round-trips the same ciphertext blob — no re-wrap (I7/I10)', async ({ page, request }) => {
  test.setTimeout(90_000);
  const { aliceFp, note_id } = await depositAndOpen(page, request, 'Alice Arch');

  // Snapshot the live row's ciphertext, spy the crypto seam from here on.
  const encBefore = await page.evaluate(async ([dbName, id]) => {
    const db = await new Promise<IDBDatabase>((res, rej) => {
      const r = indexedDB.open(dbName as string); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
    });
    const row = await new Promise<{ enc?: unknown } | undefined>((res, rej) => {
      const q = db.transaction('notes', 'readonly').objectStore('notes').get(id as string);
      q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error);
    });
    db.close();
    return row?.enc ? JSON.stringify(row.enc) : null;
  }, [`svrnty-notes-${aliceFp}`, note_id]);
  expect(encBefore).toBeTruthy();

  // Spy records every subtle call WITH its stack. The page-wide count is
  // NOT the I10 signal — the store reread timer (NotesInbox tick) and the
  // live-book poll legitimately decrypt on their own cadence. The real
  // assertion: no call's stack flows through a manage op. (I10 is proven
  // at store level by store.manage-ops.test.ts + its positive control.)
  const MANAGE_OP = /archiveNotes|_moveOpaque|unarchiveNotes|deleteNotesAtomic|restoreFromBin|deletePermanently|emptyBin/;
  await page.evaluate(() => {
    const w = window as unknown as {
      __cryptoCalls: { method: string; stack: string }[];
    };
    w.__cryptoCalls = [];
    const subtle = crypto.subtle as unknown as
      Record<string, (...a: never[]) => unknown>;
    for (const m of ['encrypt', 'decrypt', 'importKey', 'deriveKey']) {
      const orig = subtle[m].bind(crypto.subtle);
      subtle[m] = (...a: never[]) => {
        w.__cryptoCalls.push({ method: m, stack: new Error().stack ?? '' });
        return orig(...a);
      };
    }
  });

  await page.getByRole('button', { name: 'Manage', exact: true }).click();
  await page.getByTestId(`notes-check-${note_id}`).check();
  await page.getByTestId('notes-archive-btn').click();
  await expect.poll(() => idbHasNote(page, aliceFp, 'archive', note_id)).toBe(true);
  expect(await idbHasNote(page, aliceFp, 'notes', note_id)).toBe(false);

  // Byte-identical ciphertext in the archive store — the blob moved, unwrapped.
  const encAfter = await page.evaluate(async ([dbName, id]) => {
    const db = await new Promise<IDBDatabase>((res, rej) => {
      const r = indexedDB.open(dbName as string); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
    });
    const row = await new Promise<{ enc?: unknown } | undefined>((res, rej) => {
      const q = db.transaction('archive', 'readonly').objectStore('archive').get(id as string);
      q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error);
    });
    db.close();
    return row?.enc ? JSON.stringify(row.enc) : null;
  }, [`svrnty-notes-${aliceFp}`, note_id]);
  expect(encAfter).toBe(encBefore);

  const calls = await page.evaluate(() =>
    (window as unknown as {
      __cryptoCalls: { method: string; stack: string }[];
    }).__cryptoCalls);
  const fromManageOps = calls.filter((c) => MANAGE_OP.test(c.stack));
  // On failure print every stack — the cause must be legible, not guessed.
  expect(
    fromManageOps,
    `crypto calls through a manage op:\n${calls.map((c) => `${c.method}\n${c.stack}`).join('\n---\n')}`,
  ).toHaveLength(0);

  // Archived view renders the row; unarchive brings it back live.
  await page.getByTestId('notes-view-archived').click();
  await expect(page.getByTestId(`notes-archrow-${note_id}`)).toBeVisible();
  await page.getByTestId(`notes-check-${note_id}`).check();
  await page.getByTestId('notes-unarchive-btn').click();
  await expect.poll(() => idbHasNote(page, aliceFp, 'notes', note_id)).toBe(true);
});
