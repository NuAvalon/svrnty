import { test, expect, type Page } from '@playwright/test';
import {
  makeE2EIdentity,
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
    const rows: any[] = await new Promise((res, rej) => {
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
  await page.getByTestId('notes-confirm-cancel').click();
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
  await page.getByTestId('notes-confirm-cancel').click();
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
    const row = await new Promise<any>((res, rej) => {
      const q = db.transaction('notes', 'readonly').objectStore('notes').get(id as string);
      q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error);
    });
    db.close();
    return row?.enc ? JSON.stringify(row.enc) : null;
  }, [`svrnty-notes-${aliceFp}`, note_id]);
  expect(encBefore).toBeTruthy();

  const cryptoCalls = await page.evaluate(() => {
    (window as any).__cryptoCalls = 0;
    for (const m of ['encrypt', 'decrypt', 'importKey', 'deriveKey'] as const) {
      const orig = (crypto.subtle as any)[m].bind(crypto.subtle);
      (crypto.subtle as any)[m] = (...a: any[]) => { (window as any).__cryptoCalls++; return orig(...a); };
    }
    return true;
  });
  expect(cryptoCalls).toBe(true);

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
    const row = await new Promise<any>((res, rej) => {
      const q = db.transaction('archive', 'readonly').objectStore('archive').get(id as string);
      q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error);
    });
    db.close();
    return row?.enc ? JSON.stringify(row.enc) : null;
  }, [`svrnty-notes-${aliceFp}`, note_id]);
  expect(encAfter).toBe(encBefore);

  expect(await page.evaluate(() => (window as any).__cryptoCalls)).toBe(0);

  // Archived view renders the row; unarchive brings it back live.
  await page.getByTestId('notes-view-archived').click();
  await expect(page.getByTestId(`notes-archrow-${note_id}`)).toBeVisible();
  await page.getByTestId(`notes-check-${note_id}`).check();
  await page.getByTestId('notes-unarchive-btn').click();
  await expect.poll(() => idbHasNote(page, aliceFp, 'notes', note_id)).toBe(true);
});
