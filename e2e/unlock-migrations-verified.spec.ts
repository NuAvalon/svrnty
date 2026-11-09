import { test, expect, type Page } from '@playwright/test';
import { seedAliceWithBob } from './fixtures/deposit-note';

/**
 * Unlock runs the at-rest migrations (heal plaintext rows, create a missing device mailbox). They write under the session key, so they
 * must run only for an owner whose existing encrypted records open under it. Otherwise one mistyped passphrase encrypts a legacy row
 * under a key nobody knows, and it is gone for good. Real browser, real IndexedDB, the real unlock screen.
 */
const RIGHT = 'e2e-passphrase-1234';
const WRONG = 'not-the-passphrase-9876';

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('unlock-migrations@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill(RIGHT);
  await page.getByPlaceholder('Confirm passphrase').fill(RIGHT);
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 90_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

type Row = { exists: boolean; encrypted: boolean };

async function row(page: Page, store: string, match: { field: string; value: string }): Promise<Row> {
  return page.evaluate(async ({ store, match }) => {
    const db = await new Promise<IDBDatabase>((res, rej) => { const r = indexedDB.open('svrnty'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
    const all = await new Promise<Array<Record<string, unknown>>>((res, rej) => { const q = db.transaction(store, 'readonly').objectStore(store).getAll(); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); });
    db.close();
    const hit = all.find((r) => r[match.field] === match.value);
    return { exists: !!hit, encrypted: !!hit?.enc_version };
  }, { store, match });
}

async function edit(page: Page, op: { put?: { store: string; value: unknown }; del?: { store: string; key: string } }) {
  await page.evaluate(async (op) => {
    const db = await new Promise<IDBDatabase>((res, rej) => { const r = indexedDB.open('svrnty'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
    const name = (op.put?.store ?? op.del?.store) as string;
    await new Promise<void>((res, rej) => {
      const tx = db.transaction(name, 'readwrite');
      if (op.put) tx.objectStore(name).put(op.put.value as object);
      if (op.del) tx.objectStore(name).delete(op.del.key);
      tx.oncomplete = () => res();
      tx.onerror = () => rej(tx.error);
    });
    db.close();
  }, op);
}

async function atLock(page: Page) {
  await page.reload();
  await expect(page.getByPlaceholder('Enter passphrase')).toBeVisible({ timeout: 30_000 });
}

async function submit(page: Page, passphrase: string) {
  await page.getByPlaceholder('Enter passphrase').fill(passphrase);
  await page.keyboard.press('Enter');
}

test('a mistyped passphrase leaves a legacy plaintext contact alone, and the right one heals it', async ({ page }) => {
  test.setTimeout(240_000);
  await genesis(page, 'Alice');
  const { bob } = await seedAliceWithBob(page);
  // By id: once encrypted, a contact's fingerprint field is blinded.
  const bobRow = { field: 'id', value: `e2e-bob-${bob.fingerprint.slice(0, 12)}` };
  expect(await row(page, 'contacts', bobRow), 'setup: the seeded row is plaintext').toEqual({ exists: true, encrypted: false });

  await atLock(page);
  await submit(page, WRONG);
  await expect(page.getByText(/incorrect passphrase|could not decrypt/i)).toBeVisible({ timeout: 30_000 });
  expect(await row(page, 'contacts', bobRow), 'a wrong passphrase must not encrypt the row under a key nobody knows').toEqual({ exists: true, encrypted: false });

  await submit(page, RIGHT);
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
  await expect.poll(() => row(page, 'contacts', bobRow), { timeout: 20_000, message: 'the right passphrase heals it' }).toEqual({ exists: true, encrypted: true });
  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await expect(page.getByText('Bob', { exact: false }).first(), 'and the contact is still readable').toBeVisible({ timeout: 25_000 });
});

test('an owner with nothing to verify is left as it was: no heal and no mailbox under this session key', async ({ page }) => {
  test.setTimeout(240_000);
  await genesis(page, 'Alice');
  const other = 'b'.repeat(64);
  await edit(page, { put: { store: 'identities', value: { fingerprint: other, data: { identity: { fingerprint: other, public_key: 'x', name: 'Other' } } } } });
  await edit(page, { put: { store: 'keys', value: { fingerprint: other, privateKey: 'legacy-plaintext', passphrase: '' } } });
  await edit(page, { put: { store: 'contacts', value: { id: 'legacy-other-1', fingerprint: 'c'.repeat(64), owner_fingerprint: other, name: 'Legacy', added_at: new Date().toISOString() } } });

  await atLock(page);
  await submit(page, RIGHT);
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
  // Unlock has finished its migrations for the verified owner by now; give any stray write time to land.
  await expect.poll(() => row(page, 'device_mailbox', { field: 'fingerprint', value: other }), { timeout: 3_000 }).toEqual({ exists: false, encrypted: false }).catch(() => undefined);
  expect(await row(page, 'contacts', { field: 'id', value: 'legacy-other-1' })).toEqual({ exists: true, encrypted: false });
  expect(await row(page, 'keys', { field: 'fingerprint', value: other }), 'its plaintext key is not encrypted under this session key').toEqual({ exists: true, encrypted: false });
  expect(await row(page, 'device_mailbox', { field: 'fingerprint', value: other })).toEqual({ exists: false, encrypted: false });
});

test('a verified owner still gets its missing device mailbox on unlock', async ({ page }) => {
  test.setTimeout(240_000);
  await genesis(page, 'Alice');
  const fp = await page.evaluate(async () => {
    const db = await new Promise<IDBDatabase>((res, rej) => { const r = indexedDB.open('svrnty'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
    const all = await new Promise<Array<{ fingerprint: string }>>((res, rej) => { const q = db.transaction('keys', 'readonly').objectStore('keys').getAll(); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); });
    db.close();
    return all[0].fingerprint;
  });
  await edit(page, { del: { store: 'device_mailbox', key: fp } });
  expect((await row(page, 'device_mailbox', { field: 'fingerprint', value: fp })).exists, 'setup: mailbox removed').toBe(false);
  await atLock(page);
  await submit(page, RIGHT);
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
  await expect.poll(() => row(page, 'device_mailbox', { field: 'fingerprint', value: fp }), { timeout: 20_000 }).toEqual({ exists: true, encrypted: true });
});
