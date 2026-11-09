import { test, expect, type Page } from '@playwright/test';
import { seedAliceWithBob } from './fixtures/deposit-note';

/**
 * A blocked contact's book-card menu does not offer "Trust". Blocking means "I do not want this person reaching me";
 * one mis-tap on "Trust" would deposit trust for someone the owner is hiding from, and the way back is Unblock first.
 * Retracting trust that already exists stays available ("Remove trust"). Needs a keyed SVRNTY contact (the sample
 * circle is classical and never shows Trust), seeded as raw IndexedDB the way the other contact specs do.
 */
async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('blocked-trust@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 90_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

/** Patch the seeded contact through raw IndexedDB (seedAliceWithBob writes trust_level 'verified' = trusted). */
async function patchContact(page: Page, contactFp: string, patch: { trust_level?: string; blocked?: boolean }) {
  await page.evaluate(
    async ({ fp, patch }: { fp: string; patch: { trust_level?: string; blocked?: boolean } }) => {
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const r = indexedDB.open('svrnty');
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error);
      });
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction('contacts', 'readwrite');
        const store = tx.objectStore('contacts');
        const all = store.getAll();
        all.onsuccess = () => {
          const rec = (all.result as Array<Record<string, unknown>>).find((c) => c.fingerprint === fp);
          if (!rec) return reject(new Error('patchContact: seeded contact not found'));
          if (patch.trust_level !== undefined) rec.trust_level = patch.trust_level;
          if (patch.blocked !== undefined) rec.metadata = { ...((rec.metadata as object) ?? {}), blocked: patch.blocked };
          store.put(rec);
        };
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
      db.close();
    },
    { fp: contactFp, patch },
  );
}

const bobRow = (page: Page) => page.locator('[data-testid="contact-row"]').filter({ hasText: 'Bob' });
const bookCard = (page: Page) => page.locator('.contacts-book-pane [data-testid="contact-action-card"]');

/** Show the book again so it re-reads IndexedDB after a seed. */
async function refreshBook(page: Page) {
  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await expect(bobRow(page).first()).toBeVisible({ timeout: 25_000 });
}

async function openMenu(page: Page) {
  const card = bookCard(page);
  await expect(card).toBeVisible();
  const toggle = card.getByTestId('card-actions-toggle');
  await toggle.scrollIntoViewIfNeeded();
  await toggle.click({ timeout: 10_000 });
  const menu = card.getByTestId('card-actions-toggle-menu');
  await expect(menu).toBeVisible();
  // CONTROL: the menu really is the owner-action menu (Edit is always there), so "no Trust" is not an empty menu.
  await expect(menu.getByRole('menuitem', { name: 'Edit', exact: true })).toBeVisible();
  return menu;
}

/** Block Bob through the real card menu, then open his card from the Blocked view with the menu showing. */
async function blockBobAndOpenFromBlockedView(page: Page) {
  await bobRow(page).first().click();
  const first = await openMenu(page);
  await first.getByRole('menuitem', { name: 'Block', exact: true }).click();
  const confirm = page.getByTestId('trust-action-confirm');
  await expect(confirm).toHaveAttribute('data-action-kind', 'block');
  await confirm.getByTestId('trust-action-confirm-btn').click();
  await expect(confirm).toHaveCount(0);
  await expect(bobRow(page)).toHaveCount(0);

  await page.getByRole('button', { name: 'Book options' }).click();
  await page.getByRole('menuitem', { name: /view blocked contacts/i }).click();
  const row = bobRow(page).first();
  await expect(row).toBeVisible({ timeout: 15_000 });
  // A row click TOGGLES its card, and the card we blocked from may still be open: pin the state (closed), then open it.
  if (await bookCard(page).count()) {
    await row.click();
    await expect(bookCard(page)).toHaveCount(0);
  }
  await row.click();
  return openMenu(page);
}

const VIEWPORTS: Array<[string, { width: number; height: number } | null]> = [
  ['desktop', null],
  ['phone 390x844', { width: 390, height: 844 }],
];

for (const [vpName, viewport] of VIEWPORTS) {
  test.describe(`Blocked card has no Trust item — ${vpName}`, () => {
    test.setTimeout(180_000);
    if (viewport) test.use({ viewport });

    test('NEG: an unblocked, untrusted keyed contact keeps Trust', async ({ page }) => {
      await genesis(page, 'Trust Neg');
      const { bob } = await seedAliceWithBob(page);
      await patchContact(page, bob.fingerprint, { trust_level: 'known' });
      await refreshBook(page);
      await bobRow(page).first().click();
      const menu = await openMenu(page);
      await expect(menu.getByRole('menuitem', { name: 'Trust', exact: true })).toBeVisible();
      await expect(menu.getByRole('menuitem', { name: 'Remove trust', exact: true })).toHaveCount(0);
    });

    test('a blocked, untrusted contact is not offered Trust', async ({ page }) => {
      await genesis(page, 'Trust Blocked');
      const { bob } = await seedAliceWithBob(page);
      await patchContact(page, bob.fingerprint, { trust_level: 'known' });
      await refreshBook(page);
      const menu = await blockBobAndOpenFromBlockedView(page);
      await expect(menu.getByRole('menuitem', { name: 'Trust', exact: true })).toHaveCount(0);
      await expect(menu.getByRole('menuitem', { name: 'Remove trust', exact: true })).toHaveCount(0);
    });

    test('a contact who is blocked AND already trusted (e.g. from an import) can still have trust removed', async ({ page }) => {
      await genesis(page, 'Trust Retract');
      const { bob } = await seedAliceWithBob(page); // seeded as trusted ('verified')
      await patchContact(page, bob.fingerprint, { blocked: true }); // blocking through the menu clears trust, so seed the pair directly
      await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
      await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
      await page.getByRole('button', { name: 'Book options' }).click();
      await page.getByRole('menuitem', { name: /view blocked contacts/i }).click();
      await expect(bobRow(page).first()).toBeVisible({ timeout: 25_000 });
      await bobRow(page).first().click();
      const menu = await openMenu(page);
      await expect(menu.getByRole('menuitem', { name: 'Remove trust', exact: true })).toBeVisible();
      await expect(menu.getByRole('menuitem', { name: 'Trust', exact: true })).toHaveCount(0);
    });
  });
}
