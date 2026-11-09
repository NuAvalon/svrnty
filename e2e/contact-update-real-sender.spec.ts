import { test, expect, type Page } from '@playwright/test';

/**
 * A contact update sent through the REAL UI by a normal (genesis) identity reaches a real peer and is applied.
 *
 * Why this exists: the older update specs (demo-arc beat 4, deposit-contact-update.ts) simulate the SENDER in node and sign classical
 * by construction, so they could never notice if the real sender changed how it signs. Here both sides are real browser profiles:
 * genesis (so PQ keys are stored exactly as a normal user's browser stores them), the real Share-identity and Import-contact dialogs,
 * the real Identity-card Revise dialog and its Send update button, and the receiver's real poll -> verify -> apply.
 *
 * It asserts ONLY what the user sees (Alice's new email on Bob's card), so it stays true when updates later become hybrid, and it fails
 * if someone makes the sender sign hybrid before receivers can check it (pq-signing-secret.ts explains the trap; the unit pins are in
 * src/lib/identity/pq-signing-secret.test.ts). Contacts are encrypted at rest, so we read the UI, not IndexedDB.
 *
 * Desktop Chromium only: this is a transport/crypto path, not a layout; the phone matrix is covered by the card specs.
 */
async function genesis(page: Page, name: string, email: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const e = page.getByPlaceholder('your@email.com');
  if (await e.count()) await e.fill(email);
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 90_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
}

async function copyPackage(page: Page): Promise<string> {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('share-identity-from-card').click();
  await page.getByRole('tab', { name: 'Copy' }).click();
  const pre = page.locator('[role="dialog"] pre').first();
  await expect(pre).toBeVisible();
  const text = (await pre.innerText()).trim();
  await page.keyboard.press('Escape');
  return text;
}

async function importPackage(page: Page, pkg: string) {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  // two buttons say "Import Contact": the vCard one carries a test id, the signed-package one does not
  await page.locator('button:has-text("Import Contact"):not([data-testid="import-contacts-trigger"])').first().click();
  await page.getByPlaceholder('Paste the signed identity package here...').fill(pkg);
  await page.getByRole('button', { name: /Verify & Import/ }).click();
  await expect(page.locator('[role="dialog"]').getByText(/imported|added|verified|success/i).first()).toBeVisible({ timeout: 30_000 });
  await page.keyboard.press('Escape');
}

/** Open a contact's card in the book and return the card text (More expanded). */
async function cardText(page: Page, name: string): Promise<string> {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  const row = page.locator('[data-testid="contact-row"]').filter({ hasText: name }).first();
  await expect(row).toBeVisible({ timeout: 20_000 });
  const card = page.locator('.contacts-book-pane [data-testid="contact-action-card"]');
  if (!(await card.count())) await row.click(); // a row click TOGGLES its card: only open it if it is closed
  await expect(card).toBeVisible();
  const more = card.getByTestId('star-sheet-expand');
  if (await more.count()) {
    const t = (await more.innerText()).trim();
    if (/more/i.test(t)) await more.click();
  }
  return (await card.innerText()).replace(/\s+/g, ' ');
}

test('a normal identity changes their email through the real UI; the peer applies it', async ({ browser }) => {
  test.setTimeout(240_000);
  const A = await (await browser.newContext()).newPage();
  const B = await (await browser.newContext()).newPage();
  const OLD = 'alice-old@example.test';
  const NEW = 'alice-new@example.test';

  await genesis(A, 'Alice Sender', OLD);
  await genesis(B, 'Bob Receiver', 'bob-recv@example.test');
  const pkgA = await copyPackage(A);
  const pkgB = await copyPackage(B);
  await importPackage(B, pkgA); // Bob holds Alice's card
  await importPackage(A, pkgB); // Alice holds Bob, so she can pick him as a recipient

  // CONTROL: before the send, Bob's card for Alice is open and does not show the new email (the signed card does not carry her email,
  // so it arrives only with the update). The later check therefore cannot pass on a leftover.
  const before = await cardText(B, 'Alice Sender');
  expect(before).toContain('Alice Sender');
  expect(before).not.toContain(NEW);

  // Alice revises her email through the real Identity card and sends to Bob.
  await A.getByRole('tab', { name: 'Identity' }).click();
  await A.getByTestId('identity-card-methods').getByRole('button', { name: /^Revise .*mail/i }).first().click();
  const dlg = A.locator('[role="dialog"]').filter({ hasText: /Revise/ });
  await expect(dlg).toBeVisible();
  await dlg.locator('input[type="text"], input:not([type])').first().fill(NEW);
  await dlg.getByText('Bob Receiver').first().click(); // the row's label wraps the recipient checkbox
  await dlg.getByRole('button', { name: /Send update/ }).click();
  await expect(dlg.getByText(/Sent to 1 contact/i)).toBeVisible({ timeout: 30_000 });

  // Bob's poll (idle backoff up to ~15 s) fetches, verifies and applies; his card then shows the new email.
  await expect
    .poll(async () => (await cardText(B, 'Alice Sender')).includes(NEW), { timeout: 90_000, intervals: [3000, 5000] })
    .toBe(true);
});
