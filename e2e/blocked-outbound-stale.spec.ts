import { test, expect, type Page } from '@playwright/test';
import { seedAliceWithBob as seedForRevise } from './fixtures/deposit-contact-update';
import { seedAliceWithBob as seedForChat } from './fixtures/deposit-note';

/**
 * A block that lands while another tab is already open. The screen in that tab was built before the block, so the two things under test are:
 *  - Revise re-reads the address book when it opens, with no tab switch to do that by accident.
 *  - Chat re-reads the address book when Send runs, whatever the picker still shows.
 * In both, the block is made through the real card menu in a second tab, and relay POSTs are counted on the wire.
 */
const PW = 'e2e-passphrase-1234';
// Caddy sets this on every request in production; a local dev server has no Caddy, so without it every deposit shares one small bucket.
test.use({ extraHTTPHeaders: { 'x-svrnty-client-ip': '10.77.0.1' } });

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('blocked-outbound@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill(PW);
  await page.getByPlaceholder('Confirm passphrase').fill(PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 90_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

async function unlock(page: Page) {
  await page.goto('/');
  await page.getByPlaceholder('Enter passphrase').fill(PW);
  await page.getByPlaceholder('Enter passphrase').press('Enter');
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 40_000 });
}

function countDeposits(page: Page): () => number {
  let n = 0;
  page.on('request', (r) => { if (r.method() === 'POST' && r.url().includes('/api/relay/envelope')) n++; });
  return () => n;
}

/** Block Bob through the real card menu. */
async function blockBob(page: Page) {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  const row = page.locator('[data-testid="contact-row"]').filter({ hasText: 'Bob' }).first();
  await expect(row).toBeVisible({ timeout: 25_000 });
  await row.click();
  const card = page.locator('.contacts-book-pane [data-testid="contact-action-card"]');
  await expect(card).toBeVisible();
  const toggle = card.getByTestId('card-actions-toggle');
  await toggle.scrollIntoViewIfNeeded();
  await toggle.click({ timeout: 10_000 });
  await card.getByTestId('card-actions-toggle-menu').getByRole('menuitem', { name: 'Block', exact: true }).click();
  const confirm = page.getByTestId('trust-action-confirm');
  await expect(confirm).toHaveAttribute('data-action-kind', 'block');
  await confirm.getByTestId('trust-action-confirm-btn').click();
  await expect(confirm).toHaveCount(0);
  await expect(page.locator('[data-testid="contact-row"]').filter({ hasText: 'Bob' })).toHaveCount(0);
}

async function blockFromAnotherTab(page: Page) {
  const other = await page.context().newPage();
  await unlock(other);
  await blockBob(other);
  await other.close();
}

test('Revise: a block from another tab, with no tab switch here: Bob is not offered and nothing is deposited', async ({ page }) => {
  test.setTimeout(150_000);
  await genesis(page, 'Alice Stale Revise');
  await seedForRevise(page);
  const deposits = countDeposits(page);
  await unlock(page);
  await page.getByRole('tab', { name: 'Identity' }).click(); // the audience is built with Bob clean, and this tab stays here
  await page.waitForTimeout(1_500);
  await blockFromAnotherTab(page);
  await page.getByTestId('identity-card-methods').getByRole('button', { name: /^Revise .*mail/i }).first().click();
  const dialog = page.locator('[role="dialog"]').filter({ hasText: /Revise/ });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText('Bob')).toHaveCount(0);
  expect(deposits()).toBe(0);
});

test('Chat: a block from another tab while Bob is still picked here: Send is refused, nothing is deposited, the draft stays', async ({ page }) => {
  test.setTimeout(150_000);
  // Contact changes normally reach other tabs by BroadcastChannel and the picker drops Bob. This tab misses that broadcast, which is the stale list the send-time check exists for.
  await page.addInitScript(() => {
    (window as unknown as { BroadcastChannel: unknown }).BroadcastChannel = class {
      onmessage = null;
      postMessage() {}
      close() {}
      addEventListener() {}
      removeEventListener() {}
    };
  });
  await genesis(page, 'Alice Stale Chat');
  const { bob } = await seedForChat(page);
  const deposits = countDeposits(page);
  await page.getByTestId('tab-notes').click();
  const panel = page.getByTestId('notes-inbox');
  await expect(panel).toBeVisible();
  await panel.getByTestId('notes-contact-picker').selectOption(bob.fingerprint);
  const body = 'this must not reach him';
  await panel.getByTestId('notes-compose').fill(body);
  await blockFromAnotherTab(page);
  await page.bringToFront();
  await panel.getByTestId('notes-send-btn').click();
  await expect(panel.getByTestId('notes-error')).toHaveText('Not sent. This contact is blocked or removed. Your message is still in the box.');
  await expect(panel.getByTestId('notes-compose')).toHaveValue(body);
  await expect(panel.locator('[data-direction="outbound"]')).toHaveCount(0);
  expect(deposits()).toBe(0);
});

test('Chat control: an unblocked contact still gets the note, a real relay 200 through the real address book', async ({ page }) => {
  test.setTimeout(120_000);
  await genesis(page, 'Alice Chat Control');
  const { bob } = await seedForChat(page);
  const deposits = countDeposits(page);
  await page.getByTestId('tab-notes').click();
  const panel = page.getByTestId('notes-inbox');
  await expect(panel).toBeVisible();
  await panel.getByTestId('notes-contact-picker').selectOption(bob.fingerprint);
  await panel.getByTestId('notes-compose').fill('hello bob');
  const accepted = page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/api/relay/envelope') && r.status() === 200);
  await panel.getByTestId('notes-send-btn').click();
  await accepted;
  await expect(panel.getByTestId('notes-error')).toHaveCount(0);
  await expect(panel.getByTestId('notes-compose')).toHaveValue('');
  expect(deposits()).toBe(1);
});
