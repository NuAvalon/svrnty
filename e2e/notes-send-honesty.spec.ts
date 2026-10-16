import { test, expect, type Page } from '@playwright/test';
import { seedAliceWithBob } from './fixtures/deposit-note';

/**
 * SEND-HONESTY — client reliability fix Slice 1 (Apollo; Peter #171712; ☀8306–8310).
 *
 * Proves the fix for Peter's live bug "FE said FAILED TO SEND but it DID send". The compose→send path,
 * through the REAL UI, maps the deposit's TRANSPORT outcome to Hypatia's honest-state machine:
 *   2xx            → "Sent · unconfirmed."           (reached the relay; no receipt-of-record)
 *   5xx / timeout  → "Couldn't confirm this sent…"   (NEVER "failed" — a 5xx can sit over a DURABLE deposit)
 *   400 / 413      → "Not sent. Saved on this device" (authoritative refusal — provably did not land)
 * …and the sender's OWN message bubble never vanishes (transport persists the local copy BEFORE the
 * deposit attempt). We force each transport outcome with page.route on POST /api/relay/envelope.
 *
 * MATRIX NOTE ([[feedback_prove_in_playwright]]): send-status is pure DOM text driven by a JS state
 * machine — engine-agnostic (no crypto/engine-specific rendering on this path), so desktop chromium
 * proves the logic. (The note-RENDER path's mobile/hardened matrix lives in notes-roundtrip.spec.ts.)
 */

async function genesisAlice(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Alice Send');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

// Open Notes, pick Bob (the only sendable contact seedAliceWithBob installs), compose a body.
async function openNotesAndCompose(page: Page, body: string) {
  const notesTab = page.getByTestId('tab-notes');
  await expect(notesTab).toBeVisible({ timeout: 20_000 });
  await notesTab.click();
  const panel = page.getByTestId('notes-inbox');
  await expect(panel).toBeVisible();
  const picker = panel.getByTestId('notes-contact-picker');
  await expect(picker.locator('option')).not.toHaveCount(1, { timeout: 15_000 }); // >1 ⇒ Bob loaded past the placeholder
  await picker.selectOption({ index: 1 });
  await panel.getByTestId('notes-compose').fill(body);
  return panel;
}

// Force the relay deposit to a specific HTTP status (the only thing that varies the honest outcome).
async function forceDepositStatus(page: Page, status: number) {
  await page.route('**/api/relay/envelope', (route) =>
    route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(status < 300 ? { status: 'queued' } : { error: 'forced-by-e2e' }),
    }),
  );
}

test.describe('send-honesty · desktop-chromium', () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test('transient 5xx → "couldn’t confirm" (NOT "failed"), and the sender bubble persists', async ({ page }) => {
    test.setTimeout(90_000);
    await genesisAlice(page);
    await seedAliceWithBob(page);
    const body = 'does this survive a 503 honestly 🌱';
    const panel = await openNotesAndCompose(page, body);
    await forceDepositStatus(page, 503);
    await panel.getByTestId('notes-send-btn').click();

    // The honest "couldn't confirm" live status — NEVER the old false "failed"/"could not be sent".
    await expect(panel.getByTestId('notes-send-status')).toContainText(/couldn.t confirm/i, { timeout: 15_000 });
    await expect(panel.getByTestId('notes-error')).toHaveCount(0);
    await expect(panel.getByText(/could not be sent/i)).toHaveCount(0);
    // The sender's OWN message did NOT vanish (save-before-send).
    await expect(panel.getByText(body)).toBeVisible();
    // No false Delivered/Read/Expired anywhere.
    await expect(panel.getByText(/^Delivered$|^Read$|^Expired$/)).toHaveCount(0);
  });

  test('authoritative 400 → "Not sent" (honest true-failure); the local copy is still saved', async ({ page }) => {
    test.setTimeout(90_000);
    await genesisAlice(page);
    await seedAliceWithBob(page);
    const body = 'a 400 is an honest Not sent';
    const panel = await openNotesAndCompose(page, body);
    await forceDepositStatus(page, 400);
    await panel.getByTestId('notes-send-btn').click();

    await expect(panel.getByTestId('notes-send-status')).toContainText(/not sent/i, { timeout: 15_000 });
    await expect(panel.getByText(body)).toBeVisible(); // saved on this device even when refused
  });

  test('clean 2xx → "Sent · unconfirmed." (reached the relay, no receipt claimed)', async ({ page }) => {
    test.setTimeout(90_000);
    await genesisAlice(page);
    await seedAliceWithBob(page);
    const body = 'clean 200 is Sent unconfirmed';
    const panel = await openNotesAndCompose(page, body);
    await forceDepositStatus(page, 200);
    await panel.getByTestId('notes-send-btn').click();

    await expect(panel.getByTestId('notes-send-status')).toContainText(/Sent · unconfirmed/i, { timeout: 15_000 });
    await expect(panel.getByText(body)).toBeVisible();
  });
});
