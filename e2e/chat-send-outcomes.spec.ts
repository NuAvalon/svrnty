import { test, expect, type Page } from '@playwright/test';
import { seedAliceWithBob } from './fixtures/deposit-note';

/**
 * Chat send outcomes + the "ratchet is off" line, in a REAL browser (B group 2, commits 4d-1..4d-3).
 *
 * A failed send says WHERE it failed, because the cases need different things from the user:
 *   - the relay answers 5xx / the connection drops  -> UNCONFIRMED (the relay MAY have it): draft kept, no "not sent", nothing saved
 *   - the relay refuses with a 4xx (local save ok)  -> "Not sent. Saved on this device." (a definite refusal)
 *   - the relay accepts (a REAL 200), then this device cannot save a copy -> SENT, NOT SAVED: the compose box clears (a second Send would
 *     duplicate) and the text moves to a read-only, copyable panel that only Dismiss clears.
 * The unit tests pin the mapping with fake stores; this proves the same behaviour through the real UI, real IndexedDB and the real relay.
 *
 * The seeded contact (Bob) carries a verified ML-KEM key, so a send is genuinely depositable and, because Bob has never sent Alice a ratchet
 * frame, the app says the triple ratchet is OFF for him (and never says it is on).
 */

async function genesis(page: Page, name: string) {
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

/** Genesis Alice, seed Bob (with PQ keys), open Chat, pick Bob. ⚠ NO RELOAD afterwards: the session unlock lives in memory only. */
async function aliceWritingToBob(page: Page) {
  await genesis(page, 'Alice Outcomes');
  const { bob } = await seedAliceWithBob(page);
  await page.getByTestId('tab-notes').click();
  const panel = page.getByTestId('notes-inbox');
  await expect(panel).toBeVisible();
  await panel.getByTestId('notes-contact-picker').selectOption(bob.fingerprint);
  return { panel, bob };
}

const COPY = {
  unconfirmed: "Couldn't confirm it was sent. The relay may already have it.",
  savedNotSent: 'Not sent. Saved on this device.',
  sentNotSaved: "Sent to the relay, but this device couldn't save a copy. Don't send it again. Your text is below so you can copy it.",
};

test.describe('chat send outcomes (real browser)', () => {
  test('D2: a sendable contact whose app never sent us a ratchet frame shows "ratchet is off", and never says it is on', async ({ page }) => {
    test.setTimeout(120_000);
    const { panel } = await aliceWritingToBob(page);
    const line = panel.getByTestId('notes-ratchet-off');
    await expect(line).toBeVisible({ timeout: 15_000 });
    await expect(line).toContainText('Triple ratchet is off for');
    await expect(line).toContainText("this app doesn't start one yet. Messages are still end-to-end encrypted.");
    await expect(panel.getByText(/ratchet is (on|enabled|active)/i)).toHaveCount(0);
    await expect(panel.getByText(/forward secrecy/i)).toHaveCount(0);
  });

  test('UNCONFIRMED: a 502 from the gateway keeps the draft, says the relay may have it, and saves nothing as "not sent"', async ({ page }) => {
    test.setTimeout(120_000);
    await page.route('**/api/relay/envelope', (route) => route.fulfill({ status: 502, contentType: 'text/plain', body: 'bad gateway' }));
    const { panel } = await aliceWritingToBob(page);
    const body = 'gateway timed out on this one';
    await panel.getByTestId('notes-compose').fill(body);
    await panel.getByTestId('notes-send-btn').click();
    await expect(panel.getByTestId('notes-error')).toHaveText(COPY.unconfirmed);
    await expect(panel.getByTestId('notes-compose')).toHaveValue(body); // the draft is still in the box
    await expect(panel.getByTestId('notes-unsaved')).toHaveCount(0);
    await expect(panel.locator('[data-direction="outbound"]')).toHaveCount(0); // no local "not sent" record inviting a resend
    await expect(panel.getByText(/Not sent/)).toHaveCount(0);
    await expect(panel.getByText(/nothing left this device/i)).toHaveCount(0);
  });

  test('UNCONFIRMED: a dropped connection (request aborted) is the same: draft kept, "may already have it"', async ({ page }) => {
    test.setTimeout(120_000);
    await page.route('**/api/relay/envelope', (route) => route.abort('failed'));
    const { panel } = await aliceWritingToBob(page);
    const body = 'the wifi died mid-send';
    await panel.getByTestId('notes-compose').fill(body);
    await panel.getByTestId('notes-send-btn').click();
    await expect(panel.getByTestId('notes-error')).toHaveText(COPY.unconfirmed);
    await expect(panel.getByTestId('notes-compose')).toHaveValue(body);
    await expect(panel.locator('[data-direction="outbound"]')).toHaveCount(0);
  });

  test('REFUSED: a 429 (definite refusal) with a good local save says "Not sent. Saved on this device." and does not claim it reached anyone', async ({ page }) => {
    test.setTimeout(120_000);
    await page.route('**/api/relay/envelope', (route) =>
      route.fulfill({ status: 429, contentType: 'application/json', body: '{"error":"Mailbox at capacity."}' }));
    const { panel } = await aliceWritingToBob(page);
    await panel.getByTestId('notes-compose').fill('mailbox is full');
    await panel.getByTestId('notes-send-btn').click();
    await expect(panel.getByTestId('notes-send-status')).toHaveText(COPY.savedNotSent);
    await expect(panel.getByTestId('notes-error')).toHaveCount(0);
    await expect(panel.getByText(/^Delivered$/)).toHaveCount(0);
  });

  test('SENT, NOT SAVED: a real 200 from the relay, then the local save fails: compose clears, the text stays in a read-only copyable panel until Dismiss', async ({ page }) => {
    test.setTimeout(120_000);
    // Fail ONLY writes to the notes store, and only once the test flips the flag (after unlock + seeding), so everything else is real.
    await page.addInitScript(() => {
      const original = IDBObjectStore.prototype.put;
      IDBObjectStore.prototype.put = function (...args: Parameters<IDBObjectStore['put']>) {
        if ((window as unknown as { __failNotesPut?: boolean }).__failNotesPut && this.name === 'notes') {
          throw new Error('injected: notes put failed');
        }
        return original.apply(this, args);
      };
    });
    const { panel } = await aliceWritingToBob(page);
    await page.evaluate(() => { (window as unknown as { __failNotesPut?: boolean }).__failNotesPut = true; });

    const body = 'this one reached the relay but not our disk';
    await panel.getByTestId('notes-compose').fill(body);
    const posted = page.waitForResponse((r) => r.url().includes('/api/relay/envelope') && r.request().method() === 'POST');
    await panel.getByTestId('notes-send-btn').click();
    expect((await posted).status()).toBe(200); // the REAL relay accepted it

    const unsaved = panel.getByTestId('notes-unsaved');
    await expect(unsaved).toBeVisible();
    await expect(unsaved).toContainText(COPY.sentNotSaved);
    const text = panel.getByTestId('notes-unsaved-text');
    await expect(text).toHaveValue(body);
    await expect(text).toHaveAttribute('readonly', '');
    await expect(panel.getByTestId('notes-compose')).toHaveValue(''); // a second Send would duplicate: the box is cleared
    await expect(panel.getByTestId('notes-error')).toHaveCount(0);
    await expect(panel.getByText(/Retry/)).toHaveCount(0); // no retry promise: the relay cannot dedupe a resend yet

    // The text is the user's only copy, so it survives until they dismiss it, not until the next render.
    await page.waitForTimeout(1500);
    await expect(text).toHaveValue(body);
    await panel.getByTestId('notes-unsaved-dismiss').click();
    await expect(unsaved).toHaveCount(0);
  });
});
