import { test, expect, devices, type Page } from '@playwright/test';
import { seedAliceWithBob } from './fixtures/deposit-note';
import { POLL_REFUSED_COPY } from '../src/components/notes/poll-refused-notice';

/**
 * #720 copy v1 §B / v3 / v4 in a REAL browser (the launch gate Archie set, #2443): when the shared mailbox poll is refused by the relay on
 * three polls in a row, the Chat tab says so, in words that claim only what this device observed; one answered poll clears it.
 *
 * The relay is the app's own dev relay; only GET /api/relay/queue is intercepted per test (401 = refused, 200 {} = a reply that is not a
 * list, 200 [] = an answered empty poll). The background poll runs every 1.5 s, so "three in a row" is about 5 s.
 *
 * NOT driven here: lock/unlock clearing the notice (unit-tested in poll-status-events.test.ts) and the exact "2 ticks shows nothing" edge.
 */

const PASS = 'e2e-passphrase-1234';
const QUEUE = '**/api/relay/queue**';

async function genesisReceiver(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(PASS);
  await page.getByPlaceholder('Confirm passphrase').fill(PASS);
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

async function openChat(page: Page) {
  await page.getByTestId('tab-notes').click();
  await expect(page.getByTestId('notes-inbox')).toBeVisible();
}

const refuse = (page: Page, status = 401) => page.context().route(QUEUE, (r) => r.fulfill({ status, contentType: 'application/json', body: '{"error":"unauthorized"}' }));
const answer = (page: Page, body: unknown) => page.context().route(QUEUE, (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) }));

const { defaultBrowserType, ...pixel7Mobile } = devices['Pixel 7'];
void defaultBrowserType; // not a per-context option (it picks the browser, which the project already fixed)
const MATRIX: Array<{ label: string; use: Record<string, unknown> }> = [
  { label: 'desktop-chromium', use: { viewport: { width: 1280, height: 800 } } },
  { label: 'mobile-chromium (Pixel 7)', use: pixel7Mobile },
];

for (const variant of MATRIX) {
  test.describe(`poll refused notice · ${variant.label}`, () => {
    test.use(variant.use);

    test('REFUSED from the start: after three refused polls the notice names it without a time, with the hedged clock hint; an answered poll clears it', async ({ page }) => {
      test.setTimeout(120_000);
      await refuse(page);
      await genesisReceiver(page, 'Alice Refused');
      await seedAliceWithBob(page);
      await openChat(page);

      const notice = page.getByTestId('notes-poll-refused-notice');
      await expect(notice).toBeVisible({ timeout: 30_000 });
      await expect(page.getByTestId('notes-poll-refused-text')).toHaveText(POLL_REFUSED_COPY.never);
      await expect(page.getByTestId('notes-poll-refused-hint')).toHaveText(POLL_REFUSED_COPY.hint);
      // Never the words the copy forbids.
      await expect(notice).not.toContainText(/caught up|up to date|no new messages|kept|safe|\d+ (message|waiting)/i);

      await page.context().unroute(QUEUE);
      await answer(page, []);
      await expect(notice).toHaveCount(0, { timeout: 20_000 });
    });

    test('REFUSED after an answered poll: the notice names the time of the last answered poll; refused again then answered clears it', async ({ page }) => {
      test.setTimeout(120_000);
      await answer(page, []);
      await genesisReceiver(page, 'Alice Since');
      await seedAliceWithBob(page);
      await openChat(page);
      await page.waitForTimeout(4_000); // several answered polls first: the session has a "last answered" time
      await expect(page.getByTestId('notes-poll-refused-notice')).toHaveCount(0);

      await page.context().unroute(QUEUE);
      await refuse(page);
      const text = page.getByTestId('notes-poll-refused-text');
      await expect(text).toBeVisible({ timeout: 30_000 });
      await expect(text).toHaveText(/^Couldn't check for new messages since .+\. The relay refused this device's request\.$/);
      await expect(page.getByTestId('notes-poll-refused-hint')).toHaveText(POLL_REFUSED_COPY.hint);

      await page.context().unroute(QUEUE);
      await answer(page, []);
      await expect(page.getByTestId('notes-poll-refused-notice')).toHaveCount(0, { timeout: 20_000 });
    });

    test('UNREADABLE reply (200 that is not a list): the notice says the reply could not be read, never "refused", and carries NO clock hint', async ({ page }) => {
      test.setTimeout(120_000);
      await answer(page, {});
      await genesisReceiver(page, 'Alice Unreadable');
      await seedAliceWithBob(page);
      await openChat(page);

      await expect(page.getByTestId('notes-poll-refused-notice')).toBeVisible({ timeout: 30_000 });
      await expect(page.getByTestId('notes-poll-refused-text')).toHaveText(POLL_REFUSED_COPY.unreadableNever);
      await expect(page.getByTestId('notes-poll-refused-text')).not.toContainText(/refused/i);
      await expect(page.getByTestId('notes-poll-refused-hint')).toHaveCount(0);
    });
  });
}
