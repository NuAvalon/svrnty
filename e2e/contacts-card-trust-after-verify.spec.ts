import { test, expect, type Page } from '@playwright/test';

// Verify, then Trust, in one sitting, on the Contacts-tab card, in a real browser (desktop and a 390 px phone).
//
// Two identities in two contexts exchange a card the way a person does (the Share dialog's Copy tab, then Import Contact). B opens A's card on the
// Contacts tab and taps Trust: Verify opens and trusts nothing. B verifies with the fingerprint A reads out (the other-channel path), closes the
// sheet, and accepts the app's own confirmation. The contact must be Trusted, and the "verify first" refusal must not appear: the card has to
// see the stamp that was just saved, not the contact as it was when the row was clicked.
const PASS = 'e2e-passphrase-1234';
const TRUSTED = /trusted/i;

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('card-verify-trust@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill(PASS);
  await page.getByPlaceholder('Confirm passphrase').fill(PASS);
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

/** The owner's signed card text and fingerprint, from the Share dialog's Copy tab. */
async function readOwnCard(page: Page): Promise<{ card: string; fingerprint: string }> {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('share-identity-from-card').click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible({ timeout: 15_000 });
  await dialog.getByRole('tab', { name: /copy/i }).click();
  const card = (await dialog.locator('pre').first().innerText()).trim();
  const m = card.match(/"fingerprint"\s*:\s*"([0-9a-fA-F]{40,64})"/);
  expect(m, 'the card carries the owner\'s fingerprint').not.toBeNull();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  return { card, fingerprint: m![1] };
}

const VIEWPORTS: Array<[string, { width: number; height: number }]> = [
  ['desktop', { width: 1280, height: 900 }],
  ['phone 390x844', { width: 390, height: 844 }],
];

for (const [vpName, viewport] of VIEWPORTS) {
  test.describe(`Verify then Trust on the Contacts card: ${vpName}`, () => {
    test('Trust right after a saved Verify trusts the contact, with no verify-first refusal', async ({ browser }) => {
      test.setTimeout(180_000);
      const ctxA = await browser.newContext({ viewport });
      const ctxB = await browser.newContext({ viewport });
      try {
        const a = await ctxA.newPage();
        const b = await ctxB.newPage();
        await genesis(a, 'Card Owner');
        await genesis(b, 'Card Peer');
        const { card, fingerprint } = await readOwnCard(a);

        // B imports A's card (local: a real signed card, verified by the app).
        await b.getByRole('tab', { name: 'Contacts', exact: true }).click();
        await b.getByRole('button', { name: /^import contact$/i }).click();
        await b.getByPlaceholder(/paste the signed identity package/i).fill(card);
        await b.getByRole('button', { name: /verify & import/i }).click();
        await expect(b.getByRole('alert').first()).toContainText(/added successfully/i, { timeout: 20_000 });
        await b.keyboard.press('Escape');

        // B opens A's card and taps Trust: Verify opens and nothing is trusted yet.
        await b.getByText('Card Owner').first().click();
        const cardView = b.getByTestId('contact-action-card');
        await expect(cardView).toBeVisible({ timeout: 15_000 });
        await expect(cardView.getByTestId('trust-node-bond-label').first()).not.toHaveText(TRUSTED);
        await b.getByTestId('card-actions-toggle').click();
        await b.getByTestId('galaxy-trust').click();
        const sheet = b.getByTestId('verify-sheet');
        await expect(sheet, 'Trust on an unverified contact opens Verify').toBeVisible({ timeout: 10_000 });

        // B verifies with the fingerprint A reads out (the other-channel path), saves, and closes the sheet.
        await sheet.getByTestId('verify-path-other-channel').click();
        await sheet.getByTestId('verify-paste').fill(fingerprint);
        await sheet.getByTestId('verify-code-matches').check();
        await sheet.getByTestId('verify-confirm').click();
        await expect(sheet.getByTestId('verify-saved')).toBeVisible({ timeout: 15_000 });
        await sheet.getByTestId('verify-close').click();
        await expect(sheet).toHaveCount(0);

        // The app's own Trust confirmation opens by itself on the SAME card. Accepting it must trust the contact.
        const confirm = b.getByTestId('trust-action-confirm-btn');
        await expect(confirm, 'after Verify, the Trust the owner asked for goes on to its own confirmation').toBeVisible({ timeout: 15_000 });
        await confirm.click();

        // No refusal, and the contact is Trusted when read fresh (the card is closed and opened again: that read does not depend on the card's copy).
        await b.waitForTimeout(2500); // a refusal toast appears within about a second; wait first so "none shown" cannot pass before it would show
        await expect(b.getByText(/before you trust/i), 'no verify-first refusal after a saved Verify').toHaveCount(0);
        await b.keyboard.press('Escape');
        await b.getByRole('button', { name: /^close$/i }).first().click().catch(() => {});
        await b.getByText('Card Owner').first().click();
        await expect(b.getByTestId('contact-action-card')).toBeVisible({ timeout: 10_000 });
        await expect(b.getByTestId('contact-action-card').getByTestId('trust-node-bond-label').first(), 'the contact is Trusted').toHaveText(TRUSTED, { timeout: 15_000 });
      } finally {
        await ctxA.close();
        await ctxB.close();
      }
    });
  });
}
