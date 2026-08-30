import { test, expect, type Page } from '@playwright/test';

// Coverage for PR#42 — the Share-Identity QR tab now encodes the relay SHORT-LINK
// (shareUrl(code,key) = https://…/c/<code>#<key>, ~scannable URL), NOT the 25KB signed card.
// The old QR tab rendered the full exchangePackage as a QR → react-qr-code overflow
// (25828 > 18672) → dialog crash. This spec locks the fix: the QR tab opens clean and,
// on generate, renders a short-link QR — no overflow, ever.
//
// Robust genesis: fills the email field ONLY if it's present, so this passes BOTH on PR#42's
// base (email still required) AND after the merge with the email-drop (PR#41, email field gone).
async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('qr-coverage@example.test'); // present only pre-email-drop
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /begin anew/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts' })).toBeVisible({ timeout: 15_000 });
}

async function openShareQrTab(page: Page) {
  // Share identity lives on the Identity card (Master Address Book pass) — not Contacts.
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('share-identity-from-card').click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible({ timeout: 10_000 });
  await dialog.getByRole('tab', { name: /qr/i }).click();
  return dialog;
}

test.describe('Share-Identity QR tab — short-link, no 25KB overflow crash (PR#42)', () => {
  // CRASH-GONE — the demo-critical assertion. ZERO-FOOTPRINT: the QR tab now shows a Generate
  // button instead of rendering the 25KB card, so opening it writes nothing. Safe on live prod.
  test('QR tab opens clean — Generate button renders, no overflow crash', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(String(e)));
    await genesis(page, 'QR Crash Gone');
    const dialog = await openShareQrTab(page);
    await expect(dialog.getByRole('button', { name: /generate qr code/i })).toBeVisible();
    expect(errors, `QR tab crashed on open (the #38 failure mode): ${errors.join('; ')}`).toHaveLength(0);
  });

  // SCANNABLE — the full give-path: generate → a short-link QR renders. ⚠ This DOES write a
  // single-use relay blob (createRelay POST), so it is NOT zero-footprint — run against CI /
  // a local relay, NOT live prod. (Live smoke uses the crash-gone test above.)
  test('QR generate renders a scannable short-link QR (no overflow)', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(String(e)));
    await genesis(page, 'QR Scannable');
    const dialog = await openShareQrTab(page);
    await dialog.getByRole('button', { name: /generate qr code/i }).click();
    // The post-generate state shows the short-link QR + its scan hint. If the card (25KB) were
    // still being QR'd this would overflow-crash; the short URL cannot.
    await expect(dialog.getByText(/scan with a phone camera/i)).toBeVisible({ timeout: 15_000 });
    expect(errors, `QR generate crashed: ${errors.join('; ')}`).toHaveLength(0);
  });
});
