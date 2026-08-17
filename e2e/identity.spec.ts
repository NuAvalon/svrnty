import { test, expect } from '@playwright/test';

// Drives the REAL create-identity flow to the unlocked app. This is the foundation every demo-arc
// spec needs — contact import and the trust ceremony both require an unlocked identity. Real
// in-browser keygen runs here (ED25519 + ML-DSA-87 signing, Curve25519 + ML-KEM-1024 encryption),
// so the unlock assertion gets a generous timeout. Each test gets a fresh browser context, so the
// IndexedDB identity store starts empty.
test('create an identity → land in the unlocked app', async ({ page }) => {
  await page.goto('/');

  // The gate opens on 'choose' (two doors). The "Begin anew." door reveals the create form; match
  // it by its unique description so it isn't confused with the form's "Begin anew." submit button.
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();

  await page.getByPlaceholder('Your name').fill('Alice E2E');
  await page.getByPlaceholder('your@email.com').fill('alice-e2e@example.test');
  // Passphrase must be ≥12 chars and match its confirmation (the button stays disabled otherwise).
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');

  await page.getByRole('button', { name: /begin anew/i }).click();

  // After keygen, a one-time recovery-phrase screen appears (the phrase reconstructs the master
  // secret). Acknowledge it — "Continue" stays disabled until the checkbox is ticked. The check()
  // timeout absorbs the in-browser keygen.
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();

  // Now the unlocked app: the tab strip only renders with an unlocked identity, so a visible
  // Contacts tab is a reliable "we're in" signal.
  await expect(page.getByRole('tab', { name: 'Contacts' })).toBeVisible({ timeout: 15_000 });
});
