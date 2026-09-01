import { test, expect } from '@playwright/test';
import path from 'path';

// The 0.12 "import the gray sea" demo-arc flow (T11). Drives the REAL app end-to-end:
// create identity → import a multi-contact vCard → dedup preview → confirm-gate → re-import merges.
// This is the standing verification for ImportContactsDialog (React not checkable in-container).
// Multi-contact fixture is deliberate: it exercises Athena's keyless-fingerprint fix (8bb8eef) —
// with the old fingerprint='' the 2nd gray would ConstraintError on the UNIQUE index.

const VCF = path.join(__dirname, 'fixtures', 'contacts.vcf'); // 3 distinct grays (name/phone/email)

// Reuses the create-identity foundation (mirrors e2e/identity.spec.ts). Each test = fresh context
// → empty IndexedDB, so the first import lands into an empty book.
async function createIdentity(page) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Alice E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
}

test('import the gray sea: vCard → grays → dedup preview → confirm; re-import merges (idempotent)', async ({ page }) => {
  await createIdentity(page);
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();

  // First import: 3 gray contacts into an empty book → all fresh.
  await page.getByTestId('import-contacts-trigger').click();
  await expect(page.getByTestId('import-contacts-dialog')).toBeVisible();
  await page.getByTestId('vcf-input').setInputFiles(VCF);
  await expect(page.getByTestId('import-preview')).toBeVisible();
  await expect(page.getByTestId('fresh-count')).toHaveText('3');

  // Confirm-gate (B2): nothing is written until the explicit confirm — the preview above proves
  // the set is SHOWN before any addContact runs.
  await page.getByTestId('import-confirm').click();
  await expect(page.getByTestId('import-done')).toBeVisible();
  await page.getByRole('button', { name: /^Done$/ }).click();

  // Re-import the SAME .vcf → the dedup engine catches all 3 as merges (idempotent), 0 new.
  // Proves: multi-gray stored without collision (Athena's fix) + exact-key dedup end-to-end.
  await page.getByTestId('import-contacts-trigger').click();
  await page.getByTestId('vcf-input').setInputFiles(VCF);
  await expect(page.getByTestId('merge-count')).toHaveText('3');
  await expect(page.getByTestId('fresh-count')).toHaveText('0');
});
