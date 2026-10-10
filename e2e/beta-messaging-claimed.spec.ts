import { test, expect } from '@playwright/test';

/**
 * #218 composition fix — gate-ON + CLAIMED must render the working NotesInbox
 * (explainer optionally above), NOT the explainer alone.
 *
 * Before the fix: betaMessagingOn && claimed -> <BetaExplainer/> ONLY, so the
 * "unlock beta messaging" flow replaced the functioning inbox with static copy
 * (GPT review / Peter #167278 / Hypatia #167293). This proves the OPERATION on the
 * rendered page, not just the source (Peter: "prove it in playwright before fixed").
 *
 * Requires the dev server booted with NEXT_PUBLIC_SVRNTY_BETA_GATE=1 (gate ON) —
 * NEXT_PUBLIC_* inlines at dev-server start, so it is a server-env precondition, not a
 * per-test toggle. The CLAIMED state is seeded via the device-local flag
 * (readLocalBetaClaimed, keyed by the active fingerprint) — the issuer-signed redeem
 * crypto is unit-tested separately; this spec isolates the composition.
 */
test('gate-ON + claimed renders the working Notes inbox, not explainer-only', async ({ page }) => {
  test.setTimeout(90_000);

  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Beta Claimed E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();

  // identity live
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });

  // read the active fingerprint the app persisted (IndexedDB svrnty / settings / active_fingerprint)
  const fp = await page.evaluate(
    () =>
      new Promise<string | null>((resolve) => {
        const req = indexedDB.open('svrnty');
        req.onsuccess = () => {
          try {
            const db = req.result;
            const tx = db.transaction('settings', 'readonly');
            const g = tx.objectStore('settings').get('active_fingerprint');
            g.onsuccess = () => resolve((g.result && g.result.value) || null);
            g.onerror = () => resolve(null);
          } catch {
            resolve(null);
          }
        };
        req.onerror = () => resolve(null);
      }),
  );
  expect(fp, 'active fingerprint should be persisted after the ceremony').toBeTruthy();

  // seed the device-local "claimed" bit for this identity (exact key format), BEFORE first
  // activating the Notes tab so BetaMessagingTab mounts with claimed=true (no reload/relock).
  await page.evaluate((f) => {
    window.localStorage.setItem(
      'svrnty.beta-messaging.claimed:' + String(f).trim().toLowerCase(),
      '1',
    );
  }, fp);

  // open the Notes tab (first activation -> BetaMessagingTab mounts, gate ON, claimed true)
  await page.getByTestId('tab-notes').click();

  // THE FIX: explainer above + the working NotesInbox; the redeem form is gone (claimed).
  await expect(page.getByTestId('beta-messaging-explainer')).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId('notes-inbox')).toBeVisible();
  await expect(page.getByTestId('beta-redeem-form')).toHaveCount(0);
});
