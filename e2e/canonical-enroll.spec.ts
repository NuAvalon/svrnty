import { test, expect, type Page } from '@playwright/test';

// E2E: the CANONICAL OPEN-MINT door (PR#128, track-a). The UI half of the "mint your sovereign
// identity" ship-gate (Hypatia #135106); the API round-trip is co-verified separately (KB#89410).
//
// Preconditions (both live as of 2026-09-12):
//   • NEXT_PUBLIC_CANONICAL_ENROLL=true on the dev server (else "I have it" lands straight in the
//     app and the enrolling gate never appears → this test fails, by design).
//   • SATELLITE_URL points at an authority whose /verify OTP entry-gate is REMOVED (Athena
//     92118c49) so the open 4-key mint is accepted with NO email/OTP.
//
// Proves: the REAL UI drives mint → enrollCanonicalIdentity → POST /api/satellite/verify
// (proxy → SATELLITE_URL/verify) → and the honest success copy "Your sovereign identity is live"
// renders ONLY on satellite_registered:true (Hypatia G2 — not a bare 200). The stored identity is
// the canonical full-64 DID (never truncated). This is the canonical door — NOT landing.html.
//
// Run:
//   NEXT_PUBLIC_CANONICAL_ENROLL=true SATELLITE_URL=https://dev.svrnty.is npm run dev   # server
//   npx playwright test e2e/canonical-enroll.spec.ts                                    # test

const APP = 'http://localhost:3000/';
const NAME = 'Canonical E2E';
const UNLOCK_PW = 'canonical-e2e-pass-1234';
const HEX64 = /^[0-9a-f]{64}$/;

// Reads the active canonical DID straight from IndexedDB (the owner-card UI truncates the
// fingerprint to 32 hex, so assert against the store for a canonical-length check).
async function readActiveDid(page: Page): Promise<string | null> {
  return page.evaluate(async () => {
    const db: IDBDatabase = await new Promise((res, rej) => {
      const r = indexedDB.open('svrnty');
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    const get = (store: string, key: string) =>
      new Promise<any>((res, rej) => {
        const rq = db.transaction(store, 'readonly').objectStore(store).get(key);
        rq.onsuccess = () => res(rq.result);
        rq.onerror = () => rej(rq.error);
      });
    const active = await get('settings', 'active_fingerprint');
    const fp = active?.value ?? null;
    if (!fp) return null;
    const rec = await get('identities', fp);
    return rec?.data?.identity?.fingerprint ?? null;
  });
}

test('canonical open-mint: UI drives real enroll → "live" copy gates on propagation', async ({ page }) => {
  // OPT-IN staging check — unlike the rest of the e2e suite (self-contained / mocked), this drives a
  // REAL round-trip against a live open-mint authority and mints a real identity on it. It therefore
  // does NOT run in CI: it needs (a) the dev server built with NEXT_PUBLIC_CANONICAL_ENROLL=true and
  // (b) SATELLITE_URL pointed at an authority whose /verify OTP-gate is removed. Run on demand:
  //   RUN_CANONICAL_ENROLL_E2E=1 \
  //   NEXT_PUBLIC_CANONICAL_ENROLL=true SATELLITE_URL=https://dev.svrnty.is npm run dev   # server
  //   RUN_CANONICAL_ENROLL_E2E=1 npx playwright test e2e/canonical-enroll.spec.ts         # test
  test.skip(
    process.env.RUN_CANONICAL_ENROLL_E2E !== '1',
    'opt-in: set RUN_CANONICAL_ENROLL_E2E=1 + run the dev server with NEXT_PUBLIC_CANONICAL_ENROLL=true and a reachable open /verify authority (hits a live authority; skipped in CI)',
  );
  test.setTimeout(120_000);
  await page.goto(APP);

  // Mint a fresh 4-key identity (same create flow as identity.spec.ts).
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(NAME);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(UNLOCK_PW);
  await page.getByPlaceholder('Confirm passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^start$/i }).click();

  // One-time recovery reveal — real in-browser keygen (Ed25519 + X25519 + ML-DSA-87 + ML-KEM-1024)
  // runs first, so wait generously. Ack it to proceed.
  const seed = page.getByTestId('seed-phrase-display');
  await expect(seed).toBeVisible({ timeout: 60_000 });
  await page.getByRole('checkbox', { name: /written this down offline/i }).check();
  await page.getByRole('button', { name: /i have it/i }).click();

  // Flag ON → the enrolling gate (canonical enroll), NOT straight into the app. The enroll POSTs the
  // 4-key body to the authority's OPEN /verify via the proxy.
  //
  // THE LOAD-BEARING ASSERTION: the "live" heading renders ONLY when the response is
  // satellite_registered:true. A bare 200 (propagation still finalizing) shows "Finalizing…"
  // instead — so this asserts the honest-copy gate (G2) AND the real round-trip in one.
  await expect(page.getByRole('heading', { name: /your sovereign identity is live/i })).toBeVisible({
    timeout: 60_000,
  });
  await expect(page.getByText(/its binding has propagated/i)).toBeVisible();

  // The stored identity is the canonical full-64 DID (never the truncated fp the wrong-genesis
  // doors used).
  const did = await readActiveDid(page);
  expect(did ?? '').toMatch(HEX64);

  // Continue → lands in the unlocked app (tab strip only renders with an unlocked identity).
  await page.getByRole('button', { name: /^continue$/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
});
