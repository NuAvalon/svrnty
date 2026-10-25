import { test, expect, devices, type Page } from '@playwright/test';
import { seedAliceWithBob, depositNote } from './fixtures/deposit-note';

/**
 * N8 (task #700 / D-N8) — arrival-reload storm, full user path in a real browser. REDUCED port (K=20).
 *
 * A backlog of notes landing while the inbox is open used to fire an un-gated decrypt-everything reload PER ARRIVAL
 * (O(arrivals x store)); the inbox now routes every trigger through createReloadGate (src/lib/notes/reload-gate.ts)
 * and guards the thread-selection effect (thread-load-guard.ts).
 *
 * WHAT THIS IS NOT: it is NOT negative-first. It is a CORRECTNESS test (nothing lost to the gate, nothing duplicated) that
 * also passes on dev. The negative-first evidence is notes-inbox-reload-wiring.test.ts (0/6 on dev, 6/6 here) plus
 * reload-gate.test.ts. The aesDecrypts annotation below is a measured runtime comparison, informational, not a gate.
 * This drives the REAL path end to end — real genesis, real
 * signed + sealed notes (fixtures/deposit-note.ts), the REAL always-on shell poll, the REAL
 * NotesInbox subscribing to the REAL arrival bus — and asserts the CORRECTNESS invariant that
 * coalescing must not break: every one of the K notes ends up rendered exactly once, none lost to
 * the throttle window, none duplicated.
 *
 * Timing is deliberately NOT asserted (a wall-clock bound here would be flaky across machines). The
 * AES-GCM decrypt count and main-thread long-task total during the storm are attached as test
 * annotations so the numbers are recorded per run (they are informational, not a gate).
 *
 * RUN REQUIREMENT: this deposits 20 notes in quick succession, so the dev relay must be started with a raised
 * rate limit (RELAY_RATE_LIMIT_MAX=1000; dev's default is 10); the default limit would 429 the deposits.
 *
 * BROWSER MATRIX: desktop Chromium + mobile-Chromium (Pixel 7). WebKit/Firefox are not covered (same
 * flag as notes-roundtrip.spec.ts).
 */

const STORM_NOTES = 20;
const BODY_PAD = 'x'.repeat(2_000); // ~2 KB/note so decrypt + parse work is non-trivial

async function genesisReceiver(page: Page, name: string) {
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

const { defaultBrowserType: _ignoredBrowserType, ...pixel7Mobile } = devices['Pixel 7'];

const MATRIX: Array<{ label: string; use: Record<string, unknown> }> = [
  { label: 'desktop-chromium', use: { viewport: { width: 1280, height: 800 } } },
  { label: 'mobile-chromium (Pixel 7 — hardened-mobile center)', use: pixel7Mobile },
];

for (const variant of MATRIX) {
  test.describe(`notes arrival storm · ${variant.label}`, () => {
    test.use(variant.use);

    test(`${STORM_NOTES} notes arriving into an open inbox all render exactly once`, async ({ page, request }) => {
      test.setTimeout(180_000);

      // Count AES-GCM decrypts (the notes/contacts store path) + main-thread long tasks from page start.
      await page.addInitScript(() => {
        const w = window as unknown as { __aesDec: number; __longMs: number };
        w.__aesDec = 0;
        w.__longMs = 0;
        const sub = crypto.subtle;
        const orig = sub.decrypt.bind(sub);
        sub.decrypt = ((alg: AlgorithmIdentifier, ...rest: unknown[]) => {
          if (typeof alg === 'object' && (alg as { name?: string }).name === 'AES-GCM') w.__aesDec++;
          return (orig as (...a: unknown[]) => Promise<ArrayBuffer>)(alg, ...rest);
        }) as typeof sub.decrypt;
        try {
          new PerformanceObserver((list) => {
            for (const e of list.getEntries()) w.__longMs += e.duration;
          }).observe({ type: 'longtask' });
        } catch {
          /* longtask unsupported — annotation reads 0 */
        }
      });

      await genesisReceiver(page, 'Alice Storm');
      const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page); // no reload after this

      // Open the inbox FIRST so NotesInbox is mounted + subscribed while the backlog lands.
      const notesTab = page.getByTestId('tab-notes');
      await expect(notesTab).toBeVisible({ timeout: 20_000 });
      await notesTab.click();
      await expect(page.getByTestId('notes-inbox')).toBeVisible();

      const base = await page.evaluate(() => {
        const w = window as unknown as { __aesDec: number; __longMs: number };
        return { dec: w.__aesDec, long: w.__longMs };
      });

      const threadId = 'thr_storm_n8';
      const noteIds: string[] = [];
      for (let i = 0; i < STORM_NOTES; i++) {
        const dep = await depositNote(request, {
          sender: bob,
          recipientFingerprint: aliceFp,
          recipientPublicKeyArmored: aliceArmoredPub,
          fields: { body: `storm ${i} ${BODY_PAD}`, threadId },
        });
        expect(dep.status).toBe(200);
        noteIds.push(dep.note_id);
      }

      const threadBtn = page.getByTestId(`notes-thread-${threadId}`);
      await expect(threadBtn).toBeVisible({ timeout: 60_000 });
      await threadBtn.click();

      // CORRECTNESS: all K bubbles render, exactly once each. A reload dropped by the throttle window
      // (or a follow-up that never ran) would leave this short; a double render would overshoot it.
      await expect(page.locator('[data-testid^="notes-bubble-"]')).toHaveCount(STORM_NOTES, { timeout: 90_000 });
      for (const id of noteIds) {
        await expect(page.getByTestId(`notes-bubble-${id}`)).toHaveCount(1);
      }

      // Stays correct after the store settles (the periodic tick re-reads; the count must not drift).
      await page.waitForTimeout(3_500);
      await expect(page.locator('[data-testid^="notes-bubble-"]')).toHaveCount(STORM_NOTES);

      const end = await page.evaluate(() => {
        const w = window as unknown as { __aesDec: number; __longMs: number };
        return { dec: w.__aesDec, long: w.__longMs };
      });
      console.log(`STORM-RESULT ${variant.label} K=${STORM_NOTES} aesDecrypts=${end.dec - base.dec} longtaskMs=${Math.round(end.long - base.long)}`);
      test.info().annotations.push(
        { type: 'storm-aes-gcm-decrypts', description: String(end.dec - base.dec) },
        { type: 'storm-longtask-ms', description: String(Math.round(end.long - base.long)) },
      );
    });
  });
}
