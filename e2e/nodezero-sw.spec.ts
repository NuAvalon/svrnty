import { test, expect } from '@playwright/test';

// Deployed Node Zero G-D verify (Archie's "built≠deployed" bar): the REAL bundled public/sw.js (build:sw) — not
// the module-level gd-* KATs — registers, activates, adopts the signed release (TOFU pin from the served
// /.well-known/svrnty/release.json), and verifies the honest served bundle IN A REAL BROWSER without a scary
// WARN. This exercises the SW-event plumbing (install / activate / fetch), which the module tests do not.
//
// Config: playwright.sw.config.ts (prod `next start`, port 3212). Prereq: `npm run build` then
// `npx tsx scripts/sign-release.ts`. The signed delivery uses a TEST genesis — the real mint signs with the
// air-gapped Root-B; this proves the DEPLOYED pipeline, not the mint key.

type PinRecord = { publisherFpHex?: string; acceptedBundleHashHex?: string | null; diverged?: boolean; hwm?: number };

function readPin() {
  return new Promise<PinRecord | null>((resolve) => {
    const req = indexedDB.open('svrnty-nodezero');
    req.onsuccess = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('pin')) return resolve(null);
      const g = db.transaction('pin', 'readonly').objectStore('pin').get('nodezero');
      g.onsuccess = () => resolve((g.result as PinRecord) ?? null);
      g.onerror = () => resolve(null);
    };
    req.onerror = () => resolve(null);
  });
}

test('deployed SW registers + activates + adopts the signed release + verifies the honest bundle (no scary WARN)', async ({ page }) => {
  const runtimeErrors: string[] = [];
  page.on('pageerror', (e) => runtimeErrors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error') runtimeErrors.push(`console.error: ${m.text()}`); });

  await page.addInitScript(() => {
    (window as unknown as { __nzWarn: unknown[] }).__nzWarn = [];
    navigator.serviceWorker?.addEventListener('message', (e: MessageEvent) => {
      const d = (e as MessageEvent).data;
      if (d && d.type === 'NODEZERO_WARN') (window as unknown as { __nzWarn: unknown[] }).__nzWarn.push(d);
    });
  });

  // 1. first load registers the SW (layout.tsx inline script); wait for it to activate (the bundle must RUN).
  await page.goto('/', { waitUntil: 'load' });
  const activated = await page.evaluate(async () => {
    const reg = await navigator.serviceWorker.ready; // resolves once an active worker exists
    return { active: !!reg.active, scriptURL: reg.active?.scriptURL ?? '' };
  });
  expect(activated.active, 'the REAL /sw.js installs + activates without throwing (bundle runs as a SW)').toBe(true);
  expect(activated.scriptURL).toContain('/sw.js');

  // 2. reload so the SW controls this client + intercepts + adopts (fetch release.json → bootstrap pin → verify).
  await page.reload({ waitUntil: 'networkidle' });

  // 3. ADOPT completed end-to-end: poll until the pin has committed an acceptedBundleHashHex (bootstrapPin +
  //    adoptUpdate → commitAccepted ran → sig verified + manifest bound). This is the deployed-runtime proof of
  //    the adopt path the module KATs only exercise as pure functions.
  await expect.poll(async () => page.evaluate(readPin).then((p) => !!(p && p.publisherFpHex && p.acceptedBundleHashHex)),
    { message: 'SW adopts the signed release end-to-end (pin + acceptedBundleHashHex committed)', timeout: 40_000 }).toBe(true);

  const pin = await page.evaluate(readPin);
  expect(pin?.diverged, 'the honest, correctly-signed bundle did NOT diverge (verify passed in the real SW)').toBeFalsy();
  expect((pin?.acceptedBundleHashHex ?? '').length, 'acceptedBundleHashHex is a committed 32-byte hex').toBe(64);

  // 4. the honest bundle must not trigger the scary tampering WARN, nor throw in the SW handlers.
  const warns = await page.evaluate(() => (window as unknown as { __nzWarn: unknown[] }).__nzWarn ?? []);
  expect(warns, `no scary NODEZERO_WARN on the honest signed bundle (got ${JSON.stringify(warns)})`).toHaveLength(0);
  expect(runtimeErrors.filter((e) => /sw\.js|serviceworker|nodezero|indexeddb/i.test(e)), `no SW runtime errors: ${JSON.stringify(runtimeErrors)}`).toHaveLength(0);
});
