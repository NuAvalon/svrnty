import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';

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

// CSP ENFORCEMENT GATE (Flint §9 completeness — the definitive proof, beyond static extraction): serve every
// shell under the signer's exact script-src hash-union and assert the browser raises ZERO script-src violations.
// A violation = a MISSING inline-script hash → that script is CSP-BLOCKED → the shell breaks (or someone adds
// 'unsafe-inline' and defeats the lock). Flint's two-seat static extraction (#142321) already == the 24; this is
// the runtime enforcement half. The hashes come from the signer's csp-inline-hashes.json (byte-stable shells).
test('CSP enforcement gate: the signer 24-hash script-src loads every shell with ZERO script-src violations', async ({ browser }) => {
  const hashes: string[] = JSON.parse(readFileSync('public/.well-known/svrnty/csp-inline-hashes.json', 'utf8')).script_src_inline_hashes;
  expect(hashes.length, 'signer emitted inline-script hashes (run `npx tsx scripts/sign-release.ts` first)').toBeGreaterThan(0);
  const csp = [
    `default-src 'self'`,
    `script-src 'self' ${hashes.join(' ')}`, // 'self' = /_next/static chunks; hashes = the inline scripts. NO unsafe-inline.
    `style-src 'self' 'unsafe-inline'`, // Next injects inline styles; not the security-critical axis for this gate
    `img-src 'self' data: blob:`,
    `font-src 'self' data:`,
    `connect-src 'self'`,
    `object-src 'none'`,
    `base-uri 'none'`,
    `frame-ancestors 'none'`,
  ].join('; ');

  const ctx = await browser.newContext(); // fresh — no SW, isolate the CSP gate
  const page = await ctx.newPage();
  await page.addInitScript(() => {
    (window as unknown as { __csp: string[] }).__csp = [];
    document.addEventListener('securitypolicyviolation', (e: SecurityPolicyViolationEvent) => {
      (window as unknown as { __csp: string[] }).__csp.push(`${e.effectiveDirective || e.violatedDirective}|${e.blockedURI || 'inline'}|${e.sourceFile || ''}:${e.lineNumber || 0}`);
    });
  });
  // inject the launch CSP onto the navigation documents (the shells)
  await page.route('**/*', async (route) => {
    if (route.request().resourceType() !== 'document') return route.continue();
    const resp = await route.fetch();
    const headers = { ...resp.headers() };
    delete headers['content-security-policy'];
    delete headers['content-security-policy-report-only'];
    headers['content-security-policy'] = csp;
    await route.fulfill({ response: resp, headers });
  });

  const violations: string[] = [];
  for (const path of ['/', '/u/alice', '/c/testcode', '/msg', '/dev/seals', '/definitely-not-a-real-route']) {
    await page.goto(path, { waitUntil: 'load' });
    await page.waitForTimeout(400);
    const v: string[] = await page.evaluate(() => (window as unknown as { __csp: string[] }).__csp || []);
    for (const x of v) if (x.startsWith('script-src')) violations.push(`${path} → ${x}`);
    await page.evaluate(() => { (window as unknown as { __csp: string[] }).__csp = []; });
  }
  await ctx.close();
  expect(violations, `ZERO script-src violations under the signer ${hashes.length}-hash union (a violation = a MISSING inline-script hash): ${JSON.stringify(violations)}`).toHaveLength(0);
});
