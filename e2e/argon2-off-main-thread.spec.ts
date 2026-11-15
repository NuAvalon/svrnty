import { test, expect, type Page, type Browser } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { unpackVault } from '../src/lib/sync/vault';

/**
 * Exporting or restoring a vault runs Argon2id (64 MiB, three passes). On the page's own thread that is a frozen screen for seconds. This drives the REAL
 * user path (mint an identity, export a vault from the Identity tab, restore it on a new device) in a real browser under the page's real script policy,
 * and measures what the owner would feel: every stretch in which the page's own timer (every 20 ms) could not run. Each worker's lifetime is recorded in
 * page time, so the blocked time is split into the part that overlaps a derivation (what this change is about) and the rest of the flow (chunk loading,
 * reading the book: not touched by this change, reported, not asserted).
 *
 * Two things must hold with the change: the derivation happens in a WORKER that the policy allows (a same-origin script, not blob:), and the page stays
 * alive while it runs. And the file that came out of that path must be a real vault: it is unpacked here in Node, whose derivation is the synchronous one,
 * so a key the worker got wrong could not decrypt it.
 *
 * ARGON_CONTROL=1 points the same spec at the tree BEFORE the change and expects the opposite (no worker; a freeze of a second or more), so the numbers
 * are not just "small" but small compared with what the same flow did.
 *
 * Needs a PRODUCTION build (`next build && next start`): `next dev` adds compile pauses of its own and a looser policy.
 */

const CONTROL = !!process.env.ARGON_CONTROL;
const UNLOCK_PW = 'unlock-e2e-pass-1234';
const EXPORT_PW = 'export-e2e-pass-5678';
// Measured on a production build in headless Chromium (one CPU of container quota): BEFORE the change the export blocked the page for one stretch of ~5.7 s;
// AFTER it, the worst stretch while the derivation ran was 0.5-0.7 s on export and 0.3 s on restore (the app has its own periodic ~0.15 s task on the main
// thread, which gets stretched while the worker uses the CPU; the same probe on an IDLE screen read 0.14-0.52 s across runs and builds, so this is noisy).
// The two limits meet at one second: the control must show at least that, the change must stay under it.
const FROZEN_MS = 1000;
const ALIVE_MS = 1000;

test.setTimeout(240_000);
test.describe.configure({ mode: 'serial' });

declare global {
  interface Window { __probe: { on: boolean; last: number; gaps: Array<[number, number]>; long: Array<[number, number]>; spans: Array<[number, number | null]> } }
}

const PROBE = () => {
  const p = { on: false, last: performance.now(), gaps: [] as Array<[number, number]>, long: [] as Array<[number, number]>, spans: [] as Array<[number, number | null]> };
  window.__probe = p;
  setInterval(() => { const n = performance.now(); if (p.on && n - p.last > 100) p.gaps.push([p.last, n]); p.last = n; }, 20);
  try { new PerformanceObserver((l) => { if (p.on) for (const e of l.getEntries()) p.long.push([e.startTime, e.startTime + e.duration]); }).observe({ type: 'longtask', buffered: false }); } catch { /* not supported: the timer still measures */ }
  const W = window.Worker;
  window.Worker = class extends W {
    constructor(...a: ConstructorParameters<typeof W>) {
      super(...a);
      const span: [number, number | null] = [performance.now(), null];
      p.spans.push(span);
      const end = () => { if (span[1] === null) span[1] = performance.now(); };
      // a worker's first message is its "ready" note; the derivation is over at its answer (a message that carries `ok`), an error, or when the page terminates it
      this.addEventListener('message', (e) => { const d = (e as MessageEvent).data; if (d && typeof d === 'object' && 'ok' in d) end(); });
      this.addEventListener('error', end);
      const terminate = this.terminate.bind(this);
      this.terminate = () => { end(); terminate(); };
    }
  } as typeof Worker;
};

type Seen = { workers: string[]; refusals: string[] };
function watch(page: Page): Seen {
  const seen: Seen = { workers: [], refusals: [] };
  page.on('worker', (w) => seen.workers.push(w.url()));
  page.on('console', (m) => { if (/content security policy|refused to (create|load|execute)/i.test(m.text())) seen.refusals.push(m.text().slice(0, 200)); });
  return seen;
}

async function start(page: Page) { await page.evaluate(() => { const p = window.__probe; p.gaps.length = 0; p.long.length = 0; p.spans.length = 0; p.last = performance.now(); p.on = true; }); }
type Blocked = { maxGapMs: number; maxGapDuringWorkerMs: number; maxGapElsewhereMs: number; workerRunMs: number };
async function stop(page: Page): Promise<Blocked> {
  return page.evaluate(() => {
    const p = window.__probe; p.on = false;
    const now = performance.now();
    const spans = p.spans.map(([s, e]) => [s, e ?? now] as [number, number]);
    let during = 0, elsewhere = 0, all = 0;
    for (const [g0, g1] of p.gaps) {
      const len = g1 - g0; all = Math.max(all, len);
      // the part of this gap that lies inside a derivation, and the part that does not
      const inside = Math.max(0, ...spans.map(([w0, w1]) => Math.min(g1, w1) - Math.max(g0, w0)));
      during = Math.max(during, inside);
      elsewhere = Math.max(elsewhere, len - inside);
    }
    return { maxGapMs: Math.round(all), maxGapDuringWorkerMs: Math.round(during), maxGapElsewhereMs: Math.round(elsewhere), workerRunMs: Math.round(Math.max(0, ...spans.map(([w0, w1]) => w1 - w0))) };
  });
}

async function mint(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill('Argon E2E');
  await page.getByPlaceholder('Encrypts your keys at rest').fill(UNLOCK_PW);
  await page.getByPlaceholder('Confirm passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  await expect(page.getByTestId('seed-phrase-display')).toBeVisible({ timeout: 60_000 });
  await page.getByRole('checkbox', { name: /written this down offline/i }).check();
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
}

function expectations(kind: string, seen: Seen, m: Blocked) {
  const line = `workers=${seen.workers.length} derivationRan=${m.workerRunMs}ms blockedWhileDeriving=${m.maxGapDuringWorkerMs}ms blockedElsewhere=${m.maxGapElsewhereMs}ms maxGap=${m.maxGapMs}ms refusals=${seen.refusals.length}`;
  test.info().annotations.push({ type: kind, description: line });
  console.log(`[argon2-e2e] ${CONTROL ? 'CONTROL (before)' : 'WITH CHANGE'} ${kind}: ${line} workerUrls=${JSON.stringify(seen.workers)} refusals=${JSON.stringify(seen.refusals)}`);
  if (CONTROL) {
    expect(seen.workers, 'control: the old path starts no worker').toHaveLength(0);
    expect(m.maxGapMs, 'control: the page really freezes').toBeGreaterThanOrEqual(FROZEN_MS);
  } else {
    expect(seen.refusals, 'the page policy refused nothing').toEqual([]);
    expect(seen.workers.length, 'a worker ran').toBeGreaterThanOrEqual(1);
    for (const u of seen.workers) { expect(u.startsWith('blob:'), `not a blob worker: ${u}`).toBe(false); expect(u, 'a same-origin script').toMatch(/^https?:\/\/[^/]+\/_next\//); }
    expect(m.workerRunMs, 'the derivation really took seconds (so "alive" means something)').toBeGreaterThanOrEqual(FROZEN_MS);
    expect(m.maxGapDuringWorkerMs, 'the page stayed alive while the derivation ran').toBeLessThan(ALIVE_MS);
  }
}

let vaultPath = '';

test('exporting a vault: the derivation runs in a worker the policy allows, the page stays alive, and the file is a real vault', async ({ browser }, testInfo) => {
  const ctx = await browser.newContext({ acceptDownloads: true });
  const page = await ctx.newPage();
  await page.addInitScript(PROBE);
  const seen = watch(page);
  await mint(page);

  // BASELINE: the same probe over eight idle seconds on the owner's screen, nothing exported. Whatever blocks the page here is not the derivation.
  await page.getByRole('tab', { name: 'Identity' }).click();
  await start(page);
  await page.waitForTimeout(8000);
  const idle = await stop(page);
  console.log(`[argon2-e2e] IDLE BASELINE (8 s, no export): maxGap=${idle.maxGapMs}ms`);
  await page.getByTestId('card-actions-toggle').click();
  await page.getByTestId('full-backup-open').click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(UNLOCK_PW);
  await page.getByRole('button', { name: /^continue$/i }).click();
  await page.getByTestId('vault-export-passphrase').fill(EXPORT_PW);
  await page.getByTestId('vault-export-confirm').fill(EXPORT_PW);
  seen.workers.length = 0;                       // only what the EXPORT starts counts
  const download = page.waitForEvent('download', { timeout: 180_000 });
  await start(page);
  await page.getByTestId('vault-export-download').click();
  const d = await download;
  const m = await stop(page);
  vaultPath = testInfo.outputPath('argon-e2e.svrnty');
  await d.saveAs(vaultPath);
  expectations('export', seen, m);

  // the file the worker's key produced decrypts with the synchronous derivation
  const opened = await unpackVault(new Uint8Array(readFileSync(vaultPath)).buffer, EXPORT_PW);
  expect(opened.header.version).toBe(4);
  expect(opened.contents.identity).toBeTruthy();
  await ctx.close();
});

async function restore(browser: Browser) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.addInitScript(PROBE);
  const seen = watch(page);
  await page.goto('/');
  await page.getByRole('button', { name: /restore your identity from a vault file/i }).click();
  await page.setInputFiles('[data-testid="restore-file-input"]', vaultPath);
  await page.getByPlaceholder('Encryption password from export').fill(EXPORT_PW);
  seen.workers.length = 0;
  await start(page);
  await page.getByRole('button', { name: /^restore identity$/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 120_000 });
  const m = await stop(page);
  await ctx.close();
  return { seen, m };
}

test('restoring a vault on a new device: same worker, same page-stays-alive, and the restore completes', async ({ browser }) => {
  expect(vaultPath, 'the export test ran first').not.toBe('');
  const { seen, m } = await restore(browser);
  expectations('restore', seen, m);
});
