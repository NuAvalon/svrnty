import { test, expect, type Page } from '@playwright/test';

// Pre-gate 1-greeting, GIVER side (Peter #175591 / Flint spec req 6): the Gate must render the greeting
// as inert PLAIN TEXT. The greeting is untrusted content on a pre-trust surface (#583 class), so the
// test seeds a HOSTILE one and asserts it is shown verbatim as text and never interpreted.
//
// The arrival is seeded as raw JSON under settings/grow_gate_arrivals — exactly what enqueueGateArrival
// persists — so the app LOADS it through normalizeGateMap -> normalizeArrival. That makes this spec a
// browser-level regression for the bug where the store's field whitelist silently dropped `greeting`:
// if normalizeArrival loses the field, the greeting element below never appears and the test fails.

const HOSTILE =
  '<img src=x onerror="window.__pwned=1">\n<b>bold</b> https://evil.example/phish [click](javascript:alert(1))\nline two';

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('pregate-greeting@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 15_000 });
}

async function seedArrival(page: Page, arrival: Record<string, unknown>) {
  await page.evaluate(async (a) => {
    const open = () =>
      new Promise<IDBDatabase>((resolve, reject) => {
        const req = indexedDB.open('svrnty');
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    const get = (db: IDBDatabase, key: string) =>
      new Promise<any>((resolve, reject) => {
        const g = db.transaction('settings', 'readonly').objectStore('settings').get(key);
        g.onsuccess = () => resolve(g.result);
        g.onerror = () => reject(g.error);
      });
    const put = (db: IDBDatabase, value: unknown) =>
      new Promise<void>((resolve, reject) => {
        const tx = db.transaction('settings', 'readwrite');
        tx.objectStore('settings').put(value);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    const db = await open();
    const owner = (await get(db, 'active_fingerprint'))?.value;
    if (!owner) throw new Error('no owner fingerprint');
    let map: Record<string, Record<string, unknown>> = {};
    try {
      map = JSON.parse((await get(db, 'grow_gate_arrivals'))?.value || '{}');
    } catch {
      map = {};
    }
    if (!map[owner]) map[owner] = {};
    map[owner][a.fingerprint as string] = a;
    await put(db, { key: 'grow_gate_arrivals', value: JSON.stringify(map) });
    db.close();
  }, arrival);
}

const baseArrival = (over: Record<string, unknown>) => ({
  fingerprint: 'bb'.repeat(20),
  displayName: 'River',
  publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nAAA\n-----END PGP PUBLIC KEY BLOCK-----',
  epoch: 0,
  inviteNonce: 'WAIT1',
  mintChannel: 'remote',
  arrivedAt: new Date().toISOString(),
  direction: 'inbound_joiner',
  ...over,
});

async function openGateDetail(page: Page) {
  await page.getByRole('tab', { name: 'Identity', exact: true }).click();
  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  await expect(page.getByTestId('galaxy-gate')).toHaveAttribute('data-count', '1');
  await page.getByTestId('galaxy-gate').click();
  return page.getByTestId('grow-gate-arrival');
}

test.describe('pre-gate greeting — Gate render (giver side)', () => {
  test('hostile greeting is shown as inert plain text, list shows only a marker', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1280, height: 800 });
    await genesis(page, 'Greeting Giver');
    await seedArrival(page, baseArrival({ greeting: HOSTILE }));

    const row = await openGateDetail(page);
    // List row: a marker only. The message text must NOT appear in the list.
    await expect(row).toContainText('greeting');
    await expect(row).not.toContainText('evil.example');
    await expect(row).not.toContainText('onerror');

    await row.click();
    const box = page.getByTestId('grow-gate-greeting');
    await expect(box).toBeVisible(); // fails if the store dropped the field on load
    const text = page.getByTestId('grow-gate-greeting-text');

    // Verbatim text, line breaks preserved (pre-wrap), markup NOT interpreted.
    await expect(text).toHaveText(HOSTILE);
    expect(await text.evaluate((el) => getComputedStyle(el).whiteSpace)).toBe('pre-wrap');
    // No element children at all: no <img>, <b>, <a>. A URL stays inert text.
    expect(await text.evaluate((el) => el.children.length)).toBe(0);
    await expect(box.locator('a, img, b, script, iframe')).toHaveCount(0);
    // And nothing executed.
    expect(await page.evaluate(() => (window as any).__pwned)).toBeUndefined();
    // Honest framing is present: it says the greeting is unverified.
    await expect(box).toContainText(/unverified/i);
    await page.screenshot({ path: '/opt/cursor/artifacts/pregate_greeting_gate_detail.png' }).catch(() => {});
  });

  test('an arrival with no greeting shows no greeting UI', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1280, height: 800 });
    await genesis(page, 'No Greeting Giver');
    await seedArrival(page, baseArrival({}));
    const row = await openGateDetail(page);
    await expect(row).not.toContainText('greeting');
    await row.click();
    await expect(page.getByTestId('grow-gate-greeting')).toHaveCount(0);
  });

  test('an oversized stored greeting is re-capped on load (store defense-in-depth)', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1280, height: 800 });
    await genesis(page, 'Big Greeting Giver');
    await seedArrival(page, baseArrival({ greeting: 'g'.repeat(2000) }));
    const row = await openGateDetail(page);
    await row.click();
    const text = page.getByTestId('grow-gate-greeting-text');
    await expect(text).toBeVisible();
    expect((await text.innerText()).length).toBeLessThanOrEqual(500);
  });

  test('Trojan-Source spoof is stripped, Persian ZWNJ + emoji ZWJ survive, box is bidi-contained', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1280, height: 800 });
    await genesis(page, 'Bidi Giver');
    const persian = 'سلام، می\u200cخواهم'; // contains a real ZWNJ (U+200C)
    const family = '\u{1F468}\u200D\u{1F469}\u200D\u{1F467}'; // man ZWJ woman ZWJ girl
    // Raw stored value carries the spoof (RLO..PDF around a fake filename) + a BOM + zero-width space, exactly as a
    // hostile or older stored arrival could — so this exercises the persistence clamp on load, not just receive.
    const stored = `ok \u202Egnp.exe\u202C\uFEFF\u200B ${persian} ${family}`;
    await seedArrival(page, baseArrival({ greeting: stored }));
    const row = await openGateDetail(page);
    await row.click();
    const text = page.getByTestId('grow-gate-greeting-text');
    await expect(text).toBeVisible();

    const dom = await text.evaluate((el) => el.textContent || '');
    for (const cp of [0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0x200b, 0x2060, 0xfeff]) {
      expect(dom.includes(String.fromCodePoint(cp)), `U+${cp.toString(16)} must not reach the DOM`).toBe(false);
    }
    // logical order is the order the user reads: the "spoof" is now plain, readable text
    expect(dom).toContain('ok gnp.exe');
    // inclusion: the linguistically essential joiners survive byte-for-byte
    expect(dom).toContain(persian);
    expect(dom).toContain(family);
    // containment + per-paragraph base direction
    expect(await text.evaluate((el) => getComputedStyle(el).unicodeBidi)).toBe('plaintext');
  });
});

// ── FULL two-party flow, real crypto + real relay (no seeding) ───────────────────────────────────────
// Giver mints a Grow link; a SECOND browser context (a different identity/IndexedDB) joins with it, types a
// greeting, adds; the giver's own poll receives the signed joiner-response and the Gate shows the greeting.
// This is the continuous receive -> persist -> render chain the seeded tests above only cover in pieces.
test.describe('pre-gate greeting — full joiner -> giver flow', () => {
  test('joiner types a greeting, giver sees it as inert plain text at the Gate', async ({ browser }) => {
    test.setTimeout(240_000);
    const GREETING = 'hi, it is Nina <b>from the conference</b>\nsecond line https://example.test/x';

    const giverCtx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    const joinerCtx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    const giver = await giverCtx.newPage();
    const joiner = await joinerCtx.newPage();
    const t0 = Date.now();
    const step = (m: string) => console.log(`[full-flow +${Math.round((Date.now() - t0) / 1000)}s] ${m}`);
    const dump = async (tag: string) => {
      for (const [n, pg] of [['giver', giver], ['joiner', joiner]] as const) {
        try {
          await pg.screenshot({ path: test.info().outputPath(`fullflow-${tag}-${n}.png`) });
          console.log(`[dump ${tag} ${n}] url=${pg.url()}\n` + (await pg.locator('body').innerText()).slice(0, 700));
        } catch (e) { console.log(`[dump ${tag} ${n}] failed: ${String(e).slice(0, 120)}`); }
      }
    };
    try {
      step('giver genesis');
      await genesis(giver, 'Giver Gwen');
      step('giver mint link');
      await giver.getByTestId('nav-grow').click();
      const giverDialog = giver.getByTestId('grow-surface');
      await expect(giverDialog).toBeVisible();
      const linkEl = giverDialog.locator('code', { hasText: /\/c\/[A-Za-z0-9_-]+#/ });
      await expect(linkEl).toBeVisible({ timeout: 30_000 });
      const link = (await linkEl.innerText()).trim();

      step(`joiner genesis; link=${link.replace(/#.*/, '#…')}`);
      await genesis(joiner, 'Joiner Nina');
      await joiner.getByTestId('nav-grow').click();
      const jd = joiner.getByTestId('grow-surface');
      step('joiner paste+join');
      await jd.getByRole('tab', { name: 'Scan / paste' }).click();
      await jd.getByLabel(/paste your invite link/i).fill(link);
      await jd.getByRole('button', { name: /^join$/i }).click();

      await expect(joiner.getByTestId('joiner-ceremony-overlay')).toBeVisible({ timeout: 15_000 });
      step('joiner ceremony overlay mounted');
      await expect(joiner.getByText(/wants to connect/i)).toBeVisible({ timeout: 30_000 });
      step('joiner on card phase; typing greeting');
      await joiner.getByTestId('join-greeting').fill(GREETING);
      await joiner.getByTestId('join-add-to-gate').click();

      // Joiner-side honesty: reports DELIVERY only, and says no read signal will come.
      step('joiner clicked add; waiting for delivery status');
      const status = joiner.getByTestId('join-greeting-status');
      await expect(status).toContainText(/reached their mailbox/i, { timeout: 60_000 });
      await expect(status).toContainText(/won.t be told if or when they read it/i);

      // Giver side: its poll picks up the signed joiner-response; keep nudging focus (poll triggers on focus).
      step('joiner delivered; giver polling for the arrival');
      await giver.getByTestId('grow-surface').click({ position: { x: 4, y: 4 } }); // backdrop click closes the giver's own Grow dialog (it would intercept the tab click)
      await expect(giver.getByTestId('grow-surface')).toBeHidden({ timeout: 10_000 });
      await giver.getByRole('tab', { name: 'Galaxy', exact: true }).click({ timeout: 20_000 });
      await expect
        .poll(
          async () => {
            await giver.bringToFront();
            await giver.evaluate(() => window.dispatchEvent(new Event('focus')));
            return giver.getByTestId('galaxy-gate').getAttribute('data-count');
          },
          { timeout: 90_000, intervals: [2_000, 3_000, 5_000] },
        )
        .toBe('1');

      step('giver sees 1 arrival; opening');
      await giver.getByTestId('galaxy-gate').click();
      const row = giver.getByTestId('grow-gate-arrival');
      await expect(row).toContainText('greeting'); // marker, from the REAL receive path
      await row.click();
      const text = giver.getByTestId('grow-gate-greeting-text');
      await expect(text).toHaveText(GREETING);
      expect(await text.evaluate((el) => el.children.length)).toBe(0); // <b> stayed text
      await giver.screenshot({ path: '/opt/cursor/artifacts/pregate_greeting_full_flow.png' }).catch(() => {});
    } catch (e) {
      step('FAILED: ' + String(e).slice(0, 200));
      try { console.log('[overlay text] ' + (await joiner.getByTestId('joiner-ceremony-overlay').innerText({ timeout: 3000 }))); } catch { console.log('[overlay text] overlay not present'); }
      await dump('fail');
      throw e;
    } finally {
      await giverCtx.close();
      await joinerCtx.close();
    }
  });
});
