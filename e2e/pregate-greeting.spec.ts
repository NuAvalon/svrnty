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
});
