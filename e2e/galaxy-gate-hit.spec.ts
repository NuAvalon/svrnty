/**
 * The Gate's hit area is its drawn membrane, not its 248 x 96 box, and the camera fit keeps stars out of the
 * box. A star under the box's empty corners is clickable, and clicking it selects the star, not the Gate.
 * Render-glass only: pointer-events + camera fit. Nothing here touches what the Gate opens.
 */
import { expect, test, type Page } from '@playwright/test';

async function genesisWithSample(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
  await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
  await expect(page.getByTestId('trust-map')).toBeVisible();
  const load = page.getByTestId('trust-map-load-sample');
  await load.click();
  await expect(load).toBeHidden({ timeout: 150_000 });
  await expect(page.locator('[data-testid="trust-node"]').first()).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(800); // let the intro fit settle
}

type Box = { x: number; y: number; width: number; height: number };

async function gateBox(page: Page): Promise<Box> {
  const b = await page.getByTestId('galaxy-gate').boundingBox();
  if (!b) throw new Error('no Gate box');
  return b;
}

/** What sits at a screen point: 'gate' | 'star:<fp>' | 'other'. */
async function hitAt(page: Page, x: number, y: number): Promise<string> {
  return page.evaluate(
    ([px, py]) => {
      const el = document.elementFromPoint(px, py);
      if (!el) return 'none';
      if (el.closest('[data-testid="galaxy-gate"]')) return 'gate';
      const star = el.closest('[data-testid="trust-node"]');
      if (star) return `star:${star.getAttribute('data-fingerprint')}`;
      return 'other';
    },
    [x, y] as const,
  );
}

async function starCentres(page: Page): Promise<Array<{ fp: string; x: number; y: number }>> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll('[data-testid="trust-node"]')).map((n) => {
      const r = n.getBoundingClientRect();
      return { fp: n.getAttribute('data-fingerprint') || '', x: r.left + r.width / 2, y: r.top + r.height / 2 };
    }),
  );
}

const inBox = (p: { x: number; y: number }, b: Box) =>
  p.x >= b.x && p.x <= b.x + b.width && p.y >= b.y && p.y <= b.y + b.height;

for (const vp of [
  { label: 'desktop 1280x800', width: 1280, height: 800 },
  { label: 'wide 1600x640', width: 1600, height: 640 },
]) {
  test(`after the fit, no star sits under the Gate box (${vp.label})`, async ({ page }) => {
    test.setTimeout(180_000);
    await page.setViewportSize({ width: vp.width, height: vp.height });
    await genesisWithSample(page, 'Gate Fit E2E');
    const box = await gateBox(page);
    const stars = await starCentres(page);
    expect(stars.length).toBeGreaterThan(3);
    const under = stars.filter((s) => inBox(s, box));
    expect(under, `stars under the Gate box after the fit: ${JSON.stringify(under)}`).toEqual([]);
    for (const s of stars) {
      expect(await hitAt(page, s.x, s.y), `star ${s.fp.slice(0, 8)} centre`).not.toBe('gate');
    }
  });
}

test('the Gate box corners take no click; the drawn membrane does', async ({ page }) => {
  test.setTimeout(180_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  await genesisWithSample(page, 'Gate Corner E2E');
  const b = await gateBox(page);
  // corners of the 248 x 96 box, outside the drawn arc
  for (const [x, y] of [
    [b.x + 6, b.y + 6],
    [b.x + b.width - 6, b.y + 6],
    [b.x + 6, b.y + b.height - 6],
    [b.x + b.width - 6, b.y + b.height - 6],
  ]) {
    expect(await hitAt(page, x, y), `corner ${x},${y}`).not.toBe('gate');
  }
  // the membrane itself (centre, and the disk's left/right ends) is still the Gate
  for (const [x, y] of [
    [b.x + b.width / 2, b.y + b.height / 2],
    [b.x + b.width / 2 - 70, b.y + 56],
    [b.x + b.width / 2 + 70, b.y + 56],
  ]) {
    expect(await hitAt(page, x, y), `membrane ${x},${y}`).toBe('gate');
  }
});

test('a star panned under the Gate box corner is clicked as the star, not the Gate', async ({ page }) => {
  test.setTimeout(180_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  await genesisWithSample(page, 'Gate Pan E2E');
  const b = await gateBox(page);
  const target = { x: b.x + 14, y: b.y + b.height - 14 }; // inside the box, outside the arc

  const map = await page.getByTestId('trust-map').boundingBox();
  if (!map) throw new Error('no map box');
  // a start point on empty canvas (not a star, not a control)
  let start: { x: number; y: number } | null = null;
  for (let gy = map.y + 120; gy < map.y + map.height - 140 && !start; gy += 23) {
    for (let gx = map.x + 60; gx < map.x + map.width - 60 && !start; gx += 29) {
      const ok = await page.evaluate(
        ([px, py]) => {
          const el = document.elementFromPoint(px, py);
          return !!el && !!el.closest('[data-testid="trust-map"]') && !el.closest('[data-graph-node], button, a, input');
        },
        [gx, gy] as const,
      );
      if (ok) start = { x: gx, y: gy };
    }
  }
  if (!start) throw new Error('no empty canvas point to start a pan');

  const stars = await starCentres(page);
  // the star nearest the map centre: it can travel to the corner without leaving the map
  const cx = map.x + map.width / 2;
  const cy = map.y + map.height / 2;
  const star = stars.sort((p, q) => Math.hypot(p.x - cx, p.y - cy) - Math.hypot(q.x - cx, q.y - cy))[0];
  const dx = target.x - star.x;
  const dy = target.y - star.y;

  await page.mouse.move(start.x, start.y);
  await page.mouse.down();
  await page.mouse.move(start.x + dx / 2, start.y + dy / 2, { steps: 8 });
  await page.mouse.move(start.x + dx, start.y + dy, { steps: 8 });
  await page.mouse.up();
  await page.waitForTimeout(300);

  const moved = (await starCentres(page)).find((s) => s.fp === star.fp);
  if (!moved) throw new Error('star vanished after pan');
  expect(inBox(moved, b), `star after pan ${JSON.stringify(moved)} vs box ${JSON.stringify(b)}`).toBe(true);
  expect(await hitAt(page, moved.x, moved.y)).toBe(`star:${star.fp}`);

  await page.mouse.click(moved.x, moved.y);
  await expect(page.getByTestId('trust-node-detail')).toBeVisible();
  await expect(page.getByTestId('galaxy-gate-overlay')).toHaveCount(0);
});

test('clicking the drawn membrane opens the Gate; Enter and Space still open it', async ({ page }) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  await genesisWithSample(page, 'Gate Open E2E');
  const gate = page.getByTestId('galaxy-gate');
  const overlay = page.getByTestId('galaxy-gate-overlay');

  await gate.click();
  await expect(overlay).toBeVisible();
  await page.getByTestId('galaxy-gate-overlay-close').click();
  await expect(overlay).toHaveCount(0);

  for (const key of ['Enter', ' ']) {
    await gate.focus();
    await page.keyboard.press(key === ' ' ? 'Space' : key);
    await expect(overlay, `key ${JSON.stringify(key)}`).toBeVisible();
    await page.getByTestId('galaxy-gate-overlay-close').click();
    await expect(overlay).toHaveCount(0);
  }
});
