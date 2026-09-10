import { test, expect, type Page } from '@playwright/test';
import { genesis } from './helpers/genesis';

async function seedWaitingArrival(page: Page, name = 'River') {
  await page.evaluate(async (displayName) => {
    const idbGet = (store: string, key: string) =>
      new Promise<any>((resolve, reject) => {
        const req = indexedDB.open('svrnty');
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction(store, 'readonly');
          const g = tx.objectStore(store).get(key);
          g.onsuccess = () => {
            const v = g.result;
            db.close();
            resolve(v);
          };
          g.onerror = () => reject(g.error);
        };
        req.onerror = () => reject(req.error);
      });
    const idbPut = (store: string, value: unknown) =>
      new Promise<void>((resolve, reject) => {
        const req = indexedDB.open('svrnty');
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction(store, 'readwrite');
          tx.objectStore(store).put(value);
          tx.oncomplete = () => {
            db.close();
            resolve();
          };
          tx.onerror = () => reject(tx.error);
        };
        req.onerror = () => reject(req.error);
      });
    const setting = await idbGet('settings', 'active_fingerprint');
    const owner = setting?.value;
    if (!owner) throw new Error('no owner fingerprint');
    const arrival = {
      fingerprint: 'bb'.repeat(20),
      displayName,
      publicKeyArmored:
        '-----BEGIN PGP PUBLIC KEY BLOCK-----\nAAA\n-----END PGP PUBLIC KEY BLOCK-----',
      epoch: 0,
      inviteNonce: 'WAIT1',
      mintChannel: 'remote',
      arrivedAt: new Date().toISOString(),
      direction: 'inbound_joiner',
    };
    const existing = await idbGet('settings', 'grow_gate_arrivals');
    let map: Record<string, Record<string, typeof arrival>> = {};
    try {
      map = JSON.parse(existing?.value || '{}');
    } catch {
      map = {};
    }
    if (!map[owner]) map[owner] = {};
    map[owner][arrival.fingerprint] = arrival;
    await idbPut('settings', { key: 'grow_gate_arrivals', value: JSON.stringify(map) });
  }, name);
}

test.describe('Grow Gate chrome', () => {
  test('remote default keeps viral cap; in person hides it and shows Gate', async ({ page }) => {
    test.setTimeout(90_000);
    await page.setViewportSize({ width: 1280, height: 800 });
    await genesis(page, 'Gate Chrome');

    await page.getByTestId('nav-grow').click();
    const dialog = page.getByTestId('grow-surface');
    await expect(dialog).toBeVisible();

    await expect(dialog.getByTestId('grow-gate-list')).toBeVisible();
    await expect(dialog.getByText(/no one waiting/i)).toBeVisible();

    await expect(dialog.getByTestId('grow-channel-remote')).toHaveAttribute('aria-pressed', 'true');
    await expect(
      dialog.getByLabel(/number of people who can join with this link/i),
    ).toBeVisible();

    await dialog.getByTestId('grow-channel-in-person').click();
    await expect(dialog.getByTestId('grow-channel-in-person')).toHaveAttribute('aria-pressed', 'true');
    await expect(
      dialog.getByLabel(/number of people who can join with this link/i),
    ).toHaveCount(0);
    await expect(dialog.getByText(/single-use/i).first()).toBeVisible();
    await expect(dialog.getByText(/mint it when they are in front of you/i)).toBeVisible();
  });

  test('Galaxy membrane opens a searchable Gate overlay', async ({ page }) => {
    test.setTimeout(90_000);
    await page.setViewportSize({ width: 1280, height: 800 });
    await genesis(page, 'Gate Galaxy');

    await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
    const gate = page.getByTestId('galaxy-gate');
    await expect(gate).toBeVisible();
    await expect(gate).toHaveAttribute('data-count', '0');
    await expect(page.getByTestId('trust-map')).toBeVisible();
    await page.screenshot({ path: '/opt/cursor/artifacts/galaxy_gate_blackhole.png' });

    await gate.click();
    await expect(page.getByTestId('galaxy-gate-overlay')).toBeVisible();
    await expect(page.getByTestId('galaxy-gate-search')).toBeVisible();
    await expect(page.getByTestId('galaxy-gate-overlay-close')).toBeVisible();
    await page.getByTestId('galaxy-gate-overlay-close').click();
    await expect(page.getByTestId('galaxy-gate-overlay')).toHaveCount(0);

    await seedWaitingArrival(page);
    await page.getByRole('tab', { name: 'Identity', exact: true }).click();
    await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
    await expect(page.getByTestId('galaxy-gate')).toHaveAttribute('data-count', '1');
    await expect(page.getByTestId('galaxy-gate')).toHaveAttribute('aria-label', 'Gate, 1 waiting');
    await expect(page.getByTestId('galaxy-gate-spark')).toHaveCount(1);
    await page.screenshot({ path: '/opt/cursor/artifacts/galaxy_usphere_waiting.png' });
    await page.getByTestId('galaxy-gate').click();
    await expect(page.getByTestId('grow-gate-arrival')).toContainText('River');
    await page.getByTestId('galaxy-gate-search').fill('River');
    await expect(page.getByTestId('grow-gate-arrival')).toBeVisible();
    await page.screenshot({ path: '/opt/cursor/artifacts/galaxy_usphere_overlay.png' });
  });

  test('sample Known stars ignite on first appearance', async ({ page }) => {
    test.setTimeout(90_000);
    await page.setViewportSize({ width: 1280, height: 800 });
    await genesis(page, 'Gate Ignite');

    await page.getByRole('tab', { name: 'Galaxy', exact: true }).click();
    await page.getByTestId('trust-map-load-sample').click();
    await expect(page.locator('[data-testid="trust-node"][data-rise="true"]').first()).toBeVisible({
      timeout: 20_000,
    });
    await page.screenshot({ path: '/opt/cursor/artifacts/galaxy_known_stars_ignite.png' });
  });
});
