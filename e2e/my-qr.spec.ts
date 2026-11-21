import { test, expect, type Page } from '@playwright/test';

// "My QR" tab in the Share dialog, on the user path in a real browser (desktop and a 390 px phone):
//  - all five tab triggers sit fully inside the viewport (a fifth tab must not push one off a phone screen),
//  - opening My QR draws a QR and the one line that says what it is,
//  - opening it adds no request beyond the app's own background mailbox poll (the QR holds only the owner's fingerprint, computed on the device).
async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('my-qr-coverage@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

const VIEWPORTS: Array<[string, { width: number; height: number } | null]> = [
  ['desktop', null],
  ['phone 390x844', { width: 390, height: 844 }],
];

for (const [vpName, viewport] of VIEWPORTS) {
  test.describe(`My QR tab: ${vpName}`, () => {
    if (viewport) test.use({ viewport });

    test('five tabs inside the viewport; My QR shows a QR and its line; opening it adds no request beyond the background mailbox poll', async ({ page }) => {
      test.setTimeout(120_000);
      await genesis(page, 'My QR E2E');
      await page.getByRole('tab', { name: 'Identity' }).click();
      await page.getByTestId('share-identity-from-card').click();
      const dialog = page.getByRole('dialog');
      await expect(dialog).toBeVisible({ timeout: 10_000 });

      // All five triggers fully inside the viewport.
      const tabs = dialog.getByRole('tab');
      await expect(tabs).toHaveCount(5);
      const vw = page.viewportSize()!.width;
      for (let i = 0; i < 5; i++) {
        const box = await tabs.nth(i).boundingBox();
        expect(box, `tab ${i} has a box`).not.toBeNull();
        expect(box!.x, `tab ${i} left edge`).toBeGreaterThanOrEqual(0);
        expect(box!.x + box!.width, `tab ${i} right edge`).toBeLessThanOrEqual(vw);
      }

      // Opening My QR: collect every request made from the click until the QR and its line are on screen.
      // Ignored: _next/ (the dev server's own assets and hot reload), and data:/blob: URLs, which never leave the device.
      // Allowed: the app's own background mailbox poll. It is measured BEFORE the tab is opened and printed as a MEASURE line
      // (the same URL shape recurs there), so the allowance rests on a measurement; this is the app's poll on this build, not My QR's.
      const POLL = /^GET http:\/\/[^/]+\/api\/relay\/queue\?mailbox_id=mbx_[0-9a-f]{64}$/;
      let sink: string[] = [];
      page.on('request', (r) => {
        const u = r.url();
        if (u.startsWith('data:') || u.startsWith('blob:') || u.includes('/_next/')) return;
        sink.push(`${r.method()} ${u}`);
      });
      await page.waitForTimeout(2500);
      const before = sink;
      sink = [];
      const mask = (q: string) => q.replace(/mbx_[0-9a-f]{64}/, 'mbx_<64hex>');
      console.log(`MEASURE before opening the tab (2.5 s): ${before.length} request(s): ${[...new Set(before.map(mask))].join(' | ') || '(none)'}`);
      const requests = sink;
      await dialog.getByTestId('my-qr-tab').click();
      // The QR is the one svg that is not a lucide icon (the Download button carries an icon svg too).
      const qrSvg = dialog.getByTestId('my-qr').locator('svg:not(.lucide)');
      await expect(qrSvg).toHaveCount(1);
      await expect(qrSvg).toBeVisible();
      await expect(dialog.getByTestId('my-qr-line')).toContainText('This is only your fingerprint.');
      await page.waitForTimeout(1500);
      console.log(`MEASURE after opening the tab: ${requests.length} request(s), of which poll=${requests.filter((q) => POLL.test(q)).length}, other=${requests.filter((q) => !POLL.test(q)).length}`);
      expect(requests.filter((q) => !POLL.test(q)),'requests made by opening My QR, other than the background mailbox poll').toEqual([]);
    });
  });
}
