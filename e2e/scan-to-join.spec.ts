import { test, expect, type Page } from '@playwright/test';

// Camera QR-scan receive side (CURSOR_QUEUE item 1).
// Paste-code join + QR generation are already built — this spec covers Scan only:
// permission-on-tap, FIXED errors (no fragment interpolation), same JoinerCeremony path.

const SCAN_KEY = 'e2ekeyfrag';
const SCAN_CODE = 'e2escan';
const SCAN_INVITE = `https://svrnty.is/c/${SCAN_CODE}#${SCAN_KEY}`;

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const email = page.getByPlaceholder('your@email.com');
  if (await email.count()) await email.fill('scan-coverage@example.test');
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts' })).toBeVisible({ timeout: 15_000 });
}

async function openJoin(page: Page) {
  await page.getByRole('button', { name: /^join$/i }).click();
  const dialog = page.getByRole('dialog', { name: /join by link/i });
  await expect(dialog).toBeVisible();
  return dialog;
}

test.describe('Scan-to-join — camera QR receive side', () => {
  test('Scan is on-demand; denied camera shows a FIXED error; paste remains', async ({ page }) => {
    test.setTimeout(60_000);
    await page.addInitScript(() => {
      (window as unknown as { __svrntyGumCalls: number }).__svrntyGumCalls = 0;
      const err = new DOMException('Permission denied', 'NotAllowedError');
      const md = navigator.mediaDevices;
      md.getUserMedia = async () => {
        (window as unknown as { __svrntyGumCalls: number }).__svrntyGumCalls += 1;
        throw err;
      };
    });

    await genesis(page, 'Scan Denied');
    const dialog = await openJoin(page);

    await expect(dialog.getByTestId('scan-invite-button')).toBeVisible();
    await expect(dialog.getByLabel(/paste your invite link/i)).toBeVisible();

    const callsBefore = await page.evaluate(
      () => (window as unknown as { __svrntyGumCalls: number }).__svrntyGumCalls,
    );
    expect(callsBefore).toBe(0);

    await dialog.getByTestId('scan-invite-button').click();
    const err = dialog.getByTestId('scan-invite-error');
    await expect(err).toBeVisible({ timeout: 10_000 });
    await expect(err).toHaveText(/camera permission was declined/i);
    await expect(err).not.toContainText('Permission denied');

    await dialog.getByTestId('scan-invite-cancel').click();
    await expect(dialog.getByLabel(/paste your invite link/i)).toBeVisible();
    await dialog.getByLabel(/paste your invite link/i).fill('not-an-invite');
    await dialog.getByRole('button', { name: /^join$/i }).click();
    await expect(dialog.getByText(/doesn't look like a svrnty invite link/i)).toBeVisible();
  });

  test('a decoded invite mounts the existing JoinerCeremony; fragment never renders', async ({
    page,
  }) => {
    test.setTimeout(60_000);
    await page.addInitScript(
      ({ invite }) => {
        (window as unknown as { __svrntyTrackStops: number }).__svrntyTrackStops = 0;
        const gum = async () => {
          const canvas = document.createElement('canvas');
          canvas.width = 64;
          canvas.height = 64;
          const ctx = canvas.getContext('2d');
          if (ctx) {
            ctx.fillStyle = '#ffffff';
            ctx.fillRect(0, 0, 64, 64);
          }
          const stream = canvas.captureStream(8);
          for (const track of stream.getTracks()) {
            const orig = track.stop.bind(track);
            track.stop = () => {
              (window as unknown as { __svrntyTrackStops: number }).__svrntyTrackStops += 1;
              orig();
            };
          }
          return stream;
        };
        Object.defineProperty(navigator.mediaDevices, 'getUserMedia', {
          configurable: true,
          writable: true,
          value: gum,
        });
        class FakeBarcodeDetector {
          async detect() {
            return [{ rawValue: invite }];
          }
        }
        Object.defineProperty(window, 'BarcodeDetector', {
          configurable: true,
          writable: true,
          value: FakeBarcodeDetector,
        });
      },
      { invite: SCAN_INVITE },
    );

    await genesis(page, 'Scan Success');
    const dialog = await openJoin(page);
    await dialog.getByTestId('scan-invite-button').click();

    await expect(page.getByText(/opening the secure channel/i)).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('body')).not.toContainText(SCAN_KEY);
    await expect(page.locator('body')).toContainText(SCAN_CODE);

    const stops = await page.evaluate(
      () => (window as unknown as { __svrntyTrackStops: number }).__svrntyTrackStops,
    );
    expect(stops).toBeGreaterThanOrEqual(1);
  });
});
