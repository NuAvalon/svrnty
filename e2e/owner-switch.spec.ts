import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';

// The harness is injected with addScriptTag, which the page's script policy refuses, as it should.
test.use({ bypassCSP: true });

/**
 * An owner-scoped section keeps its own state (open, loaded rows, a chosen sender, notices). If the owner changed in place, with no null between, an unkeyed mount would carry the previous owner's state
 * to the next. No path in today's routing does that (every change of owner passes through null or the locked screen, which unmounts the section), so this proves the property the mount now has by
 * construction: the harness renders the SAME mount component the app uses, changes the owner in place, and looks at what is still on screen. The 'bare' variant is the mount as it was before the key.
 * Set OWNER_SWITCH_VARIANT=bare to run the same assertions against the bare mount: they must fail there.
 */
const VARIANT = (process.env.OWNER_SWITCH_VARIANT === 'bare' ? 'bare' : 'mount') as 'bare' | 'mount';
const bundle = (file: string): string =>
  execFileSync('node_modules/.bin/esbuild', [file, '--bundle', '--format=iife', '--platform=browser', '--alias:@=./src', '--jsx=automatic', '--define:process.env.NODE_ENV="development"', '--external:circomlibjs'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

async function mount(page: Page, which: 'relay' | 'held', variant: 'bare' | 'mount') {
  await page.goto('/');
  await page.addScriptTag({ content: bundle('e2e/helpers/owner-switch-harness.tsx') });
  await page.evaluate(([w, v]) => (window as unknown as { __ownerSwitch: { render(a: string, b: string): void } }).__ownerSwitch.render(w, v), [which, variant]);
}
const flip = (page: Page) => page.evaluate(() => (window as unknown as { __ownerSwitch: { flip(): void } }).__ownerSwitch.flip());
const host = (page: Page) => page.locator('#owner-switch-host');

test.describe('an in-place change of owner', () => {
  test('O1 RELAY panel: the previous owner\'s row, Checked line and open state are gone', async ({ page }) => {
    await mount(page, 'relay', VARIANT);
    await host(page).getByRole('button', { name: 'What the relay lists' }).click();
    await expect(host(page).getByText('Zelda Only-A')).toBeVisible();
    await expect(host(page).getByText(/^Checked /)).toBeVisible();
    await flip(page);
    await expect(host(page).getByText('Zelda Only-A')).toHaveCount(0);
    await expect(host(page).getByText(/^Checked /)).toHaveCount(0);
    await expect(host(page).getByRole('button', { name: 'What the relay lists' })).toHaveAttribute('aria-expanded', 'false');
  });

  test('O2 HELD section: the previous owner\'s sender, held note and open state are gone', async ({ page }) => {
    await mount(page, 'held', VARIANT);
    await host(page).getByTestId('held-section-entry').click();
    await host(page).getByTestId(/^held-section-sender-/).first().click();
    await expect(host(page).getByText('HELD-NOTE-BODY-OF-OWNER-A')).toBeVisible();
    await flip(page);
    await expect(host(page).getByText('HELD-NOTE-BODY-OF-OWNER-A')).toHaveCount(0);
    await expect(host(page).getByTestId(/^held-section-sender-/)).toHaveCount(0);
    await expect(host(page).getByTestId('held-section-entry')).toHaveAttribute('aria-expanded', 'false');
  });

  test('O3 CONTROL, RELAY: the bare mount DOES carry the previous owner\'s row to the next (this is what the key prevents, and what keeps this harness honest)', async ({ page }) => {
    await mount(page, 'relay', 'bare');
    await host(page).getByRole('button', { name: 'What the relay lists' }).click();
    await expect(host(page).getByText('Zelda Only-A')).toBeVisible();
    await flip(page);
    await expect(host(page).getByText('Zelda Only-A')).toHaveCount(1);
  });

  test('O4 CONTROL, HELD: the bare mount DOES carry the previous owner\'s held note to the next', async ({ page }) => {
    await mount(page, 'held', 'bare');
    await host(page).getByTestId('held-section-entry').click();
    await host(page).getByTestId(/^held-section-sender-/).first().click();
    await expect(host(page).getByText('HELD-NOTE-BODY-OF-OWNER-A')).toBeVisible();
    await flip(page);
    await expect(host(page).getByText('HELD-NOTE-BODY-OF-OWNER-A')).toHaveCount(1);
  });
});
