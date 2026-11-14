import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { unpackVault } from '../src/lib/sync/vault';

/**
 * Inbound arrivals: someone who joins through MY invite reaches my Gate by a signed joiner response. The pin that joiner's own card carries must
 * survive that trip too, so the contact I admit holds it. Before this change the response carried no pin, so a contact admitted this way held none.
 * Real Chromium, two isolated contexts (giver = the observer, joiner), the app's own relay (deposits need RELAY_DISK_WATERMARK_PCT=100 on this box).
 * The stored contact row is sealed, so the observer is the GIVER's own vault export, opened in Node. RED on dev by design: the admitted contact has no pin.
 */
const PW = 'e2e-passphrase-1234';
const EXPORT_PW = 'export-e2e-pass-5678';

async function genesis(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  const e = page.getByPlaceholder('your@email.com');
  if (await e.count()) await e.fill(`${name.toLowerCase().replace(/\W+/g, '')}@example.test`);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(PW);
  await page.getByPlaceholder('Confirm passphrase').fill(PW);
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 90_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 30_000 });
}
async function copyPackage(page: Page): Promise<string> {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('share-identity-from-card').click();
  await page.getByRole('tab', { name: 'Copy' }).click();
  const pre = page.locator('[role="dialog"] pre').first();
  await expect(pre).toBeVisible();
  const text = (await pre.innerText()).trim();
  await page.keyboard.press('Escape');
  return text;
}
/** The pin as the card itself carries it (read off the package text, not from the app's storage). */
function pinOf(pkgText: string): string | null {
  const m = pkgText.match(/"next_authority_commitment"\s*:\s*"([0-9a-f]{64})"/);
  return m ? m[1] : null;
}
async function openGrow(page: Page) {
  const pill = page.getByTestId('nav-grow');
  if (await pill.isVisible().catch(() => false)) { await pill.click(); return; }
  await page.getByTestId('top-nav-menu-btn').click(); // phone width: Grow lives in the top-nav menu
  await page.getByTestId('nav-grow-menu').click();
}
async function giverInviteLink(page: Page): Promise<string> {
  await openGrow(page);
  const dialog = page.getByTestId('grow-surface');
  await expect(dialog).toBeVisible();
  const code = dialog.locator('code').filter({ hasText: '/c/' }).first();
  await expect(code).toBeVisible({ timeout: 60_000 });
  const link = (await code.innerText()).trim();
  expect(link).toMatch(/\/c\/[^#\s]+#\S+/);
  return link;
}
async function joinFromLink(page: Page, link: string) {
  await openGrow(page);
  const dialog = page.getByTestId('grow-surface');
  await dialog.getByRole('tab', { name: 'Scan / paste' }).click();
  await dialog.getByLabel(/paste your invite link/i).fill(link);
  await dialog.getByRole('button', { name: /^join$/i }).click();
  await expect(page.getByTestId('join-add-to-gate')).toBeVisible({ timeout: 60_000 });
  await page.getByTestId('join-add-to-gate').click();
  await expect(page.getByText(/at your gate/i).first()).toBeVisible({ timeout: 60_000 });
}
async function unlock(page: Page) {
  await page.goto('/');
  await page.getByPlaceholder('Enter passphrase').fill(PW);
  await page.getByPlaceholder('Enter passphrase').press('Enter');
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 60_000 });
}
async function admitFromGate(page: Page) {
  await page.getByRole('tab', { name: /^Galaxy\b/ }).click(); // the tab's name gains ", new activity" while an arrival is unseen
  const gate = page.getByTestId('galaxy-gate');
  await expect(gate).toHaveAttribute('data-count', '1', { timeout: 30_000 });
  await gate.click();
  await page.getByTestId('grow-gate-arrival').first().click();
  await page.getByTestId('grow-gate-admit-confirm').click();
  await expect(page.getByTestId('grow-gate-arrival')).toHaveCount(0, { timeout: 30_000 });
}
async function exportVault(page: Page, dest: string) {
  await page.getByRole('tab', { name: 'Identity' }).click();
  await page.getByTestId('card-actions-toggle').click();
  await page.getByTestId('full-backup-open').click();
  await page.getByPlaceholder('Your everyday unlock passphrase').fill(PW);
  await page.getByRole('button', { name: /^continue$/i }).click();
  await page.getByTestId('vault-export-passphrase').fill(EXPORT_PW);
  await page.getByTestId('vault-export-confirm').fill(EXPORT_PW);
  const dl = page.waitForEvent('download');
  await page.getByTestId('vault-export-download').click();
  await (await dl).saveAs(dest);
  await page.keyboard.press('Escape'); // the "Vault downloaded" dialog stays up and covers the tab bar until it is closed
  await expect(page.getByTestId('vault-export-dialog')).toHaveCount(0, { timeout: 10_000 });
}


for (const [label, vp] of [['desktop', { width: 1280, height: 800 }], ['phone', { width: 390, height: 844 }]] as const) {
  test(`INBOUND GATE · ${label}: the contact the giver admits from a joiner's response retains the pin the joiner's card carries (read from the giver's own vault export)`, async ({ browser }, testInfo) => {
    test.setTimeout(420_000);
    const g = await browser.newContext({ viewport: vp, extraHTTPHeaders: { 'x-svrnty-client-ip': '10.77.2.1' } });
    const a = await browser.newContext({ viewport: vp, extraHTTPHeaders: { 'x-svrnty-client-ip': '10.77.2.2' } });
    const gp = await g.newPage();
    const ap = await a.newPage();
    await genesis(gp, 'Gabe Inbound');
    await genesis(ap, 'Alice Inbound');
    const pin = pinOf(await copyPackage(ap));
    expect(pin, "control: Alice's signed package really carries a 64-hex pin").not.toBeNull();
    const link = await giverInviteLink(gp);
    // close the share dialog (Escape does not close it); Gabe's page stays unlocked and keeps polling his mailbox
    await gp.getByRole('button', { name: /back to galaxy/i }).click();
    await expect(gp.getByTestId('grow-surface')).toHaveCount(0, { timeout: 15_000 });
    await joinFromLink(ap, link);
    await admitFromGate(gp); // waits for the joiner's response to arrive at Gabe's Gate
    const dest = testInfo.outputPath('gabe.svrnty');
    await exportVault(gp, dest);
    const { contents } = await unpackVault(readFileSync(dest).buffer.slice(0) as ArrayBuffer, EXPORT_PW);
    const contacts = ((contents as unknown as { trustGraph: { contacts: Array<Record<string, any>> } }).trustGraph.contacts) ?? [];
    const alice = contacts.find((c) => /alice inbound/i.test(String(c.name)));
    expect(alice, 'control: the admitted joiner is in the giver\'s export').toBeTruthy();
    console.log(`INBOUND ${label}: contact keys = ${Object.keys(alice ?? {}).sort().join(',')} | stored pin = ${alice?.next_authority_commitment ?? '(absent)'} | card pin = ${pin}`);
    expect(alice!.next_authority_commitment, 'the contact admitted from the joiner response retains the pin the joiner\'s card carried').toBe(pin);
    await g.close();
    await a.close();
  });
}
