import { test, expect, devices, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { seedAliceWithBob } from './fixtures/deposit-note';
import { resetCountLine, resetExplainer, resetButtonLabel, namedRow } from '../src/components/notes/ratchet-rows';

/**
 * #720 the thread half of reliable receive, in a REAL browser: the named rows for a contact whose frames did not open, the
 * user-initiated "Reset message session" dialog (Cancel is the default focus; nothing resets on a cancel), and what a confirmed reset
 * really does to the real IndexedDB: the session row is gone, the held records become session-reset records, the per-contact flag is
 * set in the ENCRYPTED store, and the UI shows the session-reset line and stops offering the reset.
 *
 * Seeding (dead-letter records, a session row) goes through a small esbuild-bundled harness running the app's own store modules against
 * the same notes DB; the reset itself is only ever the click on Reset in the dialog.
 */

const PASS = 'e2e-passphrase-1234';
const NAME = 'Bob';

function harnessSource(): string {
  return execFileSync('node_modules/.bin/esbuild', ['e2e/helpers/ratchet-rows-harness.ts', '--bundle', '--format=iife', '--platform=browser', '--alias:@=./src'], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
}

async function genesisReceiver(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill(PASS);
  await page.getByPlaceholder('Confirm passphrase').fill(PASS);
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

async function openChatWith(page: Page, bobFp: string) {
  await page.getByTestId('tab-notes').click();
  await expect(page.getByTestId('notes-inbox')).toBeVisible();
  await page.getByTestId(`notes-person-${bobFp}`).click();
}

/** A raw ratchet_sessions row (the key is all deleteRatchetSession looks at): proves the REAL unconditional delete on real IndexedDB. */
async function putRawSession(page: Page, bobFp: string) {
  await page.evaluate((fp) => new Promise<void>((resolve, reject) => {
    const open = indexedDB.open('svrnty-notes-' + (window as unknown as { __ownerFp: string }).__ownerFp);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction('ratchet_sessions', 'readwrite');
      tx.objectStore('ratchet_sessions').put({ peer_fingerprint: fp, version: 1, enc: { enc_version: 1, iv: 'x', ciphertext: 'x' } });
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => reject(tx.error);
    };
  }), bobFp);
}
async function sessionExists(page: Page, bobFp: string): Promise<boolean> {
  return page.evaluate((fp) => new Promise<boolean>((resolve, reject) => {
    const open = indexedDB.open('svrnty-notes-' + (window as unknown as { __ownerFp: string }).__ownerFp);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const q = db.transaction('ratchet_sessions', 'readonly').objectStore('ratchet_sessions').get(fp);
      q.onsuccess = () => { db.close(); resolve(q.result !== undefined); };
      q.onerror = () => { db.close(); reject(q.error); };
    };
  }), bobFp);
}

const row = (fp: string, o: Record<string, unknown>, n: number) => ({ envelope_id: `env-${n}`, first_seen: new Date(Date.now() - 60_000 * (10 - n)).toISOString(), blob_kind: 'json', fp, ...o });

const { defaultBrowserType, ...pixel7Mobile } = devices['Pixel 7'];
void defaultBrowserType; // not a per-context option (it picks the browser, which the project already fixed)
const MATRIX: Array<{ label: string; use: Record<string, unknown> }> = [
  { label: 'desktop-chromium', use: { viewport: { width: 1280, height: 800 } } },
  { label: 'mobile-chromium (Pixel 7)', use: pixel7Mobile },
];

for (const variant of MATRIX) {
  test.describe(`ratchet rows + reset · ${variant.label}`, () => {
    test.use(variant.use);

    test('named rows, a Cancel-default dialog, and a confirmed reset that really changes the real IndexedDB', async ({ page }) => {
      test.setTimeout(150_000);
      await genesisReceiver(page, 'Alice Reset');
      const { aliceFp, bob } = await seedAliceWithBob(page);
      const bobFp = bob.fingerprint.toLowerCase();
      await page.addScriptTag({ content: harnessSource() });
      await page.evaluate((fp) => { (window as unknown as { __ownerFp: string }).__ownerFp = fp; }, aliceFp);
      await page.evaluate(([p, f]) => window.__rr.init(p, f), [PASS, aliceFp] as const);
      await openChatWith(page, bob.fingerprint);

      // CONTROL: a healthy thread shows no rows and no reset action.
      await expect(page.getByTestId('ratchet-rows')).toHaveCount(0);
      await expect(page.getByTestId('ratchet-reset-open')).toHaveCount(0);

      // Two held desync frames from Bob, one from a stranger (must not show), and a session row.
      const other = 'cd'.repeat(32);
      await page.evaluate((rows) => window.__rr.put(rows as never), [
        row(bobFp, { reason: 'ratchet-desync', phase: 'held', cause: 'ratchet-receive-failed' }, 1),
        row(bobFp, { reason: 'ratchet-desync', phase: 'held', cause: 'ratchet-receive-failed' }, 2),
        row(other, { reason: 'ratchet-desync', phase: 'held', cause: 'ratchet-receive-failed' }, 3),
      ]);
      await putRawSession(page, bob.fingerprint); // keyed exactly as the UI will pass it to deleteRatchetSession
      expect(await sessionExists(page, bob.fingerprint)).toBe(true);

      // The thread refreshes on its own: exactly ONE row (identical lines collapse), Athena's copy by value, and the reset action.
      const want = namedRow(NAME, { kind: 'desync', phase: 'held' });
      await expect(page.getByTestId('ratchet-row')).toHaveCount(1, { timeout: 15_000 });
      await expect(page.getByTestId('ratchet-row-line')).toHaveText(want.line);
      if (want.hint) await expect(page.getByTestId('ratchet-row-hint')).toHaveText(want.hint);
      await expect(page.getByTestId('ratchet-reset-open')).toHaveText(resetButtonLabel(NAME));

      // The dialog: states the count BEFORE confirm, and focus starts on Cancel.
      await page.getByTestId('ratchet-reset-open').click();
      await expect(page.getByTestId('ratchet-reset-dialog')).toBeVisible();
      await expect(page.getByTestId('ratchet-reset-dialog')).toContainText(resetExplainer(NAME));
      await expect(page.getByTestId('ratchet-reset-count')).toHaveText(resetCountLine(NAME, 2)!);
      await expect(page.getByTestId('ratchet-reset-cancel')).toBeFocused();

      // CANCEL changes nothing: records still held, no flag, session row still there.
      await page.getByTestId('ratchet-reset-cancel').click();
      await expect(page.getByTestId('ratchet-reset-dialog')).toHaveCount(0);
      expect((await page.evaluate(() => window.__rr.list())).filter((r) => r.reason === 'ratchet-desync' && r.phase === 'held')).toHaveLength(3);
      expect(await page.evaluate((f) => window.__rr.hasFlag(f), bobFp)).toBe(false);
      expect(await sessionExists(page, bob.fingerprint)).toBe(true);

      // CONFIRM: the real reset.
      await page.getByTestId('ratchet-reset-open').click();
      await expect(page.getByTestId('ratchet-reset-cancel')).toBeFocused();
      await page.getByTestId('ratchet-reset-confirm').click();
      await expect(page.getByTestId('ratchet-reset-dialog')).toHaveCount(0, { timeout: 15_000 });
      expect(await sessionExists(page, bob.fingerprint), 'the session row is really gone from IndexedDB').toBe(false);
      const after = await page.evaluate(() => window.__rr.list());
      expect(after.filter((r) => r.fp === bobFp && r.reason === 'session-reset'), "Bob's two held frames became session-reset records").toHaveLength(2);
      expect(after.filter((r) => r.fp === other && r.reason === 'ratchet-desync' && r.phase === 'held'), "the stranger's record is untouched").toHaveLength(1);
      expect(await page.evaluate((f) => window.__rr.hasFlag(f), bobFp), 'the per-contact flag is set in the encrypted store').toBe(true);
      expect(await page.evaluate(() => window.__rr.flags())).toEqual([bobFp]);

      // The UI now says the frames were released by the reset, and no longer offers it.
      const reset = namedRow(NAME, { kind: 'session-reset' });
      await expect(page.getByTestId('ratchet-row-line')).toHaveText(reset.line, { timeout: 15_000 });
      await expect(page.getByTestId('ratchet-reset-open')).toHaveCount(0);

      // The flag lives only in the encrypted store: never in web storage, never readable at rest.
      const leaks = await page.evaluate((f) => JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)]).includes(f), bobFp);
      expect(leaks, 'no localStorage / sessionStorage copy of the contact').toBe(false);

      // A frame from Bob that opens ends the flag (the lib hook clearResetFlagIfSet), and it is idempotent.
      expect(await page.evaluate((f) => window.__rr.clearFlag(f), bobFp)).toBe(true);
      expect(await page.evaluate((f) => window.__rr.clearFlag(f), bobFp)).toBe(false);
      expect(await page.evaluate((f) => window.__rr.hasFlag(f), bobFp)).toBe(false);
    });
  });
}
