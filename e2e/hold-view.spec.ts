import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { seedAliceWithBob } from './fixtures/deposit-note';

// The harness is injected with addScriptTag, which the page's script policy refuses, as it should.
test.use({ bypassCSP: true });

/**
 * The hold view in the REAL app: the real shell, the real contact book, the real encrypted notes store. Held notes are written into the store the way the accept path leaves them (held, with held_at), and the
 * contact is blocked through the app's own contact store; the screen under test is what the owner then sees and does.
 *  - A frozen contact's own menu has "Held messages" beside Unblock, with no count and no digit; an unblocked contact's menu has none.
 *  - The view shows the notes (words, when they arrived here, the sender's time labelled as theirs, an expiring mark), the age limit and the cap, and moves or deletes them: one at a time or all at once. Delete asks first and
 *    the default is Cancel; moving does not ask. Every move and delete is counted (the row equals the full scan).
 *  - THE VIEW SENDS NOTHING: across opening, reading, moving and deleting, the page makes no request to the relay other than a read. (The recorder is proven to see a POST by a control that makes one.)
 *  - A sender with no page entry (removed, or unblocked) is reached from the Lenses & vault panel, whose entry carries no count either; "still frozen" is never said about someone who is not.
 *  - On a phone the view fits the screen.
 */
const PASS = 'e2e-passphrase-1234';
const DAY = 86_400_000;
const bundle = (file: string): string =>
  execFileSync('node_modules/.bin/esbuild', [file, '--bundle', '--format=iife', '--platform=browser', '--alias:@=./src', '--external:circomlibjs'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

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

type Seeded = { aliceFp: string; bobFp: string; bobId: string };

async function setup(page: Page, opts: { blocked: boolean }): Promise<Seeded> {
  await genesisReceiver(page, 'Alice Holds');
  const seeded = await seedAliceWithBob(page);
  await page.addScriptTag({ content: bundle('e2e/helpers/freeze-store-harness.ts') });
  await page.evaluate(([o, p]) => window.__fz.initApp(o, p), [seeded.aliceFp, PASS]);
  const bobFp = seeded.bob.fingerprint.toLowerCase();
  const bobId = `e2e-bob-${seeded.bob.fingerprint.slice(0, 12)}`;
  if (opts.blocked) await page.evaluate(([id]) => window.__fz.setBlocked(id as string, true), [bobId]);
  return { aliceFp: seeded.aliceFp, bobFp, bobId };
}

type HeldSeed = { id: string; body: string; heldAgoDays?: number; marked?: boolean };

/** Held notes as the accept path leaves them: held, held_at on this device's clock, in a held thread. */
async function seedHeld(page: Page, fp: string, threadId: string, notes: HeldSeed[]) {
  await page.evaluate(async (a) => {
    const now = Date.now();
    await window.__fz.putThread({ thread_id: a.threadId, kind: 'direct', participants: [{ fingerprint: a.fp, kind: 'human', display_name: 'Sender' }], created_at: new Date(now - 90 * a.day).toISOString(), last_activity_at: new Date(now - 90 * a.day).toISOString(), retention: { expires_at: null }, held: true } as never);
    for (const n of a.notes) {
      const heldAt = now - (n.heldAgoDays ?? 1) * a.day;
      await window.__fz.putNote({
        note_id: n.id, thread_id: a.threadId, direction: 'inbound', from_fingerprint: a.fp, to_fingerprints: [], sent_at: new Date(heldAt - a.day).toISOString(), body: n.body, participant_kind: 'human',
        retention: { expires_at: null }, wire_type: 'svrnty-note-v0', held: true, held_at: new Date(heldAt).toISOString(), ...(n.marked ? { expiry_seen_at: new Date(now - 2 * a.day).toISOString() } : {}),
      } as never);
    }
  }, { fp, threadId, notes, day: DAY });
}

const held = (page: Page, fp: string) => page.evaluate((f) => window.__fz.held(f), fp);
const scan = (page: Page, fp: string) => page.evaluate((f) => window.__fz.countHeld(f), fp);
async function expectRowEqualsScan(page: Page, fp: string, why: string) {
  expect({ why, row: await held(page, fp) }).toEqual({ why, row: { count: await scan(page, fp) } });
}
const visibleThreads = (page: Page) => page.evaluate(() => window.__fz.threads().then((r) => r.map((t) => t.thread_id).sort()));
const allNoteIds = (page: Page, t: string) => page.evaluate((x) => window.__fz.allNotes(x).then((r) => r.map((n) => n.note_id).sort()), t);

/** Contacts tab -> Book options -> View blocked contacts -> Bob's row -> his card -> its menu. */
async function openBlockedBobMenu(page: Page) {
  await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
  await page.getByRole('button', { name: 'Book options' }).click();
  await page.getByRole('menuitem', { name: /view blocked contacts/i }).click();
  const row = page.locator('[data-testid="contact-row"]').filter({ hasText: 'Bob' }).first();
  await expect(row).toBeVisible({ timeout: 25_000 });
  await row.click();
  return openCardMenu(page);
}
async function openCardMenu(page: Page) {
  const card = page.locator('.contacts-book-pane [data-testid="contact-action-card"]');
  await expect(card).toBeVisible();
  const toggle = card.getByTestId('card-actions-toggle');
  await toggle.scrollIntoViewIfNeeded();
  await toggle.click({ timeout: 10_000 });
  const menu = card.getByTestId('card-actions-toggle-menu');
  await expect(menu).toBeVisible();
  return { card, menu };
}
async function openHeldView(page: Page) {
  const { menu } = await openBlockedBobMenu(page);
  await menu.getByTestId('held-entry').click();
  const view = page.getByTestId('held-view');
  await expect(view).toBeVisible({ timeout: 15_000 });
  return view;
}

/** Identity tab -> Actions -> Lenses & vault: the panel that holds the "Held messages" entry. */
async function openLensesSection(page: Page) {
  await page.getByRole('tab', { name: 'Identity', exact: true }).click();
  await page.getByTestId('card-actions-toggle').click();
  await page.getByRole('menuitem', { name: 'Lenses & vault' }).click();
  const section = page.getByTestId('held-section');
  await expect(section).toBeVisible({ timeout: 15_000 });
  return section;
}

const INTRO = 'These arrived while you had Bob frozen. Opening, moving or deleting them sends nothing to Bob.';
const AGE = 'Notes held here longer than 30 days are marked expiring, then removed at least 7 days later.';
const CAP = "We keep up to 500 notes from each person you've frozen. After that, new notes from them aren't kept, and they stop getting delivery receipts, so they could notice.";

for (const [vpName, viewport] of [['desktop', null], ['phone 390x844', { width: 390, height: 844 }]] as const) {
  test.describe(`hold view: the frozen contact's page, ${vpName}`, () => {
    test.setTimeout(180_000);
    if (viewport) test.use({ viewport });

    test('U1 the entry is "Held messages" beside Unblock, with no count and no digit; it is there even when nothing is held; an UNBLOCKED contact has none', async ({ page }) => {
      const s = await setup(page, { blocked: true });
      const { menu } = await openBlockedBobMenu(page);
      await expect(menu.getByRole('menuitem', { name: 'Unblock', exact: true })).toBeVisible();
      const entry = menu.getByTestId('held-entry');
      await expect(entry).toHaveText('Held messages');
      expect(await entry.innerText()).not.toMatch(/\d/);
      await expect(page.getByTestId('held-view'), 'nothing is shown, and nothing was read, until the owner chooses it').toHaveCount(0);
      expect(await held(page, s.bobFp), 'and nothing is held in this case: the entry does not depend on it').toEqual({ count: 0 });
      // the control: an unblocked contact has no entry
      await page.evaluate(([id]) => window.__fz.setBlocked(id as string, false), [s.bobId]);
      await page.getByRole('tab', { name: 'Identity', exact: true }).click();
      await page.getByRole('tab', { name: 'Contacts', exact: true }).click();
      const row = page.locator('[data-testid="contact-row"]').filter({ hasText: 'Bob' }).first();
      await expect(row).toBeVisible({ timeout: 25_000 });
      await row.click();
      const again = await openCardMenu(page);
      await expect(again.menu.getByRole('menuitem', { name: 'Block', exact: true })).toBeVisible();
      await expect(again.menu.getByTestId('held-entry')).toHaveCount(0);
    });

    test('U2 the view shows the notes (words, arrived here, theirs, an expiring mark), the intro, the age limit and the cap; and the page carries no count before it is opened', async ({ page }) => {
      const s = await setup(page, { blocked: true });
      await seedHeld(page, s.bobFp, 'T-bob', [{ id: 'h1', body: 'first held words', heldAgoDays: 1 }, { id: 'h2', body: 'second held words', heldAgoDays: 3 }, { id: 'h3', body: 'an old one', heldAgoDays: 40, marked: true }]);
      const { menu } = await openBlockedBobMenu(page);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, 'before the view is opened no held note and no count appears anywhere').not.toMatch(/first held words|second held words|an old one|held messages \(|\d+ held/i);
      await menu.getByTestId('held-entry').click();
      const view = page.getByTestId('held-view');
      await expect(view).toBeVisible({ timeout: 15_000 });
      await expect(view.getByTestId('held-title')).toHaveText('Held messages');
      await expect(view.getByTestId('held-intro')).toHaveText(INTRO);
      await expect(view.getByTestId('held-age-line')).toHaveText(AGE);
      await expect(view.getByTestId('held-cap-line')).toHaveText(CAP);
      await expect(view.getByTestId('held-note-body'), 'the list has loaded before it is read (allInnerTexts does not wait)').toHaveCount(3);
      const bodies = await view.getByTestId('held-note-body').allInnerTexts();
      expect(bodies, 'newest first by when they were held').toEqual(['first held words', 'second held words', 'an old one']);
      await expect(view.getByTestId('held-note-arrived').first()).toHaveText(/^Arrived here .+/);
      await expect(view.getByTestId('held-note-theirs').first()).toHaveText(/^Sent .+, by their clock$/);
      await expect(view.getByTestId('held-note-expiring')).toHaveCount(1);
      await expect(view.getByTestId('held-note-h3').getByTestId('held-note-expiring')).toHaveText(/^Expiring\. Can be removed after .+\.$/);
      const noReply = (await view.innerText()).toLowerCase();
      expect(noReply, 'no reply and no export in this view').not.toMatch(/reply|export|evidence|download/);
    });

    test('U3 MOVE one: it leaves the view, the thread shows in an ordinary thread, the other held note stays hidden, the count follows, and the result says the contact is still frozen', async ({ page }) => {
      const s = await setup(page, { blocked: true });
      await seedHeld(page, s.bobFp, 'T-bob', [{ id: 'h1', body: 'first held words' }, { id: 'h2', body: 'second held words', heldAgoDays: 3 }]);
      expect(await visibleThreads(page)).toEqual([]);
      const view = await openHeldView(page);
      await view.getByTestId('held-note-h1').getByTestId('held-move-one').click();
      await expect(view.getByTestId('held-status')).toHaveText('Moved to your inbox. Bob is still frozen.');
      await expect(view.getByTestId('held-note-h1')).toHaveCount(0);
      await expect(view.getByTestId('held-note-h2')).toBeVisible();
      expect(await visibleThreads(page), 'the thread is now ordinary, so the moved note shows in Chat').toEqual(['T-bob']);
      expect(await page.evaluate(() => window.__fz.notes('T-bob').then((r) => r.map((n) => n.note_id))), 'and only the moved note shows: the other stays hidden').toEqual(['h1']);
      expect(await held(page, s.bobFp)).toEqual({ count: 1 });
      await expectRowEqualsScan(page, s.bobFp, 'after the move');
    });

    test('U4 DELETE one: it asks first and the default is CANCEL (it has the focus, and Enter keeps the note); Delete then removes it and the count follows; the empty thread row stays', async ({ page }) => {
      const s = await setup(page, { blocked: true });
      await seedHeld(page, s.bobFp, 'T-bob', [{ id: 'h1', body: 'first held words' }, { id: 'h2', body: 'second held words', heldAgoDays: 3 }]);
      const view = await openHeldView(page);
      await view.getByTestId('held-note-h1').getByTestId('held-delete-one').click();
      const confirm = view.getByTestId('held-confirm');
      await expect(confirm).toBeVisible();
      await expect(confirm).toContainText("Delete this note? This can't be undone.");
      const cancel = confirm.getByTestId('held-confirm-cancel');
      await expect(cancel).toHaveText('Cancel');
      await expect(cancel, 'Cancel is the default: it has the focus').toBeFocused();
      await page.keyboard.press('Enter');
      await expect(confirm).toHaveCount(0);
      await expect(view.getByTestId('held-note-h1'), 'Enter on the default kept the note').toBeVisible();
      expect(await held(page, s.bobFp)).toEqual({ count: 2 });
      await view.getByTestId('held-note-h1').getByTestId('held-delete-one').click();
      await view.getByTestId('held-confirm-delete').click();
      await expect(view.getByTestId('held-note-h1')).toHaveCount(0);
      await expect(view.getByTestId('held-note-h2')).toBeVisible();
      expect(await held(page, s.bobFp)).toEqual({ count: 1 });
      await expectRowEqualsScan(page, s.bobFp, 'after the delete');
      await view.getByTestId('held-note-h2').getByTestId('held-delete-one').click();
      await view.getByTestId('held-confirm-delete').click();
      await expect(view.getByTestId('held-empty')).toHaveText('No held messages.');
      expect(await held(page, s.bobFp)).toEqual({ count: 0 });
      expect(await page.evaluate(() => window.__fz.allThreads().then((r) => r.map((t) => t.thread_id))), 'the empty held thread row is still there').toEqual(['T-bob']);
      expect(await visibleThreads(page), 'and still hidden').toEqual([]);
    });

    test('U5 MOVE ALL needs no confirm and says how many; DELETE ALL asks with the count and the name, defaults to Cancel, and leaves the empty state', async ({ page }) => {
      const s = await setup(page, { blocked: true });
      await seedHeld(page, s.bobFp, 'T-bob', [{ id: 'h1', body: 'one' }, { id: 'h2', body: 'two', heldAgoDays: 2 }, { id: 'h3', body: 'three', heldAgoDays: 3 }, { id: 'h4', body: 'four', heldAgoDays: 4 }]);
      const view = await openHeldView(page);
      await view.getByTestId('held-delete-all').click();
      const confirm = view.getByTestId('held-confirm');
      await expect(confirm).toContainText("Delete all 4 held notes from Bob? This can't be undone.");
      await expect(confirm.getByTestId('held-confirm-cancel')).toBeFocused();
      await confirm.getByTestId('held-confirm-cancel').click();
      expect(await held(page, s.bobFp), 'Cancel deleted nothing').toEqual({ count: 4 });
      await view.getByTestId('held-note-h1').getByTestId('held-move-one').click();
      await expect(view.getByTestId('held-status')).toHaveText('Moved to your inbox. Bob is still frozen.');
      await view.getByTestId('held-move-all').click();
      await expect(view.getByTestId('held-status')).toHaveText('Moved 3 notes to your inbox. Bob is still frozen.');
      await expect(view.getByTestId('held-empty')).toHaveText('No held messages.');
      expect(await held(page, s.bobFp)).toEqual({ count: 0 });
      expect(await allNoteIds(page, 'T-bob')).toEqual(['h1', 'h2', 'h3', 'h4']);
      expect(await visibleThreads(page)).toEqual(['T-bob']);
      await expectRowEqualsScan(page, s.bobFp, 'after moving all');
    });

    test('U6 THE VIEW SENDS NOTHING: across opening, reading, moving and deleting, no request but a read reaches the relay (and the recorder is proven to see a POST)', async ({ page }) => {
      const s = await setup(page, { blocked: true });
      await seedHeld(page, s.bobFp, 'T-bob', [{ id: 'h1', body: 'one' }, { id: 'h2', body: 'two', heldAgoDays: 2 }, { id: 'h3', body: 'three', heldAgoDays: 3 }, { id: 'h4', body: 'four', heldAgoDays: 4 }]);
      const seen: Array<{ method: string; url: string }> = [];
      page.on('request', (r) => { if (r.url().includes('/api/')) seen.push({ method: r.method(), url: r.url() }); });
      const { menu } = await openBlockedBobMenu(page);
      seen.length = 0;   // from here: the owner's actions
      await menu.getByTestId('held-entry').click();
      const view = page.getByTestId('held-view');
      await expect(view).toBeVisible({ timeout: 15_000 });
      await view.getByTestId('held-note-h1').getByTestId('held-move-one').click();
      await expect(view.getByTestId('held-note-h1')).toHaveCount(0);
      await view.getByTestId('held-note-h2').getByTestId('held-delete-one').click();
      await view.getByTestId('held-confirm-delete').click();
      await expect(view.getByTestId('held-note-h2')).toHaveCount(0);
      await view.getByTestId('held-delete-all').click();
      await view.getByTestId('held-confirm-delete').click();
      await expect(view.getByTestId('held-empty')).toBeVisible();
      await page.waitForTimeout(3_000);   // the background poll gets a few turns too
      const nonRead = seen.filter((r) => r.method !== 'GET');
      expect(nonRead, `no request but a read reached the relay during the owner's actions (saw ${seen.length} reads)`).toEqual([]);
      // CONTROL: the recorder sees a POST when the page makes one, so "none" above means none
      seen.length = 0;
      await page.evaluate(() => fetch('/api/relay/envelope', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }).then(() => null, () => null));
      await expect.poll(() => seen.filter((r) => r.method === 'POST').length, { timeout: 10_000 }).toBeGreaterThan(0);
    });

    test('U7 Lenses & vault: the entry has no count and no digit even with notes; closed lists nothing; open lists the senders who are NOT frozen ("this person" + a code tag), not Bob while frozen; moving says exactly "Moved to your inbox." and never "still frozen"', async ({ page }) => {
      const s = await setup(page, { blocked: true });
      const STRANGER = 'c0ffee11'.repeat(8);
      await seedHeld(page, s.bobFp, 'T-bob', [{ id: 'h1', body: 'bob held' }]);
      await seedHeld(page, STRANGER, 'T-stranger', [{ id: 's1', body: 'stranger one' }, { id: 's2', body: 'stranger two', heldAgoDays: 2 }]);
      const section = await openLensesSection(page);
      const entry = section.getByTestId('held-section-entry');
      await expect(entry).toHaveText('Held messages');
      expect(await entry.innerText(), 'no digit on the entry even though notes are held').not.toMatch(/\d/);
      await expect(section.getByTestId('held-section-groups'), 'closed: nothing is listed and nothing was read').toHaveCount(0);
      await entry.click();
      const groups = section.getByTestId('held-section-groups');
      await expect(groups).toBeVisible({ timeout: 15_000 });
      const tag = STRANGER.slice(0, 8);
      await expect(section.getByTestId(`held-section-sender-${tag}`)).toHaveText(`this person ${tag}`);
      await expect(section.getByTestId(`held-section-sender-${s.bobFp.slice(0, 8)}`), 'Bob is frozen: his notes are reached on his own page, not here').toHaveCount(0);
      // CONTROL: unblock Bob and he is listed (the list is decided by "not frozen", not by who the sender is)
      await page.evaluate(([id]) => window.__fz.setBlocked(id as string, false), [s.bobId]);
      await entry.click();
      await entry.click();
      await expect(section.getByTestId(`held-section-sender-${s.bobFp.slice(0, 8)}`)).toBeVisible({ timeout: 15_000 });
      // the view for a sender with no name
      await section.getByTestId(`held-section-sender-${tag}`).click();
      const view = section.getByTestId('held-view');
      await expect(view).toBeVisible({ timeout: 15_000 });
      await expect(view.getByTestId('held-intro')).toContainText('These arrived while you had this person frozen.');
      await view.getByTestId('held-note-s1').getByTestId('held-move-one').click();
      await expect(view.getByTestId('held-status')).toHaveText('Moved to your inbox.');
      expect(await view.getByTestId('held-status').innerText()).not.toMatch(/still frozen/i);
      await expect(view.getByTestId('held-note-s1')).toHaveCount(0);
      await expect(view.getByTestId('held-note-s2')).toBeVisible();
      expect(await held(page, STRANGER)).toEqual({ count: 1 });
      await expectRowEqualsScan(page, STRANGER, 'after the move from the section');
    });

    test('U8 REMOVE the frozen contact through its real card menu: the held notes stay stored and are then reached from Lenses & vault', async ({ page }) => {
      const s = await setup(page, { blocked: true });
      await seedHeld(page, s.bobFp, 'T-bob', [{ id: 'h1', body: 'kept one' }, { id: 'h2', body: 'kept two', heldAgoDays: 2 }]);
      const { menu } = await openBlockedBobMenu(page);
      await menu.getByRole('menuitem', { name: 'Remove', exact: true }).click();
      const confirm = page.getByTestId('trust-action-confirm');
      await expect(confirm).toBeVisible();
      await confirm.getByTestId('trust-action-confirm-btn').click();
      await expect(confirm).toHaveCount(0);
      await expect(page.locator('[data-testid="contact-row"]').filter({ hasText: 'Bob' }), 'Bob is really gone from the book').toHaveCount(0);
      expect(await held(page, s.bobFp), 'removing the contact deletes no held note').toEqual({ count: 2 });
      expect(await allNoteIds(page, 'T-bob')).toEqual(['h1', 'h2']);
      await expectRowEqualsScan(page, s.bobFp, 'after the contact was removed');
      const section = await openLensesSection(page);
      await section.getByTestId('held-section-entry').click();
      const tag = s.bobFp.slice(0, 8);
      await section.getByTestId(`held-section-sender-${tag}`).click();
      const view = section.getByTestId('held-view');
      await expect(view.getByTestId('held-note-h1')).toBeVisible({ timeout: 15_000 });
      await expect(view.getByTestId('held-note-h2')).toBeVisible();
      expect(await view.innerText(), 'the view for a removed contact names no one and promises nothing about a freeze').not.toMatch(/still frozen/i);
    });

    test('U9 the view fits the screen: the page never scrolls sideways and the view lies inside the viewport (screenshot attached)', async ({ page }, testInfo) => {
      const s = await setup(page, { blocked: true });
      await seedHeld(page, s.bobFp, 'T-bob', [{ id: 'h1', body: 'a long held message '.repeat(12), heldAgoDays: 1 }, { id: 'h2', body: 'unbroken'.repeat(14), heldAgoDays: 3 }, { id: 'h3', body: 'old', heldAgoDays: 40, marked: true }]);
      const view = await openHeldView(page);
      await expect(view.getByTestId('held-note-h3')).toBeVisible();
      const m = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, iw: window.innerWidth, bw: document.body.scrollWidth }));
      expect(m.sw, `the page scrolls sideways (scrollWidth ${m.sw} > innerWidth ${m.iw})`).toBeLessThanOrEqual(m.iw);
      expect(m.bw, 'the body scrolls sideways').toBeLessThanOrEqual(m.iw);
      const box = await view.boundingBox();
      expect(box, 'the view has a box').not.toBeNull();
      expect(box!.x).toBeGreaterThanOrEqual(0);
      expect(box!.x + box!.width, 'the view reaches past the right edge').toBeLessThanOrEqual(m.iw + 1);
      for (const id of ['held-move-all', 'held-delete-all']) {
        const b = await view.getByTestId(id).boundingBox();
        expect(b && b.x >= 0 && b.x + b.width <= m.iw + 1, `${id} is on screen`).toBe(true);
      }
      await view.scrollIntoViewIfNeeded();
      await testInfo.attach(`hold-view-${vpName.split(' ')[0]}.png`, { body: await page.screenshot({ fullPage: false }), contentType: 'image/png' });
    });

    test('U10 Lenses & vault MOVE ALL: it says how many were moved, with no "frozen" in it, and the count follows (the sender is not frozen, so "still frozen" would be false)', async ({ page }) => {
      const s = await setup(page, { blocked: true });
      const STRANGER = 'c0ffee11'.repeat(8);
      await seedHeld(page, STRANGER, 'T-stranger', [{ id: 's1', body: 'one' }, { id: 's2', body: 'two', heldAgoDays: 2 }]);
      const section = await openLensesSection(page);
      await section.getByTestId('held-section-entry').click();
      await section.getByTestId(`held-section-sender-${STRANGER.slice(0, 8)}`).click();
      const view = section.getByTestId('held-view');
      await expect(view.getByTestId('held-note-s1')).toBeVisible({ timeout: 15_000 });
      await view.getByTestId('held-move-all').click();
      await expect(view.getByTestId('held-status')).toHaveText('Moved 2 notes to your inbox.');
      expect(await view.getByTestId('held-status').innerText()).not.toMatch(/frozen/i);
      await expect(view.getByTestId('held-empty')).toBeVisible();
      expect(await held(page, STRANGER)).toEqual({ count: 0 });
      await expectRowEqualsScan(page, STRANGER, 'after move all from the section');
      expect(await visibleThreads(page), 'the thread is ordinary now').toEqual(['T-stranger']);
      void s;
    });
  });
}
