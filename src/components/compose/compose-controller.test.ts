// Run: npx tsx --test src/components/compose/compose-controller.test.ts
// The state machine behind the sign card, with the REAL pin logic, parser, validator, queue and card model; only the clock, the store read, the pin read and the
// signer are fakes. Every rule in the controller's header has a test here that fails when the rule is broken.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ComposeController, type ControllerDeps, type StoredNote } from './compose-controller';
import { COMPOSE_NOTE_TYPE } from '@/lib/compose/compose-inbound';
import type { PinState } from '@/lib/compose/compose-pin';
import { PIN_COPY } from '@/lib/compose/compose-pin-copy';
import type { SignResult } from '@/lib/compose/compose-sign';
import { emptyMemory, type ComposeMemory } from '@/lib/compose/compose-memory';
import { CARD_COPY } from '@/lib/compose/compose-card-copy';
import type { ResolvedBus } from './compose-bus';

const PORTAL = 'ab'.repeat(32);
const OTHER = 'cd'.repeat(32);
const PINNED: PinState = { state: 'pinned', record: { v: 1, fp: PORTAL, pinned_at: '2026-10-25T00:00:00.000Z' } };
const T0 = Date.parse('2026-10-25T07:20:00.000Z');
const nonceN = (n: number) => n.toString(16).padStart(32, '0');
const req = (n = 1, over: Record<string, string> = {}) => ({ purpose: 'svrnty-loom-post-v1', fleet: 'autobots', thread: 'lane:ops', body: `hello ${n}`, nonce: nonceN(n),
  issued_at: '2026-10-25T07:20:00.000Z', expires_at: '2026-10-25T07:25:00.000Z', origin: 'noosphere.nuavalon.com', ...over });
const noteBody = (r: unknown) => JSON.stringify({ type: COMPOSE_NOTE_TYPE, request: r });

/** What survives a reload and what two tabs share: the persisted memory and the same-origin bus. */
interface World {
  store: { mem: ComposeMemory; saveFails: boolean; saves: number };
  hub: Set<{ owner: object; cb: (n: string) => void }>;
}
const newWorld = (): World => ({ store: { mem: emptyMemory(), saveFails: false, saves: 0 }, hub: new Set() });
const busFor = (w: World, owner: object): ResolvedBus => ({
  emit: (nonce) => { for (const h of [...w.hub]) if (h.owner !== owner) h.cb(nonce); }, // a BroadcastChannel never delivers to the posting tab
  subscribe: (cb) => { const h = { owner, cb }; w.hub.add(h); return () => { w.hub.delete(h); }; },
});

interface Rig {
  world: World;
  c: ComposeController;
  notes: Map<string, StoredNote>;
  signCalls: Array<{ raw: unknown; shown: Readonly<Record<string, string>> }>;
  logs: string[];
  clock: { t: number };
  pin: { value: PinState | 'throw' };
  signResult: { value: SignResult | 'throw' | 'hang'; release?: () => void };
}

function rig(over: Partial<ControllerDeps> = {}, world: World = newWorld(), shared?: { clock: { t: number }; pin: { value: PinState | 'throw' } }): Rig {
  const notes = new Map<string, StoredNote>();
  const signCalls: Rig['signCalls'] = [];
  const logs: string[] = [];
  const clock = shared?.clock ?? { t: T0 };
  const pin: Rig['pin'] = shared?.pin ?? { value: PINNED };
  const owner = {};
  const signResult: Rig['signResult'] = { value: 'throw' };
  const deps: ControllerDeps = {
    now: () => new Date(clock.t),
    getPin: async () => { if (pin.value === 'throw') throw new Error('idb'); return pin.value; },
    readNote: async (e) => notes.get(String(e.note_id)) ?? null,
    sign: async (raw, shown) => {
      signCalls.push({ raw, shown });
      const v = signResult.value;
      if (v === 'throw') throw new Error('boom');
      if (v === 'hang') {
        await new Promise<void>((r) => { signResult.release = r; });
        return { ok: true, signed: { kind: 'post', object: { ...shown }, suite: 'ed25519', sig_packet_b64: 'AAAA' } };
      }
      return v;
    },
    deriveWords: () => ['alpha', 'bravo', 'charlie', 'delta'],
    wordsConfirmed: true,
    log: (l) => logs.push(l),
    loadMemory: async () => JSON.parse(JSON.stringify(world.store.mem)) as ComposeMemory,
    saveMemory: async (m) => { if (world.store.saveFails) throw new Error('idb'); world.store.saves++; world.store.mem = JSON.parse(JSON.stringify(m)) as ComposeMemory; },
    bus: busFor(world, owner),
    ...over,
  };
  return { c: new ComposeController(deps), world, notes, signCalls, logs, clock, pin, signResult };
}
const okSigned = (object: Record<string, string>): SignResult => ({ ok: true, signed: { kind: 'post', object, suite: 'ed25519', sig_packet_b64: 'QUJD' } });
const put = (r: Rig, id: string, over: Partial<StoredNote> = {}) => r.notes.set(id, { note_id: id, from_fingerprint: PORTAL, body: noteBody(req(Number(id.replace(/\D/g, '')) || 1)), direction: 'inbound', ...over });
const arrive = (r: Rig, id: string) => r.c.onArrival({ note_id: id, thread_id: 't' });

test('a pinned sender\'s valid request becomes ONE card with the full body, the words and an Approve', async () => {
  const r = rig(); put(r, 'n1'); await arrive(r, 'n1');
  const s = r.c.getSnapshot();
  assert.equal(s.card?.mode, 'sign');
  assert.equal(s.cardNonce, nonceN(1));
  assert.ok(s.card?.mode === 'sign' && s.card.approve !== null && s.card.body === 'hello 1' && s.card.wordsLine !== null);
  assert.equal(s.waiting, 0);
});

test('the production switch OFF: the card shows, there is NO Approve, and approve() cannot sign even when called directly', async () => {
  const r = rig({ wordsConfirmed: false }); put(r, 'n1'); await arrive(r, 'n1');
  assert.ok(r.c.getSnapshot().card?.mode === 'sign' && r.c.getSnapshot().card!.mode === 'sign');
  const card = r.c.getSnapshot().card;
  assert.ok(card?.mode === 'sign' && card.approve === null);
  await r.c.approve(nonceN(1));
  assert.equal(r.signCalls.length, 0);
  assert.equal(r.c.getSnapshot().handBack, null);
});

test('a words derivation that throws or returns junk: no Approve, and approve() signs nothing', async () => {
  for (const deriveWords of [() => { throw new Error('x'); }, () => ['a', 'b'], () => ['a', 'b', 'c', 'd e']] as Array<ControllerDeps['deriveWords']>) {
    const r = rig({ deriveWords }); put(r, 'n1'); await arrive(r, 'n1');
    await r.c.approve(nonceN(1));
    assert.equal(r.signCalls.length, 0);
  }
});

test('APPROVE signs exactly what the card showed (the queue item\'s raw + its object) and then shows the hand-back, not the next card', async () => {
  const r = rig(); put(r, 'n1'); put(r, 'n2'); await arrive(r, 'n1'); await arrive(r, 'n2');
  assert.equal(r.c.getSnapshot().waiting, 1);
  const obj = (r.c.getSnapshot().card as { body: string }).body;
  assert.equal(obj, 'hello 1');
  r.signResult.value = okSigned({ ...req(1) });
  await r.c.approve(nonceN(1));
  assert.equal(r.signCalls.length, 1);
  assert.equal(r.signCalls[0].shown.body, 'hello 1');
  assert.equal((r.signCalls[0].raw as { body: string }).body, 'hello 1');
  const s = r.c.getSnapshot();
  assert.ok(s.handBack !== null && s.card === null, 'the hand-back takes the screen; the next card waits behind it');
  assert.equal(s.handBack!.title, 'Signed. Not posted yet.');
  r.c.dismissHandBack();
  assert.equal(r.c.getSnapshot().handBack, null);
  assert.equal(r.c.getSnapshot().cardNonce, nonceN(2));
});

test('SHOWN = CLICKED: an approve() naming a card that is no longer the current one signs NOTHING (the next card slid under the pointer)', async () => {
  const r = rig(); put(r, 'n1'); put(r, 'n2'); await arrive(r, 'n1'); await arrive(r, 'n2');
  r.c.dismissCard(nonceN(1)); // the first card goes away; card 2 is now current
  assert.equal(r.c.getSnapshot().cardNonce, nonceN(2));
  await r.c.approve(nonceN(1)); // a click aimed at card 1
  assert.equal(r.signCalls.length, 0);
  await r.c.approve('not-a-nonce');
  assert.equal(r.signCalls.length, 0);
  assert.equal(r.c.getSnapshot().cardNonce, nonceN(2), 'card 2 is still waiting for its own decision');
});

test('a double approve while signing makes ONE signature and ONE hand-back', async () => {
  const r = rig(); put(r, 'n1'); await arrive(r, 'n1');
  r.signResult.value = 'hang';
  const a = r.c.approve(nonceN(1));
  const b = r.c.approve(nonceN(1));
  assert.equal(r.c.getSnapshot().signing, true);
  r.signResult.release!(); await a; await b;
  assert.equal(r.signCalls.length, 1);
  assert.ok(r.c.getSnapshot().handBack !== null);
});

test('approve() is ignored while a hand-back is showing', async () => {
  const r = rig(); put(r, 'n1'); put(r, 'n2'); await arrive(r, 'n1'); await arrive(r, 'n2');
  r.signResult.value = okSigned({ ...req(1) });
  await r.c.approve(nonceN(1));
  await r.c.approve(nonceN(2));
  assert.equal(r.signCalls.length, 1);
});

test('a FAILED signature (Hypatia §6d): no hand-back, a fixed notice with ONE Close, nothing is claimed, one fixed log line with the reason code', async () => {
  for (const value of [{ ok: false, reason: 'self-verify-failed' } as SignResult, 'throw' as const]) {
    const r = rig(); put(r, 'n1'); await arrive(r, 'n1');
    r.signResult.value = value;
    await r.c.approve(nonceN(1));
    const s = r.c.getSnapshot();
    assert.equal(s.handBack, null);
    assert.equal(s.card, null);
    assert.deepEqual(s.failed, { notice: "Couldn't sign this request. Nothing was signed or posted. Ask the portal to send it again.", close: 'Close' });
    assert.equal(s.signing, false);
    assert.equal(r.logs.length, 1);
    assert.match(r.logs[0], /^A sign request was not signed \((self-verify-failed|sign-failed)\)\.$/);
  }
});

test('two arrivals AT ONCE are both queued (arrivals are serialised: neither read of the queue is lost)', async () => {
  const r = rig();
  for (let i = 1; i <= 4; i++) put(r, `n${i}`);
  await Promise.all([1, 2, 3, 4].map((i) => arrive(r, `n${i}`)));
  assert.equal(r.c.getSnapshot().waiting, 3);
});

test('a repeated nonce never makes a second card, even after the first was declined', async () => {
  const r = rig(); put(r, 'n1'); await arrive(r, 'n1');
  r.c.dismissCard(nonceN(1));
  assert.equal(r.c.getSnapshot().card, null);
  await arrive(r, 'n1');
  assert.equal(r.c.getSnapshot().card, null);
});

test('dismissCard with the wrong nonce does nothing; with the right one it removes only the shown card', async () => {
  const r = rig(); put(r, 'n1'); put(r, 'n2'); await arrive(r, 'n1'); await arrive(r, 'n2');
  r.c.dismissCard(nonceN(2));
  assert.equal(r.c.getSnapshot().cardNonce, nonceN(1));
  r.c.dismissCard(nonceN(1));
  assert.equal(r.c.getSnapshot().cardNonce, nonceN(2));
});

test('an UNPINNED verified sender: no card, a CANDIDATE is remembered, the fixed log line', async () => {
  const r = rig(); r.pin.value = { state: 'absent' }; put(r, 'n1'); await arrive(r, 'n1');
  const s = r.c.getSnapshot();
  assert.equal(s.card, null);
  assert.deepEqual(s.candidates, [PORTAL]);
  assert.deepEqual(r.logs, [PIN_COPY.unpinnedLog]);
});

test('a DIFFERENT verified key while pinned: a PASSIVE notice, no card, and the new key is a candidate for Settings to compare', async () => {
  const r = rig(); put(r, 'n1', { from_fingerprint: OTHER }); await arrive(r, 'n1');
  const s = r.c.getSnapshot();
  assert.equal(s.card, null);
  assert.equal(s.passiveNotice, PIN_COPY.changedNotice);
  assert.deepEqual(s.candidates, [OTHER]);
  r.c.dismissPassiveNotice();
  assert.equal(r.c.getSnapshot().passiveNotice, null);
});

test('a pin read that THROWS is damaged, not absent: blocked, passive notice, no card, never a first-pin offer', async () => {
  const r = rig(); r.pin.value = 'throw'; put(r, 'n1'); await arrive(r, 'n1');
  const s = r.c.getSnapshot();
  assert.equal(s.card, null);
  assert.equal(s.passiveNotice, PIN_COPY.unreadableNotice);
});

test('a locked store: no card, no candidate, no notice, only the fixed log line', async () => {
  const r = rig(); r.pin.value = { state: 'locked' }; put(r, 'n1'); await arrive(r, 'n1');
  const s = r.c.getSnapshot();
  assert.ok(s.card === null && s.passiveNotice === null && s.candidates.length === 0);
  assert.equal(r.logs.length, 1);
});

test('plain chat, an outbound copy, a missing note and a store read that throws change NOTHING and log NOTHING', async () => {
  const r = rig();
  put(r, 'n1', { body: 'hi there' });
  put(r, 'n2', { direction: 'outbound' });
  await arrive(r, 'n1'); await arrive(r, 'n2'); await arrive(r, 'ghost');
  const r2 = rig({ readNote: async () => { throw new Error('idb'); } });
  await arrive(r2, 'n3');
  for (const x of [r, r2]) {
    const s = x.c.getSnapshot();
    assert.ok(s.card === null && s.passiveNotice === null && s.candidates.length === 0 && s.handBack === null);
    assert.deepEqual(x.logs, []);
  }
});

test('a card past its expires_at disappears on tick() and can never be approved late', async () => {
  const r = rig(); put(r, 'n1'); await arrive(r, 'n1');
  let fired = 0;
  r.c.subscribe(() => { fired++; });
  r.clock.t = Date.parse('2026-10-25T07:25:01.000Z');
  r.c.tick();
  assert.equal(fired, 1);
  assert.equal(r.c.getSnapshot().card, null);
  await r.c.approve(nonceN(1));
  assert.equal(r.signCalls.length, 0);
  r.c.tick();
  assert.equal(fired, 1, 'tick with nothing changed emits nothing');
});

test('a REFUSAL card (hidden characters) is shown with Close only and approve() cannot sign it', async () => {
  const r = rig(); put(r, 'n1', { body: noteBody(req(1, { body: 'hel‮lo' })) }); await arrive(r, 'n1');
  const s = r.c.getSnapshot();
  assert.equal(s.card?.mode, 'refused');
  await r.c.approve(String(s.cardNonce));
  assert.equal(r.signCalls.length, 0);
  assert.equal(s.cardNonce, nonceN(1), 'a refusal has a nonce so Close can name it');
});

test('forgetCandidate drops one candidate and emits only when something changed', async () => {
  const r = rig(); r.pin.value = { state: 'absent' }; put(r, 'n1'); await arrive(r, 'n1');
  let fired = 0; r.c.subscribe(() => { fired++; });
  r.c.forgetCandidate(OTHER); assert.equal(fired, 0);
  r.c.forgetCandidate(PORTAL); assert.equal(fired, 1); assert.deepEqual(r.c.getSnapshot().candidates, []);
});

test('the snapshot object is stable between changes (useSyncExternalStore would loop otherwise)', async () => {
  const r = rig(); put(r, 'n1'); await arrive(r, 'n1');
  assert.equal(r.c.getSnapshot(), r.c.getSnapshot());
});

// ───────────────────────────── C1: persisted resolved nonces + cross-tab (Flint #1489) ─────────────────────────────

/** A second controller on the SAME disk and the same clock, as after a reload or in a second tab (own queue, own bus identity). */
function secondTab(r: Rig): Rig {
  return rig({}, r.world, { clock: r.clock, pin: r.pin });
}
const settle = () => new Promise<void>((res) => setTimeout(res, 0));

test('C1 RELOAD: a request that was SIGNED never raises a card again from a fresh controller on the same disk (no card, one fixed log line)', async () => {
  const a = rig(); put(a, 'n1'); await arrive(a, 'n1');
  a.signResult.value = okSigned({ ...req(1) });
  await a.c.approve(nonceN(1)); await settle();
  const b = secondTab(a); put(b, 'n1'); await arrive(b, 'n1');
  assert.equal(b.c.getSnapshot().card, null);
  assert.deepEqual(b.logs, ['A sign request that was already handled arrived again. It was not shown.']);
});

test('C1 RELOAD: a request that was DECLINED (and one closed as a refusal) never comes back either', async () => {
  const a = rig(); put(a, 'n1'); put(a, 'n2', { body: noteBody(req(2, { body: 'hel‮lo' })) });
  await arrive(a, 'n1'); await arrive(a, 'n2');
  a.c.dismissCard(nonceN(1)); a.c.dismissCard(nonceN(2)); await settle();
  const b = secondTab(a); put(b, 'n1'); put(b, 'n2', { body: noteBody(req(2, { body: 'hel‮lo' })) });
  await arrive(b, 'n1'); await arrive(b, 'n2');
  assert.equal(b.c.getSnapshot().card, null);
  assert.equal(b.c.getSnapshot().waiting, 0);
});

test('C1: a FAILED signature is also remembered (a retry is a NEW request from the portal, not the same nonce)', async () => {
  const a = rig(); put(a, 'n1'); await arrive(a, 'n1');
  a.signResult.value = { ok: false, reason: 'sign-failed' };
  await a.c.approve(nonceN(1)); await settle();
  const b = secondTab(a); put(b, 'n1'); await arrive(b, 'n1');
  assert.equal(b.c.getSnapshot().card, null);
});

test('C1: a handled nonce is remembered UNTIL the request\'s own expires_at (the stored time), and other requests are unaffected', async () => {
  const a = rig(); put(a, 'n1'); await arrive(a, 'n1');
  a.c.dismissCard(nonceN(1)); await settle();
  const b = secondTab(a); put(b, 'n2'); await arrive(b, 'n2');
  assert.equal(b.c.getSnapshot().cardNonce, nonceN(2), 'a different nonce still raises a card');
  assert.ok(Object.keys(a.world.store.mem.resolved).includes(nonceN(1)));
  assert.equal(a.world.store.mem.resolved[nonceN(1)], Date.parse('2026-10-25T07:25:00.000Z'));
});

test('C1: what is written to disk is a VALID memory holding only nonces and times (no request text, no key)', async () => {
  const a = rig(); put(a, 'n1', { body: noteBody(req(1, { body: 'SECRET-BODY-TEXT' })) }); await arrive(a, 'n1');
  a.c.dismissCard(nonceN(1)); await settle();
  const raw = JSON.stringify(a.world.store.mem);
  assert.doesNotMatch(raw, /SECRET-BODY-TEXT|lane:ops|noosphere/);
  assert.deepEqual(Object.keys(a.world.store.mem).sort(), ['noticed', 'resolved', 'v']);
});

test('C1 CROSS-TAB: approve in tab A -> tab B\'s card closes with "Handled in another tab.", which clears after 3 s; a replay in B shows nothing', async () => {
  const a = rig(); const b = secondTab(a);
  put(a, 'n1'); put(b, 'n1');
  await arrive(a, 'n1'); await arrive(b, 'n1');
  assert.equal(b.c.getSnapshot().cardNonce, nonceN(1));
  a.signResult.value = okSigned({ ...req(1) });
  await a.c.approve(nonceN(1));
  const s = b.c.getSnapshot();
  assert.equal(s.card, null);
  assert.equal(s.handledElsewhere, CARD_COPY.handledElsewhere);
  assert.equal(b.signCalls.length, 0, 'B signed nothing');
  b.clock.t += 2999; b.c.tick();
  assert.equal(b.c.getSnapshot().handledElsewhere, CARD_COPY.handledElsewhere, 'still up at 2.999 s');
  b.clock.t += 1; b.c.tick();
  assert.equal(b.c.getSnapshot().handledElsewhere, null);
  await arrive(b, 'n1');
  assert.equal(b.c.getSnapshot().card, null, 'a replay of the same note in B shows nothing');
});

test('C1 CROSS-TAB: a DECLINE in A closes B\'s card the same way; only the matching nonce closes, the rest of B\'s queue stays', async () => {
  const a = rig(); const b = secondTab(a);
  for (const x of [a, b]) { put(x, 'n1'); put(x, 'n2'); }
  await arrive(a, 'n1'); await arrive(b, 'n1'); await arrive(b, 'n2');
  a.c.dismissCard(nonceN(1));
  assert.equal(b.c.getSnapshot().cardNonce, nonceN(2), 'B advanced to its own next card');
  assert.equal(b.c.getSnapshot().waiting, 0);
});

test('C1 CROSS-TAB: a tab that is MID-SIGNING the same request is not yanked out from under the person (its card stays until it finishes)', async () => {
  const a = rig(); const b = secondTab(a);
  put(a, 'n1'); put(b, 'n1'); await arrive(a, 'n1'); await arrive(b, 'n1');
  b.signResult.value = 'hang';
  const pending = b.c.approve(nonceN(1));
  a.c.dismissCard(nonceN(1)); // the other tab declines while B is signing
  assert.equal(b.c.getSnapshot().signing, true);
  assert.equal(b.c.getSnapshot().handledElsewhere, null);
  b.signResult.release!(); await pending;
  assert.ok(b.c.getSnapshot().handBack !== null, 'B finished its own signature (the portal single-use nonce is the backstop, C2)');
});

test('C1: dispose() stops listening to other tabs', async () => {
  const a = rig(); const b = secondTab(a);
  put(b, 'n1'); await arrive(b, 'n1');
  b.c.dispose();
  put(a, 'n1'); await arrive(a, 'n1'); a.c.dismissCard(nonceN(1));
  assert.equal(b.c.getSnapshot().cardNonce, nonceN(1), 'a disposed controller ignores the bus');
});

test('C1: a message for a nonce this tab does not hold changes nothing visible but is remembered (a later arrival of it shows nothing)', async () => {
  const a = rig(); const b = secondTab(a);
  put(a, 'n1'); await arrive(a, 'n1'); a.c.dismissCard(nonceN(1));
  put(b, 'n1'); await arrive(b, 'n1');
  assert.equal(b.c.getSnapshot().card, null);
  assert.equal(b.c.getSnapshot().handledElsewhere, null);
});

test('C1: a failing disk write is logged (fixed line) and THIS tab is still protected from a replay', async () => {
  const a = rig(); a.world.store.saveFails = true;
  put(a, 'n1'); await arrive(a, 'n1'); a.c.dismissCard(nonceN(1)); await settle();
  assert.ok(a.logs.includes('The compose memory could not be saved.'));
  await arrive(a, 'n1');
  assert.equal(a.c.getSnapshot().card, null);
});

test('C1: an unreadable/lost memory reads as EMPTY (a replay of a still-valid request may raise ONE more card), it never blocks signing', async () => {
  const a = rig({ loadMemory: async () => { throw new Error('idb'); } });
  put(a, 'n1'); await arrive(a, 'n1');
  assert.equal(a.c.getSnapshot().cardNonce, nonceN(1));
});

test('C1: lock/identity switch (reset) clears THIS tab\'s memory of the queue but the disk still remembers: a replay after unlock shows nothing', async () => {
  const a = rig(); put(a, 'n1'); await arrive(a, 'n1'); a.c.dismissCard(nonceN(1)); await settle();
  a.c.reset();
  await arrive(a, 'n1');
  assert.equal(a.c.getSnapshot().card, null);
});

test('FAILED notice: it takes the screen, approve() and dismissCard() do nothing meanwhile, Close brings the next card', async () => {
  const r = rig(); put(r, 'n1'); put(r, 'n2'); await arrive(r, 'n1'); await arrive(r, 'n2');
  r.signResult.value = { ok: false, reason: 'sign-failed' };
  await r.c.approve(nonceN(1));
  assert.ok(r.c.getSnapshot().failed !== null && r.c.getSnapshot().card === null);
  await r.c.approve(nonceN(2)); r.c.dismissCard(nonceN(2));
  assert.equal(r.signCalls.length, 1);
  r.c.dismissFailed();
  assert.equal(r.c.getSnapshot().failed, null);
  assert.equal(r.c.getSnapshot().cardNonce, nonceN(2));
});

// ───────────────────────────── C3: the passive notice ─────────────────────────────

const strange = (r: Rig, id: string, from: string) => put(r, id, { from_fingerprint: from });
const OTHER2 = 'ef'.repeat(32);

test('C3: the key-changed notice is shown ONCE per sender per 24 h, even if it was dismissed; it carries only fixed copy', async () => {
  const r = rig(); strange(r, 'n1', OTHER); strange(r, 'n2', OTHER);
  await arrive(r, 'n1');
  assert.equal(r.c.getSnapshot().passiveNotice, PIN_COPY.changedNotice);
  assert.doesNotMatch(r.c.getSnapshot().passiveNotice!, new RegExp(OTHER.slice(0, 8)));
  r.c.dismissPassiveNotice();
  await arrive(r, 'n2');
  assert.equal(r.c.getSnapshot().passiveNotice, null, 'the same sender again within 24 h: no notice');
  assert.deepEqual(r.c.getSnapshot().candidates, [OTHER], 'but the key is still a Settings candidate, once');
});

test('C3: a DIFFERENT sender gets its own notice; after 24 h the first sender may notice again', async () => {
  const r = rig(); strange(r, 'n1', OTHER); strange(r, 'n2', OTHER2); strange(r, 'n3', OTHER);
  await arrive(r, 'n1'); r.c.dismissPassiveNotice();
  await arrive(r, 'n2');
  assert.equal(r.c.getSnapshot().passiveNotice, PIN_COPY.changedNotice);
  r.c.dismissPassiveNotice();
  r.clock.t += 24 * 60 * 60 * 1000;
  await arrive(r, 'n3');
  assert.equal(r.c.getSnapshot().passiveNotice, PIN_COPY.changedNotice);
});

test('C3: the limiter SURVIVES a reload (the notice is not re-shown just because the tab was refreshed)', async () => {
  const a = rig(); strange(a, 'n1', OTHER); await arrive(a, 'n1'); await settle();
  const b = secondTab(a); strange(b, 'n2', OTHER); await arrive(b, 'n2');
  assert.equal(b.c.getSnapshot().passiveNotice, null);
});

test('C3: an UNREADABLE pin notice is limited the same way, per sender', async () => {
  const r = rig(); r.pin.value = { state: 'unreadable' }; put(r, 'n1'); put(r, 'n2', { body: noteBody(req(2)) });
  await arrive(r, 'n1'); assert.equal(r.c.getSnapshot().passiveNotice, PIN_COPY.unreadableNotice);
  r.c.dismissPassiveNotice(); await arrive(r, 'n2');
  assert.equal(r.c.getSnapshot().passiveNotice, null);
});
