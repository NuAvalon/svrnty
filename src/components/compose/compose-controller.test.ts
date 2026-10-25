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

const PORTAL = 'ab'.repeat(32);
const OTHER = 'cd'.repeat(32);
const PINNED: PinState = { state: 'pinned', record: { v: 1, fp: PORTAL, pinned_at: '2026-10-25T00:00:00.000Z' } };
const T0 = Date.parse('2026-10-25T07:20:00.000Z');
const nonceN = (n: number) => n.toString(16).padStart(32, '0');
const req = (n = 1, over: Record<string, string> = {}) => ({ purpose: 'svrnty-loom-post-v1', fleet: 'autobots', thread: 'lane:ops', body: `hello ${n}`, nonce: nonceN(n),
  issued_at: '2026-10-25T07:20:00.000Z', expires_at: '2026-10-25T07:25:00.000Z', origin: 'noosphere.nuavalon.com', ...over });
const noteBody = (r: unknown) => JSON.stringify({ type: COMPOSE_NOTE_TYPE, request: r });

interface Rig {
  c: ComposeController;
  notes: Map<string, StoredNote>;
  signCalls: Array<{ raw: unknown; shown: Readonly<Record<string, string>> }>;
  logs: string[];
  clock: { t: number };
  pin: { value: PinState | 'throw' };
  signResult: { value: SignResult | 'throw' | 'hang'; release?: () => void };
}

function rig(over: Partial<ControllerDeps> = {}): Rig {
  const notes = new Map<string, StoredNote>();
  const signCalls: Rig['signCalls'] = [];
  const logs: string[] = [];
  const clock = { t: T0 };
  const pin: Rig['pin'] = { value: PINNED };
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
    ...over,
  };
  return { c: new ComposeController(deps), notes, signCalls, logs, clock, pin, signResult };
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

test('a FAILED signature: no hand-back, the card is gone, nothing is claimed, one fixed log line with the reason code', async () => {
  for (const value of [{ ok: false, reason: 'self-verify-failed' } as SignResult, 'throw' as const]) {
    const r = rig(); put(r, 'n1'); await arrive(r, 'n1');
    r.signResult.value = value;
    await r.c.approve(nonceN(1));
    const s = r.c.getSnapshot();
    assert.equal(s.handBack, null);
    assert.equal(s.card, null);
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
