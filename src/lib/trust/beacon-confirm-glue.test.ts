/* eslint-disable @typescript-eslint/no-explicit-any -- deliberately wrong inputs */
// src/lib/trust/beacon-confirm-glue.test.ts: the glue between the confirm session and the store: which keys it reads and WHEN, what it writes and under which lock, and what ends the session.
// The store, the lock and the lock hook are fakes with an event log; nothing here touches IndexedDB. Run: npx tsx --test src/lib/trust/beacon-confirm-glue.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createConfirmGlue, type GluePorts, type PublicKeyRead } from './beacon-confirm-glue';
import { NONCE_BYTES } from './beacon-confirm-code';

const b64 = (fill: number): string => Buffer.from(new Uint8Array(32).fill(fill)).toString('base64');
const KA: PublicKeyRead = { publicKey: b64(0x11), generation: 1_800_000_001 };   // the key phone A holds for itself
const KB: PublicKeyRead = { publicKey: b64(0x22), generation: 1_800_000_002 };   // the key phone B holds for itself
const T0 = 1_900_000_000_000;
const nonce = (seed: number): Uint8Array => Uint8Array.from({ length: NONCE_BYTES }, (_, i) => seed + i);
const zeros = (u: Uint8Array): boolean => Array.from(u).every((x) => x === 0);

/** One phone: a store with its own key and the key it holds for the contact, a lock, a lock hook, and an event log. */
function phone(own: PublicKeyRead, held: PublicKeyRead, seeds: number[] = [0xa0]) {
  const w = {
    own: { ...own } as PublicKeyRead | undefined, held: { ...held } as PublicKeyRead | undefined,
    events: [] as string[], confirmed: [] as Array<[string, number]>, heldAsked: [] as string[], lockedFor: [] as string[],
    hook: undefined as undefined | (() => void), hooks: 0, failWrite: false, lockFails: false, inLock: 0,
    onReadOwn: undefined as undefined | (() => void), gates: [] as Array<Promise<void>>,
    nonces: seeds.map(nonce),
  };
  const tag = (s: string): string => (w.inLock ? `${s}:locked` : s);
  const ports: GluePorts = {
    async readOwn() { w.events.push(tag('read-own')); w.onReadOwn?.(); const g = w.gates.shift(); if (g) await g; return w.own ? { ...w.own } : undefined; },
    async readHeld(c) { w.events.push(tag('read-held')); w.heldAsked.push(c); return w.held ? { ...w.held } : undefined; },
    async withContactLock(c, run) {
      if (w.lockFails) throw new Error('lock timeout');
      w.events.push('lock'); w.lockedFor.push(c); w.inLock++;
      try { return await run(); } finally { w.inLock--; w.events.push('unlock'); }
    },
    async writeConfirmed(c, g) { w.events.push(tag('write')); if (w.failWrite) throw new Error('disk secret-detail'); w.confirmed.push([c, g]); },
    onLock(fn) { w.hooks++; w.hook = fn; },
  };
  const clock = { v: T0 };
  const glue = createConfirmGlue(ports, { now: () => clock.v, mono: () => clock.v - T0 + 5_000, random: () => w.nonces.shift() ?? new Uint8Array(NONCE_BYTES) });
  return { w, glue, clock };
}
/** Phone A starts for 'bob', phone B scans for 'alice'. */
async function pair() {
  const a = phone(KA, KB), b = phone(KB, KA);
  const s = await a.glue.start('bob');
  assert.equal(s.ok, true, JSON.stringify(s));
  const j = await b.glue.joinFromScan('alice', (s as any).shown.qr);
  assert.deepEqual(j, { ok: true });
  const codeOf = (p: typeof a, who: string): string => { const r = p.glue.ownCode(who) as any; assert.equal(r.ok, true, JSON.stringify(r)); return r.code; };
  return { a, b, shown: (s as any).shown, codeOf };
}

test('GL1 two phones: each shows a DIFFERENT code (the code the other phone must be given), and the code from the other phone on either confirms the generation of the key it compared and writes it under the contact lock', async () => {
  const { a, b, codeOf } = await pair();
  const codeA = codeOf(a, 'bob'), codeB = codeOf(b, 'alice');   // both read before either session is spent
  assert.notEqual(codeA, codeB, 'the code on one screen is not the code on the other');
  a.w.events.length = 0;
  assert.equal(((await a.glue.enter('bob', codeA)) as any).kind, 'mismatch', 'the code on its OWN screen is a mismatch');
  a.w.events.length = 0; a.w.lockedFor.length = 0;
  assert.deepEqual(await a.glue.enter('bob', codeB), { kind: 'confirmed', generation: KB.generation });
  assert.deepEqual(a.w.confirmed, [['bob', KB.generation]]);
  assert.deepEqual(a.w.lockedFor, ['bob'], 'the lock is the lock of THIS contact');
  assert.deepEqual(a.w.events, ['lock', 'read-own:locked', 'read-held:locked', 'write:locked', 'unlock']);
  assert.equal(a.glue.status(), 'confirmed');
  assert.deepEqual(await b.glue.enter('alice', codeA), { kind: 'confirmed', generation: KA.generation });
  assert.deepEqual(b.w.confirmed, [['alice', KA.generation]]);
});

test('GL2 a key that changed between the start and the entry refuses: nothing is written and the session is over (the keys are read from the store at the entry, never kept from the start)', async () => {
  for (const [what, change] of [
    ['the held key replaced', (w: ReturnType<typeof phone>['w']) => { w.held = { publicKey: b64(0x33), generation: KB.generation + 1 }; }],
    ['the held key replaced at the same generation', (w: ReturnType<typeof phone>['w']) => { w.held = { publicKey: b64(0x33), generation: KB.generation }; }],
    ['the held generation moved', (w: ReturnType<typeof phone>['w']) => { w.held = { publicKey: KB.publicKey, generation: KB.generation + 1 }; }],
    ['the own key rotated', (w: ReturnType<typeof phone>['w']) => { w.own = { publicKey: b64(0x44), generation: KA.generation + 1 }; }],
  ] as const) {
    const { a, b, codeOf } = await pair();
    const good = codeOf(b, 'alice');
    change(a.w);
    const r = await a.glue.enter('bob', good) as any;
    assert.equal(r.kind, 'refused', what);
    assert.match(r.reason, /^(own|held)-changed$/, what);
    assert.deepEqual(a.w.confirmed, [], what);
    assert.equal(a.w.events.some((e) => e.startsWith('write')), false, what);
    assert.notEqual(a.glue.status(), 'open', what);
  }
});

test('GL3 the keys are read INSIDE the lock at the entry, and on every entry: none is read outside it then', async () => {
  const { a, b, codeOf } = await pair();
  const afterStart = [...a.w.events];
  assert.deepEqual(afterStart, ['read-own', 'read-held'], 'the start reads both keys, outside any lock');
  a.w.events.length = 0;
  const bad = codeOf(b, 'alice') === '000000' ? '000001' : '000000';
  assert.equal(((await a.glue.enter('bob', bad)) as any).kind, 'mismatch');
  assert.deepEqual(a.w.events, ['lock', 'read-own:locked', 'read-held:locked', 'unlock'], 'a miss reads the keys again, under the lock, and writes nothing');
  assert.deepEqual(a.w.heldAsked, ['bob', 'bob'], 'the held key asked for is the contact\'s, at the start and at the entry');
  a.w.events.length = 0;
  assert.equal(((await a.glue.enter('bob', bad)) as any).kind, 'mismatch');
  assert.equal(a.w.events.filter((e) => e === 'read-own:locked').length, 1);
  assert.equal(a.w.events.some((e) => e === 'read-own' || e === 'read-held'), false);
});

test('GL4 the lock hook is registered ONCE, and when it fires the session is gone and nothing can be entered; a new session works after', async () => {
  const a = phone(KA, KB, [0xa0, 0xb0, 0xc0]);
  assert.equal(a.w.hooks, 1, 'registered at creation');
  assert.equal(((await a.glue.start('bob')) as any).ok, true);
  assert.equal(((await a.glue.start('bob')) as any).ok, true);
  assert.equal(a.w.hooks, 1, 'still one registration after more sessions');
  a.w.hook!();
  assert.equal(a.glue.status(), 'none');
  assert.deepEqual(a.glue.ownCode('bob'), { ok: false, reason: 'no-session' });
  assert.deepEqual(await a.glue.enter('bob', '123456'), { kind: 'no-session' });
  assert.doesNotThrow(() => { a.w.hook!(); a.w.hook!(); });
  assert.equal(((await a.glue.start('bob')) as any).ok, true, 'a start after the hook is a fresh session');
  assert.equal(a.glue.status(), 'open');
});

test('GL5 firing the hook wipes the nonce of the starter that was open (the buffer the random source gave)', async () => {
  const a = phone(KA, KB, [0xa0]);
  const buf = a.w.nonces[0];
  await a.glue.start('bob');
  assert.equal(zeros(buf), false);
  a.w.hook!();
  assert.equal(zeros(buf), true);
});

test('GL6 a store write that fails is reported as not saved, with no detail, and the session is spent: the person starts again', async () => {
  const { a, b, codeOf } = await pair();
  a.w.failWrite = true;
  const r = await a.glue.enter('bob', codeOf(b, 'alice'));
  assert.deepEqual(r, { kind: 'not-saved' });
  assert.doesNotMatch(JSON.stringify(r), /secret-detail/);
  assert.deepEqual(a.w.confirmed, []);
  assert.deepEqual(await a.glue.enter('bob', codeOf(b, 'alice')), { kind: 'closed' });
});

test('GL7 unreadable keys fail closed: no session starts, and an open one ends when the keys cannot be read at the entry', async () => {
  const bad: Array<[string, (w: ReturnType<typeof phone>['w']) => void]> = [
    ['own missing', (w) => { w.own = undefined; }], ['held missing', (w) => { w.held = undefined; }],
    ['held not base64', (w) => { w.held = { publicKey: 'not a key', generation: KB.generation }; }],
    ['held 31 bytes', (w) => { w.held = { publicKey: Buffer.from(new Uint8Array(31).fill(1)).toString('base64'), generation: KB.generation }; }],
    ['held not canonical', (w) => { w.held = { publicKey: `${'A'.repeat(42)}B=`, generation: KB.generation }; }],
    ['held url-safe alphabet', (w) => { w.held = { publicKey: b64(0xfb).replace(/[+/]/g, '-'), generation: KB.generation }; }],
    ['own not a string', (w) => { w.own = { publicKey: 42 as any, generation: KA.generation }; }],
    ['held generation a string', (w) => { w.held = { publicKey: KB.publicKey, generation: '5' as any }; }],
    ['held generation NaN', (w) => { w.held = { publicKey: KB.publicKey, generation: NaN }; }],
    ['held generation not whole', (w) => { w.held = { publicKey: KB.publicKey, generation: 1.5 }; }],
    ['own generation infinite', (w) => { w.own = { publicKey: KA.publicKey, generation: Infinity }; }],
  ];
  for (const [what, spoil] of bad) {
    const p = phone(KA, KB);
    spoil(p.w);
    const r = await p.glue.start('bob') as any;
    assert.deepEqual(r, { ok: false, reason: 'keys-unreadable' }, what);
    assert.equal(p.glue.status(), 'none', what);
    const q = phone(KB, KA);
    spoil(q.w);
    assert.deepEqual(await q.glue.joinFromTyped('alice', 'AAAAA AAAAA AAAAA AAAAA AAAAA A'), { ok: false, reason: 'keys-unreadable' }, what);
  }
  const { a, b, codeOf } = await pair();
  const good = codeOf(b, 'alice');
  a.w.held = undefined;
  assert.deepEqual(await a.glue.enter('bob', good), { kind: 'keys-unreadable' });
  assert.notEqual(a.glue.status(), 'open');
  assert.deepEqual(a.w.confirmed, []);
  assert.equal(((await phone(KA, { ...KB, generation: 0 }).glue.start('bob')) as any).ok, false, 'a generation of zero is refused');
});

test('GL8 an entry for another contact takes no lock, reads nothing and costs no try', async () => {
  const { a, b, codeOf } = await pair();
  a.w.events.length = 0;
  assert.deepEqual(await a.glue.enter('carol', codeOf(b, 'alice')), { kind: 'wrong-contact' });
  assert.deepEqual(await a.glue.enter('', codeOf(b, 'alice')), { kind: 'wrong-contact' });
  assert.deepEqual(a.w.events, []);
  assert.deepEqual(a.glue.ownCode('carol'), { ok: false, reason: 'wrong-contact' });
  assert.equal(((await a.glue.enter('bob', codeOf(b, 'alice'))) as any).kind, 'confirmed');
});

test('GL9 a second session drops the first: its nonce is wiped and only the new one can be entered', async () => {
  const a = phone(KA, KB, [0xa0, 0xb0]);
  const first = a.w.nonces[0], second = a.w.nonces[1];
  await a.glue.start('bob');
  await a.glue.start('dave');
  assert.equal(zeros(first), true);
  assert.equal(zeros(second), false);
  assert.deepEqual(await a.glue.enter('bob', '123456'), { kind: 'wrong-contact' });
  assert.equal(((await a.glue.enter('dave', '123456')) as any).kind, 'mismatch');
});

test('GL10 a lock that cannot be taken is busy: nothing is read, nothing is spent, and the same entry works when the lock comes back', async () => {
  const { a, b, codeOf } = await pair();
  const good = codeOf(b, 'alice');
  a.w.events.length = 0;
  a.w.lockFails = true;
  assert.deepEqual(await a.glue.enter('bob', good), { kind: 'busy' });
  assert.deepEqual(a.w.events, []);
  assert.equal(a.glue.status(), 'open');
  a.w.lockFails = false;
  assert.equal(((await a.glue.enter('bob', good)) as any).kind, 'confirmed');
});

test('GL11 two entries at once: one confirms and writes once, the other finds the session spent', async () => {
  const { a, b, codeOf } = await pair();
  const good = codeOf(b, 'alice');
  const r = await Promise.all([a.glue.enter('bob', good), a.glue.enter('bob', good)]);
  assert.deepEqual(r.map((x: any) => x.kind).sort(), ['closed', 'confirmed']);
  assert.equal(a.w.confirmed.length, 1);
});

test('GL12 the hook firing while the keys are being read ends the entry: closed, nothing written', async () => {
  const { a, b, codeOf } = await pair();
  const good = codeOf(b, 'alice');
  a.w.onReadOwn = () => a.w.hook!();
  const r = await a.glue.enter('bob', good) as any;
  assert.notEqual(r.kind, 'confirmed');
  assert.deepEqual(a.w.confirmed, []);
});

test('GL13 a reflected key is refused with its fixed reason, and a whole session writes nothing to the console and no failure carries a key or a code', async () => {
  const calls: unknown[][] = [];
  const names = ['log', 'info', 'warn', 'error', 'debug', 'trace'] as const;
  const saved = names.map((n) => (console as any)[n]);
  names.forEach((n) => { (console as any)[n] = (...x: unknown[]) => { calls.push([n, ...x]); }; });
  try {
    assert.deepEqual(await phone(KA, KA).glue.start('bob'), { ok: false, reason: 'reflected' });
    const { a, b, codeOf } = await pair();
    a.w.failWrite = true;
    await a.glue.enter('bob', '000000'); await a.glue.enter('carol', '1'); await a.glue.enter('bob', codeOf(b, 'alice'));
    a.w.hook!();
    const bad = phone(KA, KB); bad.w.own = undefined; await bad.glue.start('bob');
  } finally { names.forEach((n, i) => { (console as any)[n] = saved[i]; }); }
  assert.deepEqual(calls, []);
});

test('GL14 a lock or a switch that arrives while the keys are being read ends the attempt: no session is installed after it, no nonce is drawn', async () => {
  for (const how of ['start', 'scan', 'typed'] as const) {
    const a = phone(KA, KB, [0xa0]);
    const b = phone(KB, KA, [0xb0]);
    const s = await b.glue.start('alice') as any;   // a real QR and its text to join with
    let release!: () => void;
    a.w.gates.push(new Promise<void>((r) => { release = r; }));
    const drawnBefore = a.w.nonces.length;
    const pending = how === 'start' ? a.glue.start('bob') : how === 'scan' ? a.glue.joinFromScan('bob', s.shown.qr) : a.glue.joinFromTyped('bob', s.shown.text);
    a.w.hook!();   // the app locks, or another account becomes active, while the read is in flight
    release();
    assert.deepEqual(await pending, { ok: false, reason: 'interrupted' }, how);
    assert.equal(a.glue.status(), 'none', how);
    assert.deepEqual(a.glue.ownCode('bob'), { ok: false, reason: 'no-session' }, how);
    assert.equal(a.w.nonces.length, drawnBefore, `${how}: nothing was drawn`);
  }
});

test('GL15 two starts that overlap: only the later one is installed, and the earlier one is told it was interrupted', async () => {
  const a = phone(KA, KB, [0xa0, 0xb0]);
  let release!: () => void;
  a.w.gates.push(new Promise<void>((r) => { release = r; }));
  const first = a.glue.start('bob');
  const second = await a.glue.start('dave') as any;
  assert.equal(second.ok, true);
  release();
  assert.deepEqual(await first, { ok: false, reason: 'interrupted' });
  assert.equal(a.glue.status(), 'open', 'the later session is still the current one');
  assert.deepEqual(a.glue.ownCode('bob'), { ok: false, reason: 'wrong-contact' });
  assert.equal((a.glue.ownCode('dave') as any).ok, true);
  assert.equal(a.w.nonces.length, 1, 'only one nonce was drawn: the interrupted start drew none');
});
