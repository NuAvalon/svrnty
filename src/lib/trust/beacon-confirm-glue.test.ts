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

// ---------- the same nonce is not joined twice ----------
async function scannerAndQr(seedA = 0xa0) {
  const a = phone(KA, KB, [seedA]);
  const s = await a.glue.start('bob') as any;
  assert.equal(s.ok, true);
  const b = phone(KB, KA, []);
  return { a, b, qr: s.shown.qr as string, text: s.shown.text as string };
}

test('GL16 joining the SAME QR a second time is refused, and it touches nothing: the live session, its code and its tries stay as they were', async () => {
  const { b, qr } = await scannerAndQr();
  assert.deepEqual(await b.glue.joinFromScan('alice', qr), { ok: true });
  const code = (b.glue.ownCode('alice') as any).code;
  assert.equal(((await b.glue.enter('alice', code === '000000' ? '000001' : '000000')) as any).kind, 'mismatch');   // one try spent
  b.w.events.length = 0;
  assert.deepEqual(await b.glue.joinFromScan('alice', qr), { ok: false, reason: 'already-used' });
  assert.equal(b.glue.status(), 'open', 'the live session is untouched');
  assert.equal((b.glue.ownCode('alice') as any).code, code);
  assert.deepEqual(b.w.events, [], 'a refused re-join reads nothing and takes no lock');
  assert.deepEqual(await b.glue.enter('alice', code === '000000' ? '000001' : '000000'), { kind: 'mismatch', attemptsLeft: 1 }, 'the tries were NOT reset by the re-join');
});

test('GL17 the same nonce typed after the scan, or scanned after it was typed, is the same nonce: refused either way (case, spaces and hyphens do not make a new one)', async () => {
  const { b, qr, text } = await scannerAndQr();
  assert.deepEqual(await b.glue.joinFromScan('alice', qr), { ok: true });
  for (const again of [text, text.toLowerCase(), text.replace(/ /g, '-'), text.replace(/ /g, '')]) assert.deepEqual(await b.glue.joinFromTyped('alice', again), { ok: false, reason: 'already-used' }, again);
  const c = await scannerAndQr(0xb0);
  assert.deepEqual(await c.b.glue.joinFromTyped('alice', c.text), { ok: true });
  assert.deepEqual(await c.b.glue.joinFromScan('alice', c.qr), { ok: false, reason: 'already-used' });
});

test('GL18 a fresh nonce is allowed, and a join that FAILED does not use its payload up', async () => {
  const { b, qr } = await scannerAndQr();
  const own = b.w.own;
  b.w.own = undefined;
  assert.deepEqual(await b.glue.joinFromScan('alice', qr), { ok: false, reason: 'keys-unreadable' });
  b.w.own = own;
  assert.deepEqual(await b.glue.joinFromScan('alice', qr), { ok: true }, 'the same QR works once the keys can be read');
  const fresh = await scannerAndQr(0xc0);
  assert.deepEqual(await b.glue.joinFromScan('alice', fresh.qr), { ok: true }, 'a different start gives a different nonce');
});

test('GL19 two joins of the same QR at once, with the first held at its key read: exactly one opens a session and the other is refused as already used (not as interrupted)', async () => {
  const { b, qr } = await scannerAndQr();
  let release!: () => void;
  b.w.gates.push(new Promise<void>((r) => { release = r; }));   // the first join to reach the store waits here
  const p1 = b.glue.joinFromScan('alice', qr), p2 = b.glue.joinFromScan('alice', qr);
  await new Promise((r) => setTimeout(r, 30));   // both have hashed their input: one is in flight at the read, the other has met it
  release();
  const r = await Promise.all([p1, p2]);
  assert.deepEqual(r.map((x: any) => (x.ok ? 'ok' : x.reason)).sort(), ['already-used', 'ok']);
  assert.equal(b.glue.status(), 'open');
});

test('GL20 the memory is per contact and is cleared by a lock or a switch of account, never by an ordinary drop or a new session', async () => {
  const { b, qr } = await scannerAndQr();
  assert.deepEqual(await b.glue.joinFromScan('alice', qr), { ok: true });
  b.glue.drop();
  assert.deepEqual(await b.glue.joinFromScan('alice', qr), { ok: false, reason: 'already-used' }, 'an explicit drop does not forget it');
  const other = await scannerAndQr(0xd0);
  assert.deepEqual(await b.glue.joinFromScan('alice', other.qr), { ok: true }, 'a new session for a fresh nonce does not forget it either');
  assert.deepEqual(await b.glue.joinFromScan('alice', qr), { ok: false, reason: 'already-used' });
  assert.deepEqual(await b.glue.joinFromScan('carol', qr), { ok: true }, 'another contact is its own memory (the session code would differ anyway)');
  b.w.hook!();
  assert.deepEqual(await b.glue.joinFromScan('alice', qr), { ok: true }, 'a lock or a switch of account clears it');
});

test('GL21 a payload that is not a nonce at all is never remembered, and never refused as already used', async () => {
  const { b, qr } = await scannerAndQr();
  for (const junk of ['garbage', '', null, undefined, 42, 'https://example.test/c/AbC#k', qr.slice(0, -1)]) {
    const r = await b.glue.joinFromScan('alice', junk as any) as any;
    assert.equal(r.ok, false);
    assert.notEqual(r.reason, 'already-used', JSON.stringify(junk));
  }
});

test('GL22 a re-join of an EARLIER nonce during another live session is refused and that session is untouched (join A, join B, re-join A)', async () => {
  const first = await scannerAndQr(0xa0);
  const second = await scannerAndQr(0xb0);
  const b = first.b;
  assert.deepEqual(await b.glue.joinFromScan('alice', first.qr), { ok: true });
  assert.deepEqual(await b.glue.joinFromScan('alice', second.qr), { ok: true });
  const code = (b.glue.ownCode('alice') as any).code;
  b.w.events.length = 0;
  assert.deepEqual(await b.glue.joinFromScan('alice', first.qr), { ok: false, reason: 'already-used' });
  assert.equal(b.glue.status(), 'open', 'the live session of the SECOND nonce is untouched');
  assert.equal((b.glue.ownCode('alice') as any).code, code);
  assert.deepEqual(b.w.events, []);
});

test('GL23 the memory is capped per contact: when it is full new joins are refused and an old nonce is NEVER evicted; a lock starts it again', async () => {
  const CAP = 64;
  const a = phone(KA, KB, Array.from({ length: CAP + 1 }, (_, i) => 0x01 + i));
  const b = phone(KB, KA, []);
  const qrs: string[] = [];
  for (let i = 0; i < CAP + 1; i++) { const s = await a.glue.start('bob') as any; assert.equal(s.ok, true, `start ${i}`); qrs.push(s.shown.qr); }
  for (let i = 0; i < CAP; i++) assert.deepEqual(await b.glue.joinFromScan('alice', qrs[i]), { ok: true }, `join ${i}`);
  assert.deepEqual(await b.glue.joinFromScan('alice', qrs[CAP]), { ok: false, reason: 'memory-full' }, 'the 65th is refused as FULL, not as a repeat: starting again would not help it');
  assert.deepEqual(await b.glue.joinFromScan('alice', qrs[0]), { ok: false, reason: 'already-used' }, 'the FIRST is still refused: nothing was evicted');
  assert.deepEqual(await b.glue.joinFromScan('carol', qrs[CAP]), { ok: true }, 'another contact has its own memory');
  b.w.hook!();
  assert.deepEqual(await b.glue.joinFromScan('alice', qrs[CAP]), { ok: true }, 'a lock empties the memory');
});

// The guard keys a join by its OWN reading of the input, separately from the session's parser. It is only sound while the two agree, so this runs both through the glue on the same inputs.
const EXTRA = ['\n', '\r', '\t', ' ', '-', '_', ':', ' ', '​', 'A', 'a', '0', '1', '=', '\0'];
const insertions = (s: string): string[] => EXTRA.flatMap((c) => Array.from({ length: s.length + 1 }, (_, i) => s.slice(0, i) + c + s.slice(i)));

test('GL24 what the session accepts, the guard keys the same: every accepted form of a nonce is remembered as that nonce on both paths, and a form the session refuses remembers nothing', async () => {
  const base = await scannerAndQr();
  const forms = (qr: string, text: string) => ({
    scan: [qr, qr.toLowerCase(), qr + '\n', qr + ' ', ' ' + qr, qr + 'A', 'x' + qr, qr.replace('confirm:1:', 'confirm:1: '), qr.slice(0, -1), ...insertions(qr)],
    typed: [text, text.toLowerCase(), text.replace(/ /g, '-'), text.replace(/ /g, ''), text.replace(/ /g, '--'), text.replace(/ /g, ' - '), ' ' + text + ' ', text + '\n', text.replace(/ /g, '\t'), ...insertions(text)],
  });
  const { scan, typed } = forms(base.qr, base.text);
  let accepted = 0, refused = 0;
  for (const [path, list] of [['scan', scan], ['typed', typed]] as const) {
    for (const v of list) {
      const x = await scannerAndQr();
      const first = await (path === 'scan' ? x.b.glue.joinFromScan('alice', v) : x.b.glue.joinFromTyped('alice', v));
      if (first.ok) {
        accepted++;
        assert.deepEqual(await x.b.glue.joinFromScan('alice', x.qr), { ok: false, reason: 'already-used' }, `${path} ${JSON.stringify(v)} was accepted but is not remembered as the nonce`);
        assert.deepEqual(await x.b.glue.joinFromTyped('alice', x.text), { ok: false, reason: 'already-used' }, `${path} ${JSON.stringify(v)} (typed twin)`);
      } else {
        refused++;
        assert.deepEqual(await x.b.glue.joinFromScan('alice', x.qr), { ok: true }, `${path} ${JSON.stringify(v)} was refused (${(first as any).reason}) but used the nonce up`);
      }
    }
  }
  assert.ok(accepted >= 6 && refused > 300, `${accepted} accepted, ${refused} refused: the variants must exercise both sides`);
});

test('GL25 the session\'s own grammar, through the glue: a QR is accepted only exactly; typed characters in any case with spaces or hyphens between them are accepted; nothing else is', async () => {
  const x = await scannerAndQr();
  const yes = async (path: 'scan' | 'typed', v: string): Promise<boolean> => { const y = await scannerAndQr(); return (path === 'scan' ? await y.b.glue.joinFromScan('alice', v) : await y.b.glue.joinFromTyped('alice', v)).ok; };
  assert.equal(await yes('scan', x.qr), true);
  for (const v of [x.text, x.text.toLowerCase(), x.text.replace(/ /g, '-'), x.text.replace(/ /g, ''), x.text.replace(/ /g, ' - '), ' ' + x.text + '-']) assert.equal(await yes('typed', v), true, JSON.stringify(v));
  for (const v of [x.qr + '\n', ' ' + x.qr, x.qr.toLowerCase(), x.qr + ' ']) assert.equal(await yes('scan', v), false, JSON.stringify(v));
  for (const v of [x.text + '\n', x.text.replace(/ /g, '\t'), x.text.replace(/ /g, '_'), x.text + 'A', x.text.slice(0, -1)]) assert.equal(await yes('typed', v), false, JSON.stringify(v));
});

test('GL26 a typed look-alike of a letter (dotless i, long s) is the session\'s refusal and nothing else, whether or not the real nonce was already joined: the guard and the session read the text the same way', async () => {
  let x: Awaited<ReturnType<typeof scannerAndQr>> | undefined;
  for (let seed = 1; seed < 200 && !x; seed++) { const c = await scannerAndQr(seed); if (c.text.includes('I') && c.text.includes('S')) x = c; }
  assert.ok(x, 'a nonce whose text holds both an I and an S');
  const lookalikes = [x.text.replace('I', '\u0131'), x.text.replace('S', '\u017f'), x.text.replace(/I/g, '\u0131').replace(/S/g, '\u017f')];
  for (const v of lookalikes) assert.deepEqual(await x.b.glue.joinFromTyped('alice', v), { ok: false, reason: 'malformed' }, `before: ${JSON.stringify(v)}`);
  assert.deepEqual(await x.b.glue.joinFromScan('alice', x.qr), { ok: true });
  for (const v of lookalikes) assert.deepEqual(await x.b.glue.joinFromTyped('alice', v), { ok: false, reason: 'malformed' }, `after: ${JSON.stringify(v)}`);
  assert.deepEqual(await x.b.glue.joinFromTyped('alice', x.text), { ok: false, reason: 'already-used' }, 'the real text is still the used nonce');
});

test('GL27 the key covers the WHOLE nonce: nonces that share their first bytes are different joins, and none is refused as a repeat of another', async () => {
  const x = nonce(0x40), y = nonce(0x40), z = nonce(0x40);
  y[NONCE_BYTES - 1] ^= 0xff;   // differs from x only in the last byte
  z[1] ^= 0xff;                 // differs from x only in the second byte
  const a = phone(KA, KB, []); a.w.nonces = [x, y, z];
  const b = phone(KB, KA, []);
  const qrs: string[] = [];
  for (let i = 0; i < 3; i++) { const s = await a.glue.start('bob') as any; assert.equal(s.ok, true, `start ${i}`); qrs.push(s.shown.qr); }
  assert.notEqual(qrs[0], qrs[1]); assert.notEqual(qrs[0], qrs[2]); assert.notEqual(qrs[1], qrs[2]);
  assert.deepEqual(await b.glue.joinFromScan('alice', qrs[0]), { ok: true });
  assert.deepEqual(await b.glue.joinFromScan('alice', qrs[1]), { ok: true }, 'same first bytes, last byte differs: a new nonce');
  assert.deepEqual(await b.glue.joinFromScan('alice', qrs[2]), { ok: true }, 'same first byte, second byte differs: a new nonce');
  assert.deepEqual(await b.glue.joinFromScan('alice', qrs[0]), { ok: false, reason: 'already-used' }, 'and the first is still a repeat');
});

test('GL28 an input the guard cannot key is the session\'s refusal and nothing else: a full memory and a join already in flight do not change what it reads as', async () => {
  const prefix = (await scannerAndQr()).qr.slice(0, -26);   // the form's prefix, taken from a real QR: the fence lets no other module spell it out
  const garbage: unknown[] = ['not a code', '', prefix, prefix + 'A'.repeat(25), 42, null];
  const ref = phone(KB, KA, []);
  const want: unknown[] = [];
  for (const g of garbage) { want.push(await ref.glue.joinFromScan('alice', g)); want.push(await ref.glue.joinFromTyped('alice', g as string)); }
  for (const w of want as any[]) { assert.equal(w.ok, false); assert.ok(w.reason !== 'already-used' && w.reason !== 'memory-full' && w.reason !== 'interrupted', JSON.stringify(w)); }

  const CAP = 64;
  const a = phone(KA, KB, Array.from({ length: CAP }, (_, i) => 0x01 + i));
  const b = phone(KB, KA, []);
  for (let i = 0; i < CAP; i++) { const s = await a.glue.start('bob') as any; assert.deepEqual(await b.glue.joinFromScan('alice', s.shown.qr), { ok: true }, `join ${i}`); }
  const full: unknown[] = [];
  for (const g of garbage) { full.push(await b.glue.joinFromScan('alice', g)); full.push(await b.glue.joinFromTyped('alice', g as string)); }
  assert.deepEqual(full, want, 'with the memory full, garbage still reads as the session\'s refusal, not as "full"');

  const c = phone(KB, KA, []);
  let release!: () => void;
  c.w.gates.push(new Promise<void>((r) => { release = r; }));
  const first = c.glue.joinFromScan('alice', 'not a code');   // held at its key read
  const second = await c.glue.joinFromScan('alice', 'not a code');
  release();
  assert.deepEqual(second, { ok: false, reason: 'interrupted' }, 'the first call began after this one took its epoch, so this one reads as interrupted: not a repeat, not full, not the session\'s refusal');
  assert.deepEqual(await first, { ok: false, reason: 'not-confirm-qr' }, 'and the call that was held reads as the session\'s own refusal');
});

test('GL29 a QR the session refuses reads as the session\'s refusal whether or not its code was already joined: the guard reads a scan exactly as the session does', async () => {
  const x = await scannerAndQr();
  const forms = [x.qr.toLowerCase(), 'x' + x.qr, ' ' + x.qr, x.qr + 'A', x.qr + '\n', x.qr.replace('confirm:1:', 'confirm:1: '), x.qr.slice(0, -1), x.qr.replace('confirm:1:', 'confirm:2:')];
  const before: any[] = [];
  for (const v of forms) before.push(await x.b.glue.joinFromScan('alice', v));
  for (const r of before) { assert.equal(r.ok, false); assert.ok(r.reason !== 'already-used', JSON.stringify(r)); }
  assert.deepEqual(await x.b.glue.joinFromScan('alice', x.qr), { ok: true });
  for (let i = 0; i < forms.length; i++) assert.deepEqual(await x.b.glue.joinFromScan('alice', forms[i]), before[i], `after: ${JSON.stringify(forms[i])}`);
  assert.deepEqual(await x.b.glue.joinFromScan('alice', x.qr), { ok: false, reason: 'already-used' }, 'the exact QR is still the used nonce');
});
