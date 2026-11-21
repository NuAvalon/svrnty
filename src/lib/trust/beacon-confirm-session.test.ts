/* eslint-disable @typescript-eslint/no-explicit-any -- deliberately wrong inputs */
// src/lib/trust/beacon-confirm-session.test.ts: the session around the code two phones compare: where the session nonce comes from, how long it lives, how many tries it allows,
// which contact it belongs to, and when it is gone. Pure: no store, no network; the clock and the random source are injected.
// Run: npx tsx --test src/lib/trust/beacon-confirm-session.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { confirmCode, NONCE_BYTES, type ConfirmRole, type KeyView, type SessionKeys } from './beacon-confirm-code';
import { startConfirmSession, joinConfirmFromScan, joinConfirmFromTyped, SESSION_MS, MAX_ATTEMPTS, type ConfirmSession } from './beacon-confirm-session';
import { parseInviteUrl } from '../invite/parseInviteUrl';

const bytes = (n: number, fill: number): Uint8Array => new Uint8Array(n).fill(fill);
const A: KeyView = { pub: bytes(32, 0x11), gen: 1_800_000_001 };   // the key phone A holds for itself
const B: KeyView = { pub: bytes(32, 0x22), gen: 1_800_000_002 };   // the key phone B holds for itself
const KEYS_A: SessionKeys = { own: A, held: B };                    // phone A: its own key, and the key it holds for B
const KEYS_B: SessionKeys = { own: B, held: A };
const NONCE = Uint8Array.from({ length: NONCE_BYTES }, (_, i) => 0xa0 + i);
const T0 = 1_900_000_000_000;
const clock = (t: { v: number }) => () => t.v;
const oracle = (k: SessionKeys, role: ConfirmRole, nonce = NONCE): string => {
  const r = confirmCode(k.own, k.held, nonce, role);
  assert.equal(r.ok, true, JSON.stringify(r));
  return (r as { ok: true; code: string }).code;
};
const other = (c: string): string => (c === '000000' ? '000001' : '000000');
const fixedRandom = (b: Uint8Array = NONCE) => (n: number): Uint8Array => { assert.equal(n, NONCE_BYTES); return b; };

/** A starter on phone A for contact 'bob', and the scanner on phone B for contact 'alice', joined by the QR the starter showed. */
function pair(t = { v: T0 }) {
  const nonce = Uint8Array.from(NONCE);   // the module owns and may wipe this buffer
  const s = startConfirmSession('bob', KEYS_A, { now: clock(t), random: fixedRandom(nonce) });
  assert.equal(s.ok, true, JSON.stringify(s));
  const start = s as Extract<typeof s, { ok: true }>;
  const j = joinConfirmFromScan('alice', KEYS_B, start.shown.qr, { now: clock(t) });
  assert.equal(j.ok, true, JSON.stringify(j));
  return { t, nonce, a: start.session, b: (j as { ok: true; session: ConfirmSession }).session, shown: start.shown };
}
const own = (s: ConfirmSession, who: string): string => {
  const r = s.ownCode(who);
  assert.equal(r.ok, true, JSON.stringify(r));
  return (r as { ok: true; code: string }).code;
};

// ---------- both phones, one session nonce ----------
test('SX1 the two phones show DIFFERENT codes, each the code the other must be given: the starter\'s code on A and the scanner\'s on B, joined by the QR, and again joined by the typed text', () => {
  const { a, b, shown } = pair();
  assert.equal(own(a, 'bob'), oracle(KEYS_A, 'starter'));
  assert.equal(own(b, 'alice'), oracle(KEYS_B, 'scanner'));
  assert.notEqual(own(a, 'bob'), own(b, 'alice'), 'the code on one screen is not the code on the other');
  const typed = joinConfirmFromTyped('alice', KEYS_B, shown.text, { now: () => T0 });
  assert.equal(typed.ok, true, JSON.stringify(typed));
  assert.equal(own((typed as { ok: true; session: ConfirmSession }).session, 'alice'), oracle(KEYS_B, 'scanner'));
  assert.equal(a.role, 'starter');
  assert.equal(b.role, 'scanner');
});

test('SX2 a key held wrongly on ONE side gives different codes, so the entry misses and nothing confirms', () => {
  const t = { v: T0 };
  const s = startConfirmSession('bob', KEYS_A, { now: clock(t), random: fixedRandom(Uint8Array.from(NONCE)) }) as any;
  const stale: SessionKeys = { own: B, held: { pub: bytes(32, 0x77), gen: A.gen } };   // B holds a different key for A
  const j = joinConfirmFromScan('alice', stale, s.shown.qr, { now: clock(t) }) as any;
  assert.notEqual(own(j.session, 'alice'), oracle(KEYS_A, 'scanner'), 'B shows a scanner code over a stale key: it is not the code A expects');
  const r = s.session.enter('bob', own(j.session, 'alice'), KEYS_A);
  assert.equal(r.kind, 'mismatch');
});

test('SX3 a match confirms the generation of the key that was compared, and the entry comes from the code alone', () => {
  const { a, b } = pair();
  const ra = a.enter('bob', own(b, 'alice'), KEYS_A);
  assert.deepEqual(ra, { kind: 'confirm', generation: B.gen });
  const { a: a2, b: b2 } = pair();
  const rb = b2.enter('alice', own(a2, 'bob'), KEYS_B);
  assert.deepEqual(rb, { kind: 'confirm', generation: A.gen });
  for (const typed of [409689, null, undefined, {}, [], true, '409689 ', ' 409689', '40968', '4096890', 'abcdef', '', '４０９６８９']) {
    const { a: x, b: y } = pair();
    const r = x.enter('bob', typed as any, KEYS_A);
    assert.notEqual(r.kind, 'confirm', JSON.stringify(typed));
    assert.equal(y.status(), 'open');
  }
});

// ---------- tries ----------
test('SX4 three tries: two misses leave it open, the third miss ends it, a fourth is refused; a match on the third still confirms', () => {
  assert.equal(MAX_ATTEMPTS, 3);
  const { a, b } = pair();
  const good = own(b, 'alice'), bad = other(good);
  assert.deepEqual(a.enter('bob', bad, KEYS_A), { kind: 'mismatch', attemptsLeft: 2 });
  assert.deepEqual(a.enter('bob', bad, KEYS_A), { kind: 'mismatch', attemptsLeft: 1 });
  assert.deepEqual(a.enter('bob', bad, KEYS_A), { kind: 'ended' });
  assert.equal(a.status(), 'ended');
  assert.deepEqual(a.enter('bob', good, KEYS_A), { kind: 'closed' });   // ONE ABOVE the limit: even the right code is refused
  const { a: a2, b: b2 } = pair();
  const g2 = own(b2, 'alice');
  a2.enter('bob', other(g2), KEYS_A); a2.enter('bob', other(g2), KEYS_A);
  assert.deepEqual(a2.enter('bob', g2, KEYS_A), { kind: 'confirm', generation: B.gen });   // AT the limit: the third try may match
});

test('SX5 an entry that is not six digits is not a try: it is named, it costs nothing, and the tries are all still there', () => {
  const { a, b } = pair();
  for (const typed of ['12345', '1234567', 'abcdef', '', null, undefined, 123456]) assert.deepEqual(a.enter('bob', typed as any, KEYS_A), { kind: 'malformed' }, JSON.stringify(typed));
  assert.deepEqual(a.enter('bob', other(own(b, 'alice')), KEYS_A), { kind: 'mismatch', attemptsLeft: 2 });
});

// ---------- time ----------
test('SX6 it lives for two minutes: one tick before the end it works, AT the end it is expired for good', () => {
  assert.equal(SESSION_MS, 120_000);
  const { t, a, b } = pair();
  const good = own(b, 'alice');   // read before the clock moves: the other phone's session expires on the same clock
  t.v = T0 + SESSION_MS - 1;
  assert.equal(a.status(), 'open');
  assert.equal(a.ownCode('bob').ok, true);
  t.v = T0 + SESSION_MS;
  assert.equal(a.status(), 'expired');
  assert.deepEqual(a.enter('bob', good, KEYS_A), { kind: 'expired' });
  assert.deepEqual(a.ownCode('bob'), { ok: false, reason: 'closed' });
  t.v = T0;   // a clock that moves back does not bring it back
  assert.equal(a.status(), 'expired');
  const j = pair({ v: T0 });
  j.t.v = T0 + 10 * SESSION_MS;
  assert.deepEqual(j.b.enter('alice', '000000', KEYS_B), { kind: 'expired' });
});

// ---------- one use ----------
test('SX7 the first match uses it up, even when the keys moved: nothing is confirmed twice', () => {
  const { a, b } = pair();
  const good = own(b, 'alice');
  assert.equal(a.enter('bob', good, KEYS_A).kind, 'confirm');
  assert.equal(a.status(), 'confirmed');
  assert.deepEqual(a.enter('bob', good, KEYS_A), { kind: 'closed' });
  assert.deepEqual(a.ownCode('bob'), { ok: false, reason: 'closed' });
  for (const [moved, why] of [[{ own: { ...A, gen: A.gen + 1 }, held: B }, 'own-changed'], [{ own: A, held: { ...B, gen: B.gen + 1 } }, 'held-changed'], [{ own: A, held: { pub: bytes(32, 0x33), gen: B.gen } }, 'held-changed']] as const) {
    const p = pair();
    assert.deepEqual(p.a.enter('bob', own(p.b, 'alice'), moved as SessionKeys), { kind: 'refused', reason: why });
    assert.equal(p.a.status(), 'ended');
    assert.deepEqual(p.a.enter('bob', own(p.b, 'alice'), KEYS_A), { kind: 'closed' });
  }
});

// ---------- the contact ----------
test('SX8 the session belongs to one contact: any other contact is refused, no try is spent, and the right one still works', () => {
  const { a, b } = pair();
  assert.deepEqual(a.ownCode('carol'), { ok: false, reason: 'wrong-contact' });
  assert.deepEqual(a.enter('carol', own(b, 'alice'), KEYS_A), { kind: 'wrong-contact' });
  assert.deepEqual(a.enter('', own(b, 'alice'), KEYS_A), { kind: 'wrong-contact' });
  assert.deepEqual(a.enter(undefined as any, own(b, 'alice'), KEYS_A), { kind: 'wrong-contact' });
  assert.deepEqual(a.enter('bob', other(own(b, 'alice')), KEYS_A), { kind: 'mismatch', attemptsLeft: 2 });   // the refused calls cost nothing
  assert.deepEqual(b.enter('bob', own(a, 'bob'), KEYS_B), { kind: 'wrong-contact' });                       // the scanner side too: it is pinned to 'alice'
  for (const bad of ['', null, undefined, 7, {}]) {
    assert.deepEqual(startConfirmSession(bad as any, KEYS_A, { now: () => T0, random: fixedRandom(Uint8Array.from(NONCE)) }), { ok: false, reason: 'invalid' });
    assert.deepEqual(joinConfirmFromTyped(bad as any, KEYS_B, 'AAAAA AAAAA AAAAA AAAAA AAAAA A', { now: () => T0 }), { ok: false, reason: 'invalid' });
  }
});

// ---------- the end ----------
test('SX9 dropping it (a lock, an identity switch, leaving the screen) ends it for good, wipes the nonce, and may be done twice', () => {
  const { a, b, nonce } = pair();
  assert.notDeepEqual(Array.from(nonce), new Array(NONCE_BYTES).fill(0));
  a.drop();
  assert.equal(a.status(), 'dropped');
  assert.deepEqual(a.enter('bob', own(b, 'alice'), KEYS_A), { kind: 'closed' });
  assert.deepEqual(a.ownCode('bob'), { ok: false, reason: 'closed' });
  assert.deepEqual(Array.from(nonce), new Array(NONCE_BYTES).fill(0), 'the starter\'s session nonce is wiped when it is dropped');
  assert.doesNotThrow(() => { a.drop(); a.drop(); });
  b.drop(); assert.equal(b.status(), 'dropped');
});

test('SX10 the session nonce is wiped at EVERY end: the first match, the third miss and the expiry as well as a drop', () => {
  const wiped = (n: Uint8Array) => Array.from(n).every((x) => x === 0);
  { const p = pair(); p.a.enter('bob', own(p.b, 'alice'), KEYS_A); assert.equal(wiped(p.nonce), true, 'after a match'); }
  { const p = pair(); for (let i = 0; i < 3; i++) p.a.enter('bob', other(own(p.b, 'alice')), KEYS_A); assert.equal(wiped(p.nonce), true, 'after the third miss'); }
  { const p = pair(); p.t.v = T0 + SESSION_MS; p.a.status(); assert.equal(wiped(p.nonce), true, 'at expiry'); }
  { const p = pair(); p.a.enter('bob', '12345', KEYS_A); assert.equal(wiped(p.nonce), false, 'a malformed entry ends nothing'); }
});

// ---------- where the nonce comes from ----------
test('SX11 the starter refuses without a good key pair or a good random source, with a fixed reason and no detail', () => {
  const ok = { now: () => T0, random: fixedRandom(Uint8Array.from(NONCE)) };
  assert.deepEqual(startConfirmSession('bob', { own: { pub: new Uint8Array(0), gen: 1 }, held: B }, ok), { ok: false, reason: 'own-key' });
  assert.deepEqual(startConfirmSession('bob', { own: A, held: { pub: new Uint8Array(0), gen: 1 } }, ok), { ok: false, reason: 'held-key' });
  assert.deepEqual(startConfirmSession('bob', { own: A, held: A }, ok), { ok: false, reason: 'reflected' });
  assert.deepEqual(startConfirmSession('bob', null as any, ok), { ok: false, reason: 'invalid' });
  for (const random of [() => { throw new Error('secret-nonce-detail'); }, () => new Uint8Array(NONCE_BYTES), () => new Uint8Array(15).fill(7), () => new Uint8Array(17).fill(7), () => null as any]) {
    const r = startConfirmSession('bob', KEYS_A, { now: () => T0, random });
    assert.deepEqual(r, { ok: false, reason: 'no-random' });
    assert.doesNotMatch(JSON.stringify(r), /secret-nonce-detail/);
  }
  const used: number[] = [];
  startConfirmSession('bob', KEYS_A, { now: () => T0, random: (n) => { used.push(n); return Uint8Array.from(NONCE); } });
  assert.deepEqual(used, [NONCE_BYTES], 'exactly one draw of exactly sixteen bytes');
});

test('SX12 with the default random source two sessions get different nonces, and the nonce is not the clock', () => {
  const s1 = startConfirmSession('bob', KEYS_A) as any, s2 = startConfirmSession('bob', KEYS_A) as any;
  assert.equal(s1.ok && s2.ok, true);
  assert.notEqual(s1.shown.qr, s2.shown.qr);
  assert.match(s1.shown.qr, /^svrnty-confirm:1:[A-Z2-7]{26}$/);
  assert.match(s1.shown.text, /^[A-Z2-7]{5}( [A-Z2-7]{5}){4} [A-Z2-7]$/);
  assert.equal(s1.shown.text.replace(/ /g, ''), s1.shown.qr.slice('svrnty-confirm:1:'.length));
  s1.session.drop(); s2.session.drop();
});

// ---------- the two ways in ----------
test('SX13 the QR form: exactly the confirm prefix, version 1, and 26 base32 characters whose last two bits are zero; anything else is refused with a fixed reason', () => {
  const t = { v: T0 };
  const s = startConfirmSession('bob', KEYS_A, { now: clock(t), random: fixedRandom(Uint8Array.from(NONCE)) }) as any;
  const body = s.shown.qr.slice('svrnty-confirm:1:'.length);
  const ok = (p: unknown) => joinConfirmFromScan('alice', KEYS_B, p, { now: clock(t) });
  assert.equal(ok(s.shown.qr).ok, true);
  const last = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const nonzeroTail = body.slice(0, 25) + last[(last.indexOf(body[25]) + 1) % 32];   // flips a low bit of the last character
  for (const bad of [
    `svrnty-confirm:2:${body}`, `svrnty-confirm:1:${body}A`, `svrnty-confirm:1:${body.slice(0, 25)}`, `svrnty-confirm:1:${body.toLowerCase()}`, `svrnty-confirm:1:${body.slice(0, 25)}1`,
    `svrnty-confirm:1: ${body}`, `svrnty-confirm:1:${body} `, `SVRNTY-CONFIRM:1:${body}`, `svrnty-confirm:1:${nonzeroTail}`, body, `x${s.shown.qr}`, `${s.shown.qr}\n`, '', 'svrnty-confirm:1:', null, undefined, 42, {}, [], true,
    'https://svrnty.is/c/AbC-_9#keymaterial', 'svrnty-invite:1:abc',
  ]) assert.deepEqual(ok(bad as any), { ok: false, reason: 'not-confirm-qr' }, JSON.stringify(bad));
  s.session.drop();
});

test('SX14 the typed form: the characters read off the other screen, in any case and with spaces or hyphens, and nothing looser', () => {
  const t = { v: T0 };
  const s = startConfirmSession('bob', KEYS_A, { now: clock(t), random: fixedRandom(Uint8Array.from(NONCE)) }) as any;
  const flat: string = s.shown.text.replace(/ /g, '');
  const ok = (p: unknown) => joinConfirmFromTyped('alice', KEYS_B, p, { now: clock(t) });
  for (const good of [s.shown.text, flat, flat.toLowerCase(), s.shown.text.replace(/ /g, '-'), ` ${s.shown.text} `, flat.match(/.{1,4}/g)!.join(' ')]) assert.equal(ok(good).ok, true, good);
  assert.deepEqual(ok(flat.slice(0, 25)), { ok: false, reason: 'short' });
  assert.deepEqual(ok(''), { ok: false, reason: 'short' });
  for (const bad of [flat + 'A', flat.slice(0, 25) + '1', flat.slice(0, 25) + '8', flat.slice(0, 20) + '!' + flat.slice(21), `svrnty-confirm:1:${flat}`, null, undefined, 42, {}, [], true]) assert.deepEqual(ok(bad as any), { ok: false, reason: 'malformed' }, JSON.stringify(bad));
  const last = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  assert.deepEqual(ok(flat.slice(0, 25) + last[(last.indexOf(flat[25]) + 1) % 32]), { ok: false, reason: 'malformed' }, 'a non-zero final bit is not a nonce this module ever shows');
  s.session.drop();
});

test('SX15 the scanner refuses without a good key pair, and an invite is never taken for a confirm', () => {
  const t = { v: T0 };
  const s = startConfirmSession('bob', KEYS_A, { now: clock(t), random: fixedRandom(Uint8Array.from(NONCE)) }) as any;
  assert.deepEqual(joinConfirmFromScan('alice', { own: { pub: new Uint8Array(0), gen: 1 }, held: A }, s.shown.qr, { now: clock(t) }), { ok: false, reason: 'own-key' });
  assert.deepEqual(joinConfirmFromScan('alice', { own: B, held: { pub: new Uint8Array(0), gen: 1 } }, s.shown.qr, { now: clock(t) }), { ok: false, reason: 'held-key' });
  assert.deepEqual(joinConfirmFromScan('alice', { own: B, held: B }, s.shown.qr, { now: clock(t) }), { ok: false, reason: 'reflected' });
  assert.deepEqual(joinConfirmFromScan('alice', null as any, s.shown.qr, { now: clock(t) }), { ok: false, reason: 'invalid' });
  assert.deepEqual(joinConfirmFromScan('alice', KEYS_B, 'https://svrnty.is/c/AbC-_9#keymaterial', { now: clock(t) }), { ok: false, reason: 'not-confirm-qr' });
  assert.equal(parseInviteUrl('https://svrnty.is/c/AbC-_9#keymaterial') !== null, true, 'the control: that really is a valid invite');
  assert.equal(parseInviteUrl(s.shown.qr), null, 'and the invite path refuses the confirm QR');
  s.session.drop();
});

// ---------- nothing leaks ----------
test('SX16 a whole session writes nothing to the console and no failure carries the nonce or a code', () => {
  const calls: unknown[][] = [];
  const names = ['log', 'info', 'warn', 'error', 'debug', 'trace'] as const;
  const saved = names.map((n) => (console as any)[n]);
  names.forEach((n) => { (console as any)[n] = (...a: unknown[]) => { calls.push([n, ...a]); }; });
  try {
    const { a, b, shown } = pair();
    a.ownCode('bob'); b.ownCode('alice'); a.ownCode('carol'); a.enter('bob', '12345', KEYS_A); a.enter('bob', other(own(b, 'alice')), KEYS_A); a.enter('carol', '000000', KEYS_A); a.enter('bob', own(b, 'alice'), KEYS_A); b.drop();
    joinConfirmFromScan('alice', KEYS_B, 'garbage'); joinConfirmFromTyped('alice', KEYS_B, 'garbage'); startConfirmSession('bob', KEYS_A, { random: () => { throw new Error(shown.text); } });
  } finally { names.forEach((n, i) => { (console as any)[n] = saved[i]; }); }
  assert.deepEqual(calls, []);
});

test('SX17 the session object has exactly its methods: no nonce, no code, no keys on it, in its own properties or in its JSON', () => {
  const { a, b, shown } = pair();
  for (const s of [a, b]) {
    assert.deepEqual(Object.getOwnPropertyNames(s).sort(), ['drop', 'enter', 'ownCode', 'role', 'status']);
    assert.deepEqual(Object.getOwnPropertySymbols(s), []);
    assert.equal(Object.getPrototypeOf(s), Object.prototype);
    const dump = JSON.stringify(s) + JSON.stringify(Object.entries(s).map(([k, v]) => (typeof v === 'function' ? k : v)));
    assert.doesNotMatch(dump, new RegExp(`${shown.text.replace(/ /g, '')}|${own(a, 'bob')}|${Buffer.from(NONCE).toString('hex')}`, 'i'));
    for (const [k, d] of Object.entries(Object.getOwnPropertyDescriptors(s))) assert.equal('get' in d, false, `${k} is a getter`);
  }
});

// ---------- a clock that fails ----------
test('SX18 a clock that fails or gives no number ends a session that is open, and starts none: it never leaves one open for good', () => {
  const badClocks: Array<[string, () => number]> = [['throws', () => { throw new Error('no clock'); }], ['NaN', () => NaN], ['Infinity', () => Infinity], ['not a number', () => 'soon' as any]];
  for (const [name, bad] of badClocks) {
    const t = { v: T0 };
    let failing = false;
    const now = () => (failing ? bad() : t.v);
    const s = startConfirmSession('bob', KEYS_A, { now, random: fixedRandom(Uint8Array.from(NONCE)) }) as any;
    assert.equal(s.ok, true, name);
    const j = joinConfirmFromScan('alice', KEYS_B, s.shown.qr, { now }) as any;
    assert.equal(j.ok, true, name);
    const good = own(j.session, 'alice');
    failing = true;
    assert.equal(s.session.status(), 'expired', `${name}: status`);
    assert.deepEqual(s.session.enter('bob', good, KEYS_A), { kind: 'expired' }, `${name}: enter`);
    assert.deepEqual(s.session.ownCode('bob'), { ok: false, reason: 'closed' }, `${name}: own code`);
    assert.equal(j.session.status(), 'expired', `${name}: scanner`);
    failing = false;   // the clock comes back: the session does not
    assert.equal(s.session.status(), 'expired', `${name}: after the clock is back`);
    // a clock that fails at the start: nothing is started, with a fixed reason
    assert.deepEqual(startConfirmSession('bob', KEYS_A, { now: bad, random: fixedRandom(Uint8Array.from(NONCE)) }), { ok: false, reason: 'invalid' }, `${name}: start`);
    assert.deepEqual(joinConfirmFromScan('alice', KEYS_B, s.shown.qr, { now: bad }), { ok: false, reason: 'invalid' }, `${name}: scan`);
    assert.deepEqual(joinConfirmFromTyped('alice', KEYS_B, s.shown.text, { now: bad }), { ok: false, reason: 'invalid' }, `${name}: typed`);
  }
});

// ---------- keys changed in place ----------
test('SX19 a key changed in place after the start is seen as changed: the session keeps its own copy of both keys', () => {
  for (const [side, expected] of [['held', 'held-changed'], ['own', 'own-changed']] as const) {
    const keys: SessionKeys = { own: { pub: bytes(32, 0x11), gen: A.gen }, held: { pub: bytes(32, 0x22), gen: B.gen } };
    const t = { v: T0 };
    const s = startConfirmSession('bob', keys, { now: clock(t), random: fixedRandom(Uint8Array.from(NONCE)) }) as any;
    const j = joinConfirmFromScan('alice', KEYS_B, s.shown.qr, { now: clock(t) }) as any;
    const good = own(j.session, 'alice');
    keys[side].pub[0] ^= 0xff;   // the caller's own array, changed in place: the same object is passed again as the keys read now
    assert.deepEqual(s.session.enter('bob', good, keys), { kind: 'refused', reason: expected }, side);
    assert.equal(s.session.status(), 'ended', side);
  }
  const keys: SessionKeys = { own: { pub: bytes(32, 0x11), gen: A.gen }, held: { pub: bytes(32, 0x22), gen: B.gen } };
  const t = { v: T0 };
  const s = startConfirmSession('bob', keys, { now: clock(t), random: fixedRandom(Uint8Array.from(NONCE)) }) as any;
  const before = Buffer.from(keys.own.pub).toString('hex') + Buffer.from(keys.held.pub).toString('hex');
  s.session.drop();
  assert.equal(Buffer.from(keys.own.pub).toString('hex') + Buffer.from(keys.held.pub).toString('hex'), before, 'the module never changes the caller\'s keys');
});

// ---------- the wall clock is moved while the session is open ----------
test('SX20 the two minutes are real minutes: a wall clock set back inside them does not stretch them, and one that runs ahead ends it early', () => {
  const w = { v: T0 }, m = { v: 5_000 };   // the wall clock, and a clock that a wall-clock change cannot move
  const open = () => {
    const s = startConfirmSession('bob', KEYS_A, { now: () => w.v, mono: () => m.v, random: fixedRandom(Uint8Array.from(NONCE)) }) as any;
    assert.equal(s.ok, true);
    return s.session as ConfirmSession;
  };
  { // set back by a minute at the one-minute mark: after two real minutes it is expired
    const a = open();
    w.v = T0 + 60_000; m.v = 5_000 + 60_000; assert.equal(a.status(), 'open');
    w.v = T0; assert.equal(a.status(), 'open', 'the step back alone ends nothing');
    w.v = T0 + 60_000; m.v = 5_000 + SESSION_MS - 1; assert.equal(a.status(), 'open', 'one tick before two real minutes');
    m.v = 5_000 + SESSION_MS; assert.equal(a.status(), 'expired', 'AT two real minutes, whatever the wall clock reads');
    w.v = T0; m.v = 5_000; assert.equal(a.status(), 'expired', 'and it stays expired');
  }
  { // the wall clock runs ahead of the real time: expired when IT shows two minutes (a device that slept)
    w.v = T0; m.v = 5_000;
    const a = open();
    w.v = T0 + SESSION_MS - 1; m.v = 5_000 + 1_000; assert.equal(a.status(), 'open');
    w.v = T0 + SESSION_MS; assert.equal(a.status(), 'expired');
  }
  { // the second clock reads LOWER than at the start: that is not time passing, so the session ends
    w.v = T0; m.v = 5_000;
    const a = open();
    m.v = 4_999; assert.equal(a.status(), 'expired');
  }
});

test('SX21 a second clock that fails or gives no number is a failing clock like the first: it starts nothing and ends what is open', () => {
  const bads: Array<[string, () => number]> = [['throws', () => { throw new Error('no clock'); }], ['NaN', () => NaN], ['Infinity', () => Infinity], ['not a number', () => 'soon' as any]];
  for (const [name, bad] of bads) {
    assert.deepEqual(startConfirmSession('bob', KEYS_A, { now: () => T0, mono: bad, random: fixedRandom(Uint8Array.from(NONCE)) }), { ok: false, reason: 'invalid' }, `${name}: start`);
    const s = startConfirmSession('bob', KEYS_A, { now: () => T0, random: fixedRandom(Uint8Array.from(NONCE)) }) as any;
    assert.deepEqual(joinConfirmFromScan('alice', KEYS_B, s.shown.qr, { now: () => T0, mono: bad }), { ok: false, reason: 'invalid' }, `${name}: scan`);
    assert.deepEqual(joinConfirmFromTyped('alice', KEYS_B, s.shown.text, { now: () => T0, mono: bad }), { ok: false, reason: 'invalid' }, `${name}: typed`);
    let failing = false;
    const a = startConfirmSession('bob', KEYS_A, { now: () => T0, mono: () => (failing ? bad() : 1_000), random: fixedRandom(Uint8Array.from(NONCE)) }) as any;
    assert.equal(a.ok, true, name);
    failing = true;
    assert.equal(a.session.status(), 'expired', `${name}: open session`);
    failing = false;
    assert.equal(a.session.status(), 'expired', `${name}: the clock is back, the session is not`);
    s.session.drop();
  }
});

// ---------- the code on your own screen does not count ----------
test('SX22 typing your own shown code is a mismatch and costs a try, on both phones; only the code shown on the OTHER phone confirms', () => {
  for (const [who, phone, other, mine, theirs] of [['starter', 'a', 'b', 'bob', 'alice'], ['scanner', 'b', 'a', 'alice', 'bob']] as const) {
    const p = pair();
    const me = p[phone], you = p[other];
    const shownHere = own(me, mine), shownThere = own(you, theirs);
    assert.notEqual(shownHere, shownThere, who);
    assert.deepEqual(me.enter(mine, shownHere, phone === 'a' ? KEYS_A : KEYS_B), { kind: 'mismatch', attemptsLeft: 2 }, `${who} typing its own code`);
    assert.deepEqual(me.enter(mine, shownHere, phone === 'a' ? KEYS_A : KEYS_B), { kind: 'mismatch', attemptsLeft: 1 }, who);
    assert.deepEqual(me.enter(mine, shownThere, phone === 'a' ? KEYS_A : KEYS_B), { kind: 'confirm', generation: (phone === 'a' ? B : A).gen }, `${who}: the code on the other phone, on the third try`);
  }
  const p = pair();
  for (let i = 0; i < 3; i++) p.a.enter('bob', own(p.a, 'bob'), KEYS_A);
  assert.equal(p.a.status(), 'ended', 'three tries with its own code end the session');
});

// ---------- the code of an ended session is never shown ----------
test('SX23 the FIRST call after the two minutes, even if it is ownCode, finds the session expired: no expired phone shows a live code (the wall clock, and the clock a wall change cannot move)', () => {
  const w = { v: T0 }, m = { v: 5_000 };
  const open = () => {
    const s = startConfirmSession('bob', KEYS_A, { now: () => w.v, mono: () => m.v, random: fixedRandom(Uint8Array.from(NONCE)) }) as any;
    assert.equal(s.ok, true);
    return s.session as ConfirmSession;
  };
  { w.v = T0; m.v = 5_000; const a = open(); assert.equal(a.ownCode('bob').ok, true); w.v = T0 + SESSION_MS; assert.deepEqual(a.ownCode('bob'), { ok: false, reason: 'closed' }, 'wall clock'); }
  { w.v = T0; m.v = 5_000; const a = open(); m.v = 5_000 + SESSION_MS; assert.deepEqual(a.ownCode('bob'), { ok: false, reason: 'closed' }, 'second clock'); }
  { w.v = T0; m.v = 5_000; const a = open(); w.v = T0 + SESSION_MS; assert.deepEqual(a.enter('bob', '000000', KEYS_A), { kind: 'expired' }, 'enter first'); }
});
