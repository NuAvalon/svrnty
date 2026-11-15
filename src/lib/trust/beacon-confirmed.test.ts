/* eslint-disable @typescript-eslint/no-explicit-any -- deliberately wrong inputs */
// src/lib/trust/beacon-confirmed.test.ts — #822 (a) S2b-1: which pairs are confirmed, and the one rule that confirms a pair.
// Run: npx tsx --test src/lib/trust/beacon-confirmed.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { decideConfirm, isBeaconConfirmed, withConfirmed, createConfirmedPort, MAX_CONFIRMED, type ConfirmSource } from './beacon-confirmed';
import type { BeaconIntakeVerdict, CardBeacon } from './beacon-contact-key';

const P1 = 'a'.repeat(64), P2 = 'b'.repeat(64);
const KEY_A = 'KEY_A', KEY_B = 'KEY_B';
const card = (key = KEY_A, gen = 5): CardBeacon => ({ beaconKey: { publicKey: key, keyGeneration: gen } });
const held = { beacon_public_key: KEY_A, beacon_key_generation: 5 };

// ---------- the rule ----------
test('C1 EVERY verdict x source: ONLY the live ceremony, and only on add / backfill / an exact keep, confirms; an import NEVER does (the replayed-card case)', () => {
  const verdicts: BeaconIntakeVerdict[] = ['add', 'backfill', 'keep', 'deferred', 'loud', 'none'];
  const sources: ConfirmSource[] = ['live-ceremony', 'import'];
  const confirmed: string[] = [];
  for (const v of verdicts) for (const s of sources) {
    const d = decideConfirm(v, undefined, s, v === 'add' || v === 'backfill' ? undefined : held, card());
    if (d.confirm) confirmed.push(`${s}/${v}`);
  }
  assert.deepEqual(confirmed.sort(), ['live-ceremony/add', 'live-ceremony/backfill', 'live-ceremony/keep']);
});

test('C2 THE REPLAY CASE: a pasted or imported card whose key EQUALS the held key is NOT evidence (it can be an old card from a seized device)', () => {
  const d = decideConfirm('keep', undefined, 'import', held, card(KEY_A, 5));
  assert.deepEqual(d, { confirm: false });
  assert.equal(decideConfirm('keep', undefined, 'live-ceremony', held, card(KEY_A, 5)).confirm, true, 'CONTROL: the same card from a live ceremony DOES confirm');
});

test('C3 a keep that was COUNTED (rollback, held-malformed) or whose key or generation differs from the held one never confirms', () => {
  for (const counted of ['rollback', 'held-malformed', 'conflict']) assert.equal(decideConfirm('keep', counted, 'live-ceremony', held, card()).confirm, false, counted);
  assert.equal(decideConfirm('keep', undefined, 'live-ceremony', held, card(KEY_B, 5)).confirm, false, 'another key');
  assert.equal(decideConfirm('keep', undefined, 'live-ceremony', held, card(KEY_A, 4)).confirm, false, 'another generation');
  assert.equal(decideConfirm('keep', undefined, 'live-ceremony', undefined, card()).confirm, false, 'nothing held');
});

test('C4 a card that carried no (valid) beacon key never confirms, and the generation recorded is the card\'s', () => {
  for (const v of ['add', 'backfill', 'keep'] as BeaconIntakeVerdict[]) assert.equal(decideConfirm(v, undefined, 'live-ceremony', held, { beaconKey: null }).confirm, false, v);
  assert.deepEqual(decideConfirm('backfill', undefined, 'live-ceremony', undefined, card(KEY_B, 9)), { confirm: true, generation: 9 });
});

// ---------- the map ----------
test('C5 isBeaconConfirmed is STRICT: 64-hex pair ids, one positive integer generation, nothing else', () => {
  assert.equal(isBeaconConfirmed({}), true);
  assert.equal(isBeaconConfirmed({ [P1]: { generation: 3 } }), true);
  for (const bad of [null, [], 'x', { short: { generation: 3 } }, { [P1]: { generation: 0 } }, { [P1]: { generation: 1.5 } }, { [P1]: { generation: '3' } }, { [P1]: { generation: NaN } },
    { [P1]: { generation: 3, extra: 1 } }, { [P1]: {} }, { [P1]: null }, { [P1.toUpperCase()]: { generation: 3 } }]) {
    assert.equal(isBeaconConfirmed(bad as any), false, JSON.stringify(bad));
  }
  const big: Record<string, { generation: number }> = {};
  for (let i = 0; i <= MAX_CONFIRMED; i++) big[i.toString(16).padStart(64, '0')] = { generation: 1 };
  assert.equal(isBeaconConfirmed(big), false, 'over the bound');
});

test('C6 withConfirmed: a NEW map, monotone (a lower generation never lowers a held one), strict inputs', () => {
  const a = withConfirmed({}, P1, 3);
  assert.deepEqual(a, { [P1]: { generation: 3 } });
  assert.deepEqual(withConfirmed(a, P1, 2), { [P1]: { generation: 3 } }, 'a lower generation does not lower');
  assert.deepEqual(withConfirmed(a, P1, 7), { [P1]: { generation: 7 } });
  assert.deepEqual(withConfirmed(a, P2, 1), { [P1]: { generation: 3 }, [P2]: { generation: 1 } });
  assert.deepEqual(a, { [P1]: { generation: 3 } }, 'the input is never mutated');
  assert.throws(() => withConfirmed({}, 'nope', 3));
  assert.throws(() => withConfirmed({}, P1, 0));
  assert.throws(() => withConfirmed({}, P1, 1.5));
});

// ---------- the port fails closed ----------
test('C7 the port: a confirmed pair is true; absent is false; a failing read, a malformed row and an inherited key are all FALSE', async () => {
  const m = { [P1]: { generation: 3 } };
  assert.equal(await createConfirmedPort(async () => m).isConfirmed(P1), true);
  assert.equal(await createConfirmedPort(async () => m).isConfirmed(P2), false);
  assert.equal(await createConfirmedPort(async () => { throw new Error('locked'); }).isConfirmed(P1), false, 'a read that fails');
  assert.equal(await createConfirmedPort(async () => ({ [P1]: { generation: 'x' } })).isConfirmed(P1), false, 'a malformed row');
  assert.equal(await createConfirmedPort(async () => null).isConfirmed(P1), false);
  assert.equal(await createConfirmedPort(async () => ({})).isConfirmed('toString'), false, 'an inherited property is not a confirmed pair');
});

// ---------- static pins ----------
function walk(dir: string, out: { path: string; text: string }[] = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) { if (name !== 'node_modules' && name !== '.next') walk(p, out); continue; }
    if (!/\.(ts|tsx)$/.test(name) || /\.test\.(ts|tsx)$/.test(name)) continue;
    out.push({ path: p, text: readFileSync(p, 'utf8') });
  }
  return out;
}
const SRC = walk(join(process.cwd(), 'src'));
const codeOnly = (t: string) => t.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).map((l) => l.replace(/\/\/.*$/, '')).join('\n');
const rel = (p: string) => p.replace(/\\/g, '/').split('/src/').pop();
const namersOf = (files: { path: string; text: string }[], re: RegExp) => files.filter((f) => re.test(codeOnly(f.text))).map((f) => rel(f.path)).sort();

test('C8 only the store and the live ceremony name the confirm writer: an import path, the contact screen and the WIRE have no way to confirm a pair (the guard FIRES on a synthetic caller, CONTROL)', () => {
  const RE = /\bmarkBeaconPairConfirmed\b/;
  assert.deepEqual(namersOf([{ path: '/x/src/components/ContactManagement.tsx', text: 'await markBeaconPairConfirmed(o, f, 3);' }, { path: '/x/src/c.ts', text: '// markBeaconPairConfirmed is for the ceremony' }], RE), ['components/ContactManagement.tsx']);
  assert.deepEqual(namersOf(SRC, RE), ['components/JoinerCeremony.tsx', 'lib/identity/client-store.ts']);
});

test('C9 the only non-test callers of decideConfirm are the live ceremony, and none passes the import source as confirming', () => {
  assert.deepEqual(namersOf(SRC, /\bdecideConfirm\(/), ['components/JoinerCeremony.tsx', 'lib/trust/beacon-confirmed.ts']);
  const joiner = SRC.find((f) => rel(f.path) === 'components/JoinerCeremony.tsx')!;
  assert.match(codeOnly(joiner.text), /decideConfirm\([^)]*'live-ceremony'/);
  assert.doesNotMatch(codeOnly(joiner.text), /decideConfirm\([^)]*'import'/);
});

test('C10 the confirmed row is in NEITHER backup direction: not in the SovereignBackup type, not built by exportAll, not touched by importAll (the guard FIRES on a synthetic body, CONTROL)', () => {
  const store = SRC.find((f) => rel(f.path) === 'lib/identity/client-store.ts')!;
  const code = codeOnly(store.text);
  const slice = (from: string, to: string) => { const a = code.indexOf(from); assert.ok(a >= 0, from); const b = code.indexOf(to, a + from.length); return code.slice(a, b < 0 ? undefined : b); };
  const bodies = {
    type: slice('export interface SovereignBackup', '\n}\n'),
    exportAll: slice('export async function exportAll(', '\nexport '),
    importAll: slice('export async function importAll(', '\nexport '),
  };
  const touches = (t: string) => /confirmed|beacon_confirmed|readBeaconConfirmed|markBeaconPairConfirmed/i.test(t);
  assert.equal(touches('const x = await readBeaconConfirmed(fp);'), true, 'CONTROL: the matcher fires');
  for (const [name, body] of Object.entries(bodies)) { assert.ok(body.length > 50, `found ${name}`); assert.equal(touches(body), false, `${name} must not carry the confirmed pairs`); }
});

test('C11 the ceremony marks a pair ONLY when the decision says confirm, and a failure to mark never stops the ceremony (guarded and swallowed)', () => {
  const joiner = SRC.find((f) => rel(f.path) === 'components/JoinerCeremony.tsx')!;
  const code = codeOnly(joiner.text);
  const at = code.indexOf('markBeaconPairConfirmed(ownerFp');
  assert.ok(at > 0, 'the call exists');
  const before = code.slice(Math.max(0, at - 260), at);
  assert.match(before, /if \(confirmDecision\.confirm && confirmDecision\.generation !== undefined\) \{\s*try \{\s*await $/, 'guarded by the decision, inside a try');
  assert.match(code.slice(at, at + 200), /\}\s*catch \{/, 'a failure to mark is swallowed: the pair stays unconfirmed, nothing is shown');
});
