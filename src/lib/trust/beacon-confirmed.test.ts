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
const HELD = (g: number | undefined) => async () => g;

test('C7 the port: a confirmed pair is true only at the held generation; absent is false; a failing read, a malformed row and an inherited key are all FALSE', async () => {
  const m = { [P1]: { generation: 3 } };
  assert.equal(await createConfirmedPort(async () => m, HELD(3)).isConfirmed(P1), true);
  assert.equal(await createConfirmedPort(async () => m, HELD(3)).isConfirmed(P2), false);
  assert.equal(await createConfirmedPort(async () => { throw new Error('locked'); }, HELD(3)).isConfirmed(P1), false, 'a read that fails');
  assert.equal(await createConfirmedPort(async () => ({ [P1]: { generation: 'x' } }), HELD(3)).isConfirmed(P1), false, 'a malformed row');
  assert.equal(await createConfirmedPort(async () => null, HELD(3)).isConfirmed(P1), false);
  assert.equal(await createConfirmedPort(async () => ({}), HELD(3)).isConfirmed('toString'), false, 'an inherited property is not a confirmed pair');
});

test('C7b GENERATION-BOUND: the stored generation must EQUAL the held key\'s, at and one either side; an unknown or malformed held generation, or a resolver that throws, is FALSE', async () => {
  const m = { [P1]: { generation: 5 } };
  const ask = (held: unknown) => createConfirmedPort(async () => m, (async () => held) as never).isConfirmed(P1);
  assert.equal(await ask(5), true, 'the same generation');
  assert.equal(await ask(6), false, 'the key was replaced by a higher generation since the confirm');
  assert.equal(await ask(4), false, 'a lower generation is not the confirmed one either');
  for (const bad of [undefined, null, 0, -5, 5.5, NaN, Infinity, '5', 2 ** 60]) assert.equal(await ask(bad), false, `held generation ${String(bad)} is not a positive safe integer`);
  assert.equal(await createConfirmedPort(async () => m, async () => { throw new Error('locked'); }).isConfirmed(P1), false, 'a resolver that throws');
  // the resolver is asked about the pair that was asked about, and only once the row has been found
  const asked: string[] = [];
  await createConfirmedPort(async () => m, async (id) => { asked.push(id); return 5; }).isConfirmed(P1);
  await createConfirmedPort(async () => m, async (id) => { asked.push(id); return 5; }).isConfirmed(P2);
  assert.deepEqual(asked, [P1], 'asked for P1; not asked for a pair with no confirmed row');
});

test('C7c THE NEGATIVE (gate 15): confirmed at N, then the held key is replaced by N+1 -> NOT confirmed (nothing is asked of the wire) until a live confirm records N+1', async () => {
  let map = withConfirmed({}, P1, 5);
  let held = 5;
  const port = createConfirmedPort(async () => map, async () => held);
  assert.equal(await port.isConfirmed(P1), true, 'confirmed at 5 and holding 5');
  held = 6;   // the replace
  assert.equal(await port.isConfirmed(P1), false, 'replaced by 6: the old confirm does not carry over');
  map = withConfirmed(map, P1, 6);   // a live re-confirm at the new generation
  assert.equal(await port.isConfirmed(P1), true, 'confirmed again at 6, holding 6');
  held = 5;   // and a held key that went BACK is not the confirmed one either (the stored entry is monotone upward)
  assert.equal(await port.isConfirmed(P1), false);
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

test('C8 NO SOURCE CONFIRMS A PAIR: only the store names the confirm writer, so no import path, no screen, no ceremony and not the WIRE can confirm (the guard FIRES on a synthetic caller, CONTROL)', () => {
  // src/ only: e2e/helpers/restore-harness.ts holds the ONLY test caller (it seeds a confirmed row to prove the restore's passphrase check opens it); no product file imports it.
  const RE = /\bmarkBeaconPairConfirmed\b/;
  assert.deepEqual(namersOf([{ path: '/x/src/components/JoinerCeremony.tsx', text: 'await markBeaconPairConfirmed(o, f, 3);' }, { path: '/x/src/c.ts', text: '// markBeaconPairConfirmed is for a bound ceremony' }], RE), ['components/JoinerCeremony.tsx']);
  assert.deepEqual(namersOf(SRC, RE), ['lib/identity/client-store.ts']);
});

test('C9 nothing outside the rule\'s own module NAMES the confirm rule yet (not a call, not an alias, not a callback): a ceremony card is not bound to the session, so the confirmed set stays empty (the guard FIRES on a synthetic caller and on an alias, CONTROL)', () => {
  const RE = /\bdecideConfirm\b/;
  assert.deepEqual(namersOf([{ path: '/x/src/components/JoinerCeremony.tsx', text: 'const d = decideConfirm(v, c, "live-ceremony", h, k);' }, { path: '/x/src/components/ContactManagement.tsx', text: 'const f = decideConfirm;' }, { path: '/x/src/c.ts', text: '// decideConfirm is for a bound ceremony' }], RE), ['components/ContactManagement.tsx', 'components/JoinerCeremony.tsx']);
  assert.deepEqual(namersOf(SRC.filter((f) => rel(f.path) !== 'lib/trust/beacon-confirmed.ts'), RE), [], 'no file outside the rule\'s own module names it');
  const wire = SRC.find((f) => rel(f.path) === 'lib/trust/beacon-wire.ts')!;
  assert.doesNotMatch(codeOnly(wire.text), /beacon-confirmed|decideConfirm|markBeaconPairConfirmed/, 'the wire has no write path to the confirmed set');
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

