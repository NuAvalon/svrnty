// src/lib/trust/beacon-wire.test.ts — #822 (a) P1: the wire is one composition; OFF means off on every path; the two unbuilt inputs fail closed.
// Run: npx tsx --test src/lib/trust/beacon-wire.test.ts
// Every "zero requests" result sits next to W2, the control: the same setup, everything on, DOES send. Without it a zero could be a broken rig.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { createBeaconWireWithGate, BeaconWireOff, type BeaconWireDeps } from './beacon-wire';
import { createBeaconLatch, type BeaconKV, type Sealer } from './beacon-ports';
import { createConfirmedPort } from './beacon-confirmed';
import type { SeedStore } from './beacon-secrets';
import type { BeaconSeeds } from '../identity/beacon-seeds';
import { isBeaconSeeds } from '../identity/beacon-seeds';
import { deriveSignals, type Point } from '../crypto/beacon-prover';
import { generateBeaconSecret, beaconPublicKey, checkBeaconPublicKey } from '../crypto/beacon-key';

const EPOCH_MS = 604_800_000;
const E = 2_900;
const MID = E * EPOCH_MS + EPOCH_MS / 2; // mid-week: only the current epoch is live
const OWNER = 'owner-1';
const PAIR = 'pair-1';
const PAIR_ID64 = 'c'.repeat(64);

// ---------- fakes, all counting ----------
function countingKV() {
  const data = new Map<string, string>();
  const n = { gets: 0, swaps: 0, keys: 0 };
  const fail = { swap: false };
  const kv: BeaconKV = {
    async get(k) { n.gets++; return data.get(k); },
    async swap(k, expected, next) {
      n.swaps++;
      if (fail.swap) throw new Error('kv swap failed');
      if (data.get(k) !== expected) return false;
      if (next === undefined) data.delete(k); else data.set(k, next);
      return true;
    },
    async keys(prefix) { n.keys++; return [...data.keys()].filter((k) => k.startsWith(prefix)); },
  };
  return { kv, data, n, fail, total: () => n.gets + n.swaps + n.keys };
}
function fakeSealer(): Sealer {
  return {
    async seal(aad, value) { return Buffer.from(aad + '\u0000' + JSON.stringify(value)).toString('base64'); },
    async open(aad, blob) {
      const txt = Buffer.from(blob, 'base64').toString('utf8');
      const i = txt.indexOf('\u0000');
      if (i < 0 || txt.slice(0, i) !== aad) throw new Error('aad mismatch or malformed');
      return JSON.parse(txt.slice(i + 1));
    },
  };
}
function countingSeeds() {
  const st = { map: {} as BeaconSeeds, reads: 0, updates: 0, resets: 0 };
  const store: SeedStore = {
    async read() { st.reads++; return { ...st.map }; },
    async update(mutate) { st.updates++; const next = mutate({ ...st.map }); assert.ok(isBeaconSeeds(next)); st.map = next; return next; },
    async reset() { st.resets++; st.map = {}; },
  };
  return { st, store };
}
type Scripted = { status?: number; body?: string };
function fakeFetch() {
  const calls: { url: string }[] = [];
  const queue: Scripted[] = [];
  const fetch: BeaconWireDeps['fetch'] = async (url) => {
    calls.push({ url });
    const s = queue.length ? queue.shift()! : { status: 200, body: '{"status":"none"}' };
    return { status: s.status ?? 200, headers: { get: (k: string) => (k.toLowerCase() === 'content-type' ? 'application/json' : null) }, text: async () => s.body ?? '' };
  };
  return { calls, queue, fetch };
}
const ok = (status: string) => ({ status: 200, body: `{"status":"${status}"}` });

/** the real keys: a secret scalar and a valid, different counterpart key */
async function realKeys(): Promise<{ x: bigint; y: Point }> {
  const x = await generateBeaconSecret(), other = await generateBeaconSecret();
  const chk = await checkBeaconPublicKey(await beaconPublicKey(other), await beaconPublicKey(x));
  assert.ok(chk.ok, 'a valid counterpart key');
  return { x, y: (chk as { ok: true; point: Point }).point };
}

async function rig(over: Partial<BeaconWireDeps> = {}, opts: { live?: () => boolean } = {}) {
  const { x, y } = await realKeys();
  const k = countingKV(), seeds = countingSeeds(), f = fakeFetch(), sealer = fakeSealer();
  const spies = { secretX: 0, counterpartY: 0, confirmed: 0, prover: 0 };
  const deps: BeaconWireDeps = {
    kv: k.kv, sealer, owner: OWNER, seeds: seeds.store,
    secretX: async () => { spies.secretX++; return x; },
    counterpartY: async () => { spies.counterpartY++; return y; },
    confirmed: { isConfirmed: async () => { spies.confirmed++; return true; } },
    fetch: f.fetch,
    prover: {
      buildDeposit: async (keys) => { spies.prover++; return { body: 'DEPOSIT-BODY', signals: await deriveSignals(keys) }; },
      signAuth: async (_op, _h, _n, _nonce, sign) => sign(new Uint8Array(64).fill(1)),
      scheduleRedeposit: (o) => o.epochStartMs + 5000,
    },
    now: () => MID,
    requestTimeoutMs: 200,
    backoffMs: () => 1000,
    ...over,
  };
  let on = true;
  const live = opts.live ?? (() => on);
  const wire = createBeaconWireWithGate(deps, live);
  return { wire, k, seeds, f, spies, sealer, setOn: (v: boolean) => { on = v; }, x, y };
}

// ---------- W2 the control first: everything on DOES send ----------
test('W2 CONTROL: switch on, pair confirmed, counterpart key known -> one deposit request to the fixed base, and state was written', async () => {
  const r = await rig();
  r.f.queue.push(ok('accepted'));
  const out = await r.wire.client.trustAtTap(PAIR);
  assert.equal(out.kind, 'deposited');
  assert.equal(r.f.calls.length, 1);
  assert.equal(r.f.calls[0].url, '/api/trust/beacon/deposit', 'the fixed same-origin base, not a parameter');
  assert.ok(r.k.n.swaps > 0, 'the pair record was written');
  assert.equal(Object.keys(r.seeds.st.map).length, 1, 'one one-time seed was minted');
});

// ---------- W1 (g): off means off ----------
test('W1 switch OFF: every method answers from constants and NOTHING is touched: no fetch, no store read or write, no seed read or write, no dependency called', async () => {
  const r = await rig();
  r.setOn(false);
  const c = r.wire.client;
  assert.deepEqual(await c.trustAtTap(PAIR), { kind: 'unsent' });
  // removeAtTap is NOT in this list: it is the one method that writes while off (the local latch), see W12
  assert.equal(await c.matchState(PAIR), 'none');
  assert.equal(await c.matchSince(PAIR), null);
  assert.equal(await c.renew(PAIR), undefined);
  assert.equal(await c.pollNow(PAIR), undefined);
  assert.equal(await c.nextRenewalAt(PAIR), undefined);
  assert.equal(await c.drainPendingWithdraws(), undefined);
  assert.equal(r.f.calls.length, 0, 'zero fetch');
  assert.equal(r.k.total(), 0, 'zero store reads AND writes (gets/swaps/keys)');
  assert.equal(r.k.data.size, 0, "no 'unsent' or any other state persisted");
  assert.deepEqual([r.seeds.st.reads, r.seeds.st.updates, r.seeds.st.resets], [0, 0, 0], 'zero seed-map reads or writes');
  assert.deepEqual(r.spies, { secretX: 0, counterpartY: 0, confirmed: 0, prover: 0 }, 'no dependency was even asked');
});

// ---------- the kill switch ----------
test('W6a switch flipped OFF after the wire was built ON: renew, pollNow, drain and trustAtTap send nothing (removeAtTap: W12)', async () => {
  const r = await rig();
  r.f.queue.push(ok('accepted'));
  assert.equal((await r.wire.client.trustAtTap(PAIR)).kind, 'deposited');
  assert.equal(r.f.calls.length, 1, 'ON: it sent');
  const writesWhileOn = r.k.n.swaps;
  r.setOn(false);
  await r.wire.client.renew(PAIR);
  await r.wire.client.pollNow(PAIR);
  await r.wire.client.drainPendingWithdraws();
  await r.wire.client.trustAtTap(PAIR);
  assert.equal(r.f.calls.length, 1, 'OFF: no further request on any path');
  assert.equal(r.k.n.swaps, writesWhileOn, 'and no further store write');
});

test('W6b the fetch layer checks the switch itself: it goes off AFTER the method gate passed and BEFORE the request -> still zero fetch', async () => {
  let calls = 0;
  const live = () => ++calls === 1; // true for the method gate only
  const r = await rig({}, { live });
  const out = await r.wire.client.trustAtTap(PAIR);
  assert.notEqual(out.kind, 'deposited');
  assert.equal(r.f.calls.length, 0, 'the request never reached the network');
  assert.ok(calls >= 2, 'the switch was read again inside the fetch, not only at the method');
});

test('W6c BeaconWireOff is a typed error with a stable code', () => {
  const e = new BeaconWireOff();
  assert.equal(e.code, 'beacon-wire-off');
  assert.ok(e instanceof Error);
});

// ---------- the two unbuilt inputs fail closed ----------
test('W3 confirmed left out -> no pair is confirmed: zero requests on every path, and the result says so', async () => {
  const r = await rig({ confirmed: undefined });
  const out = await r.wire.client.trustAtTap(PAIR);
  assert.equal(out.kind, 'unconfirmed');
  await r.wire.client.renew(PAIR);
  await r.wire.client.pollNow(PAIR);
  assert.equal(await r.wire.client.matchState(PAIR), 'none');
  assert.equal(r.f.calls.length, 0);
});

test('W4 counterpartY left out -> nothing can be derived: zero requests, no seed minted', async () => {
  const r = await rig({ counterpartY: undefined });
  const out = await r.wire.client.trustAtTap(PAIR);
  assert.notEqual(out.kind, 'deposited');
  await r.wire.client.renew(PAIR);
  await r.wire.client.pollNow(PAIR);
  assert.equal(r.f.calls.length, 0);
  assert.deepEqual(r.seeds.st.map, {}, 'no one-time seed was minted for a counterpart nobody verified');
});

// A tap clears a LOCAL 'removed' latch on purpose (client rule L5: the owner's own tap is a re-trust); only a REMOTE latch (the peer's un-trust) blocks a tap.
test("W5a a pair the PEER removed (remote latch) -> the tap says 'latched': zero requests, no new row, no seed", async () => {
  const r = await rig();
  await createBeaconLatch(r.k.kv, r.sealer, OWNER).setLatched(PAIR, 'remote');
  const out = await r.wire.client.trustAtTap(PAIR);
  assert.equal(out.kind, 'latched');
  await r.wire.client.renew(PAIR);
  await r.wire.client.pollNow(PAIR);
  assert.equal(r.f.calls.length, 0);
  assert.deepEqual(r.seeds.st.map, {});
});

test('W5b a pair I removed (local latch, a row still standing) -> never a deposit or a poll; the only traffic is the WITHDRAW that finishes the Remove. CONTROL: the same pollNow DID send before the latch', async () => {
  const r = await rig();
  r.f.queue.push(ok('accepted'));
  assert.equal((await r.wire.client.trustAtTap(PAIR)).kind, 'deposited');
  const afterDeposit = r.f.calls.length;
  await r.wire.client.pollNow(PAIR);
  assert.ok(r.f.calls.length > afterDeposit, 'CONTROL: with a standing row and no latch, a poll goes out');
  const beforeLatch = r.f.calls.length;
  await createBeaconLatch(r.k.kv, r.sealer, OWNER).setLatched(PAIR, 'local');
  await r.wire.client.pollNow(PAIR);
  assert.equal(r.f.calls.length, beforeLatch, 'latched: a poll sends nothing');
  r.f.queue.push({ status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) }, ok('withdrawn'));
  await r.wire.client.renew(PAIR);
  const urls = r.f.calls.slice(beforeLatch).map((c) => c.url);
  assert.ok(urls.length > 0, 'the half-done Remove is finished by a withdraw');
  assert.ok(urls.every((u) => u.endsWith('/beacon/nonce') || u.endsWith('/beacon/withdraw')), `only withdraw traffic, got ${JSON.stringify(urls)}`);
  assert.ok(urls.some((u) => u.endsWith('/beacon/withdraw')), 'the withdraw itself was sent');
});

// ---------- a Remove survives the switch being off ----------
test('W12 a Remove made while the switch is OFF is not lost: 0 requests, the local latch is recorded, and when the switch is on again the drain withdraws the standing row (one withdraw, no deposit)', async () => {
  const r = await rig();
  r.f.queue.push(ok('accepted'));
  assert.equal((await r.wire.client.trustAtTap(PAIR)).kind, 'deposited');
  const afterDeposit = r.f.calls.length;
  r.setOn(false);
  assert.deepEqual(await r.wire.client.removeAtTap(PAIR), { observedMatch: false });
  assert.equal(r.f.calls.length, afterDeposit, 'OFF: the Remove sent nothing');
  assert.equal(await createBeaconLatch(r.k.kv, r.sealer, OWNER).kindOf(PAIR, 'local'), 'removed', 'but it was recorded');
  r.setOn(true);
  r.f.queue.push({ status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) }, ok('withdrawn'));
  await r.wire.client.drainPendingWithdraws();
  const urls = r.f.calls.slice(afterDeposit).map((c) => c.url);
  assert.equal(urls.filter((u) => u.endsWith('/beacon/withdraw')).length, 1, `exactly one withdraw, got ${JSON.stringify(urls)}`);
  assert.ok(!urls.some((u) => u.endsWith('/beacon/deposit')), 'and no deposit');
});

test('W12b a Remove made while OFF that cannot be recorded FAILS: it never looks done', async () => {
  const r = await rig();
  r.setOn(false);
  r.k.fail.swap = true;
  await assert.rejects(() => r.wire.client.removeAtTap(PAIR));
  assert.equal(r.f.calls.length, 0);
});

// ---------- a key stored on a contact, read the way the wire will read it ----------
test("W13 a beacon key stored on a CONTACT: the wire reads it through counterpartY; a pair the PEER removed (remote latch) sends NOTHING; CONTROL: the same contact, unlatched, DOES send", async () => {
  const x = await generateBeaconSecret(), other = await generateBeaconSecret();
  const ownPub = await beaconPublicKey(x);
  const contact = { beacon_public_key: await beaconPublicKey(other), beacon_key_generation: 3 };   // what the intake stores: the base64 key and its generation
  const fromContact = async () => { const c = await checkBeaconPublicKey(contact.beacon_public_key, ownPub); return c.ok ? (c as { ok: true; point: Point }).point : undefined; };
  const control = await rig({ secretX: async () => x, counterpartY: fromContact });
  control.f.queue.push(ok('accepted'));
  assert.equal((await control.wire.client.trustAtTap(PAIR)).kind, 'deposited', 'CONTROL: a stored key is enough to send once the pair is confirmed and unlatched');
  assert.equal(control.f.calls.length, 1);
  const latched = await rig({ secretX: async () => x, counterpartY: fromContact });
  await createBeaconLatch(latched.k.kv, latched.sealer, OWNER).setLatched(PAIR, 'remote');
  assert.equal((await latched.wire.client.trustAtTap(PAIR)).kind, 'latched');
  await latched.wire.client.renew(PAIR);
  await latched.wire.client.pollNow(PAIR);
  assert.equal(latched.f.calls.length, 0, 'a stored key on a removed pair makes zero requests: the latch decides, the key enables nothing alone');
  assert.deepEqual(latched.seeds.st.map, {});
});

// ---------- the real confirmed port, and a removed pair ----------
test("W14 a pair that is MARKED confirmed but latched (the peer removed it) still sends NOTHING; CONTROL: the same confirmed pair, unlatched, DOES send; and an UNCONFIRMED pair sends nothing", async () => {
  const confirmedMap = { [PAIR_ID64]: { generation: 3 } };
  const port = createConfirmedPort(async () => confirmedMap, async () => 3);   // the held key is at generation 3, as the confirm was
  // the pair id the client asks about is the id the store used: use the same string for both, 64 hex
  const ok1 = await rig({ confirmed: port });
  assert.equal(await port.isConfirmed(PAIR_ID64), true);
  ok1.f.queue.push(ok('accepted'));
  assert.equal((await ok1.wire.client.trustAtTap(PAIR_ID64)).kind, 'deposited', 'CONTROL: confirmed + unlatched sends');
  const latched = await rig({ confirmed: port });
  await createBeaconLatch(latched.k.kv, latched.sealer, OWNER).setLatched(PAIR_ID64, 'remote');
  assert.equal((await latched.wire.client.trustAtTap(PAIR_ID64)).kind, 'latched');
  await latched.wire.client.renew(PAIR_ID64);
  await latched.wire.client.pollNow(PAIR_ID64);
  assert.equal(latched.f.calls.length, 0, 'marked confirmed AND latched: zero requests, the latch decides');
  const unconfirmed = await rig({ confirmed: createConfirmedPort(async () => ({}), async () => 3) });
  assert.equal((await unconfirmed.wire.client.trustAtTap(PAIR_ID64)).kind, 'unconfirmed');
  assert.equal(unconfirmed.f.calls.length, 0);
  // GATE 15: confirmed at 3, but the held key has since been replaced by generation 4: the same wire, the same marked pair, sends NOTHING until a live confirm at 4
  const replaced = await rig({ confirmed: createConfirmedPort(async () => confirmedMap, async () => 4) });
  assert.equal((await replaced.wire.client.trustAtTap(PAIR_ID64)).kind, 'unconfirmed', 'a pair confirmed at 3 is not confirmed for a key held at 4');
  await replaced.wire.client.renew(PAIR_ID64);
  await replaced.wire.client.pollNow(PAIR_ID64);
  assert.equal(replaced.f.calls.length, 0, 'zero requests until a live re-confirm');
});

// ---------- static guards ----------
function walk(dir: string, out: { path: string; text: string }[] = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) { if (name !== 'node_modules' && name !== '.next') walk(p, out); continue; }
    if (!/\.(ts|tsx)$/.test(name) || /\.test\.(ts|tsx)$/.test(name)) continue;
    out.push({ path: p, text: readFileSync(p, 'utf8') });
  }
  return out;
}
const SRC = walk(join(process.cwd(), 'src'));
const codeOnly = (t: string) => t.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).map((l) => l.replace(/\/\/.*$/, '')).join('\n');
const isFile = (p: string, name: string) => p.replace(/\\/g, '/').endsWith(name);
const namersOf = (files: { path: string; text: string }[], name: string) => files.filter((f) => new RegExp(`\\b${name}\\b`).test(codeOnly(f.text))).map((f) => f.path.replace(/\\/g, '/').split('/src/').pop());

/** the callers' `confirmed` must be the real evidence function, never a constant true */
export function scanWireCallers(files: { path: string; text: string }[]): string[] {
  const bad: string[] = [];
  for (const f of files) {
    if (isFile(f.path, 'src/lib/trust/beacon-wire.ts')) continue;
    const code = codeOnly(f.text);
    if (!/\bcreateBeaconWire\s*\(/.test(code)) continue;
    if (/\bconfirmed\s*:\s*\{[^}]*=>\s*(true|!0)\b/.test(code) || /\bisConfirmed\s*:[^,}]*=>\s*(true|!0)\b/.test(code) || /\bconfirmed\s*:\s*(true|\{\s*isConfirmed\s*:\s*\(\s*\)\s*=>\s*true)/.test(code)) bad.push(f.path);
  }
  return bad;
}

test('W7 the caller guard flags a constant-true confirmed (CONTROL) and finds none in the tree', () => {
  const flagged = scanWireCallers([
    { path: 'src/x/a.ts', text: 'const w = createBeaconWire({ confirmed: { isConfirmed: async () => true } });' },
    { path: 'src/x/b.ts', text: 'const w = createBeaconWire({ confirmed: { isConfirmed: () => true } });' },
    { path: 'src/x/c.ts', text: 'const w = createBeaconWire({ confirmed: qgConfirmed });' },
    { path: 'src/x/d.ts', text: '// createBeaconWire({ confirmed: { isConfirmed: async () => true } })' },
  ]);
  assert.deepEqual(flagged, ['src/x/a.ts', 'src/x/b.ts'], 'the two constant-true callers are flagged; the real function and a comment are not');
  assert.deepEqual(scanWireCallers(SRC), [], 'no caller in the tree passes a constant-true confirmed');
});

test('W8 the gate-injecting entry is named by no other non-test source file (the guard FIRES on a synthetic importer, CONTROL), and the base URL is not a parameter of the wire', () => {
  const flagged = namersOf([
    { path: '/x/src/lib/other.ts', text: "import { createBeaconWireWithGate } from './beacon-wire';" },
    { path: '/x/src/lib/comment.ts', text: '// createBeaconWireWithGate is for tests' },
  ], 'createBeaconWireWithGate');
  assert.deepEqual(flagged, ['lib/other.ts'], 'an importer is flagged; a comment is not');
  assert.deepEqual(namersOf(SRC, 'createBeaconWireWithGate'), ['lib/trust/beacon-wire.ts']);
  const wire = SRC.find((f) => isFile(f.path, 'src/lib/trust/beacon-wire.ts'))!;
  assert.doesNotMatch(codeOnly(wire.text), /\bbaseUrl\b/, 'no baseUrl in the wire: the client fixed base is the only one');
});

test("W9 trustAtTap has no caller outside the client and the wire: a new one must be reviewed for what it does with 'unsent' (nothing sent, nothing will be: no retry, no 'will send' text)", () => {
  const callers = SRC.filter((f) => /\btrustAtTap\b/.test(codeOnly(f.text))).map((f) => f.path.replace(/\\/g, '/').split('/src/').pop()).sort();
  assert.deepEqual(callers, ['lib/crypto/beacon-client.ts', 'lib/trust/beacon-wire.ts']);
});

test("W10 the secrets adapter is handed the pair's latch kind (a 'removed' pair gets no secrets and no new row): pinned by source, because the client's own latch check stops a tap first and hides this wiring from a behaviour test", () => {
  const wire = SRC.find((f) => isFile(f.path, 'src/lib/trust/beacon-wire.ts'))!;
  assert.match(codeOnly(wire.text), /createBeaconSecrets\(\{[\s\S]*\blatchKind\s*:\s*\(pairId\)\s*=>\s*latch\.kindOf\(pairId\)[\s\S]*\}\)/);
});

test('W11 the public entry takes ONE parameter: the switch cannot be overridden through createBeaconWire (only the named test entry takes a gate)', () => {
  const wire = SRC.find((f) => isFile(f.path, 'src/lib/trust/beacon-wire.ts'))!;
  assert.match(codeOnly(wire.text), /export function createBeaconWire\(deps: BeaconWireDeps\): BeaconWire \{\s*return createBeaconWireWithGate\(deps, isBeaconWireLive\);\s*\}/);
});

test('W-ON1 (source shape) the wire hands onUnexpected to the client it builds, so a bug in the hold or the self-heal reaches the caller\'s reporter', () => {
  const src = readFileSync(join(process.cwd(), 'src/lib/trust/beacon-wire.ts'), 'utf8');
  assert.match(src, /onUnexpected:\s*deps\.onUnexpected/);
  assert.match(src, /onUnexpected\?:\s*\(where:\s*'hold'\s*\|\s*'self-heal',\s*err:\s*unknown\)\s*=>\s*void/);
});
