/* eslint-disable @typescript-eslint/no-explicit-any -- test doubles and deliberately wrong inputs */
// src/lib/trust/beacon-contact-key.test.ts — #822 (a) S2a: what the intake does with the beacon key a contact's signed card carries.
// Run: npx tsx --test src/lib/trust/beacon-contact-key.test.ts
// The decisions are run against the REAL classifier's dispositions (a signed card, classifyImportedCard), not only against hand-made ones.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { decideBeaconIntake, ownBeaconFrom, knownBeaconOf, type CardBeacon, type OwnBeacon } from './beacon-contact-key';
import { signIdentityCard, classifyImportedCard } from '../identity/identity-card-sign';
import type { IdentityCard } from '../format/envelope';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { mintCanonicalFingerprint } from '../identity/fingerprint';
import { beaconPublicKey } from '../crypto/beacon-key';
import { GENERATION_FLOOR } from '../crypto/beacon-generation';
import { toSafeExportContact, toContactBookJson } from '../contacts/book-export';
import { beaconKeyConflictMessage } from '../identity/beacon-key-copy';
import { contactFromPlaintextBackup, type ContactRecord } from '../identity/client-store';

const G = (n: number) => GENERATION_FLOOR + n;

interface CanonId { fingerprint: string; publicKey: string; privateKey: string; passphrase: string; kemB64: string; sigB64: string }
async function makeCanonicalId(name: string): Promise<CanonId> {
  const pass = 'pw-' + name;
  const { privateKey: priv, publicKey: pub } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime (same keygen as core.ts).
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }], passphrase: pass, format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: priv });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: pass });
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  return { fingerprint, publicKey: pub, privateKey: priv, passphrase: pass, kemB64: uint8ToBase64(pq.kem.publicKey), sigB64: uint8ToBase64(pq.signing.publicKey) };
}
const card = (id: CanonId, over: Record<string, unknown> = {}): IdentityCard => ({
  version: '1.1', type: 'identity-exchange', created_at: '2026-11-09T00:00:00.000Z',
  identity: {
    fingerprint: id.fingerprint, display_name: 'Alice', public_key: id.publicKey, email: 'alice@example.test',
    pq_sig_public_key: id.sigB64, pq_kem_public_key: id.kemB64, next_authority_commitment: '', ...over,
  },
} as IdentityCard);

let alice: CanonId, KEY_A: string, KEY_B: string, KEY_OWN: string;
before(async () => {
  alice = await makeCanonicalId('alice');
  KEY_A = await beaconPublicKey(BigInt('111111'));
  KEY_B = await beaconPublicKey(BigInt('222222'));
  KEY_OWN = await beaconPublicKey(BigInt('333333'));
});
const signed = (over: Record<string, unknown>) => signIdentityCard(card(alice, over), alice.privateKey, alice.passphrase);
const READABLE: OwnBeacon = { state: 'readable', publicKey: undefined };
/** the real classifier's disposition for a card carrying (key, gen), given what the contact already holds */
async function dispositionFor(key: string, gen: number, held?: { beacon_public_key?: string; beacon_key_generation?: number }, own?: string): Promise<CardBeacon> {
  const d = await classifyImportedCard(await signed({ beacon_public_key: key, beacon_key_generation: gen }), { knownBeacon: knownBeaconOf(held), ownBeaconPublicKey: own });
  return { beaconKey: d.beaconKey, beaconKeyDropped: d.beaconKeyDropped };
}

// ---------- the decision ----------
test('K1 a new contact: the card key is ADDED; a known contact with no key: BACKFILLED; both carry the key and its generation', async () => {
  const d = await dispositionFor(KEY_A, G(3));
  assert.deepEqual(decideBeaconIntake(undefined, d, READABLE), { verdict: 'add', fields: { beacon_public_key: KEY_A, beacon_key_generation: G(3) } });
  assert.deepEqual(decideBeaconIntake({}, d, READABLE), { verdict: 'backfill', fields: { beacon_public_key: KEY_A, beacon_key_generation: G(3) } });
});

test('K2 TRUST-BLIND: a trusted and an untrusted contact both get the key (the decision never looks at trust)', async () => {
  const d = await dispositionFor(KEY_A, G(3));
  for (const trust of ['trusted', 'unverified', 'blocked']) {
    const out = decideBeaconIntake({ trust_level: trust } as any, d, READABLE);
    assert.equal(out.verdict, 'backfill', `trust_level ${trust}`);
    assert.equal(out.fields.beacon_public_key, KEY_A, `trust_level ${trust}`);
  }
});

test('K3 the same key at the same generation again: KEEP, nothing to write', async () => {
  const held = { beacon_public_key: KEY_A, beacon_key_generation: G(5) };
  const out = decideBeaconIntake(held, await dispositionFor(KEY_A, G(5), held), READABLE);
  assert.deepEqual(out, { verdict: 'keep', fields: {} });
});

test('K4 CONFLICT (real classifier: same generation, another key): LOUD, nothing is written, counted', async () => {
  const held = { beacon_public_key: KEY_A, beacon_key_generation: G(5) };
  const out = decideBeaconIntake(held, await dispositionFor(KEY_B, G(5), held), READABLE);
  assert.deepEqual(out, { verdict: 'loud', fields: {}, counted: 'conflict' });
});

test('K5 ROLLBACK (real classifier: a lower generation): KEEP, nothing is written, counted', async () => {
  const held = { beacon_public_key: KEY_A, beacon_key_generation: G(5) };
  const out = decideBeaconIntake(held, await dispositionFor(KEY_B, G(4), held), READABLE);
  assert.deepEqual(out, { verdict: 'keep', fields: {}, counted: 'rollback' });
});

test('K6 a held key is NEVER written by the decision: a valid HIGHER generation is a REPLACE verdict that carries the newer key APART from `fields`, which stays empty', async () => {
  const held = { beacon_public_key: KEY_A, beacon_key_generation: G(5) };
  const d = await dispositionFor(KEY_B, G(6), held);
  assert.ok(d.beaconKey, 'the classifier accepts it: a valid higher generation');
  const out = decideBeaconIntake(held, d, READABLE);
  assert.deepEqual(out, { verdict: 'replace', fields: {}, replace: { publicKey: KEY_B, keyGeneration: G(6) } });
});

test('K7 my own key reflected back on a card: dropped by the classifier, nothing stored, counted', async () => {
  const d = await dispositionFor(KEY_OWN, G(3), undefined, KEY_OWN);
  assert.equal(d.beaconKey, null);
  assert.deepEqual(decideBeaconIntake(undefined, d, { state: 'readable', publicKey: KEY_OWN }), { verdict: 'none', fields: {}, counted: 'own-key' });
});

test('K8 a card with no beacon key at all: nothing to do and nothing counted', async () => {
  const d = await classifyImportedCard(await signed({}), {});
  assert.deepEqual(decideBeaconIntake(undefined, { beaconKey: d.beaconKey, beaconKeyDropped: d.beaconKeyDropped }, READABLE), { verdict: 'none', fields: {} });
});

test('K15 DEFENSIVE: if the classifier ever let a lower generation or a different key at the same generation through, the decision still refuses to write', () => {
  const held = { beacon_public_key: KEY_A, beacon_key_generation: G(5) };
  assert.deepEqual(decideBeaconIntake(held, { beaconKey: { publicKey: KEY_B, keyGeneration: G(4) } }, READABLE), { verdict: 'keep', fields: {}, counted: 'rollback' });
  assert.deepEqual(decideBeaconIntake(held, { beaconKey: { publicKey: KEY_B, keyGeneration: G(5) } }, READABLE), { verdict: 'loud', fields: {}, counted: 'conflict' });
});

test('K22 a contact that holds a key but a missing or garbled generation STILL holds it: a valid card never overwrites it (kept, counted held-malformed); a card with no beacon key just does nothing', async () => {
  const valid = await dispositionFor(KEY_B, G(4));
  assert.ok(valid.beaconKey, 'the card carries a valid key');
  for (const gen of ['x', undefined, NaN, null, 1.5 as number | undefined, '3'] as unknown[]) {
    const held = { beacon_public_key: KEY_A, beacon_key_generation: gen } as any;
    const out = decideBeaconIntake(held, valid, READABLE);
    assert.deepEqual(out, { verdict: 'keep', fields: {}, counted: 'held-malformed' }, `generation ${String(gen)}`);
  }
  assert.deepEqual(decideBeaconIntake({ beacon_public_key: 123 as any, beacon_key_generation: 3 }, valid, READABLE), { verdict: 'keep', fields: {}, counted: 'held-malformed' }, 'a non-string key is still a held key');
  assert.deepEqual(decideBeaconIntake({ beacon_public_key: KEY_A, beacon_key_generation: 'x' as any }, { beaconKey: null }, READABLE), { verdict: 'none', fields: {} }, 'no beacon key on the card: nothing to count');
  assert.equal(decideBeaconIntake({ beacon_key_generation: 3 }, valid, READABLE).verdict, 'backfill', 'CONTROL: a record with NO key still back-fills');
});

// ---------- the own key (fail closed) ----------
test('K9 my own key UNREADABLE: the card key is dropped (the reflection check cannot run), the contact is still handled, nothing "pending" is stored, and it is counted', async () => {
  const d = await dispositionFor(KEY_A, G(3));
  assert.deepEqual(decideBeaconIntake(undefined, d, { state: 'unreadable' }), { verdict: 'none', fields: {}, counted: 'own-key-unreadable' });
  assert.deepEqual(decideBeaconIntake({}, d, { state: 'unreadable' }), { verdict: 'none', fields: {}, counted: 'own-key-unreadable' });
});

test('K10 ownBeaconFrom: no key held = readable with nothing to reflect; held = its public key; unreadable, a throwing read and a throwing derivation = UNREADABLE', async () => {
  const rec = { secret: 's', key_generation: 1, jitter_secret: 'j' } as any;
  assert.deepEqual(await ownBeaconFrom(async () => ({ state: 'none' }), async () => 'x'), { state: 'readable', publicKey: undefined });
  assert.deepEqual(await ownBeaconFrom(async () => ({ state: 'held', record: rec }), async () => 'PUB'), { state: 'readable', publicKey: 'PUB' });
  assert.deepEqual(await ownBeaconFrom(async () => ({ state: 'unreadable' }), async () => 'x'), { state: 'unreadable' });
  assert.deepEqual(await ownBeaconFrom(async () => { throw new Error('boom'); }, async () => 'x'), { state: 'unreadable' });
  assert.deepEqual(await ownBeaconFrom(async () => ({ state: 'held', record: rec }), async () => { throw new Error('boom'); }), { state: 'unreadable' });
});

test('K11 knownBeaconOf: both fields present and typed, or nothing', () => {
  assert.deepEqual(knownBeaconOf({ beacon_public_key: 'k', beacon_key_generation: 3 }), { publicKey: 'k', keyGeneration: 3 });
  assert.equal(knownBeaconOf(undefined), undefined);
  assert.equal(knownBeaconOf({ beacon_public_key: 'k' }), undefined);
  assert.equal(knownBeaconOf({ beacon_key_generation: 3 }), undefined);
  assert.equal(knownBeaconOf({ beacon_public_key: 'k', beacon_key_generation: '3' as any }), undefined);
  assert.equal(knownBeaconOf({ beacon_public_key: 'k', beacon_key_generation: NaN }), undefined);
  assert.equal(knownBeaconOf({ beacon_public_key: 'k', beacon_key_generation: 1.5 }), undefined);
  assert.equal(knownBeaconOf({ beacon_public_key: 'k', beacon_key_generation: Infinity }), undefined);
});

// ---------- the key goes nowhere a contact book goes ----------
test('K12 the plain contact-book export carries NO beacon field: the projection is an allowlist, pinned by behaviour', () => {
  const rec = {
    id: 'c1', owner_fingerprint: 'o', name: 'A', email: 'a@x.test', fingerprint: 'f'.repeat(64), public_key: 'pk', trust_level: 'trusted', added_at: '2026-01-01T00:00:00.000Z',
    beacon_public_key: KEY_A, beacon_key_generation: G(3),
  } as ContactRecord;
  const safe = JSON.stringify(toSafeExportContact(rec));
  assert.doesNotMatch(safe, /beacon/i);
  assert.doesNotMatch(toContactBookJson([rec], '2026-01-01T00:00:00.000Z'), /beacon/i);
  assert.ok(safe.includes('"name":"A"'), 'CONTROL: the same record DID export its allowlisted fields');
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

test('K13 only the card format, the card signer, the store type, the decision module and the confirm rule name the contact\'s beacon fields in non-test source: a new consumer fails here until it is reviewed (the guard FIRES on a synthetic one, CONTROL)', () => {
  const RE = /beacon_public_key|beacon_key_generation/;
  assert.deepEqual(namersOf([{ path: '/x/src/lib/new-consumer.ts', text: 'const k = contact.beacon_public_key;' }, { path: '/x/src/lib/c.ts', text: '// beacon_public_key is the card field' }], RE), ['lib/new-consumer.ts']);
  assert.deepEqual(namersOf(SRC, RE), ['lib/format/envelope.ts', 'lib/identity/client-store.ts', 'lib/identity/identity-card-sign.ts', 'lib/trust/beacon-confirmed.ts', 'lib/trust/beacon-contact-key.ts']);
});

test('K14 the decision never lets a replace write through `fields`: the replace verdict carries the key in `replace` with EMPTY fields, and across every input only add and backfill ever return fields', async () => {
  const mod = SRC.find((f) => rel(f.path) === 'lib/trust/beacon-contact-key.ts')!;
  assert.match(codeOnly(mod.text), /k\.keyGeneration\s*>\s*held\.keyGeneration\)\s*return\s*\{\s*verdict:\s*'replace',\s*fields:\s*\{\},\s*replace:/);
  // behavioural: a matrix of held x card x own-key states; any non-empty `fields` must come from add or backfill, and `replace` is present only on a replace
  const helds = [undefined, {}, { beacon_public_key: KEY_A, beacon_key_generation: G(5) }, { beacon_public_key: KEY_A, beacon_key_generation: 'x' as unknown as number }];
  const cards = [{ beaconKey: null }, { beaconKey: { publicKey: KEY_A, keyGeneration: G(5) } }, { beaconKey: { publicKey: KEY_B, keyGeneration: G(6) } }, { beaconKey: { publicKey: KEY_B, keyGeneration: G(4) } }, { beaconKey: { publicKey: KEY_B, keyGeneration: G(5) } }, { beaconKey: null, beaconKeyDropped: 'conflict' }];
  const owns: OwnBeacon[] = [READABLE, { state: 'unreadable' }];
  let replaces = 0;
  for (const h of helds) for (const c of cards) for (const o of owns) {
    const out = decideBeaconIntake(h, c as CardBeacon, o);
    if (Object.keys(out.fields).length > 0) assert.ok(out.verdict === 'add' || out.verdict === 'backfill', `fields only on add/backfill (got ${out.verdict})`);
    assert.equal(out.replace !== undefined, out.verdict === 'replace', '`replace` is present exactly on a replace verdict');
    if (out.verdict === 'replace') { replaces++; assert.deepEqual(out.fields, {}); }
  }
  assert.ok(replaces > 0, 'CONTROL: the matrix really produces a replace, so the property above is not vacuous');
});

test('KV1 no other file can fabricate a replace verdict: only the decision module names it in non-test source (a new producer fails here until it is reviewed; the guard FIRES on a synthetic one)', () => {
  const RE = /verdict:\s*'replace'/;
  assert.deepEqual(namersOf([{ path: '/x/src/lib/new-producer.ts', text: "return { verdict: 'replace', fields: {} };" }], RE), ['lib/new-producer.ts']);
  assert.deepEqual(namersOf(SRC, RE), ['lib/trust/beacon-contact-key.ts']);
});

// Every caller of classifyImportedCard that CONSUMES the beacon key must give it my own key and the key the contact holds, or the own-key and rollback rules
// cannot run. A call that does not use the beacon key must SAY so on its line: that is reviewable, and the next pin stops it being misused.
/** comments replaced by spaces of the same length, so every position (and line number) still matches the raw text */
const mask = (t: string) => t.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' ')).replace(/\/\/[^\n]*/g, (m) => ' '.repeat(m.length));
function callsOf(raw: string): { args: string; line: string }[] {
  const out: { args: string; line: string }[] = [];
  const code = mask(raw);
  const lines = raw.split('\n');
  let from = 0;
  for (;;) {
    const i = code.indexOf('classifyImportedCard(', from);
    if (i < 0) break;
    from = i + 1;
    if (/function\s*$/.test(code.slice(Math.max(0, i - 24), i))) continue; // the definition
    let depth = 0, j = i + 'classifyImportedCard'.length;
    for (; j < code.length; j++) { if (code[j] === '(') depth++; else if (code[j] === ')') { depth--; if (depth === 0) break; } }
    out.push({ args: code.slice(i, j + 1), line: lines[code.slice(0, i).split('\n').length - 1] ?? '' }); // the call's OWN raw line
  }
  return out;
}
const badCallers = (files: { path: string; text: string }[]) => files.flatMap((f) => callsOf(f.text)
  .filter((c) => !(/\bownBeaconPublicKey\b/.test(c.args) && /\bknownBeacon\b/.test(c.args)) && !/beacon-key: unused here/.test(c.line))
  .map(() => rel(f.path)));

test('K16 every classifyImportedCard call passes BOTH ownBeaconPublicKey and knownBeacon, or says on its own line that it does not use the beacon key (the guard FIRES on a synthetic caller that does neither, CONTROL)', () => {
  assert.deepEqual(badCallers([
    { path: '/x/src/a.ts', text: 'const d = await classifyImportedCard(card);' },
    { path: '/x/src/b.ts', text: 'const d = await classifyImportedCard(card, { ownBeaconPublicKey: o });' },
    { path: '/x/src/c.ts', text: 'const d = await classifyImportedCard(card, { ownBeaconPublicKey: o, knownBeacon: k });' },
    { path: '/x/src/d.ts', text: 'const d = await classifyImportedCard(card); // beacon-key: unused here (why)' },
    { path: '/x/src/e.ts', text: 'export async function classifyImportedCard(card: any, opts = {}) {}' },
    // a marked call must NOT exempt a LATER unmarked call in the same file (the scanner once matched the wrong line)
    { path: '/x/src/f.ts', text: '// note\n// note\nconst a = await classifyImportedCard(x); // beacon-key: unused here (why)\nconst b = await classifyImportedCard(y, { knownBeacon: k });' },
  ]), ['a.ts', 'b.ts', 'f.ts']);
  assert.deepEqual(badCallers(SRC), [], 'no real caller consumes the beacon key without both inputs');
  const real = SRC.flatMap((f) => callsOf(f.text).map(() => rel(f.path))).sort();
  assert.deepEqual(real, ['components/ContactManagement.tsx', 'components/JoinerCeremony.tsx', 'components/JoinerCeremony.tsx'], 'the three real call sites (a fourth must be reviewed)');
});

test('K17 nothing outside the decision module and the confirm rule reads a disposition\'s .beaconKey: a call marked "unused here" cannot be misused', () => {
  assert.deepEqual(namersOf([{ path: '/x/src/lib/x.ts', text: 'const k = d.beaconKey;' }], /\.beaconKey\b/), ['lib/x.ts'], 'CONTROL: the guard fires');
  assert.deepEqual(namersOf(SRC, /\.beaconKey\b/), ['lib/trust/beacon-confirmed.ts', 'lib/trust/beacon-contact-key.ts']);
});

test('K18 the conflict sentence is the reviewed one, names only the contact, and carries no key, generation or alarming word', () => {
  const m = beaconKeyConflictMessage('Zed');
  assert.equal(m, 'A card for "Zed" doesn\'t match a key you already have for them, so it wasn\'t applied. Your existing contact is unchanged. Their identity may be in use somewhere else. Check with them another way before relying on this card.');
  assert.doesNotMatch(m, /beacon|generation|rotation|fingerprint|hacked|compromised|stolen/i);
  assert.doesNotMatch(beaconKeyConflictMessage('Zed'), /[A-Za-z0-9+/]{40,}/, 'no key-like string');
});

test('K19 both callers name the EXISTING contact in the conflict sentence, never the name the card carries (the guard FIRES on a card-name caller, CONTROL)', () => {
  const bad = (text: string) => /beaconKeyConflictMessage\(\s*(displayName|peer\.name|contactIdentity\.[a-z_]+)\s*\)/.test(codeOnly(text));
  assert.equal(bad('setError(beaconKeyConflictMessage(peer.name));'), true);
  assert.equal(bad('x(beaconKeyConflictMessage(displayName))'), true);
  assert.equal(bad('x(beaconKeyConflictMessage(existing.name))'), false);
  for (const f of ['components/ContactManagement.tsx', 'components/JoinerCeremony.tsx']) {
    const file = SRC.find((x) => rel(x.path) === f)!;
    assert.equal(bad(file.text), false, f);
    assert.match(codeOnly(file.text), /beaconKeyConflictMessage\(existing\.name\)/, f);
  }
});

// ---------- restore: the key comes back on a fresh device, and a held key is never overwritten ----------
test('K20 a restore KEEPS the contact\'s beacon key and generation (the encrypted backup carries them back onto a fresh device), with a control that other local-only fields ARE stripped', () => {
  const raw = {
    id: 'c1', owner_fingerprint: 'o', name: 'A', email: 'a@x.test', fingerprint: 'f'.repeat(64), public_key: 'pk', trust_level: 'trusted', added_at: '2026-01-01T00:00:00.000Z',
    beacon_public_key: KEY_A, beacon_key_generation: G(3), trusted: true, verified_at: 'x',
  } as unknown as ContactRecord;
  const out = contactFromPlaintextBackup(raw) as unknown as Record<string, unknown>;
  assert.equal(out.beacon_public_key, KEY_A);
  assert.equal(out.beacon_key_generation, G(3));
  assert.equal('verified_at' in out, false, 'CONTROL: a local-only field IS stripped, so this mapping really runs');
  assert.equal('id' in out, false);
});

test('K21 the plaintext-backup contact restore writes ONLY through addContact (idempotent by fingerprint: a duplicate returns the held record and writes nothing), never an update: so a vault key cannot overwrite a held one', () => {
  const store = SRC.find((f) => rel(f.path) === 'lib/identity/client-store.ts')!;
  const code = codeOnly(store.text);
  const a = code.indexOf('export async function importPlaintextContacts(');
  const body = code.slice(a, code.indexOf('export async function importAll('));
  assert.ok(body.length > 100, 'found the function');
  assert.match(body, /\baddContact\(/);
  assert.doesNotMatch(body, /\bupdateContact\(|\bmergeContactUpdate\(|\bputContact\(/);
  const add = code.slice(code.indexOf('export async function addContact('), code.indexOf('An update to a contact'));
  assert.match(code, /ConstraintError[\s\S]{0,400}if \(existing\) return existing;/, 'a duplicate fingerprint returns the held record');
  assert.ok(add.length > 0);
});
