// src/lib/identity/identity-card-beacon.test.ts
// #588 T4: the beacon key on the SIGNED identity card (identity.beacon_public_key + identity.beacon_key_generation). Trust stays DARK.
// Run: npx tsx --test src/lib/identity/identity-card-beacon.test.ts
// Rules under test (T4 note v0.2 §3, Flint's rulings): the key rides under identity.* so the card signature covers it (a swap or a strip breaks the
// signature); a receiver stores it ONLY under a VALID signature (branches 4a/4b/4c, like the device-mailbox); a bad key drops the KEY and keeps the
// card; a lower key_generation than the highest seen is refused; the same generation with a different key is refused.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { signIdentityCard, verifySignedIdentityCard, classifyImportedCard, buildSignedIdentityCard, type SignedIdentityCard } from './identity-card-sign';
import type { IdentityCard } from '../format/envelope';
import { identityCardSigningInput } from '../format/envelope';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { mintCanonicalFingerprint } from './fingerprint';
import { beaconPublicKey } from '../crypto/beacon-key';

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
function card(id: CanonId, over: Record<string, unknown> = {}): IdentityCard {
  return {
    version: '1.1', type: 'identity-exchange', created_at: '2026-11-09T00:00:00.000Z',
    identity: {
      fingerprint: id.fingerprint, display_name: 'Alice', public_key: id.publicKey, email: 'alice@example.test',
      pq_sig_public_key: id.sigB64, pq_kem_public_key: id.kemB64, next_authority_commitment: '', ...over,
    },
  } as IdentityCard;
}
const wrapper = (id: CanonId) => ({
  identity: { fingerprint: id.fingerprint, public_key: id.publicKey, display_name: 'Alice', email: 'alice@example.test' },
  post_quantum: { kem_public_key: id.kemB64, sig_public_key: id.sigB64 },
  next_authority_commitment: '',
});

let alice: CanonId, KEY_A: string, KEY_B: string, KEY_OWN: string;
before(async () => {
  alice = await makeCanonicalId('alice');
  KEY_A = await beaconPublicKey(111111n);
  KEY_B = await beaconPublicKey(222222n);
  KEY_OWN = await beaconPublicKey(333333n);
});

const signed = (over: Record<string, unknown>) => signIdentityCard(card(alice, over), alice.privateKey, alice.passphrase);

test('C1 a card built WITHOUT a beacon key has no beacon fields at all (byte-preserving) and classifies with no key and no reason', async () => {
  const c = await buildSignedIdentityCard(wrapper(alice), alice.privateKey, alice.passphrase);
  assert.ok(!('beacon_public_key' in c.identity) && !('beacon_key_generation' in c.identity));
  assert.ok(!identityCardSigningInput(c).includes('beacon'), 'the canonical signing input never mentions beacon');
  assert.equal(await verifySignedIdentityCard(c), true);
  const d = await classifyImportedCard(c);
  assert.equal(d.importClassical, true);
  assert.equal(d.beaconKey, null);
  assert.equal(d.beaconKeyDropped, undefined);
});

test('C2 a card built WITH a beacon key carries both fields, verifies, and a receiver stores the key and the generation', async () => {
  const c = await buildSignedIdentityCard(wrapper(alice), alice.privateKey, alice.passphrase, undefined, { publicKey: KEY_A, keyGeneration: 1 });
  assert.equal(c.identity.beacon_public_key, KEY_A);
  assert.equal(c.identity.beacon_key_generation, 1);
  assert.equal(await verifySignedIdentityCard(c), true);
  const d = await classifyImportedCard(c);
  assert.deepEqual(d.beaconKey, { publicKey: KEY_A, keyGeneration: 1 });
  assert.equal(d.branch, '4b', 'the pq disposition is unchanged by the new field');
});

test('C3 SWAP: replacing the beacon key on a signed card breaks the signature; nothing is stored and the alarm is the LOUD tamper branch', async () => {
  const c = await signed({ beacon_public_key: KEY_A, beacon_key_generation: 1 });
  const evil = JSON.parse(JSON.stringify(c)) as SignedIdentityCard;
  evil.identity.beacon_public_key = KEY_B;
  assert.equal(await verifySignedIdentityCard(evil), false);
  const d = await classifyImportedCard(evil);
  assert.equal(d.branch, 3);
  assert.equal(d.alarm, 'loud');
  assert.equal(d.beaconKey, null);
  assert.equal(d.importClassical, true, 'the classical contact still imports; only the key is withheld');
});

test('C4 STRIP: removing the beacon fields from a signed card breaks the signature too (the signature covers their presence)', async () => {
  const c = await signed({ beacon_public_key: KEY_A, beacon_key_generation: 1 });
  const stripped = JSON.parse(JSON.stringify(c)) as SignedIdentityCard;
  delete (stripped.identity as any).beacon_public_key;
  delete (stripped.identity as any).beacon_key_generation;
  assert.equal(await verifySignedIdentityCard(stripped), false);
  assert.equal((await classifyImportedCard(stripped)).branch, 3);
});

test('C5 an UNSIGNED card (branch 2) carrying a beacon key stores no key (an unauthenticated carrier cannot supply one)', async () => {
  const unsigned = card(alice, { beacon_public_key: KEY_A, beacon_key_generation: 1 });
  const d = await classifyImportedCard(unsigned);
  assert.equal(d.branch, 2);
  assert.equal(d.beaconKey, null);
  assert.equal(d.beaconKeyDropped, undefined, 'a dropped-for-no-signature key is not reported as a bad key');
});

test('C6 a valid signature over a BAD key drops the key only: the card imports, the pq leg is kept, and the reason is a fixed word', async () => {
  const bad: Array<[string, string, string]> = [
    ['identity point', Buffer.from([1, ...new Array(31).fill(0)]).toString('base64'), 'identity'],
    ['garbage length', 'AAAA', 'encoding'],
    ['not base64', '!'.repeat(44), 'encoding'],
  ];
  for (const [label, key, reason] of bad) {
    const c = await signed({ beacon_public_key: key, beacon_key_generation: 1 });
    const d = await classifyImportedCard(c);
    assert.equal(d.importClassical, true, label);
    assert.equal(d.branch, '4b', label);
    assert.ok(d.pq, `${label}: pq kept`);
    assert.equal(d.beaconKey, null, label);
    assert.equal(d.beaconKeyDropped, reason, label);
  }
});

test('C7 my own beacon key arriving on a contact\'s card is dropped as own-key', async () => {
  const c = await signed({ beacon_public_key: KEY_OWN, beacon_key_generation: 1 });
  const d = await classifyImportedCard(c, { ownBeaconPublicKey: KEY_OWN });
  assert.equal(d.beaconKey, null);
  assert.equal(d.beaconKeyDropped, 'own-key');
  assert.deepEqual((await classifyImportedCard(c)).beaconKey, { publicKey: KEY_OWN, keyGeneration: 1 }, 'without my key to compare, it is a valid key');
});

test('C8 key_generation must be a positive safe integer under 2^31, and must be present with the key', async () => {
  for (const g of [0, -1, '2', Number.MAX_SAFE_INTEGER, 2 ** 31]) {
    const c = await signed({ beacon_public_key: KEY_A, beacon_key_generation: g });
    const d = await classifyImportedCard(c);
    assert.equal(d.beaconKey, null, String(g));
    assert.equal(d.beaconKeyDropped, 'generation', String(g));
  }
  const noGen = await signed({ beacon_public_key: KEY_A });
  assert.equal((await classifyImportedCard(noGen)).beaconKeyDropped, 'generation');
  const genOnly = await signed({ beacon_key_generation: 3 });
  assert.equal((await classifyImportedCard(genOnly)).beaconKeyDropped, 'generation', 'a generation with no key is malformed, not "no beacon"');
});

test('C9 ANTI-ROLLBACK: a lower generation than the highest seen is refused; the same generation with a DIFFERENT key is refused; the same key or a higher generation is taken', async () => {
  const known = { publicKey: KEY_A, keyGeneration: 5 };
  const lower = await classifyImportedCard(await signed({ beacon_public_key: KEY_B, beacon_key_generation: 4 }), { knownBeacon: known });
  assert.equal(lower.beaconKey, null); assert.equal(lower.beaconKeyDropped, 'rollback');
  const conflict = await classifyImportedCard(await signed({ beacon_public_key: KEY_B, beacon_key_generation: 5 }), { knownBeacon: known });
  assert.equal(conflict.beaconKey, null); assert.equal(conflict.beaconKeyDropped, 'conflict');
  const same = await classifyImportedCard(await signed({ beacon_public_key: KEY_A, beacon_key_generation: 5 }), { knownBeacon: known });
  assert.deepEqual(same.beaconKey, { publicKey: KEY_A, keyGeneration: 5 });
  const higher = await classifyImportedCard(await signed({ beacon_public_key: KEY_B, beacon_key_generation: 6 }), { knownBeacon: known });
  assert.deepEqual(higher.beaconKey, { publicKey: KEY_B, keyGeneration: 6 });
});

test('C10 the SENDER refuses to sign a bad key or a bad generation (a self-inconsistent card is uninstantiable)', async () => {
  const w = wrapper(alice);
  await assert.rejects(() => buildSignedIdentityCard(w, alice.privateKey, alice.passphrase, undefined, { publicKey: 'AAAA', keyGeneration: 1 }), /beacon/i);
  await assert.rejects(() => buildSignedIdentityCard(w, alice.privateKey, alice.passphrase, undefined, { publicKey: KEY_A, keyGeneration: 0 }), /beacon/i);
  await assert.rejects(() => buildSignedIdentityCard(w, alice.privateKey, alice.passphrase, undefined, { publicKey: KEY_A, keyGeneration: 1.5 }), /beacon/i);
});

test('C11 a card from an OLDER client (no beacon fields, any pq state) is untouched by this change: same dispositions as before', async () => {
  const noPq = card(alice, { pq_kem_public_key: '', pq_sig_public_key: '' });
  const d = await classifyImportedCard(noPq);
  assert.equal(d.beaconKey, null);
  assert.equal(d.beaconKeyDropped, undefined);
});

test('C8b a card whose beacon_key_generation is a FLOAT / null / NaN cannot be signed by anyone (canonicalize refuses), and a hostile unsigned-looking one must not crash the importer', async () => {
  for (const g of [1.5, null, Number.NaN]) {
    await assert.rejects(() => signed({ beacon_public_key: KEY_A, beacon_key_generation: g }), /canonicalize/, String(g));
    // a hostile sender attaches a junk signature to a card that has a float field: the classifier must answer, not throw
    const hostile = { ...card(alice, { beacon_public_key: KEY_A, beacon_key_generation: g }), signature: 'junk' };
    let threw: unknown;
    let d: any;
    try { d = await classifyImportedCard(hostile); } catch (e) { threw = e; }
    assert.equal(threw, undefined, `classifyImportedCard threw for ${String(g)}`);
    assert.equal(d.beaconKey, null);
  }
});
