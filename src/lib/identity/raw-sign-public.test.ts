// A contact's Ed25519 signing key from the book's record, bound to the fingerprint, and the pairwise secret it gives.
// Run: npx tsx --test src/lib/identity/raw-sign-public.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { extractRawSign } from './raw-sign';
import { mintCanonicalFingerprint } from './fingerprint';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { deriveSharedSecret } from '../crypto/mutual-trust';
import { isUsableEd25519Point, primaryEd25519PointOf, signPubForContact, type ContactKeyMaterial } from './raw-sign-public';

interface Id { contact: ContactKeyMaterial; seed: Uint8Array; signPub: Uint8Array }

// curve 'ed25519' is what core.ts passes (a valid runtime value that the types do not list); 'ed25519Legacy' is the same key format.
async function identity(name: string, curve: 'ed25519' | 'ed25519Legacy' = 'ed25519Legacy'): Promise<Id> {
  const passphrase = `pw-${name}`;
  // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve, userIDs: [{ name, email: `${name}@t.test` }], passphrase, format: 'armored' });
  const decrypted = await decryptKey({ privateKey: await readPrivateKey({ armoredKey: privateKey }), passphrase });
  const pq = generatePQKeypairBundle();
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: decrypted, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  const { seed, signPub } = extractRawSign(decrypted);
  return {
    contact: { fingerprint, public_key: publicKey, pq_kem_public_key: uint8ToBase64(pq.kem.publicKey), pq_sig_public_key: uint8ToBase64(pq.signing.publicKey) },
    seed, signPub,
  };
}

let a: Id;
let b: Id;
let c: Id;
before(async () => {
  [a, b, c] = [await identity('alice'), await identity('bob'), await identity('carol', 'ed25519')];
});

test('a bound contact\'s key IS the key the private side extracts (byte for byte), for both ways the app can generate an identity', async () => {
  for (const id of [a, b, c]) {
    const got = (await signPubForContact(id.contact)) as Uint8Array;
    assert.equal(got.length, 32);
    assert.equal(bytesToHex(got), bytesToHex(id.signPub));
  }
});

test('the pairwise secret is SYMMETRIC: each side uses its own seed and the other side\'s key read from the book record', async () => {
  const fromA = deriveSharedSecret(a.seed, (await signPubForContact(b.contact)) as Uint8Array);
  const fromB = deriveSharedSecret(b.seed, (await signPubForContact(a.contact)) as Uint8Array);
  assert.equal(bytesToHex(fromA), bytesToHex(fromB));
  const ac = deriveSharedSecret(a.seed, (await signPubForContact(c.contact)) as Uint8Array);
  assert.notEqual(bytesToHex(fromA), bytesToHex(ac), 'bound to the pair');
});

test('BINDING: C\'s key presented with B\'s fingerprint (and B\'s post-quantum keys) is null', async () => {
  assert.equal(await signPubForContact({ ...b.contact, public_key: c.contact.public_key }), null);
});

test('BINDING: B\'s key with C\'s post-quantum keys, or with none, is null', async () => {
  assert.equal(await signPubForContact({ ...b.contact, pq_kem_public_key: c.contact.pq_kem_public_key, pq_sig_public_key: c.contact.pq_sig_public_key }), null);
  assert.equal(await signPubForContact({ ...b.contact, pq_kem_public_key: undefined, pq_sig_public_key: undefined }), null);
});

test('EXACT fingerprint: a respelling or a prefix of the right fingerprint is null (fingerprintMatchesKey alone would accept some of these)', async () => {
  const fp = b.contact.fingerprint;
  for (const bad of [fp.toUpperCase(), fp.slice(0, 40), fp.slice(0, 32), fp.slice(0, 16), ` ${fp}`, `${fp} `, `0x${fp}`, fp.replace(/^(.{8})/, '$1:'), fp.slice(0, 63), `${fp}0`, '']) {
    assert.equal(await signPubForContact({ ...b.contact, fingerprint: bad }), null, JSON.stringify(bad.slice(0, 12)) + '/' + bad.length);
  }
});

test('garbled input is null and never throws: truncated or garbage armor, an empty key, a missing field, a non-object', async () => {
  const k = b.contact.public_key;
  for (const bad of [k.slice(0, k.length >> 1), k.replace(/[A-Za-z0-9]{8}/, 'AAAAAAAA'), 'not a key', '', undefined as unknown as string, null as unknown as string]) {
    assert.equal(await signPubForContact({ ...b.contact, public_key: bad }), null);
  }
  for (const bad of [null, undefined, 5, 'x', {}] as unknown[]) assert.equal(await signPubForContact(bad as ContactKeyMaterial), null);
});

test('the unbound reader never throws either: garbage, empty, truncated armor and non-strings are null', async () => {
  const k = b.contact.public_key;
  for (const bad of ['', 'not a key', k.slice(0, k.length >> 1), '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----', 5 as unknown as string, null as unknown as string, undefined as unknown as string]) {
    assert.equal(await primaryEd25519PointOf(bad), null);
  }
  assert.equal(bytesToHex((await primaryEd25519PointOf(k)) as Uint8Array), bytesToHex(b.signPub), 'and it does read a good key');
});

test('PRIMARY KEY ONLY: an RSA primary with an Ed25519 subkey is null (and the subkey is never read)', async () => {
  const rsa = await generateKey({
    type: 'rsa', rsaBits: 2048, userIDs: [{ name: 'r', email: 'r@t.test' }], format: 'armored',
    subkeys: [{ type: 'ecc', curve: 'ed25519Legacy', sign: true }],
  } as never);
  assert.equal(await primaryEd25519PointOf(rsa.publicKey), null);
  assert.equal(await signPubForContact({ ...b.contact, public_key: rsa.publicKey }), null);
});

test('another curve is null: a P-256 primary', async () => {
  const p256 = await generateKey({ type: 'ecc', curve: 'nistP256', userIDs: [{ name: 'p', email: 'p@t.test' }], format: 'armored' });
  assert.equal(await primaryEd25519PointOf(p256.publicKey), null);
});

test('SMALL ORDER: the identity point, the order-2 point, and a point with a small-order component are not usable; a real key is', () => {
  const identityPt = new Uint8Array(32);
  identityPt[0] = 1;
  const order2 = Uint8Array.from([0xec, ...new Array(30).fill(0xff), 0x7f]);
  const real = ed25519.getPublicKey(a.seed);
  const mixed = ed25519.Point.fromBytes(real).add(ed25519.Point.fromBytes(order2)).toBytes();
  assert.equal(isUsableEd25519Point(identityPt), false);
  assert.equal(isUsableEd25519Point(new Uint8Array(32)), false);
  assert.equal(isUsableEd25519Point(order2), false);
  assert.equal(isUsableEd25519Point(mixed), false, 'a real point plus a small-order point has a torsion component');
  assert.equal(isUsableEd25519Point(new Uint8Array(32).fill(255)), false, 'not a point at all');
  assert.equal(isUsableEd25519Point(new Uint8Array(31)), false);
  assert.equal(isUsableEd25519Point(real), true);
});

test('the returned bytes are a copy: changing them does not change a later read', async () => {
  const first = (await signPubForContact(a.contact)) as Uint8Array;
  first.fill(0);
  assert.equal(bytesToHex((await signPubForContact(a.contact)) as Uint8Array), bytesToHex(a.signPub));
});

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (name === 'node_modules' || name === '.next') continue;
      sourceFiles(p, out);
    } else if (/\.(ts|tsx)$/.test(name) && !/\.test\.(ts|tsx)$/.test(name)) out.push(p);
  }
  return out;
}

test('GUARD: no other source file imports the unbound reader; the only way to a contact\'s signing key is signPubForContact', () => {
  const root = new URL('../../../', import.meta.url).pathname;
  const hits: string[] = [];
  for (const dir of ['src', 'app', 'scripts']) {
    let files: string[] = [];
    try { files = sourceFiles(join(root, dir)); } catch { continue; }
    for (const f of files) if (/primaryEd25519PointOf/.test(readFileSync(f, 'utf8'))) hits.push(f.slice(root.length));
  }
  assert.deepEqual(hits, ['src/lib/identity/raw-sign-public.ts']);
});
