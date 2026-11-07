// The epoch-note seam built from its parts, end to end with real keys and real note crypto: a note a real contact sealed for us is adopted; every
// other case lands on the safe side. Run: npx tsx --test src/lib/sync/epoch-seam.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { extractRawSign } from '@/lib/identity/raw-sign';
import { mintCanonicalFingerprint } from '@/lib/identity/fingerprint';
import { generatePQKeypairBundle, uint8ToBase64 } from '@/lib/crypto/pq';
import { deriveSharedSecret } from '@/lib/crypto/mutual-trust';
import { signPubForContact } from '@/lib/identity/raw-sign-public';
import { buildEpochNote } from '@/lib/trust/psi-epoch-note';
import { buildEpochSealedPlaintext } from '@/lib/trust/psi-epoch-sealed';
import { restoreEpochRecord } from '@/lib/trust/psi-epoch-book';
import { createPairSecretCache } from '@/lib/trust/psi-pair-secret-cache';
import { buildPsiEpochAdoption, type ContactRecord } from '@/lib/identity/client-store';
import { UnlockCycleEnded, makeUnlockCycle } from '@/lib/crypto/unlock-cycle';
import { buildEpochSeam, installEpochSeam, openEpochPackage, ownerSeedFromCycle, type EpochSeamDeps } from './epoch-seam';

interface Id { fp: string; seed: Uint8Array; record: ContactRecord; privateKey: string; passphrase: string }

async function identity(name: string): Promise<Id> {
  const passphrase = `pw-${name}`;
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'ed25519Legacy', userIDs: [{ name, email: `${name}@t.test` }], passphrase, format: 'armored' });
  const decrypted = await decryptKey({ privateKey: await readPrivateKey({ armoredKey: privateKey }), passphrase });
  const pq = generatePQKeypairBundle();
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: decrypted, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  const { seed } = extractRawSign(decrypted);
  return {
    fp: fingerprint, seed, privateKey, passphrase,
    record: {
      id: `c-${name}`, owner_fingerprint: 'owner', fingerprint, name, email: '', public_key: publicKey, trust_level: 'unverified', added_at: 't',
      pq_kem_public_key: uint8ToBase64(pq.kem.publicKey), pq_sig_public_key: uint8ToBase64(pq.signing.publicKey),
    } as ContactRecord,
  };
}

let me: Id;
let x: Id;
let y: Id;
before(async () => {
  [me, x, y] = [await identity('me'), await identity('x'), await identity('y')];
});

const NOW = 29_000_000;
const field = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (n + i) % 256);

async function noteFrom(sender: Id, epoch = NOW * 2 ** 20 + 1, claim = sender.fp): Promise<Uint8Array> {
  const sPair = deriveSharedSecret(sender.seed, (await signPubForContact(me.record)) as Uint8Array);
  const wire = buildEpochNote({ sPair, fpSender: sender.fp, fpReceiver: me.fp, epoch, know: field(1), trust: field(2) });
  return buildEpochSealedPlaintext(wire, claim);
}

function world(over: { on?: boolean; records?: ContactRecord[]; seed?: Uint8Array | null; blocked?: string[] } = {}) {
  const book = new Map<string, ContactRecord>();
  for (const r of over.records ?? [x.record, y.record]) book.set(r.fingerprint, { ...r, ...(over.blocked?.includes(r.fingerprint) ? { blocked: true } : {}) });
  const store = new Map<string, ContactRecord>([...book.values()].map((r) => [r.id, r]));
  const seeds: Uint8Array[] = [];
  const log = { lookups: 0, seedCalls: 0, adopts: 0 };
  const deps: EpochSeamDeps = {
    ownerFp: me.fp,
    receiveOn: over.on !== false,
    openPackage: async (blob) => (blob === 'PKG' ? new Uint8Array(0) : null),
    getContactByFingerprint: async (_o, fp) => { log.lookups++; return book.get(fp) ?? null; },
    ownerSeed: async () => {
      log.seedCalls++;
      if (over.seed === null) return null;
      const s = (over.seed ?? me.seed).slice();
      seeds.push(s);
      return s;
    },
    cache: createPairSecretCache(() => {}),
    nowMinutes: () => NOW,
    adopt: async (id, decide) => {
      log.adopts++;
      const rec = store.get(id) as ContactRecord;
      const next = buildPsiEpochAdoption(rec, decide);
      if (next === null) return { applied: false };
      store.set(id, next);
      return { applied: true };
    },
  };
  return { deps, log, seeds, store, held: (id: string) => store.get(id)?.psi_epoch as string | undefined };
}

test('END TO END: a note a real contact sealed for us is adopted, and the stored record holds its epoch', async () => {
  const w = world();
  const seam = buildEpochSeam(w.deps);
  assert.deepEqual(await seam.receive(await noteFrom(x)), { kind: 'adopted' });
  assert.equal(restoreEpochRecord(w.held('c-x'))?.cur.e, NOW * 2 ** 20 + 1);
  assert.equal(w.held('c-y'), undefined, 'and nothing else changed');
});

test('open is the injected opener: it hands back the package\'s plaintext, or null for anything it cannot open', async () => {
  const seam = buildEpochSeam(world().deps);
  assert.ok((await seam.open('PKG')) instanceof Uint8Array);
  assert.equal(await seam.open('something else'), null);
});

test('the signing seed is fetched only on a cache miss, and zeroed straight after the derivation', async () => {
  const w = world();
  const seam = buildEpochSeam(w.deps);
  await seam.receive(await noteFrom(x, NOW * 2 ** 20 + 1));
  assert.equal(w.log.seedCalls, 1);
  assert.ok(w.seeds.every((s) => s.every((b) => b === 0)), 'the copy the seam was given is zeroed');
  await seam.receive(await noteFrom(x, NOW * 2 ** 20 + 2));
  assert.equal(w.log.seedCalls, 1, 'the second note is served from the cache: no second seed');
  assert.equal(w.deps.cache.size(), 1);
});

test('the cache is keyed by the contact\'s signing key: the same contact id under a different bound key derives afresh', async () => {
  const w = world();
  const seam = buildEpochSeam(w.deps);
  await seam.receive(await noteFrom(x));
  assert.equal(w.log.seedCalls, 1);
  // a second seam over the same cache where the contact id now carries another valid identity's material
  const rotated = { ...y.record, id: x.record.id };
  const w2 = world({ records: [rotated] });
  const seam2 = buildEpochSeam({ ...w2.deps, cache: w.deps.cache });
  await seam2.receive(await noteFrom(y));
  assert.equal(w2.log.seedCalls, 1, 'a different peer key under the same id is a miss, so the seed is needed again');
  assert.equal(w.deps.cache.size(), 2);
});

test('a key that is not the contact\'s (the record carries Y\'s key under X\'s fingerprint) is UNVERIFIED: no secret, no seed, nothing written', async () => {
  const forged = { ...x.record, public_key: y.record.public_key };
  const w = world({ records: [forged, y.record] });
  assert.deepEqual(await buildEpochSeam(w.deps).receive(await noteFrom(x)), { kind: 'unverified' });
  assert.equal(w.log.seedCalls, 0);
  assert.equal(w.log.adopts, 0);
});

test('no seed (locked, cycle ended) is UNVERIFIED, never a bad-MAC record and never adopted', async () => {
  const w = world({ seed: null });
  assert.deepEqual(await buildEpochSeam(w.deps).receive(await noteFrom(x)), { kind: 'unverified' });
  assert.equal(w.log.adopts, 0);
});

test('a seed that makes the derivation THROW (wrong length) is UNVERIFIED (defence in depth beside the point checks), and is still zeroed', async () => {
  const w = world({ seed: new Uint8Array(5) });
  assert.deepEqual(await buildEpochSeam(w.deps).receive(await noteFrom(x)), { kind: 'unverified' });
  assert.equal(w.log.adopts, 0);
  assert.ok(w.seeds.every((s) => s.every((b) => b === 0)));
});

test('a blocked contact is dropped before the seed is touched', async () => {
  const w = world({ blocked: [x.fp] });
  assert.deepEqual(await buildEpochSeam(w.deps).receive(await noteFrom(x)), { kind: 'blocked-drop' });
  assert.equal(w.log.seedCalls, 0);
  assert.equal(w.held('c-x'), undefined);
});

test('a sender not in the book is unverified; the seed is not touched', async () => {
  const w = world({ records: [y.record] });
  assert.deepEqual(await buildEpochSeam(w.deps).receive(await noteFrom(x)), { kind: 'unverified' });
  assert.equal(w.log.seedCalls, 0);
});

test('REPLAY: X\'s valid note claiming to be Y is a bad MAC, and nothing is written for either', async () => {
  const w = world();
  assert.deepEqual(await buildEpochSeam(w.deps).receive(await noteFrom(x, undefined, y.fp)), { kind: 'bad-mac' });
  assert.equal(w.held('c-x'), undefined);
  assert.equal(w.held('c-y'), undefined);
});

test('F1 off: nothing is looked up, no seed is fetched, nothing is written', async () => {
  const w = world({ on: false });
  assert.deepEqual(await buildEpochSeam(w.deps).receive(await noteFrom(x)), { kind: 'benign-ack' });
  assert.deepEqual(w.log, { lookups: 0, seedCalls: 0, adopts: 0 });
});

test('two notes from two different contacts handled at the same time each use THEIR OWN contact\'s record (the secret follows the contact id, not the latest lookup)', async () => {
  const w = world();
  const seam = buildEpochSeam(w.deps);
  const [nx, ny] = [await noteFrom(x), await noteFrom(y)]; // build both first, so the two receives really overlap
  const [rx, ry] = await Promise.all([seam.receive(nx), seam.receive(ny)]);
  assert.deepEqual(rx, { kind: 'adopted' });
  assert.deepEqual(ry, { kind: 'adopted' });
  assert.notEqual(w.held('c-x'), undefined);
  assert.notEqual(w.held('c-y'), undefined);
  assert.equal(w.deps.cache.size(), 2);
});

test('SAME CONTACT, TWO NOTES AT ONCE, with the book answering R1 then R2: each note derives from the record ITS lookup returned', async () => {
  const w = world();
  const good = x.record;
  const unbound = { ...x.record, public_key: y.record.public_key }; // the same contact after a (bad) change: Y's key under X's fingerprint
  const answers = [good, unbound];
  let n = 0;
  const seam = buildEpochSeam({ ...w.deps, getContactByFingerprint: async () => { const rec = answers[n++] ?? unbound; await Promise.resolve(); return rec; } });
  const [nx1, nx2] = [await noteFrom(x, NOW * 2 ** 20 + 1), await noteFrom(x, NOW * 2 ** 20 + 2)];
  const [r1, r2] = await Promise.all([seam.receive(nx1), seam.receive(nx2)]);
  assert.deepEqual(r1, { kind: 'adopted' }, 'note 1 used R1, the record its own lookup returned');
  assert.deepEqual(r2, { kind: 'unverified' }, 'note 2 used R2, which does not bind to the fingerprint');
});

test('openEpochPackage: not an envelope is null; bytes come back as bytes; a package that does not open (any ordinary error) is null, not a throw', async () => {
  const pkg = { v: 1 };
  assert.equal(await openEpochPackage('x', { asPackage: () => null, open: async () => new Uint8Array(3) }), null);
  assert.deepEqual(await openEpochPackage('x', { asPackage: () => pkg, open: async () => Uint8Array.of(1, 2, 3) }), Uint8Array.of(1, 2, 3));
  assert.equal(await openEpochPackage('x', { asPackage: () => pkg, open: async () => null }), null);
  assert.equal(await openEpochPackage('x', { asPackage: () => pkg, open: async () => { throw new Error('wrong key / corrupt'); } }), null, 'a malformed package is not a poison pill');
});

test('openEpochPackage: an ENDED unlock cycle is rethrown (cannot tell), never turned into "not an epoch package"', async () => {
  await assert.rejects(openEpochPackage('x', { asPackage: () => ({}), open: async () => { throw new UnlockCycleEnded(); } }), UnlockCycleEnded);
});

test('installEpochSeam: with the switch off nothing is BUILT and nothing is returned; only exactly true installs it', () => {
  let built = 0;
  const build = () => { built++; return buildEpochSeam(world().deps); };
  for (const off of [false, undefined, null, 0, 1, 'true', {}] as unknown[]) {
    assert.equal(installEpochSeam(off as boolean, build), undefined, String(off));
  }
  assert.equal(built, 0, 'the builder was never called while off');
  assert.ok(installEpochSeam(true, build));
  assert.equal(built, 1);
});

test('GUARD: the seam builder never names the epoch field', () => {
  const src = readFileSync(new URL('./epoch-seam.ts', import.meta.url), 'utf8').replace(/^\s*(\/\/|\*|\/\*).*$/gm, '');
  assert.doesNotMatch(src, /psi_epoch|PSI_EPOCH_FIELD|adoptPsiEpoch|buildPsiEpochAdoption/);
});

test('NEG: after an epoch derive the cycle\'s key is intact: a second extractRawSign on the SAME cycle still passes its seed/signPub invariant and returns the same seed', async () => {
  const cycle = makeUnlockCycle(me.privateKey, me.passphrase);
  try {
    const w = world();
    const seam = buildEpochSeam({ ...w.deps, ownerSeed: ownerSeedFromCycle(cycle) });
    assert.deepEqual(await seam.receive(await noteFrom(x)), { kind: 'adopted' }, 'control: the derive ran through the real cycle');
    const again = extractRawSign(await cycle.key()); // throws "seed<->signPub mismatch" if the derive zeroed the key's own seed
    assert.deepEqual([...again.seed], [...me.seed]);
  } finally {
    cycle.drop();
  }
});

test('an ended cycle gives no seed: the secret cannot be derived and nothing is adopted', async () => {
  const cycle = makeUnlockCycle(me.privateKey, me.passphrase);
  cycle.drop();
  const w = world();
  const seam = buildEpochSeam({ ...w.deps, ownerSeed: ownerSeedFromCycle(cycle) });
  assert.deepEqual(await seam.receive(await noteFrom(x)), { kind: 'unverified' });
  assert.equal(w.log.adopts, 0);
});
