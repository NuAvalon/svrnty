// src/lib/crypto/recovery-shards.test.ts
// The recovery pieces (Shamir shares of the master secret) were covered only by an un-run selftest. These are the gate-tier checks, written BEFORE the
// per-piece commitment (ledger task: recovery pieces as sealed notes). What they pin, and why:
//   R1  every M-subset (and every larger set, in any order) recombines to the secret
//   R2  fewer than M pieces NEVER give the secret (today: wrong bytes, no error; the check is "never the secret", so it survives a later throw)
//   R3  one flipped byte in a piece: every set that uses it misses the secret, every set that does not still recovers (Shamir has no integrity of its own)
//   R4  a piece from ANOTHER split (same secret or not) does not recombine
//   R5  the labels (index, threshold, identity_fingerprint) are not read by the RAW primitive reconstructFromShards: the real x-coordinate is inside `data`.
//       This is why a commitment must bind the label to the piece. The app path, recoverFromShards, now checks the labels against the vault's list and names
//       a relabelled piece (recovery-wiring.test.ts W2b); this test keeps documenting the primitive it is built on.
//   R6  duplicates and truncated pieces are refused
//   R7  createShards' guards and output shape
//   R8  the whole chain through a real vault: M good pieces open it, a bad piece among exactly M is refused (and named) and never returns a bundle
//   R9  restore with one bad piece among M+1: the information is there (subset search + the vault's own hash check finds the good M), and recoverFromShards
//       now does it (R9b), by the vault's list when it has one and by that search when it does not.
//       Two bad pieces among M+1 never recover (R9a, R9c), through one helper (flipTwoApart): the same byte flipped in both can cancel.
// Run: npx tsx --test src/lib/crypto/recovery-shards.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createShards, reconstructFromShards, createKeyVault, recoverFromShards, generateMasterSecret,
  type Shard, type PrivateKeyBundle, type KeyVault,
} from './recovery';

const FP = 'a'.repeat(64);
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const b64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));
const toB64 = (u: Uint8Array) => Buffer.from(u).toString('base64');

/** Every k-subset of 0..n-1, in order. */
function subsets(n: number, k: number): number[][] {
  const out: number[][] = [];
  const walk = (start: number, cur: number[]) => {
    if (cur.length === k) { out.push([...cur]); return; }
    for (let i = start; i < n; i++) { cur.push(i); walk(i + 1, cur); cur.pop(); }
  };
  walk(0, []);
  return out;
}
/** True only when the pieces recombine to `secret`. A throw counts as "does not recover". */
async function recovers(pieces: Shard[], secret: Uint8Array): Promise<boolean> {
  try { return sameBytes(await reconstructFromShards(pieces), secret); } catch { return false; }
}
/** The piece with one bit of one data byte flipped. */
function flip(piece: Shard, pos: number): Shard {
  const d = b64(piece.data);
  d[pos] ^= 1;
  return { ...piece, data: toB64(d) };
}
const pick = (all: Shard[], idx: number[]) => idx.map((i) => all[i]);
/** The first two pieces made bad, at DIFFERENT bytes (10 and 11). Shamir works byte by byte: with the SAME byte flipped in both, the two errors can cancel (about 0.8% of random
 *  splits, because each piece has a random x-coordinate) and the true secret comes back. At different bytes each byte has one bad piece and its error cannot cancel. */
const flipTwoApart = (pieces: Shard[]): Shard[] => pieces.map((p, i) => (i < 2 ? flip(p, 10 + i) : p));

const CONFIGS: Array<[n: number, m: number]> = [[5, 3], [4, 2], [6, 4], [3, 3]];

test('R1 every M-subset of N, and every larger set, in either order, recombines to the secret', async () => {
  for (const [n, m] of CONFIGS) {
    const secret = generateMasterSecret();
    const all = await createShards(secret, m, n, FP);
    for (let k = m; k <= n; k++) for (const s of subsets(n, k)) {
      assert.ok(await recovers(pick(all, s), secret), `N=${n} M=${m} subset ${s.join(',')}`);
      assert.ok(await recovers(pick(all, [...s].reverse()), secret), `N=${n} M=${m} reversed ${s.join(',')}`);
    }
  }
});

test('R2 fewer than M pieces never give the secret; one piece or none is refused', async () => {
  for (const [n, m] of CONFIGS) {
    const secret = generateMasterSecret();
    const all = await createShards(secret, m, n, FP);
    for (let k = 2; k < m; k++) for (const s of subsets(n, k)) {
      assert.equal(await recovers(pick(all, s), secret), false, `N=${n} M=${m}: ${k} pieces ${s.join(',')} must not recover`);
    }
  }
  const all = await createShards(generateMasterSecret(), 3, 5, FP);
  // OUR guard's own words, not the library's ("shares must have at least 2 ..."): the library refuses these too, so a loose match would hide our guard going.
  await assert.rejects(() => reconstructFromShards([all[0]]), { message: 'Need at least 2 shards to reconstruct' });
  await assert.rejects(() => reconstructFromShards([]), { message: 'Need at least 2 shards to reconstruct' });
});

test('R3 one flipped byte: every set that uses the piece misses the secret, every set that does not still recovers (all 33 bytes of the piece)', async () => {
  const [n, m] = [5, 3];
  const secret = generateMasterSecret();
  const all = await createShards(secret, m, n, FP);
  assert.equal(b64(all[0].data).length, 33, 'a piece is the 32 secret bytes plus the x-coordinate');
  const subs = subsets(n, m);
  for (const victim of [0, 2, 4]) for (let pos = 0; pos < 33; pos++) {
    const mangled = all.map((p, i) => (i === victim ? flip(p, pos) : p));
    for (const s of subs) {
      const ok = await recovers(pick(mangled, s), secret);
      assert.equal(ok, !s.includes(victim), `piece ${victim} byte ${pos}, subset ${s.join(',')}`);
    }
  }
});

test('R4 a piece from another split does not recombine, with the same secret or another one', async () => {
  const [n, m] = [5, 3];
  const secret = generateMasterSecret();
  const a = await createShards(secret, m, n, FP);
  for (const otherSecret of [secret, generateMasterSecret()]) {
    const b = await createShards(otherSecret, m, n, FP);
    for (const slot of [0, 1, 4]) {
      const mixed = a.map((p, i) => (i === slot ? b[i] : p));
      for (const s of subsets(n, m)) assert.equal(await recovers(pick(mixed, s), secret), !s.includes(slot), `foreign piece at ${slot}, subset ${s.join(',')}`);
    }
    // M-1 of one split plus one of another is not M of anything
    assert.equal(await recovers([a[0], a[1], b[2]], secret), false);
  }
});

test('R5 the RAW primitive reconstructFromShards reads only `data`: the index, threshold and identity labels are ignored (the app path checks them: see recovery-wiring.test.ts)', async () => {
  const secret = generateMasterSecret();
  const all = await createShards(secret, 3, 5, FP);
  const relabelled = pick(all, [0, 2, 4]).map((p, i) => ({ ...p, index: 90 + i, threshold: 2, identity_fingerprint: 'b'.repeat(64) }));
  assert.ok(await recovers(relabelled, secret), 'wrong labels still recover: nothing authenticates them yet');
  assert.deepEqual(all.map((p) => p.index), [1, 2, 3, 4, 5]);
  assert.ok(all.every((p) => p.threshold === 3 && p.identity_fingerprint === FP), 'the labels are carried as written');
});

test('R6 the same piece twice, and a truncated piece, are refused', async () => {
  const all = await createShards(generateMasterSecret(), 3, 5, FP);
  await assert.rejects(() => reconstructFromShards([all[0], all[0], all[1]]));
  const short = { ...all[1], data: toB64(b64(all[1].data).subarray(0, 20)) };
  await assert.rejects(() => reconstructFromShards([all[0], short, all[2]]));
  const longer = { ...all[1], data: toB64(new Uint8Array([...b64(all[1].data), 7])) };
  await assert.rejects(() => reconstructFromShards([all[0], longer, all[2]]));
});

test('R7 createShards: its guards, its output shape, and fresh randomness each split', async () => {
  const s = generateMasterSecret();
  await assert.rejects(() => createShards(s, 1, 3, FP), { message: 'Threshold must be at least 2' });
  await assert.rejects(() => createShards(s, 4, 3, FP), { message: 'Total shares must be >= threshold' });
  await assert.rejects(() => createShards(s, 2, 256, FP), { message: 'Maximum 255 shares' });
  assert.equal((await createShards(s, 2, 255, FP)).length, 255);
  assert.equal((await createShards(s, 2, 2, FP)).length, 2, 'N == M is allowed');
  const a = await createShards(s, 3, 5, FP);
  const b = await createShards(s, 3, 5, FP);
  assert.deepEqual(a.map((p) => p.index), [1, 2, 3, 4, 5]);
  assert.equal(new Set(a.map((p) => p.data)).size, 5, 'five different pieces');
  assert.ok(a.every((p, i) => p.data !== b[i].data), 'a second split of the same secret shares no piece with the first');
  assert.equal(await recovers(a.slice(0, 3), new Uint8Array(32)), false, 'and a piece set is not the all-zero secret');
});

const BUNDLE: PrivateKeyBundle = {
  classical_private_key: '-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----',
  classical_passphrase: 'p', pq_signing_secret_key: 'c2lnbg==', pq_kem_secret_key: 'a2Vt',
};

test('R8 through a real vault: every M good pieces open it; a bad piece among exactly M is refused and never returns a bundle; M-1 never does', async () => {
  const [n, m] = [5, 3];
  const { vault, shards } = await createKeyVault(BUNDLE, m, n, FP);
  for (const s of subsets(n, m)) assert.deepEqual(await recoverFromShards(vault, pick(shards, s)), BUNDLE, `subset ${s.join(',')}`);
  for (const s of subsets(n, m)) {
    const mangled = pick(shards, s).map((p, i) => (i === 0 ? flip(p, 3) : p));
    await assert.rejects(() => recoverFromShards(vault, mangled), (e: unknown) => (e as { code?: string }).code === 'recovery-pieces-insufficient', `bad piece in ${s.join(',')}`);
  }
  for (const s of subsets(n, m - 1)) await assert.rejects(() => recoverFromShards(vault, pick(shards, s)), `${m - 1} pieces ${s.join(',')}`);
});

/** What the wiring stage must do, stated with today's primitives: try the M-subsets of what was handed in, keep the one the vault's own hash accepts. */
async function recoverBySubsetSearch(vault: KeyVault, pieces: Shard[], m: number): Promise<PrivateKeyBundle> {
  let last: unknown = new Error('no pieces');
  for (const s of subsets(pieces.length, m)) {
    try { return await recoverFromShards(vault, pick(pieces, s)); } catch (e) { last = e; }
  }
  throw last;
}

test('R9a the information is there: M+1 pieces with one bad still restore by subset search (every position of the bad piece)', async () => {
  const [n, m] = [5, 3];
  const { vault, shards } = await createKeyVault(BUNDLE, m, n, FP);
  for (const s of subsets(n, m + 1)) for (let bad = 0; bad < s.length; bad++) {
    const handed = pick(shards, s).map((p, i) => (i === bad ? flip(p, 10) : p));
    assert.deepEqual(await recoverBySubsetSearch(vault, handed, m), BUNDLE, `subset ${s.join(',')} bad ${bad}`);
  }
  // and with TWO bad among M+1 there is no good M left: it must fail, not return something (flipTwoApart: why the bytes differ)
  const two = flipTwoApart(pick(shards, [0, 1, 2, 3]));
  await assert.rejects(() => recoverBySubsetSearch(vault, two, m));
});

test('R9c two bad pieces among M+1 never give the secret, over 1000 fresh splits (flipTwoApart: its errors cannot cancel; with the same byte flipped they do about 0.8% of the time)', async () => {
  const [n, m] = [5, 3];
  for (let k = 0; k < 1000; k++) {
    const secret = generateMasterSecret();
    const two = flipTwoApart(pick(await createShards(secret, m, n, FP), [0, 1, 2, 3]));
    for (const sub of subsets(4, m)) assert.equal(await recovers(pick(two, sub), secret), false, `split ${k}, pieces ${sub.join(',')}`);
  }
});

test('R9b recoverFromShards itself restores from M+1 pieces with one bad', async () => {
  const { vault, shards } = await createKeyVault(BUNDLE, 3, 5, FP);
  const handed = pick(shards, [0, 1, 2, 3]).map((p, i) => (i === 1 ? flip(p, 10) : p));
  assert.deepEqual(await recoverFromShards(vault, handed), BUNDLE);
});
