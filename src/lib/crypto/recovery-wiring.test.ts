// src/lib/crypto/recovery-wiring.test.ts
// Stage 3a of the recovery-pieces work: the commitment list lives in the vault OUTER (vault.shamir.pieces, readable without the passphrase, so a person who lost
// the device still has it with the backup file), and recoverFromShards checks the pieces against it BEFORE combining. Written BEFORE the code.
// The one rule behind every test: the vault's own master_secret_hash is the FINAL authority. A list (or a threshold, or anything else in the outer, which comes
// from a file that can be tampered with) can only MISCLASSIFY pieces. It can never make a wrong secret pass, and a wrong bundle is never returned.
//   W1  createKeyVault writes the list; it commits to exactly the pieces it made and carries no piece data
//   W2  the checked path: every M-subset opens it; M+1 with one bad opens it (the R9b target); a bad, relabelled or foreign piece is named by index and reason
//   W3  a FORGED list, a forged threshold, a garbage outer: restore refuses or opens with the RIGHT bundle; never a wrong one
//   W4  a legacy vault (no list): the same recoveries by subset search on the vault hash, capped; past the cap it refuses and says so, never tries fewer
//   W5  attachPieceCommitments (existing identities): idempotent, never overwrites, refuses unless the held pieces open the vault, writes nothing otherwise
//   W6  refusals name index + reason only, never piece data or a commitment value; no screen calls recoverFromShards yet, and the day one does this fails
// Run: npx tsx --test src/lib/crypto/recovery-wiring.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  createKeyVault, recoverFromShards, checkPieces, attachPieceCommitments, MAX_SUBSET_SEARCH,
  RecoveryPiecesRefused, type KeyVault, type PrivateKeyBundle, type Shard,
} from './recovery';
import { commitSet, commitPiece, parseCommitments, newSetId } from './recovery-commit';

const FP = 'a'.repeat(64);
const BUNDLE: PrivateKeyBundle = {
  classical_private_key: '-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----',
  classical_passphrase: 'p', pq_signing_secret_key: 'c2lnbg==', pq_kem_secret_key: 'a2Vt',
};
const b64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));
const toB64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
const flip = (p: Shard, pos = 10): Shard => { const d = b64(p.data); d[pos] ^= 1; return { ...p, data: toB64(d) }; };
const pick = (all: Shard[], idx: number[]) => idx.map((i) => all[i]);
const code = (e: unknown) => (e as { code?: string }).code;
const withoutList = (v: KeyVault): KeyVault => { const { pieces: _p, ...rest } = v.shamir; void _p; return { ...v, shamir: rest }; };
const withList = (v: KeyVault, pieces: unknown): KeyVault => ({ ...v, shamir: { ...v.shamir, pieces } as KeyVault['shamir'] });
async function made(m = 3, n = 5) { return createKeyVault(BUNDLE, m, n, FP); }
function subsets(n: number, k: number): number[][] {
  const out: number[][] = []; const walk = (s: number, cur: number[]) => { if (cur.length === k) { out.push([...cur]); return; } for (let i = s; i < n; i++) { cur.push(i); walk(i + 1, cur); cur.pop(); } };
  walk(0, []); return out;
}
/** Never a wrong bundle: either the right one comes back or it refuses. Returns the refusal's code (or 'ok'). */
async function outcome(vault: KeyVault, pieces: Shard[]): Promise<string> {
  try { assert.deepEqual(await recoverFromShards(vault, pieces), BUNDLE, 'a bundle came back that is not the right one'); return 'ok'; } catch (e) {
    if (e instanceof assert.AssertionError) throw e;
    return code(e) ?? 'threw';
  }
}

test('W1 createKeyVault writes the list into the vault outer: it commits to exactly the pieces it made, and holds no piece data', async () => {
  const { vault, shards } = await made(3, 5);
  const list = parseCommitments(vault.shamir.pieces);
  assert.ok(list, 'the list is in the exact stored shape');
  assert.deepEqual(Object.keys(list!.commitments).sort(), ['1', '2', '3', '4', '5']);
  for (const s of shards) assert.equal(list!.commitments[String(s.index)], commitPiece(list!.set_id, s.index, s.data));
  assert.equal(vault.shamir.threshold, 3);
  assert.equal(vault.shamir.total_shares, 5);
  const json = JSON.stringify(vault);
  for (const s of shards) assert.equal(json.includes(s.data), false, 'no piece in the vault outer');
  const second = await made(3, 5);
  assert.notEqual(second.vault.shamir.pieces!.set_id, list!.set_id, 'a fresh set id for every split');
});

test('W2 the checked path: every M-subset opens it; M+1 with ONE BAD opens it (R9b, now a pass); fewer than M refuses and names what it saw', async () => {
  const { vault, shards } = await made(3, 5);
  for (let k = 3; k <= 5; k++) for (const s of subsets(5, k)) assert.equal(await outcome(vault, pick(shards, s)), 'ok', `subset ${s.join(',')}`);
  for (const s of subsets(5, 4)) for (let bad = 0; bad < 4; bad++) {
    const handed = pick(shards, s).map((p, i) => (i === bad ? flip(p) : p));
    assert.equal(await outcome(vault, handed), 'ok', `M+1 ${s.join(',')} bad ${bad}`);
  }
  for (const s of subsets(5, 2)) assert.equal(await outcome(vault, pick(shards, s)), 'recovery-pieces-insufficient', `2 pieces ${s.join(',')}`);
  assert.equal(await outcome(vault, []), 'recovery-pieces-insufficient');
  // a bad piece among exactly M: refused with a typed refusal, and checkPieces NAMES the piece (index + reason), which the old restore could not
  const handed = pick(shards, [0, 1, 2]).map((p, i) => (i === 1 ? flip(p) : p));
  await assert.rejects(() => recoverFromShards(vault, handed), (e: unknown) => e instanceof RecoveryPiecesRefused && (e as RecoveryPiecesRefused).code === 'recovery-pieces-insufficient');
  const named = checkPieces(vault, handed);
  assert.deepEqual([named.listed, named.good.map((p) => p.index), named.bad], [true, [1, 3], [{ index: 2, reason: 'mismatch' }]]);
});

test('W2b (R5 flipped) the checked path NAMES a relabelled, foreign or repeated piece and never counts it as good; the vault hash, not the label, decides a restore', async () => {
  const { vault, shards } = await made(3, 5);
  const other = await made(3, 5);
  for (const label of [4, 5, 9, 255]) {
    const relabelled = { ...shards[0], index: label };
    // one real piece and one relabelled: too few to open it, refused, and checkPieces names the relabelled one (the old restore could not)
    await assert.rejects(() => recoverFromShards(vault, [relabelled, shards[1]]), (e: unknown) => e instanceof RecoveryPiecesRefused);
    assert.deepEqual(checkPieces(vault, [relabelled, shards[1]]).bad, [{ index: label, reason: label > 5 ? 'unknown-index' : 'mismatch' }], `label ${label}`);
    // M real pieces + a relabelled one: opens it, the relabelled one is just not counted
    assert.equal(await outcome(vault, [relabelled, shards[1], shards[2], shards[3]]), 'ok', `label ${label}`);
  }
  // exactly M, one of them genuine bytes under the wrong label: the label is not what protects the secret, the vault hash is, and it passes
  assert.equal(await outcome(vault, [{ ...shards[0], index: 4 }, shards[1], shards[2]]), 'ok', 'right bytes, wrong label, exactly M: the hash proves the secret');
  // a piece of ANOTHER split of the same identity: named, and it does not count toward M
  await assert.rejects(() => recoverFromShards(vault, [shards[0], shards[1], other.shards[2]]), (e: unknown) => e instanceof RecoveryPiecesRefused);
  assert.deepEqual(checkPieces(vault, [shards[0], shards[1], other.shards[2]]).bad, [{ index: 3, reason: 'mismatch' }]);
  assert.equal(await outcome(vault, [shards[0], shards[1], other.shards[2], shards[3]]), 'ok');
  // the same piece handed three times is one piece, and the repeats are named
  await assert.rejects(() => recoverFromShards(vault, [shards[0], shards[0], shards[0]]), (e: unknown) => e instanceof RecoveryPiecesRefused);
  assert.deepEqual(checkPieces(vault, [shards[0], shards[0], shards[0]]).bad, [{ index: 1, reason: 'duplicate' }, { index: 1, reason: 'duplicate' }]);
  assert.equal(await outcome(vault, [shards[0], shards[0], shards[1], shards[2]]), 'ok');
});

test('W3a a FORGED list that marks a bad piece good: the vault hash still refuses, or the right bundle comes back by the fallback; never a wrong one', async () => {
  const { vault, shards } = await made(3, 5);
  const setId = newSetId();
  const bad = flip(shards[1]);
  // the attacker commits to the corrupted piece, so the list says every piece is good
  const forged = withList(vault, commitSet(setId, shards.map((p) => (p.index === 2 ? bad : p))));
  assert.equal(await outcome(forged, [shards[0], bad, shards[2]]), 'recovery-code-wrong', 'exactly M, one bad, list lies: refuse by the vault hash');
  assert.equal(await outcome(forged, [shards[0], bad, shards[2], shards[3]]), 'ok', 'M+1: the fallback finds the good M by the vault hash');
  assert.equal(await outcome(forged, [shards[0], shards[1], shards[2]]), 'ok', 'good pieces the forged list calls bad still open it');
  // a list that marks GOOD pieces bad (denial: it commits to corrupted copies of every piece): the hash fallback still opens it
  const denial = withList(vault, commitSet(setId, shards.map((p) => flip(p, 3))));
  for (const s of subsets(5, 3)) assert.equal(await outcome(denial, pick(shards, s)), 'ok', `denial list, subset ${s.join(',')}`);
});

test('W3b a garbage or substituted outer: a list that does not parse is no list; a forged threshold never yields a wrong bundle', async () => {
  const { vault, shards } = await made(3, 5);
  const good4 = [shards[0], flip(shards[1]), shards[2], shards[3]];
  const garbageLists: unknown[] = [null, 'x', 7, [], {}, { v: 2 }, { v: 1, set_id: 'zz', commitments: {} }, { ...vault.shamir.pieces, extra: 1 }];
  for (const g of garbageLists) assert.equal(await outcome(withList(vault, g), good4), 'ok', `garbage list ${JSON.stringify(g)?.slice(0, 40)}`);
  for (const t of [1, 0, -1, 2, 4, 5, 255, 256, 1.5, NaN, Infinity, '3', null, undefined]) {
    const forged = { ...vault, shamir: { ...vault.shamir, threshold: t as number } };
    await outcome(forged, pick(shards, [0, 1, 2, 3, 4])); // ok or a refusal: outcome() itself fails the test on a wrong bundle
    const withBad = await outcome(forged, [shards[0], flip(shards[1]), shards[2]]);
    assert.notEqual(withBad, 'ok', `threshold ${String(t)} with a bad piece among exactly M must refuse`);
  }
  assert.equal(await outcome({ ...vault, master_secret_hash: 'f'.repeat(64) }, pick(shards, [0, 1, 2])), 'recovery-code-wrong', 'a vault whose hash is not the secret\'s: nothing opens it');
});

test('W4 a legacy vault (no list): the same recoveries by subset search on the vault hash, capped, and refused past the cap without trying fewer', async () => {
  const { vault, shards } = await made(3, 5);
  const legacy = withoutList(vault);
  for (const s of subsets(5, 3)) assert.equal(await outcome(legacy, pick(shards, s)), 'ok');
  for (const s of subsets(5, 4)) for (let bad = 0; bad < 4; bad++) assert.equal(await outcome(legacy, pick(shards, s).map((p, i) => (i === bad ? flip(p) : p))), 'ok');
  assert.equal(await outcome(legacy, [shards[0], flip(shards[1]), shards[2]]), 'recovery-code-wrong', 'exactly M with one bad: the old answer, by code');
  assert.equal(await outcome(legacy, pick(shards, [0, 1])), 'recovery-pieces-insufficient');
  assert.equal(await outcome(legacy, [shards[0], shards[0], shards[0]]), 'recovery-pieces-insufficient', 'one piece handed three times is one piece');
  assert.equal(await outcome(legacy, [shards[0], shards[0], shards[1], shards[2]]), 'ok', 'repeats are ignored, three distinct pieces open it');
  assert.equal(MAX_SUBSET_SEARCH, 1000);
  // C(12,6) = 924 <= 1000 is searched; C(13,6) = 1716 > 1000 is refused up front
  const twelve = await made(6, 12);
  const l12 = withoutList(twelve.vault);
  assert.equal(await outcome(l12, twelve.shards.map((p, i) => (i === 7 ? flip(p) : p))), 'ok', 'a search of 924 subsets finds the good six');
  const thirteen = await made(6, 13);
  const l13 = withoutList(thirteen.vault);
  assert.equal(await outcome(l13, thirteen.shards.map((p, i) => (i === 7 ? flip(p) : p))), 'recovery-pieces-search-too-large', 'past the cap: refuse and say so');
  assert.equal(await outcome(l13, thirteen.shards), 'ok', 'no bad piece: the one combine of everything needs no search, so the cap does not apply');
});

test('W4c repeats do not inflate the search: many copies of a few pieces are still a few pieces (the cap counts distinct pieces)', async () => {
  const { vault, shards } = await made(6, 7);
  const legacy = withoutList(vault);
  // 7 distinct pieces, one of them bad, plus 7 more repeats of good ones: 14 handed, 7 distinct. C(14,6) = 3003 would be refused; C(7,6) = 7 is searched.
  const handed = [...shards.map((p, i) => (i === 3 ? flip(p) : p)), ...shards.filter((_, i) => i !== 3).slice(0, 5), shards[0], shards[1]];
  assert.equal(handed.length, 14);
  assert.equal(await outcome(legacy, handed), 'ok');
});

test('W5 attachPieceCommitments (existing identities): idempotent, never overwrites, refuses unless the held pieces open the vault, and writes nothing otherwise', async () => {
  const { vault, shards } = await made(3, 5);
  const legacy = withoutList(vault);
  const before = JSON.stringify(legacy);
  const r = attachPieceCommitments(legacy, shards);
  assert.equal(JSON.stringify(legacy), before, 'the input vault is not mutated');
  assert.equal((await r).ok, true);
  const attached = (await r) as { ok: true; vault: KeyVault; attached: boolean };
  assert.equal(attached.attached, true);
  const list = parseCommitments(attached.vault.shamir.pieces);
  assert.ok(list);
  for (const s of shards) assert.equal(list!.commitments[String(s.index)], commitPiece(list!.set_id, s.index, s.data));
  assert.equal(attached.vault.master_secret_hash, legacy.master_secret_hash);
  assert.equal(await outcome(attached.vault, [shards[0], flip(shards[1]), shards[2], shards[3]]), 'ok', 'and the attached vault now names a bad piece');
  // idempotent: a second attach changes nothing
  const again = (await attachPieceCommitments(attached.vault, shards)) as { ok: true; vault: KeyVault; attached: boolean };
  assert.equal(again.ok, true);
  assert.equal(again.attached, false);
  assert.equal(JSON.stringify(again.vault), JSON.stringify(attached.vault));
  // never overwrites an existing list, even when the pieces held are different: the first list stays
  const otherSplit = (await made(3, 5)).shards;
  const keep = (await attachPieceCommitments(attached.vault, otherSplit)) as { ok: true; vault: KeyVault; attached: boolean };
  assert.equal(keep.ok, true);
  assert.equal(keep.attached, false);
  assert.equal(JSON.stringify(keep.vault.shamir.pieces), JSON.stringify(attached.vault.shamir.pieces));
  // M pieces open the vault, but a list over only some labels would call the other holders' pieces unknown: refuse until ALL of them are held
  const incomplete = (await attachPieceCommitments(legacy, pick(shards, [0, 1, 2]))) as { ok: boolean; reason?: string; vault?: unknown };
  assert.deepEqual([incomplete.ok, incomplete.reason, incomplete.vault], [false, 'pieces-incomplete', undefined]);
  // an existing list that does not parse is NOT overwritten either: refuse, so a damaged restore record is looked at
  const junk = (await attachPieceCommitments(withList(legacy, { v: 1, junk: true }), shards)) as { ok: false; reason: string };
  assert.deepEqual([junk.ok, junk.reason], [false, 'existing-list-unreadable']);
  // refuses, and returns no vault, when the held pieces do not recombine to the vault's master_secret_hash
  for (const [name, held] of [['a bad piece', [shards[0], flip(shards[1]), shards[2], shards[3], shards[4]]], ['too few', pick(shards, [0, 1])], ['another identity\'s pieces', otherSplit], ['none', []]] as const) {
    const res = (await attachPieceCommitments(legacy, held as Shard[])) as { ok: boolean; reason?: string; vault?: unknown };
    assert.equal(res.ok, false, name);
    assert.equal(res.reason, 'pieces-do-not-open-vault', name);
    assert.equal(res.vault, undefined, `${name}: nothing to write`);
  }
});

test('W6 refusals carry no data and checkPieces names index + reason only; and no screen calls recoverFromShards yet: the day one does, the refusal codes need a screen sentence', async () => {
  const { vault, shards } = await made(3, 5);
  const handed = [shards[0], flip(shards[1]), shards[2]];
  try { await recoverFromShards(vault, handed); assert.fail('should refuse'); } catch (e) {
    assert.ok(e instanceof RecoveryPiecesRefused);
    const dump = JSON.stringify({ message: (e as Error).message, code: code(e), own: Object.keys(e as object) });
    for (const p of shards) assert.equal(dump.includes(p.data), false, 'no piece data');
    for (const c of Object.values(vault.shamir.pieces!.commitments)) assert.equal(dump.includes(c), false, 'no commitment value');
    assert.equal(dump.includes(vault.shamir.pieces!.set_id), false, 'no set id');
    assert.deepEqual(Object.keys(e as object).sort(), ['code', 'name'], 'the refusal carries a code and a name and nothing else of its own: no data channel');
  }
  const report = JSON.stringify(checkPieces(vault, handed).bad);
  for (const p of shards) assert.equal(report.includes(p.data), false);
  for (const c of Object.values(vault.shamir.pieces!.commitments)) assert.equal(report.includes(c), false);
  assert.deepEqual(Object.keys(checkPieces(vault, handed).bad[0]).sort(), ['index', 'reason']);
  assert.deepEqual(checkPieces({ ...vault, shamir: { ...vault.shamir, pieces: { junk: 1 } as never } }, handed), { listed: false, good: handed, bad: [] }, 'no readable list: nothing to name');
  // the guard: the only callers of recoverFromShards are in src/lib/crypto and the vault selftest. A screen that starts calling it must map
  // recovery-pieces-insufficient / recovery-pieces-search-too-large (and recovery-code-wrong) to a sentence, by code, in classifyRestoreFailure.
  const SRC = resolve(__dirname, '..', '..');
  const hits: string[] = [];
  const walk = (dir: string) => { for (const n of readdirSync(dir)) { const p = join(dir, n); if (statSync(p).isDirectory()) { if (n !== 'node_modules') walk(p); } else if (/\.(ts|tsx)$/.test(n) && !/\.(test|spec|selftest)\.tsx?$/.test(n)) { const code = readFileSync(p, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, ''); if (/\brecoverFromShards\(/.test(code)) hits.push(p.slice(SRC.length + 1)); } } };
  walk(SRC);
  assert.deepEqual(hits.sort(), ['lib/crypto/recovery.ts'], 'a new caller of recoverFromShards: give the new refusal codes a screen sentence (classifyRestoreFailure + a copy row) before this guard is updated');
});
