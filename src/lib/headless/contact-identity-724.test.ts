// #724: the headless contact book can't be overwritten around the fingerprint↔key binding.
// S1-S4: HeadlessStore.upsertContact rules (pure store, placeholder keys). A1-A4: the real `devin-comm admit` CLI with real
// canonical identities (openpgp ed25519 + ML-KEM-1024 + ML-DSA-87), in a temp agent dir.
// Run: npx tsx --test src/lib/headless/contact-identity-724.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { mintCanonicalFingerprint } from '../identity/fingerprint';
import { HeadlessStore } from './headless-store';
import { ADMIT_LOG, keysSha256, sha256Hex, withAdmitLog } from './admit-log';

const ROOT = resolve(__dirname, '..', '..', '..');
const TSX = join(ROOT, 'node_modules', 'tsx', 'dist', 'cli.mjs');

function store(): { s: HeadlessStore; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'svrnty-724-'));
  return { s: new HeadlessStore({ path: join(dir, 'store.json'), lockDir: dir }), dir };
}

test('S1 an id held by a DIFFERENT fingerprint is refused, and that contact is untouched', () => {
  const { s } = store();
  s.upsertContact({ id: 'X', fingerprint: 'fpX', name: 'ember', public_key: 'pkX', trust_level: 'trusted' });
  assert.throws(() => s.upsertContact({ id: 'X', fingerprint: 'fpY', name: 'ember', public_key: 'pkY' }), /different fingerprint/);
  const x = s.getContactByFingerprint('fpX');
  assert.equal(x?.public_key, 'pkX');
  assert.equal(x?.trust_level, 'trusted');
  assert.equal(s.getContactByFingerprint('fpY'), null);
});

test('S2 a keyed record replaces the key set as ONE unit (no old PQ key survives under a new classical key)', () => {
  const { s } = store();
  s.upsertContact({ id: 'X', fingerprint: 'fpX', public_key: 'pk-old', pq_kem_public_key: 'kem-old', pq_sig_public_key: 'sig-old' });
  s.upsertContact({ id: 'X', fingerprint: 'fpX', public_key: 'pk-new' });
  const x = s.getContactByFingerprint('fpX');
  assert.equal(x?.public_key, 'pk-new');
  assert.equal(x?.pq_kem_public_key, undefined);
  assert.equal(x?.pq_sig_public_key, undefined);
});

test('S3 a record with no key fields (trust/metadata) leaves the keys as they were', () => {
  const { s } = store();
  s.upsertContact({ id: 'X', fingerprint: 'fpX', public_key: 'pk', pq_kem_public_key: 'kem', pq_sig_public_key: 'sig' });
  s.upsertContact({ id: 'X', fingerprint: 'fpX', trust_level: 'trusted' } as never);
  const x = s.getContactByFingerprint('fpX');
  assert.deepEqual([x?.public_key, x?.pq_kem_public_key, x?.pq_sig_public_key, x?.trust_level], ['pk', 'kem', 'sig', 'trusted']);
});

test('S4 a fingerprint match keeps the row\'s own id', () => {
  const { s } = store();
  s.upsertContact({ id: 'X', fingerprint: 'fpX', public_key: 'pk' });
  s.upsertContact({ id: 'other-id', fingerprint: 'fpX', public_key: 'pk', name: 'renamed' });
  assert.equal(s.getContactByFingerprint('fpX')?.id, 'X');
  assert.equal(s.listContacts().length, 1);
});

async function identity(name: string) {
  const passphrase = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime.
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase,
    format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  return { fingerprint, public_key: publicKey, pq_kem_public_key: uint8ToBase64(pq.kem.publicKey), pq_sig_public_key: uint8ToBase64(pq.signing.publicKey), name };
}

function admit(dir: string, card: object): { rc: number | null; out: string; f: string } {
  const f = join(dir, `card-${Math.random().toString(16).slice(2)}.json`);
  writeFileSync(f, JSON.stringify(card));
  const r = spawnSync(process.execPath, [TSX, join(ROOT, 'scripts', 'devin-comm.ts'), 'admit', f], {
    // A minimal env on purpose: no inherited SVRNTY_* setting reaches the admit.
    env: { PATH: process.env.PATH ?? '', HOME: dir, SVRNTY_AGENT_DIR: dir, NODE_ENV: 'test' }, encoding: 'utf8', timeout: 120_000,
  });
  return { rc: r.status, out: (r.stdout ?? '') + (r.stderr ?? ''), f };
}
const book = (dir: string) => JSON.parse(readFileSync(join(dir, 'store.json'), 'utf8')).contacts as Array<Record<string, unknown>>;

test('A1-A4 devin-comm admit: binds keys to the fingerprint; forged / mixed cards are refused and change nothing', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'svrnty-724-cli-'));
  const x = await identity('ember');
  const y = await identity('mallory');

  const a1 = admit(dir, x);
  assert.equal(a1.rc, 0, a1.out);
  assert.match(a1.out, new RegExp(`admitted ${x.fingerprint}`));

  // A2: X's fingerprint with Mallory's keys (the key-corruption card) → refused, X unchanged.
  const a2 = admit(dir, { ...y, fingerprint: x.fingerprint, name: 'ember' });
  assert.notEqual(a2.rc, 0);
  assert.match(a2.out, /keys do not hash to its fingerprint/);
  assert.equal(book(dir).find((c) => c.fingerprint === x.fingerprint)?.public_key, x.public_key);

  // A3: a durable_id that names X on Mallory's own valid identity (the substitution card) → refused.
  const a3 = admit(dir, { ...y, durable_id: x.fingerprint, name: 'ember' });
  assert.notEqual(a3.rc, 0);
  assert.match(a3.out, /durable_id and fingerprint differ/);
  assert.equal(book(dir).length, 1);

  // A4: re-admitting X's own card is a no-op (same row, same keys).
  const a4 = admit(dir, x);
  assert.equal(a4.rc, 0, a4.out);
  assert.equal(book(dir).length, 1);
  assert.equal(book(dir)[0].public_key, x.public_key);
});

// L1-L6: the append-only admit provenance log (#724 follow-up; Mneme + Archie 2026-10-30). A write with no line fails here.
const logLines = (dir: string) =>
  existsSync(join(dir, ADMIT_LOG)) ? readFileSync(join(dir, ADMIT_LOG), 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];

test('L1-L3 devin-comm admit: every outcome leaves a provenance line, with hashes and no card body', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'svrnty-724-log-'));
  const x = await identity('ember');
  const y = await identity('mallory');

  const a1 = admit(dir, x);
  assert.equal(a1.rc, 0, a1.out);
  let log = logLines(dir);
  assert.deepEqual(log.map((l) => [l.source, l.fp, l.result]), [['admit', x.fingerprint, 'admitting'], ['admit', x.fingerprint, 'admitted']]);
  assert.equal(log[1].card_sha256, sha256Hex(readFileSync(a1.f)));
  assert.equal(log[1].keys_sha256, keysSha256(x));
  assert.equal(statSync(join(dir, ADMIT_LOG)).mode & 0o777, 0o600);

  // L2: refusals are logged with their reason, and add no admitting line.
  assert.notEqual(admit(dir, { ...y, fingerprint: x.fingerprint, name: 'ember' }).rc, 0);
  assert.notEqual(admit(dir, { ...y, durable_id: x.fingerprint, name: 'ember' }).rc, 0);
  assert.notEqual(admit(dir, { name: 'no-keys' }).rc, 0);
  log = logLines(dir);
  assert.deepEqual(log.slice(2).map((l) => l.result), ['refused:unbound', 'refused:durable-id', 'refused:no-key']);
  assert.equal(log[2].keys_sha256, keysSha256(y));

  // L3: hashes and the fingerprint only, never key text or a name.
  const text = readFileSync(join(dir, ADMIT_LOG), 'utf8');
  for (const leak of [x.public_key.slice(40, 80), x.pq_kem_public_key.slice(0, 40), y.pq_sig_public_key.slice(0, 40), 'ember', 'mallory', 'no-keys']) {
    assert.ok(!text.includes(leak), `log leaks ${leak.slice(0, 12)}`);
  }
});

test('L4 write-ahead: if the log line cannot be written, the admit fails and the book is untouched', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'svrnty-724-log-'));
  mkdirSync(join(dir, ADMIT_LOG));                 // appending to a directory fails (EISDIR)
  const x = await identity('ember');
  const r = admit(dir, x);
  assert.notEqual(r.rc, 0, r.out);
  assert.ok(!existsSync(join(dir, 'store.json')) || book(dir).length === 0);
});

test('L5 withAdmitLog: admitting before the write; admitted after it, or failed and rethrown', () => {
  const dir = mkdtempSync(join(tmpdir(), 'svrnty-724-log-'));
  const prov = { source: 'join' as const, fp: 'ab'.repeat(32), card_sha256: 'c', keys_sha256: 'k' };
  const seen: number[] = [];
  withAdmitLog(dir, prov, () => { seen.push(logLines(dir).length); });
  assert.deepEqual(seen, [1]);
  assert.throws(() => withAdmitLog(dir, prov, () => { throw new Error('disk full'); }), /disk full/);
  assert.deepEqual(logLines(dir).map((l) => l.result), ['admitting', 'admitted', 'admitting', 'failed']);
  withAdmitLog(dir, { ...prov, fp: 'not a fingerprint\n{"result":"admitted"}' }, () => {});
  assert.match(logLines(dir).at(-1).fp, /^unparseable:[0-9a-f]{16}$/);
});

test('L6 every store.upsertContact in devin-comm.ts runs inside withAdmitLog (join, admit-gate, admit)', () => {
  const src = readFileSync(join(ROOT, 'scripts', 'devin-comm.ts'), 'utf8').split('\n');
  const sites = src.map((l, i) => [l, i] as const).filter(([l]) => l.includes('store.upsertContact('));
  assert.equal(sites.length, 3);
  for (const [, i] of sites) {
    assert.ok(src.slice(Math.max(0, i - 5), i + 1).some((l) => l.includes('withAdmitLog(')), `unlogged contact write at devin-comm.ts:${i + 1}`);
  }
});

// #724 follow-up (Apollo #2203): the OTHER headless writer, updateContact(id, patch), guards identity itself.
test('U1 updateContact refuses a patch that changes the fingerprint; the row is untouched', () => {
  const { s } = store();
  s.upsertContact({ id: 'X', fingerprint: 'fpX', name: 'ember', public_key: 'pkX', trust_level: 'trusted' });
  assert.throws(() => s.updateContact('X', { fingerprint: 'fpY' }), /immutable/);
  const x = s.getContactByFingerprint('fpX');
  assert.equal(x?.trust_level, 'trusted');
  assert.ok(!s.getContactByFingerprint('fpY'), 'no row under the new fingerprint');
});

test('U2 updateContact refuses a patch that changes any key field; the row keeps its keys', () => {
  const { s } = store();
  s.upsertContact({ id: 'X', fingerprint: 'fpX', name: 'ember', public_key: 'pkX', pq_kem_public_key: 'kemX', pq_sig_public_key: 'sigX' });
  assert.throws(() => s.updateContact('X', { public_key: 'pkY' }), /public_key/);
  assert.throws(() => s.updateContact('X', { pq_kem_public_key: 'kemY' }), /pq_kem_public_key/);
  assert.throws(() => s.updateContact('X', { pq_sig_public_key: 'sigY' }), /pq_sig_public_key/);
  const x = s.getContactByFingerprint('fpX');
  assert.deepEqual([x?.public_key, x?.pq_kem_public_key, x?.pq_sig_public_key], ['pkX', 'kemX', 'sigX']);
});

test('U3 control: a whole-row patch that repeats the identity and changes only a label is applied', () => {
  const { s } = store();
  s.upsertContact({ id: 'X', fingerprint: 'fpX', name: 'ember', public_key: 'pkX' });
  const row = s.getContactByFingerprint('fpX')!;
  s.updateContact('X', { ...row, name: 'ember (Weft)' });
  assert.equal(s.getContactByFingerprint('fpX')?.name, 'ember (Weft)');
});
