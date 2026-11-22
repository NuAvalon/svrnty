// src/lib/headless/know-cli.test.ts
//
// The command-line side of the headless KNOW seats (S53 follow-up): what a dev dogfood run does on top of know-psi.ts.
// Run: npx tsx --test src/lib/headless/know-cli.test.ts
//
// What each group refutes (a property that PROTECTS someone, not "the code runs"):
//   - SEAT HOME GUARDS: a real person's identity is not driven by these commands. Only a throwaway artifact, only
//     from an explicit env dir (never the shared sandbox fallback, never an argv path), only from a private real
//     directory the caller owns.
//   - REPORT: "mutual Know" is shown only when THIS seat consented AND the sync core completed an exchange since the run
//     began. A stale marker from an earlier run, a one-sided consent, or an empty book never reads as mutual. The output
//     carries 8-hex prefixes and counts only: no names, emails, keys, or full fingerprints.
//   - KNOW-ON: consent is recorded locally only AFTER the satellite accepted the allowed row, and never for a blocked,
//     private, unknown or own contact. A failed row leaves no consent flag behind.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { SerializedMintArtifact } from '@/lib/identity/headless-mint';
import { HeadlessStore } from './headless-store';
import { DEV_SATELLITE_URL } from './know-psi';
import {
  KnowCliGuardError,
  agentHomeFromEnv, refuseDirInArgv, assertSeatHome, buildKnowReport, knowOn,
} from './know-cli';

// ── helpers ──────────────────────────────────────────────────────────────────
const FP_ME = 'a1'.repeat(20);
const FP_P1 = 'b2'.repeat(20);
const FP_P2 = 'c3'.repeat(20);
const FP_P3 = 'd4'.repeat(20);
const SINCE = '2026-11-22T01:00:00.000Z';

function artifact(over: { fp?: string; throwaway?: boolean; seed?: Uint8Array } = {}): SerializedMintArtifact {
  const seed = over.seed ?? new Uint8Array(randomBytes(32));
  return {
    public: { durable_id: over.fp ?? FP_ME },
    private: { ed25519_seed: Buffer.from(seed).toString('base64'), classical_private_key: 'X', classical_kpass: 'Y' },
    recovery_mode: null,
    throwaway: over.throwaway ?? true,
  } as unknown as SerializedMintArtifact;
}

function seedOf(a: SerializedMintArtifact): Uint8Array {
  return new Uint8Array(Buffer.from((a.private as { ed25519_seed: string }).ed25519_seed, 'base64'));
}

function contact(fp: string, extra: Record<string, unknown> = {}) {
  return {
    id: `id-${fp.slice(0, 6)}`, fingerprint: fp, public_key: `ARMORED-KEY-OF-${fp.slice(0, 6)}`,
    name: `Name Of ${fp.slice(0, 4)}`, email: `${fp.slice(0, 4)}@example.test`, ...extra,
  };
}

function bookWith(...rows: Array<ReturnType<typeof contact>>): HeadlessStore {
  const s = new HeadlessStore();
  for (const r of rows) s.upsertContact(r as never);
  return s;
}

const iso = (ms: number) => new Date(ms).toISOString();
const SINCE_MS = Date.parse(SINCE);

// ── SEAT HOME GUARDS ─────────────────────────────────────────────────────────
test('home from env: unset, empty and relative values refuse; there is no fallback to the shared sandbox dir', () => {
  assert.throws(() => agentHomeFromEnv({}), KnowCliGuardError);
  assert.throws(() => agentHomeFromEnv({ SVRNTY_AGENT_DIR: '' }), KnowCliGuardError);
  assert.throws(() => agentHomeFromEnv({ SVRNTY_AGENT_DIR: '   ' }), KnowCliGuardError);
  assert.throws(() => agentHomeFromEnv({ SVRNTY_AGENT_DIR: 'seat1' }), KnowCliGuardError);
  assert.throws(() => agentHomeFromEnv({ SVRNTY_AGENT_DIR: './seat1' }), KnowCliGuardError);
  assert.equal(agentHomeFromEnv({ SVRNTY_AGENT_DIR: '/home/x/seat1' }), '/home/x/seat1');
});

test('home from env: only trailing slashes are trimmed, and the shared sandbox dir is never returned', () => {
  assert.equal(agentHomeFromEnv({ SVRNTY_AGENT_DIR: '/home/x/seat1/' }), '/home/x/seat1/'.replace(/\/+$/, ''));
  assert.notEqual(agentHomeFromEnv({ SVRNTY_AGENT_DIR: '/home/x/seat1' }), '/home/alpha/devin-sandbox/.svrnty-agent');
});

test('argv: a seat directory is never taken from the command line, whatever the flag is called', () => {
  for (const bad of [['--agent-dir', '/x'], ['--agent-dir=/x'], ['--dir', '/x'], ['--dir=/x'], ['--home=/x'], ['--seat-dir', '/x'], ['--svrnty-agent-dir=/x']]) {
    assert.throws(() => refuseDirInArgv(['know-report', ...bad]), KnowCliGuardError, `argv ${bad.join(' ')}`);
  }
  assert.doesNotThrow(() => refuseDirInArgv(['know-report', '--since', SINCE]));
  assert.doesNotThrow(() => refuseDirInArgv([]));
});

function fsOf(entries: Record<string, { dir?: boolean; link?: boolean; uid?: number; mode?: number }>) {
  return {
    lstat(p: string) {
      const e = entries[p];
      if (!e) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      // what lstat really reports: a symlink is neither a directory nor a file (never both, as an earlier fake of mine did)
      return {
        isDirectory: () => e.dir === true && e.link !== true, isFile: () => e.dir !== true && e.link !== true,
        uid: e.uid ?? 1000, mode: e.mode ?? (e.dir ? 0o040700 : 0o100600),
      };
    },
  };
}
const DIR = '/home/x/seat1';
const GOOD_FS = () => fsOf({ [DIR]: { dir: true }, [`${DIR}/mint.json`]: {} });

test('seat home: a private real directory owned by the caller with a 0600 throwaway mint passes', () => {
  assert.doesNotThrow(() => assertSeatHome(DIR, artifact(), GOOD_FS(), 1000));
});

test('seat home: a throwaway flag that is false, missing or the string "true" refuses (a real identity is never driven)', () => {
  for (const t of [false, undefined, 'true', 1, null]) {
    const a = artifact(); (a as unknown as Record<string, unknown>).throwaway = t;
    assert.throws(() => assertSeatHome(DIR, a, GOOD_FS(), 1000), KnowCliGuardError, `throwaway=${String(t)}`);
  }
});

test('seat home: a symlinked directory refuses', () => {
  assert.throws(() => assertSeatHome(DIR, artifact(), fsOf({ [DIR]: { dir: true, link: true }, [`${DIR}/mint.json`]: {} }), 1000), KnowCliGuardError);
});

test('seat home: a path that is not a directory refuses', () => {
  assert.throws(() => assertSeatHome(DIR, artifact(), fsOf({ [DIR]: { dir: false }, [`${DIR}/mint.json`]: {} }), 1000), KnowCliGuardError);
});

test('seat home: a directory owned by someone else refuses', () => {
  assert.throws(() => assertSeatHome(DIR, artifact(), fsOf({ [DIR]: { dir: true, uid: 0 }, [`${DIR}/mint.json`]: {} }), 1000), KnowCliGuardError);
});

test('seat home: any group or other permission bit on the directory refuses (0750, 0705, 0755 each alone)', () => {
  for (const mode of [0o040750, 0o040705, 0o040755, 0o040770, 0o040701]) {
    assert.throws(() => assertSeatHome(DIR, artifact(), fsOf({ [DIR]: { dir: true, mode }, [`${DIR}/mint.json`]: {} }), 1000), KnowCliGuardError, `mode ${mode.toString(8)}`);
  }
});

test('seat home: mint.json with any group or other bit, wrong owner, a symlink, or missing refuses', () => {
  for (const mode of [0o100640, 0o100604, 0o100644, 0o100660]) {
    assert.throws(() => assertSeatHome(DIR, artifact(), fsOf({ [DIR]: { dir: true }, [`${DIR}/mint.json`]: { mode } }), 1000), KnowCliGuardError, `mode ${mode.toString(8)}`);
  }
  assert.throws(() => assertSeatHome(DIR, artifact(), fsOf({ [DIR]: { dir: true }, [`${DIR}/mint.json`]: { uid: 0 } }), 1000), KnowCliGuardError);
  assert.throws(() => assertSeatHome(DIR, artifact(), fsOf({ [DIR]: { dir: true }, [`${DIR}/mint.json`]: { link: true } }), 1000), KnowCliGuardError);
  assert.throws(() => assertSeatHome(DIR, artifact(), fsOf({ [DIR]: { dir: true } }), 1000), KnowCliGuardError);
});

test('seat home: a read-only 0400 mint.json and a 0700 directory both pass (stricter than 0600 is fine)', () => {
  assert.doesNotThrow(() => assertSeatHome(DIR, artifact(), fsOf({ [DIR]: { dir: true, mode: 0o040700 }, [`${DIR}/mint.json`]: { mode: 0o100400 } }), 1000));
});

// The same guards on a REAL directory, real symlinks and real modes (no fake lstat): this is what stops a link being followed.
function realSeat(label: string): { root: string; dir: string; mint: string } {
  const root = mkdtempSync(join(tmpdir(), `know-cli-${label}-`));
  const dir = join(root, 'seat');
  mkdirSync(dir, { mode: 0o700 });
  chmodSync(dir, 0o700);
  const mint = join(dir, 'mint.json');
  writeFileSync(mint, JSON.stringify({ throwaway: true }), { mode: 0o600 });
  chmodSync(mint, 0o600);
  return { root, dir, mint };
}
const UID = typeof process.getuid === 'function' ? process.getuid() : -1;
const REAL_FS = { lstat: lstatSync };

test('real directory: a private seat with a 0600 mint.json owned by the caller passes', () => {
  const s = realSeat('ok');
  try { assert.doesNotThrow(() => assertSeatHome(s.dir, artifact(), REAL_FS, UID)); } finally { rmSync(s.root, { recursive: true, force: true }); }
});

test('real directory: a symlink to a good seat directory is refused, not followed', () => {
  const s = realSeat('dirlink');
  const link = join(s.root, 'link');
  symlinkSync(s.dir, link);
  try {
    assert.doesNotThrow(() => assertSeatHome(s.dir, artifact(), REAL_FS, UID)); // control: the target itself is fine
    assert.throws(() => assertSeatHome(link, artifact(), REAL_FS, UID), KnowCliGuardError);
  } finally { rmSync(s.root, { recursive: true, force: true }); }
});

test('real directory: a mint.json that is a symlink to a good file is refused, not followed', () => {
  const s = realSeat('mintlink');
  const real = join(s.root, 'elsewhere.json');
  writeFileSync(real, JSON.stringify({ throwaway: true }), { mode: 0o600 });
  rmSync(s.mint);
  symlinkSync(real, s.mint);
  try { assert.throws(() => assertSeatHome(s.dir, artifact(), REAL_FS, UID), KnowCliGuardError); } finally { rmSync(s.root, { recursive: true, force: true }); }
});

test('real directory: a group- or world-readable seat directory or mint.json is refused, each alone', () => {
  for (const [what, path, mode] of [['dir 0755', 'dir', 0o755], ['dir 0750', 'dir', 0o750], ['dir 0705', 'dir', 0o705], ['mint 0644', 'mint', 0o644], ['mint 0640', 'mint', 0o640], ['mint 0604', 'mint', 0o604]] as const) {
    const s = realSeat('mode');
    try {
      chmodSync(path === 'dir' ? s.dir : s.mint, mode);
      assert.throws(() => assertSeatHome(s.dir, artifact(), REAL_FS, UID), KnowCliGuardError, what);
      chmodSync(path === 'dir' ? s.dir : s.mint, path === 'dir' ? 0o700 : 0o600);
      assert.doesNotThrow(() => assertSeatHome(s.dir, artifact(), REAL_FS, UID), `${what} restored`); // control: the same seat passes once the mode is right
    } finally { rmSync(s.root, { recursive: true, force: true }); }
  }
});

test('real directory: a missing seat directory or a missing mint.json is refused', () => {
  const s = realSeat('missing');
  try {
    assert.throws(() => assertSeatHome(join(s.root, 'nope'), artifact(), REAL_FS, UID), KnowCliGuardError);
    rmSync(s.mint);
    assert.throws(() => assertSeatHome(s.dir, artifact(), REAL_FS, UID), KnowCliGuardError);
  } finally { rmSync(s.root, { recursive: true, force: true }); }
});

// ── REPORT ───────────────────────────────────────────────────────────────────
test('report: mutual only when this seat consented AND the exchange completed after the run began', () => {
  const book = bookWith(
    contact(FP_P1, { open_visibility: true, mutual: { they_trust_me: null, last_sync: iso(SINCE_MS + 60_000), reciprocal: false } }),
  );
  const r = buildKnowReport(book, SINCE);
  assert.equal(r.rows.length, 1);
  assert.equal(r.rows[0].peer, FP_P1.slice(0, 8));
  assert.equal(r.rows[0].consented, true);
  assert.equal(r.rows[0].mutual, true);
  assert.deepEqual(r.counts, { contacts: 1, consented: 1, mutual: 1 });
});

test('report: a completed exchange from BEFORE the run (a stale marker) does not read as mutual', () => {
  const book = bookWith(contact(FP_P1, { open_visibility: true, mutual: { they_trust_me: null, last_sync: iso(SINCE_MS - 3_600_000), reciprocal: false } }));
  const r = buildKnowReport(book, SINCE);
  assert.equal(r.rows[0].mutual, false);
  assert.equal(r.counts.mutual, 0);
});

test('report: the boundary is inclusive and exact (one second before is not mutual, the same instant and one second after are)', () => {
  const at = (ms: number) => contact(FP_P1, { open_visibility: true, mutual: { they_trust_me: null, last_sync: iso(ms), reciprocal: false } });
  assert.equal(buildKnowReport(bookWith(at(SINCE_MS - 1000)), SINCE).rows[0].mutual, false);
  assert.equal(buildKnowReport(bookWith(at(SINCE_MS - 1)), SINCE).rows[0].mutual, false);
  assert.equal(buildKnowReport(bookWith(at(SINCE_MS)), SINCE).rows[0].mutual, true);
  assert.equal(buildKnowReport(bookWith(at(SINCE_MS + 1000)), SINCE).rows[0].mutual, true);
});

test('report: a one-sided consent (mine only, no exchange completed) is shown as consented but never mutual', () => {
  const r = buildKnowReport(bookWith(contact(FP_P1, { open_visibility: true })), SINCE);
  assert.equal(r.rows[0].consented, true);
  assert.equal(r.rows[0].mutual, false);
});

test('report: an exchange marker without consent from this seat (withdrawn, or never given) is never mutual', () => {
  const stamp = { they_trust_me: null, last_sync: iso(SINCE_MS + 5000), reciprocal: false };
  const r = buildKnowReport(bookWith(contact(FP_P1, { open_visibility: false, mutual: stamp }), contact(FP_P2, { mutual: stamp })), SINCE);
  for (const row of r.rows) { assert.equal(row.consented, false); assert.equal(row.mutual, false); }
  assert.equal(r.counts.mutual, 0);
});

test('report: a null, missing or unparseable last_sync is never mutual', () => {
  for (const ls of [null, undefined, '', 'not-a-date', 12345]) {
    const r = buildKnowReport(bookWith(contact(FP_P1, { open_visibility: true, mutual: { they_trust_me: null, last_sync: ls, reciprocal: false } })), SINCE);
    assert.equal(r.rows[0].mutual, false, `last_sync=${String(ls)}`);
  }
});

test('report: a missing or unparseable --since refuses (without it a stale marker cannot be told from a fresh one)', () => {
  const book = bookWith(contact(FP_P1, { open_visibility: true }));
  for (const bad of [undefined, '', 'yesterday', 'NaN'] as unknown[]) {
    assert.throws(() => buildKnowReport(book, bad as string), KnowCliGuardError, `since=${String(bad)}`);
  }
});

test('report: a contact with no consent, no exchange and no circle is left out; counts still count every contact', () => {
  const book = bookWith(contact(FP_P1, { open_visibility: true }), contact(FP_P2), contact(FP_P3));
  const r = buildKnowReport(book, SINCE);
  assert.deepEqual(r.rows.map((x) => x.peer), [FP_P1.slice(0, 8)]);
  assert.deepEqual(r.counts, { contacts: 3, consented: 1, mutual: 0 });
});

test('report: carries 8-hex prefixes and counts only (no names, emails, keys, full fingerprints, circle members)', () => {
  const book = bookWith(contact(FP_P1, {
    open_visibility: true, disclosed_circle: [FP_P2, FP_P3], psi_session_id: 'SESSION-ID-SECRET',
    mutual: { they_trust_me: true, last_sync: iso(SINCE_MS + 1000), reciprocal: true },
  }));
  const text = JSON.stringify(buildKnowReport(book, SINCE));
  for (const secret of [FP_P1, FP_P2, FP_P3, 'Name Of', '@example.test', 'ARMORED-KEY', 'SESSION-ID-SECRET', 'they_trust_me']) {
    assert.ok(!text.includes(secret), `report leaks ${secret}`);
  }
  assert.ok(text.includes(FP_P1.slice(0, 8)));
  assert.equal(buildKnowReport(book, SINCE).rows[0].disclosed, 2);
});

test('report: rows are sorted by peer prefix, so two runs of the same book print the same thing', () => {
  const book = bookWith(contact(FP_P3, { open_visibility: true }), contact(FP_P1, { open_visibility: true }), contact(FP_P2, { open_visibility: true }));
  assert.deepEqual(buildKnowReport(book, SINCE).rows.map((x) => x.peer), [FP_P1, FP_P2, FP_P3].map((f) => f.slice(0, 8)));
});

// ── KNOW-ON ──────────────────────────────────────────────────────────────────
function knowOnRig(book: HeadlessStore, addResult: boolean | 'throw' = true) {
  const log: string[] = [];
  const calls: Array<Record<string, unknown>> = [];
  const realUpdate = book.updateContact.bind(book);
  book.updateContact = ((id: string, patch: Record<string, unknown>) => { log.push('write'); realUpdate(id, patch as never); }) as never;
  const addAllowedSender = async (a: Record<string, unknown>) => {
    log.push('add'); calls.push(a);
    if (addResult === 'throw') throw new Error('network down');
    return addResult;
  };
  return { log, calls, deps: { addAllowedSender: addAllowedSender as never } };
}

test('know-on: the satellite row is added FIRST, and only then is consent recorded locally', async () => {
  const a = artifact();
  const book = bookWith(contact(FP_P1));
  const rig = knowOnRig(book);
  const r = await knowOn(a, book, FP_P1, rig.deps);
  assert.deepEqual(rig.log, ['add', 'write']);
  assert.equal(r.ok, true);
  assert.equal(book.listContacts()[0].open_visibility, true);
});

test('know-on: the row is added for this owner and this peer, signed with this seat\'s own seed, to the DEV allowed endpoint', async () => {
  const a = artifact();
  const book = bookWith(contact(FP_P1));
  const rig = knowOnRig(book);
  await knowOn(a, book, FP_P1, rig.deps);
  assert.equal(rig.calls.length, 1);
  assert.equal(rig.calls[0].ownerFp, FP_ME);
  assert.equal(rig.calls[0].senderFp, FP_P1);
  assert.deepEqual(Array.from(rig.calls[0].seed as Uint8Array), Array.from(seedOf(a)));
  assert.equal(rig.calls[0].base, `${DEV_SATELLITE_URL}/allowed`);
});

test('know-on: a satellite that refuses the row (false) leaves NO consent flag behind and reports why', async () => {
  const book = bookWith(contact(FP_P1));
  const rig = knowOnRig(book, false);
  const r = await knowOn(artifact(), book, FP_P1, rig.deps);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'relay-refused');
  assert.deepEqual(rig.log, ['add']);
  assert.notEqual(book.listContacts()[0].open_visibility, true);
});

test('know-on: a thrown network error leaves NO consent flag behind and does not escape as a crash', async () => {
  const book = bookWith(contact(FP_P1));
  const rig = knowOnRig(book, 'throw');
  const r = await knowOn(artifact(), book, FP_P1, rig.deps);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'relay-refused');
  assert.deepEqual(rig.log, ['add']);
  assert.notEqual(book.listContacts()[0].open_visibility, true);
});

test('know-on: a peer that is not in this seat\'s book makes no request and writes nothing', async () => {
  const book = bookWith(contact(FP_P1));
  const rig = knowOnRig(book);
  const r = await knowOn(artifact(), book, FP_P2, rig.deps);
  assert.deepEqual([r.ok, r.reason], [false, 'unknown-contact']);
  assert.deepEqual(rig.log, []);
});

test('know-on: the seat\'s own fingerprint makes no request and writes nothing', async () => {
  const book = bookWith(contact(FP_ME), contact(FP_P1));
  const rig = knowOnRig(book);
  const r = await knowOn(artifact(), book, FP_ME, rig.deps);
  assert.deepEqual([r.ok, r.reason], [false, 'self']);
  assert.deepEqual(rig.log, []);
});

test('know-on: a blocked contact (either spelling) makes no request and writes nothing', async () => {
  for (const extra of [{ blocked: true }, { metadata: { blocked: true } }]) {
    const book = bookWith(contact(FP_P1, extra));
    const rig = knowOnRig(book);
    const r = await knowOn(artifact(), book, FP_P1, rig.deps);
    assert.deepEqual([r.ok, r.reason], [false, 'blocked'], JSON.stringify(extra));
    assert.deepEqual(rig.log, []);
  }
});

test('know-on: a per-contact-private contact makes no request and writes nothing', async () => {
  const book = bookWith(contact(FP_P1, { per_contact_private: true }));
  const rig = knowOnRig(book);
  const r = await knowOn(artifact(), book, FP_P1, rig.deps);
  assert.deepEqual([r.ok, r.reason], [false, 'private']);
  assert.deepEqual(rig.log, []);
});

test('know-on: a real (non-throwaway) artifact refuses before any request', async () => {
  const book = bookWith(contact(FP_P1));
  const rig = knowOnRig(book);
  await assert.rejects(() => knowOn(artifact({ throwaway: false }), book, FP_P1, rig.deps), KnowCliGuardError);
  assert.deepEqual(rig.log, []);
});

test('know-on: a fingerprint that is not lowercase hex refuses before any request (it goes into a URL path)', async () => {
  const book = bookWith(contact(FP_P1));
  const rig = knowOnRig(book);
  for (const bad of ['../x', 'AB'.repeat(20), `${FP_P1}/x`, '', 'zz'.repeat(20)]) {
    await assert.rejects(() => knowOn(artifact(), book, bad, rig.deps), KnowCliGuardError, bad);
  }
  assert.deepEqual(rig.log, []);
});
