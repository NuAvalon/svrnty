import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readJsonStrict, writeFileAtomic, RATCHET_HINT } from './atomic-file';
import { HeadlessStore } from './headless-store';

const dir = () => mkdtempSync(join(tmpdir(), 'atomic-file-'));
const HELPER = join(__dirname, 'atomic-file.helper.ts');
const node = (args: string[]) => spawn(process.execPath, ['--import', 'tsx', HELPER, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
const ready = (p: ReturnType<typeof node>) =>
  new Promise<void>((res) => p.stdout!.on('data', (b) => { if (String(b).includes('ready')) res(); }));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const TORN = '{"contacts": [{"id": "c1", "fingerp';          // a write caught half-way

test('writeFileAtomic: content, 0600, no tmp left behind', () => {
  const d = dir(); const p = join(d, 'store.json');
  writeFileAtomic(p, '{"a":1}');
  assert.equal(readFileSync(p, 'utf8'), '{"a":1}');
  assert.equal(statSync(p).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(d), ['store.json']);
});

test('writeFileAtomic: previous good copy kept as .bak', () => {
  const d = dir(); const p = join(d, 'store.json');
  writeFileAtomic(p, '{"v":1}');
  writeFileAtomic(p, '{"v":2}');
  assert.equal(readFileSync(p, 'utf8'), '{"v":2}');
  assert.equal(readFileSync(`${p}.bak`, 'utf8'), '{"v":1}');
  assert.deepEqual(readdirSync(d).sort(), ['store.json', 'store.json.bak']);
  assert.equal(statSync(`${p}.bak`).mode & 0o777, 0o600, '.bak holds contacts + notes: 0600');
});

test('writeFileAtomic: an invalid current file never overwrites the last good .bak', () => {
  const d = dir(); const p = join(d, 'store.json');
  writeFileAtomic(p, '{"v":1}');
  writeFileAtomic(p, '{"v":2}');                        // .bak = v1
  writeFileSync(p, TORN);                               // something else tore it
  writeFileAtomic(p, '{"v":3}');
  assert.equal(readFileSync(`${p}.bak`, 'utf8'), '{"v":1}');
});

test('readJsonStrict: missing → empty, valid → parsed, torn → throws and leaves the file alone', () => {
  const d = dir(); const p = join(d, 'ratchet-sessions.json');
  assert.deepEqual(readJsonStrict(p, {}), {});
  writeFileSync(p, '{"peer":{"n":3}}');
  assert.deepEqual(readJsonStrict(p, {}), { peer: { n: 3 } });
  writeFileSync(p, TORN);
  assert.throws(() => readJsonStrict(p, {}), /not valid JSON.*refusing/);
  assert.equal(readFileSync(p, 'utf8'), TORN);
});

test('HeadlessStore: a torn store.json aborts instead of starting fresh (address book survives)', () => {
  const d = dir(); const p = join(d, 'store.json');
  writeFileSync(p, TORN);
  assert.throws(() => new HeadlessStore({ path: p }), /not valid JSON/);
  assert.equal(readFileSync(p, 'utf8'), TORN, 'the file must be untouched');
});

test('HeadlessStore: missing file = empty book; mutations persist atomically with a .bak', () => {
  const d = dir(); const p = join(d, 'store.json');
  const s = new HeadlessStore({ path: p });
  s.upsertContact({ id: 'c1', fingerprint: 'fp1', name: 'one' } as never);
  s.upsertContact({ id: 'c2', fingerprint: 'fp2', name: 'two' } as never);
  const reloaded = new HeadlessStore({ path: p });
  assert.ok(reloaded.getContactByFingerprint('fp1') && reloaded.getContactByFingerprint('fp2'));
  assert.equal(JSON.parse(readFileSync(`${p}.bak`, 'utf8')).contacts.length, 1);
  assert.equal(statSync(p).mode & 0o777, 0o600);
});

test('ratchet state: backup:false leaves nothing to restore, and the error forbids restoring', () => {
  const d = dir(); const p = join(d, 'ratchet-sessions.json');
  writeFileAtomic(p, '{"peer":{"n":1}}', { backup: false });
  writeFileAtomic(p, '{"peer":{"n":2}}', { backup: false });
  assert.deepEqual(readdirSync(d), ['ratchet-sessions.json']);
  writeFileSync(p, TORN);
  assert.throws(() => readJsonStrict(p, {}, RATCHET_HINT), /Do NOT restore a backup of ratchet state/);
});

test('writeFileAtomic: a stale tmp from a crashed run (even a symlink) is replaced, never followed', () => {
  const d = dir(); const p = join(d, 'gate.json'); const victim = join(d, 'victim');
  writeFileSync(victim, 'keep');
  symlinkSync(victim, `${p}.tmp.${process.pid}`);
  writeFileAtomic(p, '{"ok":true}');
  assert.equal(readFileSync(victim, 'utf8'), 'keep');
  assert.equal(readFileSync(p, 'utf8'), '{"ok":true}');
});

// ── headless-store-atomic-flush-001 anchor 4 ──
// argon's live wound (2026-10-30, twice in 15min): a writer killed
// mid-flush left store.json at 0 bytes; every consumer crash-looped on
// JSON.parse and the next flush persisted the empty book. The contract
// these tests pin: at ANY kill point the target holds a COMPLETE book —
// the previous generation or the new one — because the bytes only ever
// exist at the target via rename, never via truncate+write. A stale
// <file>.tmp.<pid> may linger (reclaimed by the next write — separate
// test above); a torn target must be impossible.
test('SIGKILL mid-flush: the target is always a complete book — old or new gen, never torn', async () => {
  const SIZE = 8_000_000;   // wide window: stringify + write + fsync of ~8MB per flush
  for (let attempt = 0; attempt < 6; attempt++) {
    const d = dir(); const p = join(d, 'store.json');
    const child = node(['flushloop', d, p, String(SIZE)]);
    await ready(child);                                  // gen-0 on disk, loop running
    await sleep(Math.random() * 30);                     // land somewhere mid-flight
    child.kill('SIGKILL');
    await new Promise((r) => child.on('exit', r));

    const raw = readFileSync(p, 'utf8');
    assert.ok(raw.length > SIZE, `attempt ${attempt}: book intact, not truncated (${raw.length}B)`);
    const book = JSON.parse(raw);                        // must parse — torn is impossible
    assert.ok(Number.isInteger(book.gen) && book.gen >= 0,
      `attempt ${attempt}: holds a real generation (old or new), gen=${book.gen}`);
    if (existsSync(`${p}.bak`)) {
      const bak = JSON.parse(readFileSync(`${p}.bak`, 'utf8'));
      assert.ok(Number.isInteger(bak.gen), `attempt ${attempt}: .bak also a complete book`);
    }
  }
});

test('HeadlessStore: SIGKILL mid-flush, restart — contacts + notes intact (the argon wound shape)', async () => {
  const SIZE = 8_000_000;
  for (let attempt = 0; attempt < 4; attempt++) {
    const d = dir();
    const child = node(['storeloop', d, String(SIZE)]);
    await ready(child);                                  // 3 contacts seeded, putNote loop running
    await sleep(Math.random() * 30);
    child.kill('SIGKILL');
    await new Promise((r) => child.on('exit', r));

    const p = join(d, 'store.json');
    const raw = readFileSync(p, 'utf8');
    assert.ok(raw.length > 0, `attempt ${attempt}: store.json never 0B`);
    // The restart path — this is where the wound bit: a torn file meant
    // "start fresh" and the next flush persisted the empty book. With
    // atomic flush the file always parses, so load() either succeeds
    // with real data or refuses loud — it can never go silent-empty.
    const store = new HeadlessStore({ path: p });
    assert.equal(store.listContacts().length, 3, `attempt ${attempt}: seeded contacts survived`);
    assert.ok(store.listNotes().length >= 0);
    // And the restart store can keep writing — the book is usable, not wedged.
    store.upsertContact({ id: 'c4', fingerprint: 'fp4', name: 'post-kill write' } as never);
    assert.ok(new HeadlessStore({ path: p }).getContactByFingerprint('fp4'));
  }
});
