// The password envelope of the export dialogs: what it writes, what it still reads, what it refuses.
// Run: node --import tsx --test src/lib/crypto/password-envelope.test.ts
// Known answers below were computed OUTSIDE this code: Argon2id straight from @noble/hashes, PBKDF2 and AES-256-GCM from node:crypto.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDecipheriv, pbkdf2Sync } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { argon2id } from '@noble/hashes/argon2.js';
import {
  sealWithPassword, openWithPassword, EnvelopeRefused, LEGACY_PBKDF2_ITERATIONS, ENVELOPE_KDF_ARGON2ID, ENVELOPE_KDF_LEGACY_PBKDF2, LEGACY_PASSWORD_METHOD_NOTICE,
} from './password-envelope';
import { ARGON2_MAX_MEMORY_COST, ARGON2_MAX_TIME_COST } from './kdf';

const PW = 'envelope-pass-123';
const PLAIN = 'hello envelope: {"k":1}';
const dec = (u: Uint8Array) => new TextDecoder().decode(u);

const ARGON_KAT = { algorithm: 'AES-256-GCM', kdf: 'argon2id', kdf_params: { time_cost: 1, memory_cost: 1024, parallelism: 1 }, salt: 'BwcHBwcHBwcHBwcHBwcHBw==', iv: 'CQkJCQkJCQkJCQkJ', data: 'I1xQ6FvFFo2Ary8JVxqvF5g2jBINIJr6pm7dIKxiOVzAAVtIu39o' };
const LEGACY_KAT = { encrypted: true, algorithm: 'AES-256-GCM', kdf: 'PBKDF2-SHA256-100k', salt: 'BwcHBwcHBwcHBwcHBwcHBw==', iv: 'CQkJCQkJCQkJCQkJ', data: 'BDHMOAGt/+B4Pm3vQwAUTKFTgfhp7eD9yFkK/uq96KLFoMH++Xt1' };
const clone = <T,>(o: T): T => JSON.parse(JSON.stringify(o));

/** Decrypt a sealed envelope with an implementation that shares nothing with the module: noble for the key, node:crypto for AES-GCM and the AAD it must carry. */
function independentOpen(env: { kdf_params: { time_cost: number; memory_cost: number; parallelism: number }; salt: string; iv: string; data: string }, pw: string): string {
  const p = env.kdf_params;
  const key = Buffer.from(argon2id(new TextEncoder().encode(pw), Buffer.from(env.salt, 'base64'), { t: p.time_cost, m: p.memory_cost, p: p.parallelism, dkLen: 32 }));
  const raw = Buffer.from(env.data, 'base64');
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(env.iv, 'base64'));
  d.setAAD(Buffer.from(`svrnty-password-envelope-v1|AES-256-GCM|argon2id|${p.time_cost}|${p.memory_cost}|${p.parallelism}`));
  d.setAuthTag(raw.subarray(raw.length - 16));
  return Buffer.concat([d.update(raw.subarray(0, raw.length - 16)), d.final()]).toString();
}

// ---------- WRITE: Argon2id only ----------
test('E1 sealing writes the Argon2id format: the header is argon2id with the library parameters, a fresh 16-byte salt and 12-byte iv, and NEVER the older tag', async () => {
  const a = await sealWithPassword(new TextEncoder().encode(PLAIN), PW);
  assert.equal(a.kdf, ENVELOPE_KDF_ARGON2ID);
  assert.notEqual(a.kdf as string, ENVELOPE_KDF_LEGACY_PBKDF2);
  assert.equal(a.algorithm, 'AES-256-GCM');
  assert.deepEqual(a.kdf_params, { time_cost: 3, memory_cost: 65536, parallelism: 1 });
  assert.equal(Buffer.from(a.salt, 'base64').length, 16);
  assert.equal(Buffer.from(a.iv, 'base64').length, 12);
  assert.ok(!JSON.stringify(a).includes('PBKDF2'), 'no trace of the older method anywhere in what is written');
  // an implementation that shares nothing with this module opens it: the format is the one it claims to be
  assert.equal(independentOpen(a, PW), PLAIN);
  // salt and iv are fresh on every seal
  const b = await sealWithPassword(new TextEncoder().encode(PLAIN), PW);
  assert.notEqual(a.salt, b.salt);
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.data, b.data);
});

// ---------- READ: the current format ----------
test('E2 the known Argon2id envelope opens to its plaintext, and is not marked legacy', async () => {
  const r = await openWithPassword(clone(ARGON_KAT), PW);
  assert.equal(dec(r.plaintext), PLAIN);
  assert.equal(r.legacy, false);
});

test('E3 a wrong password, or any change to what the tag covers (a parameter, the salt, the iv, the data), fails to decrypt', async () => {
  await assert.rejects(openWithPassword(clone(ARGON_KAT), 'not-the-password'));
  const mut = (f: (e: typeof ARGON_KAT) => void) => { const e = clone(ARGON_KAT); f(e); return e; };
  await assert.rejects(openWithPassword(mut((e) => { e.kdf_params.time_cost = 2; }), PW), Error, 'time_cost is authenticated');
  await assert.rejects(openWithPassword(mut((e) => { e.kdf_params.parallelism = 2; }), PW), Error, 'parallelism is authenticated');
  await assert.rejects(openWithPassword(mut((e) => { e.salt = Buffer.alloc(16, 8).toString('base64'); }), PW), Error, 'salt');
  await assert.rejects(openWithPassword(mut((e) => { e.iv = Buffer.alloc(12, 8).toString('base64'); }), PW), Error, 'iv');
  await assert.rejects(openWithPassword(mut((e) => { const b = Buffer.from(e.data, 'base64'); b[0] ^= 1; e.data = b.toString('base64'); }), PW), Error, 'data');
});

test('E4 hostile Argon2id parameters are refused BEFORE any derivation: a code, no work, nothing from the file echoed', async () => {
  const bad = [
    { time_cost: 1, memory_cost: ARGON2_MAX_MEMORY_COST + 1, parallelism: 1 },
    { time_cost: ARGON2_MAX_TIME_COST + 1, memory_cost: 1024, parallelism: 1 },
    { time_cost: 1, memory_cost: 1024, parallelism: 99 },
    { time_cost: 0, memory_cost: 1024, parallelism: 1 },
    { time_cost: 1.5, memory_cost: 1024, parallelism: 1 },
    { time_cost: 'MARKER' as unknown as number, memory_cost: 1024, parallelism: 1 },
  ];
  for (const p of bad) {
    const e = clone(ARGON_KAT); e.kdf_params = p;
    const t0 = performance.now();
    await assert.rejects(openWithPassword(e, PW), (err: unknown) => err instanceof EnvelopeRefused && err.code === 'unsafe-params' && !err.message.includes('MARKER'));
    assert.ok(performance.now() - t0 < 500, 'refused without running a derivation (a real one takes seconds)');
  }
  const noParams = clone(ARGON_KAT) as Record<string, unknown>; delete noParams.kdf_params;
  await assert.rejects(openWithPassword(noParams, PW), (err: unknown) => err instanceof EnvelopeRefused && err.code === 'unsafe-params');
});

// ---------- READ: the older format, read-only ----------
test('E5 the known older-format envelope still opens, and says it is legacy', async () => {
  const r = await openWithPassword(clone(LEGACY_KAT), PW);
  assert.equal(dec(r.plaintext), PLAIN);
  assert.equal(r.legacy, true);
  assert.equal(LEGACY_PBKDF2_ITERATIONS, 100_000);
  assert.equal(Buffer.from(pbkdf2Sync(PW, Buffer.alloc(16, 7), 100_000, 32, 'sha256')).length, 32, 'the constant is what the known answer was made with');
  await assert.rejects(openWithPassword(clone(LEGACY_KAT), 'not-the-password'));
});

test('E6 the older-format iteration count is OURS: a file that names its own (1, or a billion) changes nothing, so it can neither unlock faster nor stall the page', async () => {
  for (const iterations of [1, 1_000, 10_000, 1_000_000_000]) {
    const e = { ...clone(LEGACY_KAT), iterations, kdf_iterations: iterations, kdf_params: { iterations } };
    const t0 = performance.now();
    const r = await openWithPassword(e, PW);
    assert.equal(dec(r.plaintext), PLAIN, `iterations=${iterations} in the file is ignored`);
    assert.ok(performance.now() - t0 < 5000, 'no unbounded work');
  }
});

// ---------- READ: what is refused ----------
test('E7 a file we cannot identify is refused by tag, never tried: another tag, no tag, a lookalike, or something that is not an envelope', async () => {
  const refuse = async (e: unknown, code: string) => assert.rejects(openWithPassword(e, PW), (err: unknown) => err instanceof EnvelopeRefused && err.code === code, JSON.stringify(e)?.slice(0, 60));
  for (const kdf of ['argon2i', 'argon2d', 'PBKDF2-SHA256-1k', 'PBKDF2-SHA256-600k', 'pbkdf2-sha256-100k', 'scrypt', '', 'argon2id ']) {
    await refuse({ ...clone(LEGACY_KAT), kdf }, 'unknown-kdf');
  }
  const noTag = clone(LEGACY_KAT) as Record<string, unknown>; delete noTag.kdf;
  await refuse(noTag, 'unknown-kdf');
  await refuse({ ...clone(LEGACY_KAT), kdf: null }, 'unknown-kdf');
  for (const junk of [null, Error, 'x', 7, true]) await refuse(junk, 'not-an-envelope');
  for (const f of ['salt', 'iv', 'data'] as const) { const e = clone(LEGACY_KAT) as Record<string, unknown>; delete e[f]; await refuse(e, 'bad-field'); }
  await refuse({ ...clone(ARGON_KAT), salt: Buffer.alloc(8, 1).toString('base64') }, 'bad-field');
  await refuse({ ...clone(ARGON_KAT), iv: Buffer.alloc(16, 1).toString('base64') }, 'bad-field');
});

test('E8 an older-format file is not accepted by being relabelled, and an Argon2id file is not accepted as an older one', async () => {
  // the tag selects the derivation; the wrong derivation gives the wrong key, so the data does not decrypt
  await assert.rejects(openWithPassword({ ...clone(LEGACY_KAT), kdf: 'argon2id', kdf_params: ARGON_KAT.kdf_params }, PW));
  await assert.rejects(openWithPassword({ ...clone(ARGON_KAT), kdf: 'PBKDF2-SHA256-100k' }, PW));
});

// ---------- the older method is never WRITTEN ----------
const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', '..'); // src/
const walk = (d: string): string[] => readdirSync(d).flatMap((n) => { const p = join(d, n); return statSync(p).isDirectory() ? walk(p) : [p]; });
const app = () => walk(join(SRC, '..', 'app')).concat(walk(SRC)).filter((f) => /\.(ts|tsx)$/.test(f) && !/\.test\.(ts|tsx)$/.test(f) && !f.endsWith('.selftest.ts'));
const code = (f: string) => readFileSync(f, 'utf8').split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');

test('E9 no application code writes the older format: the tag string appears only in the read module, and no dialog derives a PBKDF2 key itself', () => {
  const tag = app().filter((f) => code(f).includes('PBKDF2-SHA256-100k')).map((f) => relative(SRC, f));
  assert.deepEqual(tag, ['lib/crypto/password-envelope.ts'], 'the legacy tag is named in exactly one place');
  const dialogs = app().filter((f) => /components\/(SecureImportExportDialogs|SoverentityFrontend)\.tsx$/.test(f));
  assert.equal(dialogs.length, 2);
  for (const f of dialogs) {
    const c = code(f);
    assert.ok(!/['"`]PBKDF2['"`]/.test(c), `${relative(SRC, f)} names no PBKDF2 algorithm literal, so it derives no such key itself`);
    assert.ok(!/iterations:\s*100_?000/.test(c), `${relative(SRC, f)} names no 100k iteration count`);
  }
});

test('E10 the dialogs reach the envelope only through seal / open, and both writers seal', () => {
  const dlg = code(join(SRC, 'components/SecureImportExportDialogs.tsx'));
  assert.equal((dlg.match(/sealWithPassword\(/g) ?? []).length, 2, 'the contacts export and the private-key export both seal');
  assert.equal((dlg.match(/openWithPassword\(/g) ?? []).length, 1, 'the contacts import opens');
  const fe = code(join(SRC, 'components/SoverentityFrontend.tsx'));
  assert.equal((fe.match(/openWithPassword\(/g) ?? []).length, 2, 'the full-backup and key-file restores open');
  assert.ok(!/sealWithPassword\(/.test(fe), 'the restore screen writes nothing');
});

test('E11 the notice after an older-format restore says what to do, and is defined once', () => {
  assert.match(LEGACY_PASSWORD_METHOD_NOTICE, /older, weaker password method/);
  assert.match(LEGACY_PASSWORD_METHOD_NOTICE, /export a new copy/i);
  const users = app().filter((f) => code(f).includes('LEGACY_PASSWORD_METHOD_NOTICE')).map((f) => relative(SRC, f)).sort();
  assert.ok(users.includes('lib/crypto/password-envelope.ts'));
  assert.ok(users.includes('components/SecureImportExportDialogs.tsx') && users.includes('components/SoverentityFrontend.tsx'), 'both restore surfaces show it: ' + users.join(', '));
  assert.ok(!app().some((f) => !/password-envelope\.ts$/.test(f) && code(f).includes('older, weaker password method')), 'the wording is not copied anywhere');
});
