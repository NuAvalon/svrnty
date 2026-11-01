// src/lib/headless/loom-sign-mint-parse.test.ts
// Run: npx tsx --test src/lib/headless/loom-sign-mint-parse.test.ts
//
// F-339 (Archie lane:svrnty #3205, Flint #3217; G-RO-8): scripts/loom-sign.ts reads mint.json, a SECRET file. On Node 22 a JSON.parse
// error QUOTES part of its input, and the CLI printed e.message, so a truncated or corrupt mint put a fragment of a private key field on
// stderr (which loom/cli.py logs). Every mint failure must now print ONE fixed line and none of the file's bytes; a valid mint still signs.
// The CLI is spawned for real (the same way loom/cli.py runs it via LOOM_SIGN_TS).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { mintHeadlessAgent, serializeMintArtifact } from '../identity/headless-mint';
import { base64ToUint8 } from '../crypto/pq';

const REPO = resolve(__dirname, '../../..');
const CLI = join(REPO, 'scripts', 'loom-sign.ts');
const FIXED = 'mint.json unreadable'; // = MINT_UNREADABLE in scripts/loom-sign.ts (not imported: importing the CLI would run it)

function run(args: string[], env: Record<string, string | undefined>, stdin = ''): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((done, fail) => {
    const e: NodeJS.ProcessEnv = { ...process.env, ...env };
    for (const k of Object.keys(env)) if (env[k] === undefined) delete e[k];
    const p = spawn(process.execPath, ['--import', 'tsx', CLI, ...args], { cwd: REPO, env: e });
    let out = '', err = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    const t = setTimeout(() => { p.kill('SIGKILL'); fail(new Error(`CLI timed out: ${args.join(' ')}\n${err}`)); }, 60_000);
    p.on('exit', (code) => { clearTimeout(t); done({ code, out, err }); });
    p.stdin.end(stdin);
  });
}

/** Every 6-char window of `secret` that shows up in `text` (a fragment the size of Archie's probe or smaller is a leak). */
const fragments = (text: string, secret: string) => {
  const hits: string[] = [];
  for (let i = 0; i + 6 <= secret.length; i++) if (text.includes(secret.slice(i, i + 6))) hits.push(secret.slice(i, i + 6));
  return hits;
};

test('G-RO-8 / F-339: a malformed mint prints ONLY the fixed line (exit 1) for every mint-reading verb; none of its bytes reach stderr', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loomsign-'));
  try {
    const minted = serializeMintArtifact(await mintHeadlessAgent({ throwaway: true })) as { private: Record<string, string> };
    const good = JSON.stringify(minted);
    const seed = minted.private.ed25519_seed;
    const bad: Record<string, string> = {
      // Archie's probe: an unquoted seed value, so Node's message quotes the bytes around the error position
      unquoted: good.replace(`"ed25519_seed":"${seed}"`, `"ed25519_seed":${seed}`),
      truncated: good.slice(0, good.indexOf(seed) + 12), // a partial write that stops inside the seed
      // every private field (each verb reads a different subset), so the decode fails whichever field the verb reads first
      'bad-base64': JSON.stringify({ ...minted, private: Object.fromEntries(Object.entries(minted.private).map(([k, v]) => [k, `${v.slice(0, 10)}%%${v.slice(12)}`])) }),
      'no-private': JSON.stringify({ ...minted, private: undefined }),
    };
    assert.notEqual(bad.unquoted, good, 'fixture: the seed really was unquoted');
    const card = join(dir, 'card.json');
    writeFileSync(card, '{}'); // a contact card is public and parsed first; the mint parse is what fails
    for (const [name, text] of Object.entries(bad)) {
      const mint = join(dir, `${name}.json`);
      writeFileSync(mint, text, { mode: 0o600 });
      for (const args of [['sign'], ['contact-encrypt', card], ['contact-decrypt']]) {
        const r = await run(args, { SVRNTY_MINT: mint, SVRNTY_AGENT_DIR: undefined }, 'hello loom');
        const at = `${name} / ${args[0]}`;
        assert.equal(r.code, 1, `${at}: non-zero exit`);
        assert.equal(r.err.trim(), FIXED, `${at}: stderr is exactly the fixed line`);
        assert.equal(r.out, '', `${at}: nothing on stdout`);
        for (const [k, v] of Object.entries(minted.private)) assert.deepEqual(fragments(r.err, v), [], `${at}: no fragment of private.${k} on stderr`);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('G-RO-8 control: a VALID mint still signs; the signature verifies against the seed\'s public key; stderr is empty', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loomsign-'));
  try {
    const minted = serializeMintArtifact(await mintHeadlessAgent({ throwaway: true })) as { private: Record<string, string> };
    const mint = join(dir, 'mint.json');
    writeFileSync(mint, JSON.stringify(minted), { mode: 0o600 });
    const r = await run(['sign'], { SVRNTY_MINT: mint, SVRNTY_AGENT_DIR: undefined }, 'hello loom');
    assert.equal(r.code, 0, r.err);
    assert.equal(r.err, '');
    const pub = ed25519.getPublicKey(base64ToUint8(minted.private.ed25519_seed));
    assert.ok(ed25519.verify(hexToBytes(r.out.trim()), new TextEncoder().encode('hello loom'), pub), 'a real ed25519 signature');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('G-RO-8 control: no SVRNTY_MINT / SVRNTY_AGENT_DIR is still the env refusal (exit 2), unchanged', async () => {
  const r = await run(['sign'], { SVRNTY_MINT: undefined, SVRNTY_AGENT_DIR: undefined }, 'x');
  assert.equal(r.code, 2);
  assert.match(r.err, /^refusing: set SVRNTY_MINT or SVRNTY_AGENT_DIR/);
});
