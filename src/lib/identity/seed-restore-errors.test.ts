// The recovery-code (seed) restore: what the owner is told is decided by the thrower's CODE, never by its text, and no thrower's text reaches the screen.
// Real vault bytes (createKeyVault / packVault) are cut in the places that reach each thrower; the screen's wiring and the throw sites are pinned statically.
// Run: node --import tsx --test src/lib/identity/seed-restore-errors.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { classifyRestoreFailure, RESTORE_MESSAGES } from './restore-errors';
import { RestoreThrow } from '../crypto/coded-error';
import { createKeyVault, recoverFromSeedPhrase, seedPhraseToMasterSecret, type PrivateKeyBundle } from '../crypto/recovery';
import { createVaultContents, packVault, readVaultHeader, extractRecoveryVault, type VaultIdentity } from '../sync/vault';

const FP = 'a'.repeat(64);
const read = (p: string) => readFileSync(new URL(p, import.meta.url), 'utf8');
const codeOf = (fn: () => unknown): string | undefined => { try { fn(); } catch (e) { return (e as { code?: string }).code; } return undefined; };

let packed = new Uint8Array(0);
let seedPhrase = '';
let keyVault: unknown;

before(async () => {
  const bundle: PrivateKeyBundle = { classical_private_key: 'k', classical_passphrase: 'p', pq_signing_secret_key: 's', pq_kem_secret_key: 'm', identity_fingerprint: FP };
  const made = await createKeyVault(bundle, 2, 3, FP);
  seedPhrase = made.seedPhrase;
  keyVault = made.vault;
  const identity = {
    version: '1.0', created_at: '2026-11-15T00:00:00Z',
    identity: { name: 'n', email: '', fingerprint: FP, public_key: 'pk' },
    verification: { status: 'unverified', method: null, verified_at: null },
    metadata: { client_version: 't', key_type: 't', key_usage: [] },
  } as VaultIdentity;
  const contents = createVaultContents(identity, { classical: { privateKey: '', passphrase: '' }, pq: null } as never, { edges: [], contacts: [] } as never, {}, made.vault);
  packed = new Uint8Array(await packVault(contents, 'correct horse battery staple'));
});

const ab = (b: Uint8Array): ArrayBuffer => b.slice().buffer as ArrayBuffer;
/** The offset where the recovery envelope starts in a v4 file: magic 8, header length 4, header, body length 4, body. */
const recoveryStart = (): number => {
  const headerLen = new DataView(packed.buffer, packed.byteOffset).getUint32(8, false);
  const bodyLenOffset = 8 + 4 + headerLen;
  return bodyLenOffset + 4 + new DataView(packed.buffer, packed.byteOffset).getUint32(bodyLenOffset, false);
};

test('X1 the intact file opens: the real recovery vault comes out and the real recovery code opens it', async () => {
  const kv = extractRecoveryVault(ab(packed));
  assert.deepEqual(kv, keyVault);
  const bundle = await recoverFromSeedPhrase(kv, seedPhrase);
  assert.equal(bundle.identity_fingerprint, FP);
});

test('X2 each real thrower carries its code: wrong and malformed recovery codes, a truncated file at each step, no recovery vault, an unreadable one', async () => {
  assert.equal(codeOf(() => seedPhraseToMasterSecret('not a code')), 'recovery-code-malformed');
  await assert.rejects(recoverFromSeedPhrase(keyVault as never, 'a'.repeat(8) + (' ' + 'b'.repeat(8)).repeat(7)), (e: unknown) => (e as RestoreThrow).code === 'recovery-code-wrong');
  const rs = recoveryStart();
  assert.equal(codeOf(() => extractRecoveryVault(ab(packed.slice(0, 10)))), 'vault-truncated', 'ends inside the header length');
  assert.equal(codeOf(() => extractRecoveryVault(ab(packed.slice(0, 8 + 4 + 5)))), 'vault-truncated', 'ends inside the header');
  assert.equal(codeOf(() => extractRecoveryVault(ab(packed.slice(0, rs - 1)))), 'vault-truncated', 'ends inside the body');
  assert.equal(codeOf(() => extractRecoveryVault(ab(packed.slice(0, rs)))), 'vault-no-recovery', 'ends exactly where the recovery vault would start');
  const garbage = new Uint8Array([...packed.slice(0, rs), ...new TextEncoder().encode('{ not json')]);
  assert.equal(codeOf(() => extractRecoveryVault(ab(garbage))), 'vault-recovery-unreadable', 'the recovery vault is not JSON');
  const wrongShape = new Uint8Array([...packed.slice(0, rs), ...new TextEncoder().encode('{"a":1}')]);
  assert.equal(codeOf(() => extractRecoveryVault(ab(wrongShape))), 'vault-recovery-unreadable', 'the recovery vault is JSON of the wrong shape');
});

test('X3 the file-pick throwers carry codes: a header that does not parse, not a vault, a legacy v2 file, a v3 file with no recovery vault', () => {
  assert.equal(codeOf(() => readVaultHeader(ab(packed.slice(0, 8)))), 'vault-not-a-vault', 'the magic and nothing else: the header is empty');
  assert.equal(codeOf(() => readVaultHeader(ab(packed.slice(0, 40)))), 'vault-not-a-vault', 'the header ends mid-string');
  assert.equal(codeOf(() => readVaultHeader(new ArrayBuffer(3))), 'vault-not-a-vault', 'too short to be a vault');
  const v2 = packed.slice(); v2[7] = 2;
  assert.equal(codeOf(() => readVaultHeader(ab(v2))), 'vault-legacy-v2');
  const v3 = packed.slice(); v3[7] = 3;
  assert.equal(codeOf(() => extractRecoveryVault(ab(v3))), 'vault-v3-no-recovery');
});

test('X4 every code maps to the approved sentence, and the generic one is only for a failure nobody coded', () => {
  const by = (code: string) => classifyRestoreFailure(new RestoreThrow(code as never, 'the thrower\'s own text'));
  assert.deepEqual(by('recovery-code-wrong'), { code: 'wrong-recovery-code', message: "That recovery code doesn't match this backup." });
  assert.equal(by('recovery-code-malformed').message, "That recovery code isn't in the right form. Check it and enter it again.");
  assert.equal(by('vault-truncated').message, "This file ends too early to be a complete backup, so it can't be restored. If you have another copy, try that one.");
  assert.equal(by('vault-recovery-unreadable').message, "Part of this backup can't be read, so it can't be restored. If you have another copy, try that one.");
  assert.equal(by('vault-not-a-vault').message, RESTORE_MESSAGES.unrecognizedFormat);
  assert.equal(by('identity-older-format').message, "This backup uses an older identity format that this version of the app can't restore.");
  assert.equal(by('vault-legacy-v2').message, 'This backup uses an old format this app no longer opens. If your identity is still open on another device, make a new backup there.');
  assert.equal(by('vault-v3-no-recovery').message, "This backup was made before recovery codes existed, so it can't be restored with a recovery code. Use its passphrase with Restore identity instead.");
  assert.equal(by('vault-no-recovery').message, "Recovery codes weren't set up for this backup, so it can't be restored with a recovery code. Press I have my passphrase, then Restore identity.");
  for (const code of ['recovery-code-wrong', 'recovery-code-malformed', 'vault-truncated', 'vault-recovery-unreadable', 'vault-not-a-vault', 'identity-older-format', 'vault-legacy-v2', 'vault-v3-no-recovery', 'vault-no-recovery']) {
    assert.doesNotMatch(by(code).message, /the thrower's own text/, `${code}: the thrower's text is never the sentence`);
    assert.doesNotMatch(by(code).message, /corrupt|\byet\b/i, `${code}: never "corrupt", never "yet"`);
  }
});

test('X5 NEG: text decides nothing. A message that mentions a hash, a mismatch or a seed phrase, a SyntaxError, a bare Error: all are the generic sentence', () => {
  for (const e of [
    new Error('Invalid master secret — hash mismatch'),
    new Error('Invalid seed phrase — expected 64 hex characters (32 bytes)'),
    new Error('master secret mismatch in some other step'),
    new SyntaxError('Unexpected end of JSON input'),
    Object.assign(new Error('hash mismatch'), { code: 'something-else' }),
  ]) {
    const f = classifyRestoreFailure(e);
    assert.equal(f.code, 'unknown', `${e.message}`);
    assert.equal(f.message, RESTORE_MESSAGES.unknown);
    assert.doesNotMatch(f.message, /hash|mismatch|seed|JSON/i, 'no text from the error reaches the sentence');
  }
});

// ---------- static pins ----------
const screen = read('../../components/SoverentityFrontend.tsx');
const body = (start: string, end: string) => { const a = screen.indexOf(start); assert.ok(a >= 0, `${start} found`); return screen.slice(a, screen.indexOf(end, a + start.length)); };

test('X6 the seed handler and the file-pick handler show only classified sentences: no text test on a message, no raw message, no fallback text of their own', () => {
  const seed = body('const handleSeedVaultRestore = async () => {', 'const handleDevicePasswordSubmit');
  const pick = body('const handleFileSelect = async', '/** v4 dual-envelope');
  assert.doesNotMatch(seed, /master secret\|seed phrase|\.test\(msg\)|msg \|\|/, 'the regex on the message is gone');
  assert.match(seed, /classifyRestoreFailure\(err\)/);
  assert.match(pick, /classifyRestoreFailure\(err\)/);
  assert.doesNotMatch(pick, /err instanceof Error \? err\.message/, 'the pick handler no longer shows the error\'s own text');
  assert.doesNotMatch(seed, /err instanceof Error \? err\.message : ''/);
  // the only error text either handler may show is a restore refusal's, which is itself a fixed sentence
  for (const [name, h] of [['seed', seed], ['pick', pick]] as const) {
    const shown = [...h.matchAll(/setRestoreError\(([^)]*)\)/g)].map((m) => m[1]).filter((a) => /\.message|\bmsg\b/.test(a));
    assert.ok(shown.every((a) => /isRestoreDomainRefusal|err instanceof Error \? err\.message : 'Restore refused\.'/.test(a) || /failure\.message/.test(a)), `${name}: ${shown.join(' / ')}`);
  }
  assert.ok(!/VaultUnsupportedFormat/.test(seed + pick), 'the screen never reads the unsupported-format error itself');
});

test('X7 the sentences that send the owner to the passphrase path name the buttons the screen has, so they change together', () => {
  const label = /isBinaryVault \? '([^']+)' : 'Open Vault'/.exec(screen)?.[1];
  assert.equal(label, 'Restore identity', 'the passphrase path\'s button on a .svrnty file');
  // the button that brings the passphrase form back from the recovery-code path
  const step = />\s*(I have my passphrase)\s*<\/button>/.exec(screen)?.[1];
  assert.equal(step, 'I have my passphrase', 'the step back to the passphrase path');
  assert.ok(RESTORE_MESSAGES.v3NoRecovery.includes(`with ${label} instead.`), 'the v3 sentence names the button that is already on screen');
  assert.ok(RESTORE_MESSAGES.noRecoveryVault.includes(`Press ${step}, then ${label}.`), 'the no-recovery-vault sentence names the step and the button');
});

test('X8 LEAK PIN: no throw in the three recovery files interpolates a value, except the two unsupported-format throws that carry file HEADER fields and reach the console only', () => {
  const files = ['../crypto/recovery.ts', '../sync/vault.ts', '../../components/recovery/seedVaultRestore.ts'];
  const allowed = /^new VaultUnsupportedFormat\(`Unsupported vault format: \$\{header\.format\} v\$\{header\.version\}`\)$/;
  let throws = 0;
  for (const f of files) {
    const src = read(f).split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
    for (const m of src.matchAll(/throw\s+([\s\S]*?);\s*\n/g)) {
      throws++;
      const stmt = m[1].replace(/\s+/g, ' ').trim();
      if (allowed.test(stmt)) continue;
      // what is left once every plain string literal is removed must be the constructor call and punctuation: no identifier, no interpolation
      const rest = stmt.replace(/'(?:[^'\\]|\\.)*'/g, "''").replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/`[^`$]*`/g, '``');
      assert.doesNotMatch(rest, /\$\{/, `${f}: interpolation in: ${stmt.slice(0, 90)}`);
      const ctor = /^new (\w+)\(/.exec(rest);
      const args = ctor ? rest.slice(ctor[0].length).replace(/\)$/, '') : rest;
      assert.doesNotMatch(args.replace(/['"`]{2}|[\s+,]/g, ''), /\w/, `${f}: a non-literal reaches a throw: ${stmt.slice(0, 90)}`);
    }
  }
  assert.ok(throws >= 15, `the throws are found (found ${throws})`);
});
