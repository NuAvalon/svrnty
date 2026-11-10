// src/lib/trust/pointer-v2-wire.test.ts — task #809 step 2: pointer v2 bytes and their gate.
// Run: npx tsx --test src/lib/trust/pointer-v2-wire.test.ts
// Real keys (Ed25519 + ML-DSA-87 identity, the real authority derivation), the real hybrid seal. No network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { deriveNextAuthorityKeypair, deriveNextAuthorityCommitment } from '../identity/fingerprint';
import { ownerAuthorityCommitment } from '../crypto/owner-authority-commitment';
import { sealLivingBookHybrid } from '../crypto/living-book-sleeve';
import { mintHybridRecipient } from '../sync/hybrid-test-fixture';
import { LpParseError } from '../crypto/lp-reader';
import {
  encodePointerV2,
  isCanonicalRelayOrigin,
  parsePointerV2,
  pointerV2Prefix,
  pointerV2SigningInput,
  assertCanonicalPointerV2,
  UnverifiedPointerV2,
  PointerV2Refused,
  POINTER_V2_RELAY_MAX,
  type PointerV2Fields,
  type HybridSig,
  type AuthorityBlock,
  type PointerV2VerifyDeps,
} from './pointer-v2-wire';

const msgOf = (e: unknown) => (e instanceof Error ? e.message : String(e));

// ---------- fixtures ----------
function identityKeys() {
  const edSecret = randomBytes(32);
  const dsa = ml_dsa87.keygen(randomBytes(32));
  return { edSecret, edPublic: ed25519.getPublicKey(edSecret), dsaSecret: dsa.secretKey, dsaPublic: dsa.publicKey };
}
const signHybrid = (msg: Uint8Array, edSecret: Uint8Array, dsaSecret: Uint8Array): HybridSig => ({ ed: ed25519.sign(msg, edSecret), dsa: ml_dsa87.sign(msg, dsaSecret) });

function build(opts: { authority?: boolean; relay?: string; identityEpoch?: number; pointerEpoch?: number } = {}) {
  const id = identityKeys();
  const master = randomBytes(32);
  const auth = deriveNextAuthorityKeypair(master, 1);
  const pin = ownerAuthorityCommitment(auth.edPublic, auth.dsaPublic);
  const rotationPin = deriveNextAuthorityCommitment(master, 1);
  const f: PointerV2Fields = {
    mailboxId: sha256(randomBytes(16)),
    relay: opts.relay ?? 'https://relay.example.org',
    identityEpoch: opts.identityEpoch ?? 3,
    pointerEpoch: opts.pointerEpoch ?? 9,
    x25519Pub: randomBytes(32),
    mlkem1024Ek: randomBytes(1568),
    hasAuthority: !!opts.authority,
  };
  const prefix = pointerV2Prefix(f);
  const idSig = signHybrid(pointerV2SigningInput(prefix, false), id.edSecret, id.dsaSecret);
  const authority: AuthorityBlock | undefined = opts.authority
    ? { edPublic: auth.edPublic, dsaPublic: auth.dsaPublic, sig: signHybrid(pointerV2SigningInput(prefix, true), auth.edSecret, auth.dsaSecret) }
    : undefined;
  const bytes = encodePointerV2(f, idSig, authority);
  return { f, bytes, id, auth, pin, rotationPin, deps: { identity: { edPublic: id.edPublic, dsaPublic: id.dsaPublic }, authorityPin: pin }, prefixLen: prefix.length };
}

const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
const KAT_FIELDS: PointerV2Fields = {
  mailboxId: fill(32, 0x11), relay: 'https://relay.example.org', identityEpoch: 3, pointerEpoch: 9,
  x25519Pub: fill(32, 0x22), mlkem1024Ek: fill(1568, 0x33), hasAuthority: true,
};
const KAT_SIG: HybridSig = { ed: fill(64, 0x44), dsa: fill(4627, 0x55) };
const KAT_AUTH: AuthorityBlock = { edPublic: fill(32, 0x66), dsaPublic: fill(2592, 0x77), sig: { ed: fill(64, 0x88), dsa: fill(4627, 0x99) } };

const parseReason = (b: Uint8Array) => { try { parsePointerV2(b); } catch (e) { return e instanceof LpParseError ? e.reason : 'other:' + msgOf(e); } return 'accepted'; };

// ---------- KAT ----------
test('P1 known-answer vector: fixed fields and signatures encode to exactly these bytes', () => {
  const b = encodePointerV2(KAT_FIELDS, KAT_SIG, KAT_AUTH);
  const relayLen = KAT_FIELDS.relay.length;
  assert.equal(b.length, 4 + 32 + 4 + relayLen + 8 + 8 + 32 + 1568 + 64 + 4627 + 32 + 2592 + 64 + 4627);
  assert.equal(bytesToHex(b.slice(0, 4)), '4d500201', 'magic, version, flags (authority)');
  assert.equal(bytesToHex(b.slice(4, 36)), '11'.repeat(32));
  assert.equal(bytesToHex(sha256(b)), '7a8e0a5dddec0c2e5cf0abfb5be236c1650fe01b99363ca711b9c0d2d423001e');
  const noAuth = encodePointerV2({ ...KAT_FIELDS, hasAuthority: false }, KAT_SIG);
  assert.equal(bytesToHex(noAuth.slice(0, 4)), '4d500200');
  assert.equal(noAuth.length, b.length - (32 + 2592 + 64 + 4627));
});

// ---------- round trip with real keys ----------
test('P2 round trip: identity-only and authority-signed pointers verify and return exactly their fields', () => {
  for (const authority of [false, true]) {
    const { f, bytes, deps } = build({ authority });
    const v = parsePointerV2(bytes).verify(deps);
    assert.equal(v.mailboxId, 'mbx2_' + bytesToHex(f.mailboxId));
    assert.equal(v.relay, f.relay);
    assert.equal(v.identityEpoch, 3);
    assert.equal(v.pointerEpoch, 9);
    assert.deepEqual([...v.x25519Pub], [...f.x25519Pub]);
    assert.deepEqual([...v.mlkem1024Ek], [...f.mlkem1024Ek]);
    assert.equal(v.authoritySigned, authority);
    assert.ok(Object.isFrozen(v));
  }
});

// ---------- strict parse ----------
test('P3 strict parse: every malformation is refused with a stable reason', () => {
  const { bytes } = build({ authority: true });
  const mut = (f: (b: Uint8Array) => void) => { const b = bytes.slice(); f(b); return b; };
  assert.equal(parseReason(bytes), 'accepted');
  assert.equal(parseReason(mut((b) => { b[0] = 0; })), 'bad-header');
  assert.equal(parseReason(mut((b) => { b[2] = 1; })), 'bad-header', 'version');
  assert.equal(parseReason(mut((b) => { b[3] = 0x02; })), 'bad-header', 'unknown flag bit');
  assert.equal(parseReason(new Uint8Array([...bytes, 0])), 'trailing-bytes');
  assert.equal(parseReason(bytes.slice(0, bytes.length - 1)), 'truncated');
  assert.equal(parseReason(new Uint8Array(0)), 'truncated');
  const relayLpAt = 4 + 32;
  assert.equal(parseReason(mut((b) => new DataView(b.buffer).setUint32(relayLpAt, POINTER_V2_RELAY_MAX + 1, false))), 'length-over-max');
  assert.equal(parseReason(bytes.slice(0, relayLpAt + 4 + 10)), 'length-overrun', 'the prefix says 25 bytes of relay and only 10 are left');
  const epochAt = relayLpAt + 4 + 'https://relay.example.org'.length;
  assert.equal(parseReason(mut((b) => new DataView(b.buffer).setBigUint64(epochAt, BigInt('9007199254740992'), false))), 'unsafe-integer');
  assert.equal(parseReason(mut((b) => { b[relayLpAt + 4] = 0x68 ^ 0x20; })), 'bad-field', 'relay must be a plain https origin in lower case');
  assert.equal(parseReason(mut((b) => { b[relayLpAt + 4] = 0xff; })), 'bad-utf8');
  // flag set but the authority block is missing, and the block present with the flag clear
  const noBlock = build({ authority: false }).bytes.slice();
  noBlock[3] = 0x01;
  assert.equal(parseReason(noBlock), 'truncated');
  const withBlock = build({ authority: true }).bytes.slice();
  withBlock[3] = 0x00;
  assert.equal(parseReason(withBlock), 'trailing-bytes');
});

test('P4 relay shape: only a plain lower-case https origin is encodable', () => {
  const ok = (relay: string) => { try { build({ relay }); return true; } catch { return false; } };
  assert.ok(ok('https://relay.example.org'));
  assert.ok(ok('https://relay.example.org:8443'));
  for (const bad of ['http://relay.example.org', 'https://Relay.example.org', 'https://relay.example.org/', 'https://relay.example.org/path', 'https://user@relay.example.org', 'https://relay example', 'relay.example.org', '', 'https://' + 'a'.repeat(300) + '.org']) {
    assert.equal(ok(bad), false, bad.slice(0, 40));
  }
});

test('R2 canonical relay origin: one spelling per origin, no IP literal, no localhost, no empty or edge-hyphen label, port 1-65535 never 443 never leading zero', () => {
  const ok = (relay: string) => { try { build({ relay }); return true; } catch { return false; } };
  for (const good of ['https://relay.example.org', 'https://relay.example.org:8443', 'https://a.io:1', 'https://a.io:65535', 'https://r-1.example.org', 'https://relay.example.org:444', 'https://a1.b2.c3.de', 'https://' + 'a'.repeat(63) + '.org']) {
    assert.equal(ok(good), true, good);
  }
  const bad = [
    'https://relay.example.org:443', 'https://relay.example.org:0443', 'https://relay.example.org:00443', 'https://relay.example.org:0', 'https://relay.example.org:65536', 'https://relay.example.org:99999', 'https://relay.example.org:123456', 'https://relay.example.org:', 'https://relay.example.org:80a',
    'https://a..b.org', 'https://.relay.example.org', 'https://relay.example.org.', 'https://-a.example.org', 'https://a-.example.org', 'https://a.-b.example.org', 'https://a.b-.example.org',
    'https://127.0.0.1', 'https://127.0.0.1:8471', 'https://10.0.0.5', 'https://1.2.3.4.5', 'https://192.168.1.1:8443', 'https://999.999.999.999', 'https://localhost', 'https://localhost:8471', 'https://relay.localhost', 'https://[::1]', 'https://[::1]:8471', 'https://0x7f.1', 'https://2130706433',
    'https://' + 'a'.repeat(64) + '.org', 'https://' + ('a'.repeat(60) + '.').repeat(5) + 'org', 'https://a', 'https://relay.example.org#x', 'https://relay.example.org?x', 'https://u:p@relay.example.org', 'HTTPS://relay.example.org', 'https://relay.exa_mple.org', 'https://relay.example.org:8443:1',
    'https://xn--e1afmkfd.example', 'https://relay.xn--a1example', 'https://127.0x1', 'https://0x7f.0x0.0x0.0x1', 'https://10.0x0.0x5', 'https://192.168.0x0.0x1', 'https://169.254.169.0xfe', 'https://a.1b', 'https://a.0x', 'https://a.b.9',
  ];
  for (const b of bad) assert.equal(ok(b), false, b.slice(0, 60));
  assert.equal(ok('https://relay.example.org:' + '1'.repeat(10)), false);
});

test('R2 round trip: every origin the check accepts is exactly what a URL parser makes of it (no number, no normalisation)', () => {
  const urlOk = (s: string) => { try { const u = new URL(s); return u.origin === s && s === 'https://' + u.host; } catch { return false; } };
  // the five that the first version let through, each parsed to an IP address
  for (const s of ['https://127.0x1', 'https://0x7f.0x0.0x0.0x1', 'https://10.0x0.0x5', 'https://192.168.0x0.0x1', 'https://169.254.169.0xfe']) {
    assert.equal(new URL(s).hostname.split('.').length, 4, 'the URL parser reads it as an IPv4 address: ' + s);
    assert.equal(isCanonicalRelayOrigin(s), false, s);
  }
  // deterministic fuzz over the pieces that make hosts, ports and numbers confusable
  const pieces = ['a', 'z', '0', '1', '9', '0x', '0xf', 'x', '-', 'xn--', 'a1', '1a', 'localhost', 'example', 'org', 'io', 'E', '_'];
  const ports = ['', ':443', ':80', ':0', ':8443', ':65535', ':65536', ':08', ':1', ':99999'];
  let seed = 0x9e3779b9, accepted = 0, total = 0;
  const next = (n: number) => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed % n; };
  for (let i = 0; i < 30000; i++) {
    const nl = 1 + next(4);
    const labels = Array.from({ length: nl }, () => Array.from({ length: 1 + next(3) }, () => pieces[next(pieces.length)]).join(''));
    const s = 'https://' + labels.join('.') + ports[next(ports.length)];
    total++;
    if (isCanonicalRelayOrigin(s)) { accepted++; assert.ok(urlOk(s), 'accepted but a URL parser changes it: ' + s); }
  }
  assert.ok(accepted > 200, 'the fuzz reaches the accepting branch: ' + accepted + ' of ' + total);
});

test('R2 the longest relay that fits is 247 host characters (the whole origin is capped at 255 bytes)', () => {
  const ok = (relay: string) => { try { build({ relay }); return true; } catch { return false; } };
  const host = (n: number) => ['a'.repeat(63), 'a'.repeat(63), 'a'.repeat(63), 'a'.repeat(n - 63 * 3 - 3)].join('.');
  assert.equal(host(247).length, 247);
  assert.equal(ok('https://' + host(247)), true);
  assert.equal(ok('https://' + host(248)), false);
});

test('R2 the parser applies the same rule to bytes it did not encode', () => {
  const { bytes } = build({ relay: 'https://relay.example.org:65535' });
  const relayAt = 4 + 32 + 4; // magic/version/flags, mailbox id, relay length prefix
  const parseReason = (b: Uint8Array) => { try { parsePointerV2(b); return 'parsed'; } catch (e) { return e instanceof LpParseError ? e.reason : 'other'; } };
  assert.equal(parseReason(bytes), 'parsed');
  const at = (b: Uint8Array, from: string, to: string) => { const c = b.slice(); const i = Buffer.from(c).indexOf(from, relayAt); assert.ok(i >= relayAt, 'anchor ' + from); assert.equal(from.length, to.length); c.set(Buffer.from(to), i); return c; };
  assert.equal(parseReason(at(bytes, ':65535', ':65536')), 'bad-field', 'port above 65535');
  assert.equal(parseReason(at(bytes, ':65535', ':00443')), 'bad-field', 'leading zero');
  assert.equal(parseReason(at(bytes, 'relay.example', 'rela-.example')), 'bad-field', 'edge hyphen');
  assert.equal(parseReason(at(bytes, 'relay.example', 'relay..xample')), 'bad-field', 'empty label');
  assert.equal(parseReason(at(bytes, 'relay.example.org', '127.0.0.1.1.1.1.1')), 'bad-field', 'IP-shaped host');
  const plain = build({ relay: 'https://relay.example.org' }).bytes;
  assert.equal(parseReason(at(plain, 'relay.example.org', 'localhost.example')), 'parsed', 'a name that merely starts with localhost is a name');
  assert.equal(parseReason(at(plain, 'relay.example.org', 'abcdefg.localhost')), 'bad-field', 'the localhost suffix');
});

test('R1 the authority pin is the LABELLED owner-authority commitment: a reveal whose raw sha256 equals the pin is refused', () => {
  const { bytes, deps, pin, rotationPin, id, auth } = build({ authority: true });
  const refusal = (d: PointerV2VerifyDeps) => { try { parsePointerV2(bytes).verify(d); return 'accepted'; } catch (e) { return e instanceof PointerV2Refused ? e.reason : 'other'; } };
  assert.equal(refusal(deps), 'accepted');
  // the ROTATION commitment of the very same authority keys is the raw sha256(ed || dsa): a wrong-role pin must not pass
  const raw = bytesToHex(sha256(Uint8Array.from([...auth.edPublic, ...auth.dsaPublic])));
  assert.equal(raw, rotationPin, 'the raw hash IS the rotation commitment of these keys');
  assert.notEqual(raw, pin);
  assert.equal(refusal({ ...deps, authorityPin: raw }), 'authority-pin-mismatch');
  assert.equal(refusal({ ...deps, authorityPin: ownerAuthorityCommitment(auth.edPublic, auth.dsaPublic) }), 'accepted');
  assert.equal(rotationPin.length, 64);
  assert.equal(refusal({ ...deps, authorityPin: pin.toUpperCase() }), 'no-authority-pin', 'the pin is lower-case hex only');
  assert.ok(id.edPublic.length === 32);
});

// ---------- verification is a real gate ----------
test('P5 flip one byte of every signed field: the identity signature refuses it', () => {
  const { bytes, deps, prefixLen } = build({ authority: false });
  const reasonAt = (at: number) => {
    const b = bytes.slice(); b[at] ^= 1;
    try { parsePointerV2(b).verify(deps); return 'accepted'; } catch (e) { return e instanceof PointerV2Refused ? e.reason : e instanceof LpParseError ? 'parse:' + e.reason : 'other'; }
  };
  for (const [name, at] of [['mailbox id', 6], ['identity epoch', 4 + 32 + 4 + 25 + 7], ['pointer epoch', 4 + 32 + 4 + 25 + 8 + 7], ['x25519', prefixLen - 1568 - 5], ['mlkem', prefixLen - 5]] as const) {
    assert.equal(reasonAt(at), 'bad-identity-sig', name);
  }
  assert.equal(reasonAt(prefixLen + 3), 'bad-identity-sig', 'the Ed25519 half');
  assert.equal(reasonAt(prefixLen + 64 + 100), 'bad-identity-sig', 'the ML-DSA half');
});

test('P6 BOTH halves are required: either half failing alone refuses the pointer, with no fallback', () => {
  const { bytes, deps } = build();
  const good = parsePointerV2(bytes);
  const stubs = (ed: boolean, dsa: boolean) => ({ edVerify: () => ed, dsaVerify: () => dsa });
  assert.doesNotThrow(() => good.verify({ ...deps, verifiers: stubs(true, true) }));
  for (const [ed, dsa] of [[true, false], [false, true], [false, false]] as const) {
    assert.throws(() => good.verify({ ...deps, verifiers: stubs(ed, dsa) }), (e: unknown) => e instanceof PointerV2Refused && e.reason === 'bad-identity-sig');
  }
  let dsaCalls = 0;
  assert.throws(() => good.verify({ ...deps, verifiers: { edVerify: () => false, dsaVerify: () => { dsaCalls++; return true; } } }));
  assert.equal(dsaCalls, 0, 'the cheap half runs first, and a failure there never reaches the expensive half');
  assert.throws(() => good.verify({ ...deps, verifiers: { edVerify: () => { throw new Error('x'); }, dsaVerify: () => true } }), (e: unknown) => e instanceof PointerV2Refused, 'a throwing primitive is a refusal');
});

test('P7 authority block: the pin must match, the authority signature must verify, and the flag cannot be stripped or forged', () => {
  const { bytes, deps, id, prefixLen, f } = build({ authority: true });
  const refusal = (b: Uint8Array, d: PointerV2VerifyDeps = deps) => { try { parsePointerV2(b).verify(d); return 'accepted'; } catch (e) { return e instanceof PointerV2Refused ? e.reason : 'parse'; } };
  assert.equal(refusal(bytes), 'accepted');
  assert.equal(refusal(bytes, { ...deps, authorityPin: undefined }), 'no-authority-pin');
  assert.equal(refusal(bytes, { ...deps, authorityPin: 'ab'.repeat(32) }), 'authority-pin-mismatch');
  const authAt = prefixLen + 64 + 4627;
  const flip = (at: number) => { const b = bytes.slice(); b[at] ^= 1; return b; };
  assert.equal(refusal(flip(authAt + 3)), 'authority-pin-mismatch', 'a changed revealed key no longer hashes to the pin');
  assert.equal(refusal(flip(authAt + 32 + 2592 + 3)), 'bad-authority-sig');
  assert.equal(refusal(flip(authAt + 32 + 2592 + 64 + 100)), 'bad-authority-sig');
  // STRIPPING: drop the block and clear the flag. The identity signature covered the flag, so this is a different claim and it fails.
  const stripped = bytes.slice(0, authAt); stripped[3] = 0;
  assert.equal(refusal(stripped), 'bad-identity-sig');
  // The identity key alone CAN sign an identity-only pointer for the same fields; that is a valid identity-only pointer, not a forgery, and says authoritySigned false.
  const honest = encodePointerV2({ ...f, hasAuthority: false }, signHybrid(pointerV2SigningInput(pointerV2Prefix({ ...f, hasAuthority: false }), false), id.edSecret, id.dsaSecret));
  assert.equal(parsePointerV2(honest).verify(deps).authoritySigned, false);
});

test('P8 a pointer signed under another identity key is refused', () => {
  const { bytes } = build();
  const other = identityKeys();
  assert.throws(() => parsePointerV2(bytes).verify({ identity: { edPublic: other.edPublic, dsaPublic: other.dsaPublic } }), (e: unknown) => e instanceof PointerV2Refused && e.reason === 'bad-identity-sig');
  assert.throws(() => parsePointerV2(bytes).verify({ identity: { edPublic: new Uint8Array(31), dsaPublic: other.dsaPublic } }), (e: unknown) => e instanceof PointerV2Refused && e.reason === 'bad-identity-key');
});

// ---------- opacity, no echo, canonical ----------
test('P9 nothing is readable before verify, and no refusal echoes the input', () => {
  const { bytes } = build({ authority: true });
  const u = parsePointerV2(bytes);
  assert.ok(u instanceof UnverifiedPointerV2);
  assert.deepEqual(Object.keys(u), []);
  assert.equal(JSON.stringify(u), '{}');
  assert.deepEqual(Object.getOwnPropertyNames(Object.getPrototypeOf(u)).sort(), ['constructor', 'verify']);
  const marker = new TextEncoder().encode('https://marker-attacker.example');
  const b = bytes.slice(); b.set(marker.slice(0, 20), 4 + 32 + 4);
  try { parsePointerV2(b); } catch (e) {
    assert.ok(/^binary object refused \([a-z-]+\)$/.test(msgOf(e)));
    assert.ok(!msgOf(e).includes('marker'));
  }
  try { build({ relay: 'https://Marker-Attacker.example' }); } catch (e) { assert.ok(!msgOf(e).includes('Marker')); }
});

test('P10 the canonical re-encode guard throws on a mismatch', () => {
  const bytes = encodePointerV2(KAT_FIELDS, KAT_SIG, KAT_AUTH);
  assertCanonicalPointerV2(KAT_FIELDS, KAT_SIG, KAT_AUTH, bytes);
  const other = bytes.slice(); other[40] ^= 1;
  assert.throws(() => assertCanonicalPointerV2(KAT_FIELDS, KAT_SIG, KAT_AUTH, other), (e: unknown) => e instanceof LpParseError && e.reason === 'non-canonical');
});

test('P11 a Buffer passed in is copied: changing it after the parse cannot change what verify checks', () => {
  const { bytes, deps } = build({ authority: true });
  const buf = Buffer.from(bytes);
  const u = parsePointerV2(buf);
  buf.fill(0);
  assert.doesNotThrow(() => u.verify(deps));
});

// ---------- size, on the real hybrid seal ----------
test('P12 sealed size: both forms fit one request with margin', async () => {
  const r = await mintHybridRecipient();
  for (const authority of [false, true]) {
    const { bytes } = build({ authority });
    const sealed = (await sealLivingBookHybrid(bytes, r.publicKeyArmored, r.pqKemPublicKey)).length;
    console.log(`# pointer v2 ${authority ? 'with authority' : 'identity-only'}: ${bytes.length} B -> sealed ${sealed} B (cap 65536)`);
    assert.ok(sealed <= 65536 * 0.75);
    assert.ok(Math.abs(sealed - (Math.ceil(bytes.length / 3) * 4 + 2354)) <= 64);
  }
});

// ---------- purity and darkness ----------
test('P13 the module is pure: no I/O, no clock, no randomness', () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const src = readFileSync(join(here, 'pointer-v2-wire.ts'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  for (const bad of ['fetch(', 'localStorage', 'indexedDB', 'Date.now', 'new Date', 'Math.random', 'randomBytes', 'getRandomValues', "from 'fs'", 'process.env', 'keygen', '.sign(']) {
    assert.ok(!src.includes(bad), `pointer-v2-wire.ts must not use ${bad}`);
  }
});

test('P14 dark: nothing outside tests imports the pointer v2 module', () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const hits: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) { if (n !== 'node_modules') walk(p); continue; }
      if (!/\.(ts|tsx)$/.test(n) || /\.test\.(ts|tsx)$/.test(n)) continue;
      if (/from ['"][^'"]*pointer-v2-wire['"]/.test(readFileSync(p, 'utf8')) && !/(pointer-v2-wire|rotation-receive)\.ts$/.test(p)) hits.push(p); // rotation-receive is the one consumer, itself guarded dark by its own test
    }
  };
  walk(root);
  assert.deepEqual(hits, []);
});

test('P15 domain separation: a signature made for one role does not verify in the other', () => {
  const { f, id, pin, deps } = build({ authority: true });
  const prefix = pointerV2Prefix(f);
  const master = randomBytes(32);
  const auth = deriveNextAuthorityKeypair(master, 1);
  const authPin = ownerAuthorityCommitment(auth.edPublic, auth.dsaPublic);
  // the authority key signs over the IDENTITY domain input, and the identity key signs over the AUTHORITY domain input
  const crossAuth: AuthorityBlock = { edPublic: auth.edPublic, dsaPublic: auth.dsaPublic, sig: signHybrid(pointerV2SigningInput(prefix, false), auth.edSecret, auth.dsaSecret) };
  const okId = signHybrid(pointerV2SigningInput(prefix, false), id.edSecret, id.dsaSecret);
  assert.throws(() => parsePointerV2(encodePointerV2(f, okId, crossAuth)).verify({ ...deps, authorityPin: authPin }), (e: unknown) => e instanceof PointerV2Refused && e.reason === 'bad-authority-sig');
  const crossId = signHybrid(pointerV2SigningInput(prefix, true), id.edSecret, id.dsaSecret);
  const goodAuth: AuthorityBlock = { edPublic: auth.edPublic, dsaPublic: auth.dsaPublic, sig: signHybrid(pointerV2SigningInput(prefix, true), auth.edSecret, auth.dsaSecret) };
  assert.throws(() => parsePointerV2(encodePointerV2(f, crossId, goodAuth)).verify({ ...deps, authorityPin: authPin }), (e: unknown) => e instanceof PointerV2Refused && e.reason === 'bad-identity-sig');
  assert.ok(pin.length === 64);
});
