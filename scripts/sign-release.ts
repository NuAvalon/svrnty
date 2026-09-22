// scripts/sign-release.ts — Node Zero G-C signer-walk (the release pipeline).
//
// Walks the PROD build output → the served-asset §4 manifest → bundle_hash → a signed release object, and emits
// the atomic /.well-known/svrnty/release.json the G-D service worker fetches + verifies (gd-delivery →
// verifyReleaseEpoch0 → verifyServedManifest). Run AFTER `npm run build` (needs .next/ + the real public/sw.js).
//
// WHAT IT SIGNS (Archie #142294 — the REAL SW, never a placeholder; build:sw already made public/sw.js real):
//   • .next/static/**          → /_next/static/**   (immutable content-hashed chunks/css/media) — exact-path SRI
//   • public/**                → /**                (icons, svgs, manifest.json, fonts, the REAL sw.js) — exact-path
//   • .next/server/app/*.html  → route path (/, /u, /c, /msg, /dev/seals, /_not-found) — shell content-membership
//
// PATH CONVENTION: buildPathToServedPath MUST agree byte-for-byte with the SW walker (gd-pathname.manifestPath)
// and the watchtower — the SIGNER leg of the #141748 3-impl convergence. Co-witnessed against
// src/sw/path-canon.kat.json's signerBuildPath→expectedPath cases (Apollo's independent leg closes signer≡SW).
//
// MODES (Archie #142398 — G4 real-genesis full-chain verify at the Root-B ceremony):
//   (no args)                   TEST-genesis full run — proves the pipeline end-to-end (today's dev-first-verify).
//   --pubkeys <file>            G4 SOVEREIGN emit-preimage: walk → manifest + bundle_hash + the release PREIMAGE
//                               for the AIR-GAP to sign with the real secret keys. The secret NEVER leaves the
//                               air-gap (it only signs a ~130B preimage). → public/.well-known/svrnty/sign-request.json
//   --pubkeys <file> --sig <f>  G4 assemble+verify: real pubkeys + air-gap sig → release.json + full dev-verify
//                               against the REAL genesis (then `npm run test:sw` = deployed-SW-verify in-browser).
//   <file> = JSON {sign_pub, enc_pub, kem_pub, sig_pub} b64 (the G0 genesis pubkeys). --sig <f> = the sig hex.
//
// Runner: npx tsx scripts/sign-release.ts [--pubkeys <file> [--sig <file>]]

import { readdirSync, statSync, readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, resolve, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { computeBundleHash, serializeManifest, verifyServedManifest, type ManifestEntry } from '../src/lib/crypto/bundle-manifest.js';
import { encodeReleaseSigningInput, signRelease, RELEASE_GRAMMAR_VERSION } from '../src/lib/crypto/release-object.js';
import { deriveCanonicalFingerprintHex } from '../src/lib/identity/fingerprint.js';
import { verifyReleaseEpoch0, type PinnedLineage } from '../src/sw/gd-verify.js';
import { verifyAsset, verifyShell, shellHashSet } from '../src/sw/gd-verify-flow.js';
import { manifestPathClass } from '../src/sw/gd-pathname.js';
import { parseDeliveredRelease } from '../src/sw/gd-delivery.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const b64 = (u8: Uint8Array) => Buffer.from(u8).toString('base64');
const die = (msg: string): never => { console.error(`\n✗ ${msg}`); process.exit(1); };
const fill = (len: number, byte: number) => new Uint8Array(len).fill(byte);

const argv = process.argv.slice(2);
const argVal = (flag: string): string | null => { const i = argv.indexOf(flag); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null; };
const PUBKEYS_FILE = argVal('--pubkeys');
const SIG_FILE = argVal('--sig');
interface Genesis { signPub: Uint8Array; encPub: Uint8Array; kemPub: Uint8Array; sigPub: Uint8Array; }
function readPubkeys(file: string): Genesis {
  const j = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
  const b = (k: string): Uint8Array => { const v = j[k]; if (typeof v !== 'string') die(`pubkeys file missing string ${k}`); return new Uint8Array(Buffer.from(v as string, 'base64')); };
  const g: Genesis = { signPub: b('sign_pub'), encPub: b('enc_pub'), kemPub: b('kem_pub'), sigPub: b('sig_pub') };
  const need: Array<[keyof Genesis, number]> = [['signPub', 32], ['encPub', 32], ['kemPub', 1568], ['sigPub', 2592]];
  for (const [k, n] of need) if (g[k].length !== n) die(`pubkeys.${k} must be ${n}B, got ${g[k].length}`);
  return g;
}

// ── the served-path convention (MUST match src/sw/gd-pathname.ts manifestPath + path-canon.kat.json) ──
function buildPathToServedPath(buildRel: string): string | null {
  const p = buildRel.split('\\').join('/'); // as-served, forward-slash, no decode/normalize
  if (p.startsWith('.next/static/')) return '/_next/static/' + p.slice('.next/static/'.length);
  // The signer's OWN delivery output (release.json + csp + sign-request) is served but verified by its SIGNATURE,
  // not manifest-membership. Exclude it — else a re-run walks the prior release.json back INTO the manifest
  // (circular: the manifest would depend on the release.json that carries the bundle_hash) → non-deterministic.
  if (p.startsWith('public/.well-known/')) return null;
  if (p.startsWith('public/')) return '/' + p.slice('public/'.length);
  if (p.startsWith('.next/server/app/') && p.endsWith('.html')) {
    const route = p.slice('.next/server/app/'.length, -'.html'.length);
    return route === 'index' ? '/' : '/' + route;
  }
  return null;
}

function walk(dir: string): string[] {
  const out: string[] = [];
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

// ── 0. co-witness the path convention against the shared vector (the SIGNER leg of the 3-impl convergence) ──
const vec = JSON.parse(readFileSync(join(ROOT, 'src/sw/path-canon.kat.json'), 'utf8')) as {
  cases: Array<{ name: string; signerBuildPath?: string; expectedPath: string | null }>;
};
let cw = 0;
for (const c of vec.cases) {
  if (!c.signerBuildPath) continue;
  const got = buildPathToServedPath(c.signerBuildPath);
  if (got !== c.expectedPath) die(`path-canon CO-WITNESS FAIL: ${c.name}: buildPathToServedPath(${JSON.stringify(c.signerBuildPath)}) = ${JSON.stringify(got)} != ${JSON.stringify(c.expectedPath)}`);
  cw++;
}
console.log(`✓ path-canon signer leg: ${cw}/${cw} signerBuildPath→expectedPath cases agree with the shared vector`);

// ── 1. WALK the build → ManifestEntry[] (dedup-guarded) ──
if (!existsSync(join(ROOT, '.next'))) die('no .next/ — run `npm run build` first');
const seen = new Map<string, string>(); // servedPath → buildRel
const entries: ManifestEntry[] = [];
const shellBytesByPath = new Map<string, Uint8Array>();
const collect = (files: string[], onlyHtml = false) => {
  for (const abs of files) {
    if (onlyHtml && !abs.endsWith('.html')) continue;
    const buildRel = relative(ROOT, abs).split('\\').join('/');
    const servedPath = buildPathToServedPath(buildRel);
    if (servedPath === null) continue;
    // Non-ASCII guard (Apollo #142315): the signer emits the RAW name, but the SW's manifestPath (URL.pathname)
    // PERCENT-ENCODES non-ASCII (and distinguishes NFC/NFD) → the SW's exact-path lookup would MISS this manifest
    // key → false-WARN (fail-CLOSED). Fail LOUD at sign-time. (Proper fix if ever needed: percent-encode
    // per-segment. Next content-hashes chunks + public/ is ASCII → never fires; doubles as the all-ASCII proof.)
    if (/[^\x00-\x7F]/.test(servedPath)) die(`non-ASCII served path ${JSON.stringify(servedPath)} (${buildRel}) — signer emits raw, SW percent-encodes → divergent lookup. Percent-encode or rename (Apollo #142315).`);
    if (seen.has(servedPath)) die(`duplicate served path ${servedPath} (${buildRel} vs ${seen.get(servedPath)})`);
    seen.set(servedPath, buildRel);
    const bytes = new Uint8Array(readFileSync(abs));
    entries.push({ path: servedPath, contentHash: sha256(bytes) });
    if (manifestPathClass(servedPath) === 'shell') shellBytesByPath.set(servedPath, bytes);
  }
};
collect(walk(join(ROOT, '.next/static')));
collect(walk(join(ROOT, 'public')));
collect(walk(join(ROOT, '.next/server/app')), true);

const nStatic = entries.filter((e) => manifestPathClass(e.path) === 'static').length;
const nShell = entries.filter((e) => manifestPathClass(e.path) === 'shell').length;
if (nShell === 0) die('walked 0 shells — the static shells (.next/server/app/*.html) are missing');
if (!seen.has('/sw.js')) die('/sw.js not in the manifest — build:sw did not run (would ship a placeholder/absent SW)');
console.log(`✓ walked ${entries.length} served assets: ${nStatic} static exact-path, ${nShell} shells (content-membership)`);
console.log(`  shells: ${[...shellBytesByPath.keys()].sort().join(', ')}`);

// ── 2. bundle_hash + canonical manifest bytes (Apollo's frozen §4 primitive) ──
const bundleHash = computeBundleHash(entries);
const manifestBytes = serializeManifest(entries);
console.log(`✓ bundle_hash = ${bytesToHex(bundleHash)}  (manifest ${manifestBytes.length}B, ${entries.length} entries)`);

// ── emit the atomic delivery for a genesis + sig, run the SW's OWN parse+verify, write release.json + CSP union ──
function emitAndVerify(g: Genesis, sig: Uint8Array, label: string): void {
  const fpHex = deriveCanonicalFingerprintHex(g.signPub, g.encPub, g.kemPub, g.sigPub);
  const grammarVersion = RELEASE_GRAMMAR_VERSION, versionCounter = 1, epoch = 0;
  const delivery = {
    v: 1, publisher_fp: fpHex,
    release: { grammar_version: grammarVersion, bundle_hash: bytesToHex(bundleHash), version_counter: versionCounter, epoch, sig: b64(sig) },
    manifest: b64(manifestBytes),
    genesis: { sign_pub: b64(g.signPub), enc_pub: b64(g.encPub), kem_pub: b64(g.kemPub), sig_pub: b64(g.sigPub) },
  };
  const parsed = parseDeliveredRelease(JSON.parse(JSON.stringify(delivery)));
  if (!parsed.ok) return die(`self-verify: gd-delivery rejected the ${label} delivery: ${parsed.error}`);
  const pinned: PinnedLineage = { publisherFpHex: fpHex, genesis: g, hwm: 0, followedEpoch: 0 };
  const vr = verifyReleaseEpoch0(parsed.release, parsed.releasePublisherFp, pinned);
  if (!vr.accepted || vr.kind !== 'accept') die(`self-verify: verifyReleaseEpoch0 REJECTED — the ${label} sig does not verify against the ${label} genesis over bundle_hash ${bytesToHex(bundleHash)} (kind=${vr.kind}, reason=${vr.reason ?? ''})`);
  const verifiedEntries = verifyServedManifest(parsed.manifestBytes, parsed.release.bundleHash); // throws if manifest != bundle_hash
  const accepted = new Map<string, string>();
  for (const e of verifiedEntries) accepted.set(e.path, bytesToHex(e.contentHash));
  const aChunk = entries.find((e) => manifestPathClass(e.path) === 'static' && e.path.startsWith('/_next/static/'));
  if (aChunk) { const bytes = new Uint8Array(readFileSync(join(ROOT, seen.get(aChunk.path)!))); if (verifyAsset(accepted, aChunk.path, bytes) !== 'ok') die(`self-verify: verifyAsset('${aChunk.path}') != ok`); }
  const shells = shellHashSet(accepted);
  for (const [path, bytes] of shellBytesByPath) if (verifyShell(shells, bytes) !== 'ok') die(`self-verify: verifyShell for ${path} != ok`);
  const outDir = join(ROOT, 'public/.well-known/svrnty');
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'release.json'), JSON.stringify(delivery));
  const inlineHashes = new Set<string>();
  for (const [, bytes] of shellBytesByPath) { const html = Buffer.from(bytes).toString('utf8'); for (const m of html.matchAll(/<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/g)) { if (m[1].length === 0) continue; inlineHashes.add(`'sha256-${b64(sha256(new TextEncoder().encode(m[1])))}'`); } }
  writeFileSync(join(outDir, 'csp-inline-hashes.json'), JSON.stringify({ generated_from: 'signer-walk over the prod build shells', script_src_inline_hashes: [...inlineHashes].sort() }, null, 2));
  console.log(`✓ release.json (${label} genesis) written + DEV-VERIFY ACCEPTED (HWM 0→${vr.newHwm}, ${shells.size} shells + chunk SRI). publisher_fp ${fpHex.slice(0, 16)}…`);
  console.log(`✓ CSP inline-hash union: ${inlineHashes.size} hashes → public/.well-known/svrnty/csp-inline-hashes.json`);
}

// ── 3. MODE dispatch ──
if (PUBKEYS_FILE && !SIG_FILE) {
  // G4 SOVEREIGN emit-preimage: the air-gap signs the ~130B preimage with the real secret keys; secret never leaves.
  const gp = readPubkeys(PUBKEYS_FILE);
  const fpHex = deriveCanonicalFingerprintHex(gp.signPub, gp.encPub, gp.kemPub, gp.sigPub);
  const preimage = encodeReleaseSigningInput({ grammarVersion: RELEASE_GRAMMAR_VERSION, publisherFp: hexToBytes(fpHex), bundleHash, versionCounter: 1, epoch: 0 });
  const outDir = join(ROOT, 'public/.well-known/svrnty');
  mkdirSync(outDir, { recursive: true });
  const req = { v: 1, publisher_fp: fpHex, grammar_version: RELEASE_GRAMMAR_VERSION, version_counter: 1, epoch: 0, bundle_hash: bytesToHex(bundleHash), preimage_hex: bytesToHex(preimage), manifest: b64(manifestBytes), pubkeys: { sign_pub: b64(gp.signPub), enc_pub: b64(gp.encPub), kem_pub: b64(gp.kemPub), sig_pub: b64(gp.sigPub) } };
  writeFileSync(join(outDir, 'sign-request.json'), JSON.stringify(req, null, 2));
  console.log(`✓ EMIT-PREIMAGE (sovereign) — publisher_fp ${fpHex.slice(0, 16)}…  bundle_hash ${bytesToHex(bundleHash).slice(0, 16)}…`);
  console.log(`  preimage (${preimage.length}B) + manifest → public/.well-known/svrnty/sign-request.json`);
  console.log(`  AIR-GAP: sig = ed25519.sign(preimage, edSeed) ‖ ml_dsa87.sign(preimage, dsaSecret)   [secret never leaves]`);
  console.log(`  THEN: npx tsx scripts/sign-release.ts --pubkeys ${PUBKEYS_FILE} --sig <sig-hex-file>   → assemble release.json + verify`);
  process.exit(0);
}

let g: Genesis, sig: Uint8Array, label: string;
if (PUBKEYS_FILE && SIG_FILE) {
  // G4 assemble+verify: real pubkeys + real air-gap sig → release.json + full dev-verify against the REAL genesis.
  g = readPubkeys(PUBKEYS_FILE);
  const sigHex = readFileSync(SIG_FILE, 'utf8').trim().replace(/^0x/, '');
  if (!/^[0-9a-fA-F]+$/.test(sigHex) || sigHex.length % 2 !== 0) die(`--sig file must be even-length hex (ed25519 64B ‖ ml-dsa), got ${sigHex.slice(0, 32)}…`);
  sig = hexToBytes(sigHex);
  if (sig.length <= 64) die(`sig too short (${sig.length}B) — need ed25519 64B + ml-dsa leg`);
  label = 'REAL';
} else {
  // DEFAULT: TEST genesis full run — proves the pipeline end-to-end (today's dev-first-verify).
  const ED_SEED = fill(32, 0x11);
  const dsa = ml_dsa87.keygen(fill(32, 0x22));
  g = { signPub: ed25519.getPublicKey(ED_SEED), encPub: fill(32, 0x33), kemPub: fill(1568, 0x44), sigPub: dsa.publicKey };
  const fpHex = deriveCanonicalFingerprintHex(g.signPub, g.encPub, g.kemPub, g.sigPub);
  const si = encodeReleaseSigningInput({ grammarVersion: RELEASE_GRAMMAR_VERSION, publisherFp: hexToBytes(fpHex), bundleHash, versionCounter: 1, epoch: 0 });
  sig = signRelease(si, ED_SEED, dsa.secretKey);
  label = 'TEST';
}
emitAndVerify(g, sig, label);
console.log(`\n✓ SIGNER-WALK complete (${label} genesis) — manifest + release over the REAL build (incl the real sw.js).`);
