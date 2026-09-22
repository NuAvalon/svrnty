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
// and the watchtower — the SIGNER leg of the #141748 3-impl convergence. Co-witnessed here against
// src/sw/path-canon.kat.json's signerBuildPath→expectedPath cases (Apollo's independent leg closes signer≡SW).
//
// This uses a TEST genesis (deterministic) to prove the pipeline end-to-end: DEV-FIRST-VERIFY round-trips the
// signed output through the SW's OWN parse+verify path. The REAL mint signs with the air-gapped genesis (Root-B)
// in the mint ceremony — this walk produces the manifest + preimage that ceremony signs.
//
// Runner: npx tsx scripts/sign-release.ts

import { readdirSync, statSync, readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, resolve, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { computeBundleHash, serializeManifest, verifyServedManifest, type ManifestEntry } from '../src/lib/crypto/bundle-manifest.js';
import { encodeReleaseSigningInput, signRelease, RELEASE_GRAMMAR_VERSION, type ReleaseObject } from '../src/lib/crypto/release-object.js';
import { deriveCanonicalFingerprintHex } from '../src/lib/identity/fingerprint.js';
import { verifyReleaseEpoch0, type PinnedLineage } from '../src/sw/gd-verify.js';
import { verifyAsset, verifyShell, shellHashSet } from '../src/sw/gd-verify-flow.js';
import { manifestPathClass } from '../src/sw/gd-pathname.js';
import { parseDeliveredRelease } from '../src/sw/gd-delivery.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const b64 = (u8: Uint8Array) => Buffer.from(u8).toString('base64');
const die = (msg: string): never => { console.error(`\n\u2717 ${msg}`); process.exit(1); };

// ── the served-path convention (MUST match src/sw/gd-pathname.ts manifestPath + path-canon.kat.json) ──
function buildPathToServedPath(buildRel: string): string | null {
  const p = buildRel.split('\\').join('/'); // as-served, forward-slash, no decode/normalize
  if (p.startsWith('.next/static/')) return '/_next/static/' + p.slice('.next/static/'.length);
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
  if (got !== c.expectedPath) {
    die(`path-canon CO-WITNESS FAIL: ${c.name}: buildPathToServedPath(${JSON.stringify(c.signerBuildPath)}) = ${JSON.stringify(got)} != ${JSON.stringify(c.expectedPath)}`);
  }
  cw++;
}
console.log(`\u2713 path-canon signer leg: ${cw}/${cw} signerBuildPath\u2192expectedPath cases agree with the shared vector`);

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
if (!seen.has('/sw.js')) die('/sw.js not in the manifest — build:sw did not run (would ship a placeholder-less/absent SW)');
console.log(`\u2713 walked ${entries.length} served assets: ${nStatic} static exact-path, ${nShell} shells (content-membership)`);
console.log(`  shells: ${[...shellBytesByPath.keys()].sort().join(', ')}`);

// ── 2. bundle_hash + canonical manifest bytes (Apollo's frozen §4 primitive) ──
const bundleHash = computeBundleHash(entries);
const manifestBytes = serializeManifest(entries);
console.log(`\u2713 bundle_hash = ${bytesToHex(bundleHash)}  (manifest ${manifestBytes.length}B, ${entries.length} entries)`);

// ── 3. sign with the TEST genesis (dev-first-verify; the real mint signs with the air-gapped Root-B) ──
const fill = (len: number, byte: number) => new Uint8Array(len).fill(byte);
const ED_SEED = fill(32, 0x11);
const dsa = ml_dsa87.keygen(fill(32, 0x22));
const genesis = { signPub: ed25519.getPublicKey(ED_SEED), encPub: fill(32, 0x33), kemPub: fill(1568, 0x44), sigPub: dsa.publicKey };
const fpHex = deriveCanonicalFingerprintHex(genesis.signPub, genesis.encPub, genesis.kemPub, genesis.sigPub);
const fpRaw = hexToBytes(fpHex);
const grammarVersion = RELEASE_GRAMMAR_VERSION, versionCounter = 1, epoch = 0;
const si = encodeReleaseSigningInput({ grammarVersion, publisherFp: fpRaw, bundleHash, versionCounter, epoch });
const release: ReleaseObject = { grammarVersion, bundleHash, versionCounter, epoch, sig: signRelease(si, ED_SEED, dsa.secretKey) };
console.log(`\u2713 signed release (TEST genesis) — publisher_fp ${fpHex.slice(0, 16)}\u2026 grammar_version ${grammarVersion} counter ${versionCounter} epoch ${epoch}`);

// ── 4. emit the atomic delivery (gd-delivery wire format) ──
const delivery = {
  v: 1,
  publisher_fp: fpHex,
  release: { grammar_version: grammarVersion, bundle_hash: bytesToHex(bundleHash), version_counter: versionCounter, epoch, sig: b64(release.sig) },
  manifest: b64(manifestBytes),
  genesis: { sign_pub: b64(genesis.signPub), enc_pub: b64(genesis.encPub), kem_pub: b64(genesis.kemPub), sig_pub: b64(genesis.sigPub) },
};
const outDir = join(ROOT, 'public/.well-known/svrnty');
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, 'release.json'), JSON.stringify(delivery));
console.log(`\u2713 wrote public/.well-known/svrnty/release.json  (${JSON.stringify(delivery).length}B, TEST genesis — gitignored, NOT the mint delivery)`);

// ── 5. DEV-FIRST-VERIFY: round-trip the emitted delivery through the SW's OWN parse + verify path ──
const parsed = parseDeliveredRelease(JSON.parse(JSON.stringify(delivery)));
if (!parsed.ok) die(`self-verify: gd-delivery rejected our own delivery: ${parsed.error}`);
const pinned: PinnedLineage = { publisherFpHex: fpHex, genesis, hwm: 0, followedEpoch: 0 };
const vr = verifyReleaseEpoch0(parsed.release, parsed.releasePublisherFp, pinned);
if (!vr.accepted || vr.kind !== 'accept') die(`self-verify: verifyReleaseEpoch0 did not accept (kind=${vr.kind}, reason=${vr.reason ?? ''})`);
const verifiedEntries = verifyServedManifest(parsed.manifestBytes, parsed.release.bundleHash); // throws if manifest != bundle_hash
const accepted = new Map<string, string>();
for (const e of verifiedEntries) accepted.set(e.path, bytesToHex(e.contentHash));
const aChunk = entries.find((e) => manifestPathClass(e.path) === 'static' && e.path.startsWith('/_next/static/'));
if (aChunk) {
  const bytes = new Uint8Array(readFileSync(join(ROOT, seen.get(aChunk.path)!)));
  if (verifyAsset(accepted, aChunk.path, bytes) !== 'ok') die(`self-verify: verifyAsset('${aChunk.path}') != ok`);
}
const shells = shellHashSet(accepted);
for (const [path, bytes] of shellBytesByPath) {
  if (verifyShell(shells, bytes) !== 'ok') die(`self-verify: verifyShell for ${path} != ok`);
}
console.log(`\u2713 DEV-VERIFY: delivery round-trips gd-delivery\u2192verifyReleaseEpoch0\u2192verifyServedManifest\u2192verifyAsset/verifyShell \u2014 ACCEPTED (HWM 0\u2192${vr.newHwm}); ${shells.size} shells + chunk SRI ok`);

// ── 6. CSP inline-hash union (byproduct for Flint's §9 hash-CSP script-src) ──
const inlineHashes = new Set<string>();
for (const [, bytes] of shellBytesByPath) {
  const html = Buffer.from(bytes).toString('utf8');
  for (const m of html.matchAll(/<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/g)) {
    if (m[1].length === 0) continue;
    inlineHashes.add(`'sha256-${b64(sha256(new TextEncoder().encode(m[1])))}'`);
  }
}
writeFileSync(join(outDir, 'csp-inline-hashes.json'), JSON.stringify({ generated_from: 'signer-walk over the prod build shells', script_src_inline_hashes: [...inlineHashes].sort() }, null, 2));
console.log(`\u2713 CSP inline-hash union: ${inlineHashes.size} distinct inline-script hashes \u2192 public/.well-known/svrnty/csp-inline-hashes.json (for Flint's script-src)`);

console.log('\n\u2713 SIGNER-WALK complete \u2014 manifest + release signed over the REAL build (incl the real sw.js).');
