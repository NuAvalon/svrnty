// src/sw/gd-verify-flow.ts
// Node Zero G-D — the two-mode verify flow + per-asset SRI, wiring the verify-core (gd-verify), the pin store
// (gd-pin-store), Apollo's manifest primitive (bundle-manifest), and the WARN floor (gd-warn).
//
// VERIFY-CURRENT (steady state): each served manifest-covered asset is SRI-checked against the ACCEPTED manifest
//   (SHA256(content) == accepted[path]). No recognizeRelease, no counter — cheap, per request. (Flint #141762
//   two-modes: never call recognizeRelease when the served bundle already == the accepted one.)
// ADOPT-UPDATE (a new release is offered): verify the release SIG (epoch-0) AND SHA256(served-manifest) ==
//   release.bundleHash AND counter > HWM; only then adopt the new manifest as accepted + advance HWM. A failed
//   adopt does NOT change the accepted manifest — WARN + keep serving the last verified one (never brick, §3).
//
// The accepted manifest bytes are cached (Cache API) so per-asset SRI survives SW restarts. Never throws.

import { verifyServedManifest, parseManifest, type ManifestEntry } from '../lib/crypto/bundle-manifest.js';
import { verifyReleaseEpoch0, type PinnedLineage } from './gd-verify.js';
import type { ReleaseObject } from '../lib/crypto/release-object.js';
import { readPin, commitAccepted } from './gd-pin-store.js';
import { broadcastWarn } from './gd-warn.js';
import { manifestPathClass } from './gd-pathname.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

const ACCEPTED_CACHE = 'nodezero-accepted';
const ACCEPTED_KEY = '/__nodezero__/accepted-manifest'; // synthetic key — never fetched from network

function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** The accepted manifest as a path → contentHash-hex map (for per-asset SRI), or null if none adopted. */
export async function loadAcceptedManifest(): Promise<Map<string, string> | null> {
  try {
    const cache = await caches.open(ACCEPTED_CACHE);
    const resp = await cache.match(ACCEPTED_KEY);
    if (!resp) return null;
    const entries = parseManifest(new Uint8Array(await resp.arrayBuffer())); // our own already-verified bytes
    const map = new Map<string, string>();
    for (const e of entries) map.set(e.path, bytesToHex(e.contentHash));
    return map;
  } catch {
    return null; // corrupt cache → behave as no-accepted (re-adopt path)
  }
}

async function storeAcceptedManifest(bytes: Uint8Array): Promise<void> {
  const cache = await caches.open(ACCEPTED_CACHE);
  await cache.put(ACCEPTED_KEY, new Response(bytes));
}

async function pinnedLineage(): Promise<PinnedLineage | null> {
  const pin = await readPin();
  if (!pin) return null;
  return {
    publisherFpHex: pin.publisherFpHex,
    genesis: {
      signPub: b64ToBytes(pin.signPubB64), encPub: b64ToBytes(pin.encPubB64),
      kemPub: b64ToBytes(pin.kemPubB64), sigPub: b64ToBytes(pin.sigPubB64),
    },
    hwm: pin.hwm,
    followedEpoch: 0,
  };
}

export type AdoptResult = { adopted: true; hwm: number } | { adopted: false; reason: string };

/**
 * ADOPT-UPDATE: verify a served release + its served manifest bytes against the pinned lineage; adopt iff the
 * release sig is valid (epoch-0), the manifest binds to release.bundleHash, and counter > HWM. Never throws. On
 * any failure the accepted manifest is UNCHANGED and a WARN is raised (never brick).
 */
export async function adoptUpdate(
  release: ReleaseObject,
  releasePublisherFp: Uint8Array,
  servedManifestBytes: Uint8Array,
): Promise<AdoptResult> {
  const pinned = await pinnedLineage();
  if (!pinned) return { adopted: false, reason: 'no pin — bootstrap first' };

  const sig = verifyReleaseEpoch0(release, releasePublisherFp, pinned);
  if (!sig.accepted) {
    await broadcastWarn({ kind: 'verify-fail', reason: `release rejected: ${sig.reason}`, publisherFpHex: pinned.publisherFpHex });
    return { adopted: false, reason: sig.reason ?? 'release verify failed' };
  }
  let entries: ManifestEntry[];
  try {
    entries = verifyServedManifest(servedManifestBytes, release.bundleHash); // SHA256(served)==bundle_hash then parse
  } catch {
    await broadcastWarn({ kind: 'verify-fail', reason: 'served manifest != signed bundle_hash', publisherFpHex: pinned.publisherFpHex });
    return { adopted: false, reason: 'manifest != bundle_hash' };
  }
  if (entries.length === 0) {
    await broadcastWarn({ kind: 'verify-fail', reason: 'empty manifest', publisherFpHex: pinned.publisherFpHex });
    return { adopted: false, reason: 'empty manifest' };
  }
  await storeAcceptedManifest(servedManifestBytes);
  await commitAccepted(sig.newHwm, bytesToHex(release.bundleHash));
  return { adopted: true, hwm: sig.newHwm };
}

export type AssetVerdict = 'ok' | 'mismatch' | 'unknown';

/**
 * VERIFY-CURRENT per-asset SRI. `ok` = served content matches the accepted manifest; `mismatch` = path IS in the
 * manifest but the hash differs (swapped/tampered → WARN); `unknown` = path not in the manifest (the caller,
 * with its asset-walk, decides: a manifest-covered path that's missing is a WARN; a genuinely dynamic/uncovered
 * path — /api, SSR — is not SRI-checked). This function never fetches or throws; it is pure over the map.
 */
export function verifyAsset(accepted: Map<string, string>, path: string, content: Uint8Array): AssetVerdict {
  const want = accepted.get(path);
  if (want === undefined) return 'unknown';
  return bytesToHex(sha256(content)) === want ? 'ok' : 'mismatch';
}

/**
 * The set of accepted SHELL content-hashes (hex), derived from the accepted manifest by keeping only entries
 * whose path is a shell route (manifestPathClass === 'shell'). A prerendered shell is served byte-identically
 * across infinite dynamic paths (/u/alice ≡ /u/bob), so shells are verified by CONTENT MEMBERSHIP over this set
 * rather than exact-path lookup. Empty set = no shells adopted (every navigation then WARNs — fail-closed).
 */
export function shellHashSet(accepted: Map<string, string>): Set<string> {
  const set = new Set<string>();
  for (const [path, hashHex] of accepted) {
    if (manifestPathClass(path) === 'shell') set.add(hashHex);
  }
  return set;
}

/**
 * VERIFY-CURRENT for a NAVIGATION (shell): is the served navigation HTML one of the publisher's known shells?
 * `ok` iff SHA256(served) ∈ the accepted shell-hash set; `mismatch` otherwise (a swapped/injected shell, incl.
 * an injected inline <script> since the bootstrap is inside the hashed bytes) → WARN. Path-independent by design.
 */
export function verifyShell(shellHashes: Set<string>, content: Uint8Array): 'ok' | 'mismatch' {
  return shellHashes.has(bytesToHex(sha256(content))) ? 'ok' : 'mismatch';
}
