// src/sw/gd-delivery.ts
// Node Zero G-D — the release-delivery WIRE format (Athena's lane: I produce it in the G-C signer AND parse it
// here in G-D, so the format is consistent by construction). Served at /.well-known/svrnty/release.json.
//
// ATOMIC by design: the release object AND the canonical manifest bytes ship in ONE document. A split delivery
// (release.json + a separate manifest.bin) can transiently disagree during a deploy — v2 release, v1 manifest —
// which the bundle_hash bind would (correctly) reject as a WARN, but that is a self-inflicted false-alarm. One
// document = one atomic version. (The optional `genesis` block is present on bootstrap-capable deliveries so a
// first-install client can capture the TOFU pin from the same fetch.)
//
// This is ORIGIN-SERVED = attacker input. parseDeliveredRelease NEVER throws and is FAIL-CLOSED: it returns an
// explicit tagged union `{ok:true,...} | {ok:false,error}` (Flint #142038 — a `{ok}` discriminant is harder to
// fumble than an `'error' in x` in-check). Every field is bounds/type-checked before use; there is NO
// partial-object escape path, so a later stage can never dereference a half-valid release. The crypto (sig +
// bundle_hash bind) is verified downstream; this layer only guarantees a structurally well-formed object or a
// typed rejection the caller treats as "no valid release".

import type { ReleaseObject } from '../lib/crypto/release-object.js';
import type { DeliveredGenesis } from './gd-bootstrap.js';

export interface DeliveredRelease {
  release: ReleaseObject; // bundleHash(32) / versionCounter / epoch / sig
  releasePublisherFp: Uint8Array; // 32 — the publisher_fp bound inside the release preimage (bytes, for verify)
  manifestBytes: Uint8Array; // the canonical §4 manifest bytes (verifyServedManifest checks SHA256==bundle_hash)
  genesis?: DeliveredGenesis; // present on bootstrap-capable deliveries (genesis pubkeys for first-install TOFU)
}

// Tagged union — the caller does `if (!r.ok) return …` (fail-closed) before touching any release field.
export type ParsedDelivery = ({ ok: true } & DeliveredRelease) | { ok: false; error: string };

function fail(error: string): { ok: false; error: string } {
  return { ok: false, error };
}

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null;
}

function hexToBytes(h: unknown, expectedLen: number): Uint8Array | null {
  if (typeof h !== 'string' || h.length !== expectedLen * 2) return null;
  if (!/^[0-9a-fA-F]+$/.test(h)) return null;
  const out = new Uint8Array(expectedLen);
  for (let i = 0; i < expectedLen; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function b64ToBytes(s: unknown): Uint8Array | null {
  if (typeof s !== 'string' || s.length === 0) return null;
  let bin: string;
  try {
    bin = atob(s);
  } catch {
    return null; // not valid base64
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Parse a served release delivery. Returns `{ok:true, ...DeliveredRelease}` on success, or `{ok:false, error}`
 * on any malformation. Structural + type validation only — the signature and the manifest⇄bundle_hash bind are
 * checked downstream (verifyReleaseEpoch0 / verifyServedManifest). epoch is validated as a non-negative safe
 * integer here; the epoch-0-only launch policy is enforced by verifyReleaseEpoch0 (not duplicated here).
 */
export function parseDeliveredRelease(raw: unknown): ParsedDelivery {
  if (!isRecord(raw)) return fail('delivery is not an object');
  if (raw.v !== 1) return fail(`unsupported delivery version: ${String(raw.v)}`);

  const releasePublisherFp = hexToBytes(raw.publisher_fp, 32);
  if (!releasePublisherFp) return fail('publisher_fp is not 32-byte hex');

  if (!isRecord(raw.release)) return fail('release block missing');
  const r = raw.release;

  const bundleHash = hexToBytes(r.bundle_hash, 32);
  if (!bundleHash) return fail('release.bundle_hash is not 32-byte hex');

  if (!Number.isSafeInteger(r.version_counter) || (r.version_counter as number) < 1) {
    return fail('release.version_counter is not a safe integer >= 1');
  }
  if (!Number.isSafeInteger(r.epoch) || (r.epoch as number) < 0) {
    return fail('release.epoch is not a non-negative safe integer');
  }

  const sig = b64ToBytes(r.sig);
  if (!sig || sig.length <= 64) return fail('release.sig missing or too short (need ed25519 64B + ML-DSA leg)');

  const manifestBytes = b64ToBytes(raw.manifest);
  if (!manifestBytes) return fail('manifest bytes missing or not base64');

  const release: ReleaseObject = {
    bundleHash,
    versionCounter: r.version_counter as number,
    epoch: r.epoch as number,
    sig,
  };

  // Optional genesis (bootstrap deliveries). Structural presence only — gd-bootstrap does the length + the
  // fp == SHA256(pubkeys) substitution-reject before pinning.
  let genesis: DeliveredGenesis | undefined;
  if (raw.genesis !== undefined) {
    if (!isRecord(raw.genesis)) return fail('genesis present but not an object');
    const g = raw.genesis;
    for (const k of ['sign_pub', 'enc_pub', 'kem_pub', 'sig_pub'] as const) {
      if (typeof g[k] !== 'string' || (g[k] as string).length === 0) return fail(`genesis.${k} missing`);
    }
    genesis = {
      publisherFpHex: raw.publisher_fp as string,
      signPubB64: g.sign_pub as string,
      encPubB64: g.enc_pub as string,
      kemPubB64: g.kem_pub as string,
      sigPubB64: g.sig_pub as string,
      firstCounter: release.versionCounter,
    };
  }

  return { ok: true, release, releasePublisherFp, manifestBytes, genesis };
}
