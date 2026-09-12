// CANONICAL ENROLL — the permanent, OPEN identity-mint registration path (Apollo's lane, track-a).
//
// Blueprint model (svrnty_how_it_all_works_blueprint §Identity/§Invite/§PSI; Peter #135459, Archie
// #135495): mint = display name + passphrase → you're in. NO email, NO OTP, NO account. The mint is
// OPEN — sybil-resistance is STRUCTURAL, not a server gate: an uninvited / mass-minted id is in no
// one's graph → isolated + undiscoverable (§PSI known-unverified is private by construction), so a
// flood of fake mints is harmless. The "invite" is the GIVER's client-side QR/link introduction
// (Grow→Join), NOT a server enrollment gate or tracker table.
//
// This module registers the minted 4-key identity's PUBLIC keys with the authority (POST /verify) so
// the identity is reachable for mailbox/PSI — with NO gate fields. It SUPERSEDES the two pre-canonical
// wrong-genesis doors (armored SoverentityFrontend slug-register, KB#89341; truncated-fp landing.html).
//
// The encoding trap it closes: /verify re-derives the DID as SHA256(sign‖enc‖kem‖sig) over the RAW
// public-key bytes and b64-decodes + length-checks the PQ legs. So we send the RAW keys as base64 —
// NEVER the armored OpenPGP key, NEVER hex for the PQ legs, NEVER a truncated fp. The /verify contract
// is validated end-to-end on dev (KB#89386); encoding per Flint's option-B sign-off.

import { canonicalPubsFromArmoredPublicKey } from './fingerprint';
import { uint8ToBase64 } from '../crypto/pq';

/** The exact /verify request body for a canonical 4-key (hybrid) mint. Field NAMES are historical
 *  misnomers — the VALUES are X25519-32B / ML-KEM-1024-1568B / ML-DSA-87-2592B. */
export interface CanonicalVerifyFields {
  fingerprint: string; // full-64 hex canonical DID = SHA256(sign‖enc‖kem‖sig)
  public_key: string; // base64 raw Ed25519 (32B) — NOT the armored OpenPGP key
  x25519_pk: string; // base64 raw X25519 enc (32B)
  mlkem768_pk: string; // base64 raw ML-KEM-1024 kem (1568B)
  mldsa65_pk: string; // base64 raw ML-DSA-87 sig (2592B)
  key_version: 2; // 2 = hybrid PQ
}

/** Build the /verify body from a minted identity (= generateIdentity().identity / IdentityData).
 *  Reuses the vetted canonicalPubsFromArmoredPublicKey derivation (same as buildSatelliteRegisterFields
 *  and the mint path) and emits base64 directly from the RAW bytes. Returns null if key material is
 *  missing (fail-closed — caller must not POST a partial bundle). */
export async function buildCanonicalVerifyFields(identity: {
  identity?: { fingerprint?: string; public_key?: string; name?: string };
  post_quantum?: { kem_public_key?: string; sig_public_key?: string };
}): Promise<CanonicalVerifyFields | null> {
  const armored = identity?.identity?.public_key;
  const kemB64 = identity?.post_quantum?.kem_public_key;
  const sigB64 = identity?.post_quantum?.sig_public_key;
  if (!armored || !kemB64 || !sigB64) return null;
  const pubs = await canonicalPubsFromArmoredPublicKey(armored, kemB64, sigB64);
  return {
    fingerprint: pubs.fingerprint,
    public_key: uint8ToBase64(pubs.signPub), // raw Ed25519 → b64 (NOT armored)
    x25519_pk: uint8ToBase64(pubs.encPub), // raw X25519 → b64
    mlkem768_pk: uint8ToBase64(pubs.kemPub), // raw ML-KEM-1024 → b64
    mldsa65_pk: uint8ToBase64(pubs.sigPub), // raw ML-DSA-87 → b64
    key_version: 2,
  };
}

/** True iff the OPEN canonical-enroll is wired end-to-end (the authority's /verify accepts the open,
 *  no-OTP mint). FALSE until the OTP entry-gate is removed from /verify AND the open path is
 *  e2e-verified — same claim-gate discipline as isPSIDiscoveryLive: flip the flag WITH the wire,
 *  never ahead of it, so the default build never fires an enroll the server would 404. */
export function isCanonicalEnrollLive(): boolean {
  return process.env.NEXT_PUBLIC_CANONICAL_ENROLL === 'true';
}

export interface EnrollResult {
  ok: boolean; // /verify returned 2xx (the authority accepted the mint)
  satelliteRegistered: boolean; // propagation confirmed — gate the "minted / live" copy on THIS, not ok (G2)
  status?: string;
  profileUrl?: string;
  error?: string;
}

type FetchLike = typeof fetch;

/** OPEN mint registration: build the /verify body and POST it to the proxy with NO gate fields.
 *  Gate success copy on `satelliteRegistered` (full propagation), not merely `ok` — a 200-but-false is
 *  the 429 soft-fail window where the binding is still finalizing (Hypatia G2). */
export async function enrollCanonicalIdentity(
  identity: Parameters<typeof buildCanonicalVerifyFields>[0],
  fetchImpl: FetchLike = fetch,
): Promise<EnrollResult> {
  const fields = await buildCanonicalVerifyFields(identity);
  if (!fields) {
    return { ok: false, satelliteRegistered: false, error: 'identity is missing key material' };
  }
  const res = await fetchImpl('/api/satellite/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(fields),
  });
  const data = await res.json().catch(() => ({} as Record<string, unknown>));
  if (!res.ok) {
    return {
      ok: false,
      satelliteRegistered: false,
      status: typeof data?.status === 'string' ? data.status : undefined,
      error:
        (typeof data?.detail === 'string' && data.detail) ||
        (typeof data?.error === 'string' && data.error) ||
        `HTTP ${res.status}`,
    };
  }
  return {
    ok: true,
    satelliteRegistered: data?.satellite_registered === true,
    status: typeof data?.status === 'string' ? data.status : undefined,
    profileUrl: typeof data?.profile_url === 'string' ? data.profile_url : undefined,
  };
}
