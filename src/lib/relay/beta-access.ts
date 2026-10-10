// src/lib/relay/beta-access.ts
// Layer (A) beta-access token — "does this user have messaging at all," 1 per address book.
// Gates the over-wire DUMB mailbox (/api/relay, §5.1 inviteRequired seam), NOT the keystone smart
// mailbox. Format + verify per svrnty_access_token_A_format_v0.md (Apollo, crypto-lead).
//
// Reuses the EXISTING envelope primitives (sign-envelope.ts / canonical.ts) — NO new signer — exactly
// like mailbox-auth.ts + slug-claim.ts. The issuer (Peter) signs under DOMAIN_BETA_ACCESS; the relay
// verifies against a PINNED issuer key (the trust root; env, see §4 of the format). The token is bound
// to `sub` (the redeemer's canonical fp) and is non-transferable: redemption ALSO requires owner-auth
// for deriveMailboxId(sub) (claim endpoint, DOMAIN_MAILBOX_CLAIM) — a leaked token is useless without
// sub's key. This module does the TOKEN half (decode + issuer-sig + exp); the owner-auth half +
// one-time jti + claim-registry live in mailbox-auth.ts + claim-registry.ts, composed by the endpoint.

import { canonicalize } from '@/lib/format/canonical';
import { signWithEnvelope, verifyWithEnvelope, type EnvelopeSignature } from '@/lib/crypto/sign-envelope';

/** Domain tag — mirrors the svrnty:mailbox-poll:v1 / svrnty:note:v0 family (sign-envelope LP binds it). */
export const DOMAIN_BETA_ACCESS = 'svrnty:beta-access:v0';

export const BETA_ACCESS_TYP = 'svrnty:beta-access:v0';
export const BETA_ACCESS_SCOPE = 'messaging';

export interface BetaAccessTokenV0 {
  v: 0;
  typ: typeof BETA_ACCESS_TYP;
  iss: string; // issuer (Peter's beta-gate) identity fp — must equal the pinned issuer fp
  sub: string; // redeemer's canonical fp — "1 per address book"; bound to owner-auth at claim
  jti: string; // unique token id (hex) — one-time redemption + revocation handle
  iat: number; // issued-at, epoch ms (INTEGER — canonicalize forbids floats)
  exp?: number; // expiry epoch ms; OMITTED (field-absent) = no expiry. NEVER null — canonicalize() throws on null.
  scope: typeof BETA_ACCESS_SCOPE;
  sig: EnvelopeSignature; // issuer signature over every field EXCEPT sig
}

/** The signed input: canonicalize every field EXCEPT `sig` (the pinned DOMAIN_BETA_ACCESS preimage). */
function betaAccessSigningInput(t: Omit<BetaAccessTokenV0, 'sig'>): string {
  // exp is OMITTED when absent — canonicalize() throws on null + forbids floats (epoch-ms ints only);
  // field-absent = no-expiry (format v0 §2, Apollo's ran-it fix). Key order is irrelevant — canonicalize sorts.
  const base = { v: t.v, typ: t.typ, iss: t.iss, sub: t.sub, jti: t.jti, iat: t.iat, scope: t.scope };
  return canonicalize(t.exp === undefined ? base : { ...base, exp: t.exp });
}

// ── cross-env base64url (browser client + Node relay both run adjacent modules) ──
function b64urlEncode(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s: string): string {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

export function encodeBetaAccessToken(token: BetaAccessTokenV0): string {
  return b64urlEncode(JSON.stringify(token));
}

/** Parse the wire token, fail-closed on ANY malformed field. Returns null (never throws). */
export function decodeBetaAccessToken(wire: string): BetaAccessTokenV0 | null {
  try {
    const t = JSON.parse(b64urlDecode(wire));
    if (
      t?.v !== 0 ||
      t?.typ !== BETA_ACCESS_TYP ||
      typeof t?.iss !== 'string' ||
      typeof t?.sub !== 'string' ||
      typeof t?.jti !== 'string' ||
      typeof t?.iat !== 'number' ||
      !(t?.exp === undefined || typeof t?.exp === 'number') || // absent=no-expiry; null is INVALID (never signed)
      t?.scope !== BETA_ACCESS_SCOPE ||
      typeof t?.sig?.classical !== 'string' ||
      (t?.sig?.pq_signature !== undefined && typeof t?.sig?.pq_signature !== 'string')
    ) {
      return null;
    }
    return t as BetaAccessTokenV0;
  } catch {
    return null;
  }
}

/** The relay's pinned issuer trust-root (format §4; sourced from env at the endpoint). */
export interface PinnedIssuer {
  fingerprint: string; // SVRNTY_BETA_ISSUER_FP
  publicKeyArmored: string; // SVRNTY_BETA_ISSUER_PUBKEY
  pqSigningPublicKey?: Uint8Array; // optional — a canonical (hybrid) issuer
}

export type BetaTokenVerdict =
  | { ok: true }
  | { ok: false; reason: 'bad-issuer' | 'bad-sig' | 'expired' };

/**
 * Verify the TOKEN half (format §3 steps 1 + 4-exp): the token is signed by the PINNED issuer and not
 * expired. The issuer is the trust root — NO fingerprintMatchesKey on it, the pin IS the trust (so
 * token.iss must equal the pinned fp AND the sig must verify against the pinned key). jti-unseen (§3.4)
 * + owner-auth (§3.2) + sub-binding (§3.3) are the endpoint's job (registry + mailbox-auth). Fail-closed.
 */
export async function verifyBetaAccessToken(token: BetaAccessTokenV0, issuer: PinnedIssuer, now: number): Promise<BetaTokenVerdict> {
  // 1a. iss must equal the pinned issuer fp — the token claims OUR trust root, not some other issuer.
  if (token.iss !== issuer.fingerprint) return { ok: false, reason: 'bad-issuer' };
  // 1b. issuer signature over the canonical token (every field except sig), under DOMAIN_BETA_ACCESS.
  let sigOk = false;
  try {
    sigOk = await verifyWithEnvelope(
      DOMAIN_BETA_ACCESS,
      betaAccessSigningInput(token),
      token.sig,
      issuer.publicKeyArmored,
      issuer.pqSigningPublicKey,
    );
  } catch {
    sigOk = false;
  }
  if (!sigOk) return { ok: false, reason: 'bad-sig' };
  // 4-exp. expiry (absent = no expiry; format §3 step-4 = "exp absent || now<=exp").
  if (token.exp !== undefined && now > token.exp) return { ok: false, reason: 'expired' };
  return { ok: true };
}

/**
 * ISSUER-SIDE signer (format §4). Peter runs this (a small CLI) to mint a token for a beta user's
 * `sub` fp. Lives here so tests + the CLI share ONE implementation and the wire can't drift. Not
 * called by the relay — the relay only verifies.
 */
export async function signBetaAccessToken(
  fields: { iss: string; sub: string; jti: string; iat: number; exp?: number },
  issuerPrivateKeyArmored: string,
  issuerPassphrase: string,
  issuerPqSecret?: Uint8Array,
): Promise<BetaAccessTokenV0> {
  const unsigned: Omit<BetaAccessTokenV0, 'sig'> = {
    v: 0,
    typ: BETA_ACCESS_TYP,
    iss: fields.iss,
    sub: fields.sub,
    jti: fields.jti,
    iat: fields.iat,
    scope: BETA_ACCESS_SCOPE,
    ...(fields.exp !== undefined ? { exp: fields.exp } : {}), // omit when no expiry (never null)
  };
  const sig = await signWithEnvelope(DOMAIN_BETA_ACCESS, betaAccessSigningInput(unsigned), issuerPrivateKeyArmored, issuerPassphrase, issuerPqSecret);
  return { ...unsigned, sig };
}
