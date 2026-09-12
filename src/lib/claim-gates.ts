// src/lib/claim-gates.ts
//
// CLAIM GATES — the honesty-gate made systematic (Archie #129179: "governance-as-architecture").
//
// A claim gate is ONE honest boolean answering "is this capability REAL yet?" — imported by BOTH:
//   • the user-facing copy  → show the true claim only when the gate is true, else the honest hedge
//   • the CI launch_claim_sweep → assert no surface claims a capability the gate says isn't live
// One source of truth, no per-surface divergence, self-flips WITH the wire (never ahead of it).
//
// PATTERN — mirrors components/biometric/biometric-seam.ts `isBiometricSeamLive`, which Archie cleared
// in #101 as "the do-no-harm fix, done right": each gate is an honest CONSTANT tied to the wire by
// comment and GUARDED by claim-gates.test.ts (asserting false). It is deliberately NOT a runtime probe.
// The test prevents a premature/dishonest flip: whoever wires the capability flips the constant AND
// updates the test in the same change, so CI enforces copy ⇔ reality.

// The honest-signal barrel: re-export the biometric gate so every claim gate imports from ONE module.
// (biometric-seam exports pure, node-safe helpers — no JSX — so this is a plain function re-export.)
export { isBiometricSeamLive } from '../components/biometric/biometric-seam';

/**
 * ML-KEM-1024 post-quantum ENCRYPTION (encapsulation) is wired into the send/seal path.
 *
 * FALSE today: `hybridEncapsulate()` has ZERO real callers (only the crypto/index barrel re-export) —
 * the seal is classical OpenPGP. Cards CARRY a pq_kem public key (mint = ED25519+ML-DSA-87+ML-KEM-1024)
 * but nothing encrypts with it yet. Carrying a key ≠ protection.
 * Flip to true WITH the first real `hybridEncapsulate` caller (and update claim-gates.test.ts).
 */
export function isPQEncapLive(): boolean {
  return false;
}

/**
 * ML-DSA-87 post-quantum SIGNING is wired into the identity/card-sign path.
 *
 * FALSE today: `buildSignedIdentityCard()` signs classical-only (does not thread pqSigningSecretKey →
 * SUITE_CLASSICAL). Cards carry a pq_sig public key but are not PQ-signed.
 * Flip to true WITH the card-sign path threading the PQ secret (and update claim-gates.test.ts).
 */
export function isPQSignLive(): boolean {
  return false;
}

/**
 * Post-quantum protection is FULLY live — BOTH the ML-KEM encryption AND the ML-DSA signature paths
 * are wired + verified. Use for a blanket "post-quantum protected" claim. Where a surface is specific,
 * prefer the granular gate: `isPQEncapLive` for encryption claims, `isPQSignLive` for signature claims.
 */
export function isPQWireLive(): boolean {
  return isPQEncapLive() && isPQSignLive();
}

/**
 * PSI mutual-contact DISCOVERY (the KNOW-layer "trust map") is wired end-to-end and safe to run.
 *
 * FALSE today: wired but DO-NOT-ADVERTISE. The client wire-in (per-peer blinder persisted on the
 * contact record → initiator completes on a later tick → mutual set applied; forward-revocation on
 * retract) ships gated OFF — startKnowLayerSync is not started while this is false, so prod carries
 * PSI dormant + honest (no discovery runs, no "see who you both know" claim). Flip to true WITH the
 * passing e2e verify (determinism / unlinkability / set-change→new-session / stateless-reload) + Flint's
 * at-rest-blinder co-verify (and update claim-gates.test.ts). Alpha safety baseline is client-side D1
 * mutual-consent; the relay-level mutual-reveal fairness-gate is post-alpha (Archie #134280).
 */
export function isPSIDiscoveryLive(): boolean {
  // Env-driven so the wired-but-dormant PSI discovery can be exercised for QA on DEV without shipping
  // it live to prod. NEXT_PUBLIC_* is inlined at build: the DEV build sets
  // NEXT_PUBLIC_PSI_DISCOVERY_LIVE=true; PROD leaves it unset → false = dormant/honest by construction
  // (no discovery runs, no "see who you both know" claim). After the full QA-1st (mechanism: Apollo/
  // Flint · claims: Hypatia) + Flint's at-rest co-verify, this becomes an unconditional true and the
  // env read retires.
  return process.env.NEXT_PUBLIC_PSI_DISCOVERY_LIVE === 'true';
}
