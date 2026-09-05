# svrnty — frontend build queue

Work top-down: the top task first, then the next. Build UI to spec (**render-glass**) — the crypto / gate / PSI / trust plumbing lives behind stable hooks maintained by the core team; **wire the UI to those hooks, NEVER modify them**. Open **ONE PR per task** into the canonical branch. Copy that makes a security / recovery / trust **CLAIM** needs review before merge — open the PR, do **not** self-merge crypto/claim surfaces. See `.cursor/rules`.

> ⚠️ **EXCEPTION for Task #1 (§5) ONLY:** §5 is an **AUTHORIZED crypto-plumbing exception** (architecture + security review), governed by `.cursor/rules/svrnty-section5-exception.mdc`. For §5 you DO modify the named identity/crypto sites — but ONLY by implementing the exact construction inlined below (make **NO** crypto decisions), as **ONE draft PR** reviewed against the acceptance checklist **before** any merge. Everywhere else, the standing render-glass "never touch crypto" boundary is fully in force.

## 1. §5 — Greenfield Identity + Auth: self-certifying fingerprint + raw Ed25519 auth  [AUTHORIZED crypto-plumbing exception — see .cursor/rules/svrnty-section5-exception.mdc]

**Context:** the identity base is greenfield (a clean slate; zero real identities to migrate). The satellite side is done + verified (register re-derives the fp + enforces exact key lengths: 200/200/200 happy-path, all wrong-length → 400). This task builds the CLIENT side to match, byte-for-byte.

**What changes — ONLY these sites:**
- **(a) Identity `sign` key (scalar-extract — NO new key)** → use the EXISTING OpenPGP primary Ed25519 as the raw `sign` key via scalar-extract (see the snippet) — read the seed TRANSIENTLY for signing, NEVER persist a new copy (it IS the vaulted OpenPGP key, already encrypted-at-rest). Do NOT generate or store a new/separate key.
- **(b) Fingerprint derivation** → replace OpenPGP `getFingerprint()` as the canonical identity ID with the SHA256 bundle below, at ~3 sites: `src/lib/identity/browser-identity.ts`, `src/lib/identity/core.ts`, `src/lib/identity/fingerprint.ts`.
- **(c) Wire** the raw `tag#3` signFn + the `/bind` ceremony (client path) + the `buildPsiSyncOptions` seam (`know-layer-sync.ts` ~:196) + the PSI trigger.
- **KEEP** OpenPGP for encryption/cards + the ~10 existing signing paths (exchange / hybrid / sign-envelope / identity-card-sign / seal / contact-update / joiner-response / slug-claim). Do NOT rip out OpenPGP.

**The canonical fingerprint (BYTE-EXACT — must match the satellite; implement exactly, NO decisions):**
```
fp = hex( SHA256( sign_pub ‖ enc_pub ‖ kem_pub ‖ sig_pub ) )   [≥16-char hex prefix]
exact order:  sign ‖ enc ‖ kem ‖ sig   ·   raw pubkey bytes   ·   EXACT FIPS lengths:
  Ed25519 sign = 32 · X25519 enc = 32 · ML-KEM-1024 kem = 1568 · ML-DSA-87 sig = 2592
0x40-STRIP both sign and enc pubkeys (algo-22 native-point prefix) BEFORE hashing / register.
```
- `sign_pub` = the scalar-extracted, 0x40-stripped Ed25519 pubkey (snippet: `extractRawSign().signPub`).
- `enc_pub`  = `strip0x40(encSubkey.keyPacket.publicParams.Q)` — the OpenPGP **encryption subkey's** X25519 pubkey (NOT the primary), canonical 32B.
- `kem_pub` / `sig_pub` = the ML-KEM / ML-DSA pubkeys already produced today.
If the client fp doesn't byte-match the satellite's derivation, register returns **400**.

**Auth preimages (byte-exact — implement exactly):**
- **/bind** (register the raw `sign` key as the bound sig_pubkey): `Ed25519(sign_seed, "svrnty-bind:{sign_pubkey_hex}:{nonce}:{epoch}")`. Prerequisite for tag#3 (unbound → tag#3 403s).
- **tag#3 PSI auth:** `Ed25519(sign_seed, "svrnty-psi-auth:{fp}:{unix}")`, wire `"{unix}:{b64sig}"`, ±30s window.
Both sign with the scalar-extracted Ed25519 seed (snippet: `rawSign`).

**PROVEN crypto core — COPY VERBATIM (do NOT re-derive; author NO crypto here):**
```ts
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';

// svrnty identity = openpgp generateKey({type:'ecc',curve:'ed25519'}) → algo 22 (eddsaLegacy):
//   privateParams.seed = raw 32B Ed25519 seed; publicParams.Q = 33B (0x40 native-point prefix).
// PROVEN: noble.getPublicKey(seed) === strip0x40(Q) AND noble.sign(seed) verifies vs it.
const strip0x40 = (q: Uint8Array): Uint8Array =>
  (q.length === 33 && q[0] === 0x40) ? q.slice(1) : q;   // canonical 32B raw point

// key MUST be DECRYPTED first: await openpgp.decryptKey({ privateKey: readPrivateKey({armoredKey}), passphrase })
export function extractRawSign(decryptedIdentityKey: any): { seed: Uint8Array; signPub: Uint8Array } {
  const kp = decryptedIdentityKey.keyPacket;
  const seed: Uint8Array = kp.privateParams.seed;                       // 32B raw private — IN-MEMORY ONLY, never persist (it IS the vaulted openpgp key)
  const signPub = strip0x40(kp.publicParams.A ?? kp.publicParams.Q);    // 32B canonical Ed25519 pubkey
  // FAIL-CLOSED invariant — never sign with an inconsistent key:
  if (bytesToHex(ed25519.getPublicKey(seed)) !== bytesToHex(signPub))
    throw new Error('scalar-extract invariant failed: seed↔signPub mismatch');
  return { seed, signPub };
}

// raw Ed25519 auth-sign for tag#3 + /bind (raw 64B sig over EXACT preimage bytes)
export const rawSign = (preimage: Uint8Array, seed: Uint8Array): Uint8Array => ed25519.sign(preimage, seed);
```
For the fp bundle: `sign_pub = extractRawSign(key).signPub`; `enc_pub = strip0x40(encSubkey.keyPacket.publicParams.Q)`; `fp = SHA256(sign_pub ‖ enc_pub ‖ kem ‖ sig)`.

**Guardrails (non-negotiable — from `.cursor/rules/svrnty-section5-exception.mdc`):**
1. Scoped to the named §5 sites ONLY — NOT a blanket identity/crypto open.
2. Build to byte-exact spec, NO crypto DECISIONS. If a value is ambiguous or you'd have to CHOOSE a crypto value → **STOP and flag for review**. Call `@noble`; never hand-roll crypto.
3. **ONE draft PR. Do NOT self-merge.** Reviewed against the acceptance checklist (below) + the empirical acceptance tests BEFORE any merge.
4. **Data-privacy invariant:** tags / blocked-flags / group-labels are device-local — NEVER serialize onto any publish / PSI-sync / export payload. §5 touches PSI → assert with a NEGATIVE test.
5. **KEEP untouched:** OpenPGP encryption/cards + the 10 signing paths; vault unlock/recovery (`initSessionKey` / `verifyPassphrase`); the satellite/server; gate/visibility/consent/trust-semantics; the seal.
6. The `sign` seed is **IN-MEMORY ONLY** (it IS the vaulted OpenPGP key, already encrypted-at-rest) — read it transiently for signing, NEVER persist a new copy. The key MUST be decrypted (passphrase) before extraction.
7. **No internal refs in committed output (public repo):** NEVER echo agent names, internal KB/doc references, or internal spec/invariant labels into committed code, comments, or PR text. Neutral product terms only.

**Acceptance checklist (the built PR is reviewed against these — build so they pass):**
- [ ] fp byte-exactness: client `SHA256(sign‖enc‖kem‖sig)[≥16]` == satellite derivation (exact order, raw bytes, exact lengths).
- [ ] fp commits to ALL 4 keys (omitting any one changes the fp).
- [ ] raw-sign vectors: /bind + tag#3 verify server-side; round-trip register→bind→tag#3→200.
- [ ] scalar-extract correctness: `noble.getPublicKey(seed) == 0x40-stripped Q` AND `noble.sign` verifies vs the committed pubkey (the snippet's fail-closed invariant).
- [ ] single basis: no residual OpenPGP-`getFingerprint()` in identity/auth/discovery.
- [ ] reject-wrong-length: a bundle with any key ≠ its FIPS length → register 400.

---
*Queue updated 2026-09-05.*
*#1 = §5 Greenfield Identity+Auth refactor — governed by `.cursor/rules/svrnty-section5-exception.mdc` (architecture + security review). Proven scalar-extract snippet inlined. AUTHORIZED crypto-plumbing exception — the exact construction is plumbed with NO crypto decisions; ONE draft PR, no self-merge; the built seam is reviewed against the acceptance checklist before trust.*
*Prior queue: GROW 2-tab = DONE (merged to main as PR #104). biometric-honesty + top-nav = DONE (PR #101 + #102). All cleared.*
