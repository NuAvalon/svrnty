# svrnty — frontend build queue

Work top-down: the top task first, then the next. Build to spec. Open **ONE PR per task**. Copy/code that makes a security / recovery / trust **CLAIM** needs review before merge — do **not** self-merge crypto/claim surfaces. See `.cursor/rules`.

## 1. Mint-Build Recipe v2 (KERI authority-key pre-rotation) — CRYPTO/GENESIS · DRAFT PR ONLY · CO-VERIFY GATES MERGE

**Genesis-permanent crypto surface — build the CODE as a DRAFT PR; do NOT self-merge.** Build exactly the files below (5 files + tsx tests). Stacks on current main (post-#110). Spec is Flint-crypto-co-verified GREEN (#131330). After the draft PR opens, Apollo + Flint co-verify the BUILT output against the 3 build-time nail-downs (reveal-match encoding parity: ed25519 32B ‖ ML-DSA 2592B raw; dedicated rotation domain-tag e.g. `svrnty:rotation:v1`; anchor-PQ-sig unchanged) BEFORE any merge. CODE only — NOT a live mint. Full authoritative spec follows verbatim:

---
# Mint-Build Recipe v2 — wire DurableIdentity + next_authority_commitment (KERI authority-key pre-rotation) into genesis

> **SUPERSEDES v1.** Flint's crypto call (#131318): adopt KERI authority-key pre-rotation. The genesis-permanent commitment is over the next raw **hybrid SIGN-ONLY rotation-AUTHORITY key** (ed25519+ML-DSA, seed-derived, NO openpgp), NOT the next operational keys. This DESIGNS OUT flag-c / the enc-leg endianness / the whole deterministic-openpgp-keygen prerequisite (there is no enc-leg to commit). Anti-theft is identical. Determinism is trivially provable (ed25519.getPublicKey + ml_dsa.keygen from KDF legs).

## SCOPE (launch)
Ships: **(1) next_authority_commitment minted at genesis** [the one-way-door + anti-theft linchpin] · **(2) the extensible schema** [versioned card + open successor-KIND] · **(3) the ROTATION verifier** [address book authenticates a rotation via the pre-committed authority]. Recovery/revocation kinds = POST-launch via the extensible kind-field. The rotation EMITTER UX = post-launch; the verifier + genesis commitment ship now (the one-way-door).

**Anti-theft model:** genesis commits `H(K_auth_1)`. A thief holds the current OPERATIONAL keys but NOT the cold seed → cannot derive `K_auth_1` → cannot authorize a rotation → cannot hijack. Only the authority (raw ed25519+ML-DSA, sign-only) is seed-derived; operational openpgp keys are fresh-random at each rotation (as at genesis today).

---
## FILE 1 — src/lib/identity/envelope.ts (types + version + extensibility)

**(1a) IdentityCard.identity += next_authority_commitment** (the genesis one-way-door field). ADD to `IdentityCard.identity`:
```ts
    next_authority_commitment: string;  // 64-hex = SHA256(next-epoch raw hybrid AUTHORITY pubkeys: ed25519 ‖ ML-DSA). Genesis-permanent. The rotation verifier checks a revealed K_auth against it. '' for pre-mint/legacy cards.
```
**(1b) DurableIdentity += next_authority_commitment** (construct at genesis; today format-only). ADD after `epoch`:
```ts
  next_authority_commitment: string;    // epoch+1 pre-committed authority-key hash — the anti-theft pin
```
**(1c) SuccessorAuth — rotation kind carries the authority reveal + signature. Extensible KIND** (open discriminant; verifier FAIL-CLOSES on unknown kind). Rotation kind shape:
```ts
  | { kind: 'rotation';
      auth_pubkeys: { sign: string; pq_sig: string };   // revealed K_auth (ed25519 ‖ ML-DSA), must hash to prior epoch's next_authority_commitment
      sig_by_authority: string;                          // hybrid sig BY K_auth over the successor signing-input (below)
    }
  // recovery / revocation / authority-transfer kinds slot in POST-LAUNCH — the kind field is an OPEN discriminant; verifier switch has a default that FAIL-CLOSES (throws) on unknown kind. NOT a closed union.
```
**(1d) Card schema version bump** `'1.0' → '1.1'` (now carries next_authority_commitment).
**(1e) identityCardSigningInput UNCHANGED** — `canonicalize(card, {exclude:['signature','pq_signature']})` covers all present fields → next_authority_commitment is signed FOR FREE once on card.identity. (Note it so Cursor doesn't add an exclude.)

**Extensibility contract (Archie/Flint #131135):** ADDITIVE display/non-security fields → tolerate (ignore-unknown, they stay under the signature via canonicalize). SECURITY-relevant future fields (revoked, downgrade/algorithm flag, authority/epoch change) → ride a schema VERSION bump; an old verifier that doesn't understand that version must FAIL-CLOSED on the affected decision, NEVER silently-ignore (X.509 critical-vs-non-critical model).

---
## FILE 2 — src/lib/identity/fingerprint.ts (the next-authority commitment)

Add `deriveNextAuthorityCommitment` — commits the epoch+1 rotation-AUTHORITY key, derived from the cold seed. SIGN-ONLY (ed25519+ML-DSA), so NO openpgp / NO ECDH / NO endianness / NO deterministic-openpgp-keygen. Re-derivable at rotation from the same seed.
```ts
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

/** Pre-commit the NEXT epoch's rotation-AUTHORITY key: SHA256(authEd ‖ authDsa), both raw sign-only pubs
 *  DERIVED deterministically from masterSecret via domain-separated HKDF. Genesis calls this while masterSecret
 *  is in-hand (before fill(0)). At rotation, the owner re-derives K_auth from the same cold seed, reveals these
 *  two pubs (verifier checks H(reveal)==commitment), and signs the successor with the matching secrets. */
export function deriveNextAuthorityCommitment(masterSecret: Uint8Array, epoch: number): string {
  const leg = (name: string, len: number) =>
    hkdf(sha256, masterSecret, undefined, `svrnty:rotation-authority:v1:epoch-${epoch}:${name}`, len);
  const authEd  = ed25519.getPublicKey(leg('ed', 32));            // 32B raw ed25519 (sign-only) — deterministic
  const authDsa = ml_dsa87.keygen(leg('dsa', 32)).publicKey;     // 2592B ML-DSA-87 (sign-only) — deterministic (FIPS-204 seed = 32B ξ)
  return bytesToHex(sha256(concatBytes(authEd, authDsa)));        // 64-hex — the authority commitment
}
```
✅ FLINT CO-VERIFY (crypto, #131318): (a) HKDF domain-sep — distinct `info` per leg; (b) ed25519.getPublicKey(seed) + ml_dsa87.keygen(seed) are DETERMINISTIC from the KDF legs (already-solid; trivial spike optional — the fragile openpgp path is DESIGNED OUT); (c) K_auth is SIGN-ONLY → no ECDH/hybrid-encryption concern applies to it; (d) commitment = SHA256(authEd‖authDsa), stable ordering. **flag-c is MOOT (no enc-leg).**

---
## FILE 3 — src/lib/identity/browser-identity.ts (genesis mint)

masterSecret is in-hand between `createKeyVault` (returns it) and `masterSecret.fill(0)`. Insert the commitment there.
```ts
    // after: const { vault, shards, seedPhrase, masterSecret } = await createKeyVault(...);
    const next_authority_commitment = deriveNextAuthorityCommitment(masterSecret, 1);
    // then assign onto the identity wrapper (see NB) + build the durable record:
    identity.next_authority_commitment = next_authority_commitment;              // wrapper top-level, beside post_quantum (beat-3: card-sign reads it here)
    identity.durable = { fingerprint, epoch: 0, next_authority_commitment };     // DurableIdentity, constructed at genesis (was format-only)
    // ... then masterSecret.fill(0); storeIdentity(fingerprint, identity); ...
```
NB: `identity` is built BEFORE createKeyVault today (fingerprint minted first). Keep it early and ASSIGN the two fields post-createKeyVault (minimal reorder).
⚠ ORDER INVARIANT: `deriveNextAuthorityCommitment` MUST run BEFORE `masterSecret.fill(0)`. Cursor: put the derive line immediately after the createKeyVault destructure.

## FILE 3b — src/lib/identity/core.ts (parallel genesis path)
Same insert (deriveNextAuthorityCommitment(masterSecret,1) after createKeyVault, before fill(0); assign next_authority_commitment + durable at the identity wrapper-level). Both genesis paths must mint identically.

---
## FILE 4 — src/lib/identity/identity-card-sign.ts (carry it in the signed card)

buildSignedIdentityCard reads pq the wrapper-aware way (`const pq = idData?.post_quantum ?? identity?.post_quantum` — the #109 beat-3 fix). Read next_authority_commitment IDENTICALLY (or it repeats beat-3):
```ts
  const next_authority_commitment = idData?.next_authority_commitment ?? identity?.next_authority_commitment ?? '';   // SAME wrapper-aware read as pq
  // ... card = { version: '1.1', type, created_at, identity: { ...existing..., next_authority_commitment } }
```
next_authority_commitment rides the existing card signature (canonicalize covers it). The build-time fp↔key guard stays.

---
## FILE 5 — src/lib/contacts/contact-update.ts (the ROTATION verifier)

Replace the `epoch-ahead-needs-lineage` TODO throw with the rotation lineage-verify. For a successor with `kind:'rotation'`, ALL required:
1. `sha256(revealed auth_pubkeys.sign ‖ auth_pubkeys.pq_sig) === known.next_authority_commitment` — **the pre-commitment match (anti-theft check): only the seed-holder could produce a K_auth hashing to the committed value.**
2. `sig_by_authority` verifies under the revealed K_auth (BOTH ed25519 + ML-DSA legs) over the GENERIC signing-input = `canonicalize({durable_id, prior_epoch, prior authority commitment, successor_epoch, new_fingerprint, next_authority_commitment})` — reuse sign-envelope.ts (LP + domain-sep, single-source signingInput).
3. `successor.epoch === known.epoch + 1` (monotonic).
4. `new_fingerprint === deriveCanonicalFingerprintHex(new operational pubs)` (the new op identity is well-formed).
5. UNKNOWN `kind` → FAIL-CLOSED (throw) — do not silently accept.
On success: adopt the new epoch → advance known.{epoch, fingerprint, operational keys, next_authority_commitment} (the successor carries the NEXT epoch's next_authority_commitment → the chain continues).

Note: the OPERATIONAL keys in the successor are FRESH-RANDOM (generated at rotation like genesis) — they are NOT pre-committed; the authority signature is what authenticates them. This is why no deterministic-openpgp keygen is needed.

### ⚠ BUILD-TIME NAIL-DOWNS (Flint spec-co-verify #131330 — GREEN; nail these at build)
1. **Reveal-match encoding parity (FILE 5 step 1):** decode the revealed `auth_pubkeys.sign`/`auth_pubkeys.pq_sig` STRINGS → raw bytes and hash in the EXACT same order + representation as FILE 2's derive-side: `sha256(authEd(32B raw ed25519) ‖ authDsa(2592B raw ML-DSA-87))`. Decode-then-hash on the verify side MUST byte-match derive-then-hash on the genesis side. (Fixed-length operands → injective; just match the encoding — no length-prefix.)
2. **Dedicated domain tag (FILE 5 step 2):** `sig_by_authority` via sign-envelope.ts MUST use a DEDICATED domain tag `svrnty:rotation:v1` — must NOT collide with any other envelope domain (card-sign, mailbox-auth, note-auth, etc.).
3. **anchor-PQ-sig UNCHANGED:** genesis still PASSES `pqSigningSecretKey` at `signIdentityCard` (hybrid card sig) — confirm byte-unchanged at co-verify (this recipe doesn't touch it).
(Flint re-checks all 3 at the built co-verify; folded here so Cursor builds them right the first time.)

---
## GUARDS / TESTS (framework-free, tsx --test — the CI runner, NOT vitest)
1. **Grown-card guard** (beat-3 mirror): a card built from a genesis identity carries a non-empty `next_authority_commitment` at card.identity, 64-hex.
2. **Commitment determinism**: `deriveNextAuthorityCommitment(masterSecret,1)` === re-run from the same masterSecret+epoch (deterministic, re-derivable at rotation).
3. **Rotation round-trip**: mint identity → derive K_auth_1 from seed → build a rotation successor {reveal K_auth_1, sign new epoch} → verifier ACCEPTS (H(reveal)==commitment + sig verifies + epoch+1). And negatives: wrong K_auth (H mismatch) → REJECT; bad authority sig → REJECT; unknown kind → FAIL-CLOSED.
4. **Signed-input**: tampering next_authority_commitment breaks the card signature (canonicalized) — assert.

## CO-VERIFY (before merge)
- **Flint (crypto):** deriveNextAuthorityCommitment determinism (trivial) + K_auth sign-only + the reveal→H-match→authority-sig chain in the verifier + generic signing-envelope domain-sep. anchor-PQ-sig (genesis PASSES pqSigningSecretKey at signIdentityCard) — UNCHANGED but confirm.
- **Apollo (wiring + empirical):** field wired at genesis (both paths) wrapper-level (beat-3) + signed + version-bump; the EMPIRICAL round-trip (mint→derive K_auth→rotation-successor→verifier accepts + the negatives) run headless (tsx --test); extensibility (additive vs security-critical-version-fail-closed); grown-card guard.

## SEQUENCING
Stacks AFTER #110 (merged, 690cc289c). The extensible schema + card version-bump can build in parallel; the next_authority_commitment mint + verifier land together (the one-way-door). correct-fresh > flawed-now.
