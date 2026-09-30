# svrnty — frontend build queue

The top unchecked item below is the task. Build UI to spec (render-glass) — the crypto / gate / PSI / trust plumbing lives behind stable hooks maintained by the core team; wire the UI to those hooks, never modify them. Open ONE PR into the canonical branch.

## ✅ 1. Camera QR-scan — receive side  [DONE — shipped in #96, not a task]
Built + merged. Kept for provenance only.

## ✅ 2. Encrypt / Decrypt tab — no-wire PQ-hybrid contact messaging  [DONE — merged #155/#157/#158, live on dev.svrnty.is, seam-signed. Spec kept for provenance.]

A new **"Encrypt / Decrypt"** tab in svrnty.is: pick a svrnty contact → encrypt or decrypt a message (PQ-hybrid, authenticated sign-then-seal). Ciphertext is **copy-pasted by the user over any channel** — **NO WIRE**, zero network calls, zero relay traffic. Crypto is DONE + co-verified on main (PR #155: `src/lib/crypto/contact-message.ts` + `src/lib/identity/raw-sign.ts`). Wire the UI to these hooks; do NOT reimplement crypto.

### Hooks + exact field contract (from contact-message.ts)
- **`encryptToContact(message, contact, sender) → Promise<string>`** (armored ciphertext):
  - `contact: ContactKeys` = picked recipient's card `{ public_key (OpenPGP armored), pq_kem_public_key (b64), pq_sig_public_key (b64), fingerprint }`
  - `sender: SenderKeys` = the logged-in user's OWN `{ signSeed (extractRawSign.seed, 32B), sigSecret (ML-DSA-87 secret), senderFingerprint (user's 64-hex id) }`
- **`decryptFromContact(armored, me, senderCard?) → Promise<{ message, senderVerified, senderFingerprint } | null>`**:
  - `me: MyKeys` = user's OWN `{ x25519Sec (extractRawEnc.encSec, 32B), mlkem1024Sec, x25519Pub, mlkem1024Pub, myFingerprint }`
  - `senderCard?: ContactKeys` = the sender's card from the user's contacts. Pass it → `senderVerified=true` when authentic; omit → decrypts but `senderVerified=false`.
- **`extractRawEnc(decryptedIdentityKey) → { encSec, encPub }`** and **`extractRawSign(...) → { seed, ... }`** (raw-sign.ts) — how the UI derives the user's raw secrets from their unlocked identity.

### ★ WIRING GATE (must get right first-render — Flint's #155 advisory)
`me.myFingerprint` MUST be the user's **real identity id** = `deriveCanonicalFingerprintHex` over the user's own keys. If it's wrong, the recipient-binding check fails → `senderVerified=FALSE` on a genuinely-authentic message (fails SAFE — never a forgery-accept — but the tab then wrongly reads "unverified"). Populate it from the real identity, not a placeholder.

### UI
- **Contact picker:** dropdown from the existing address book, showing name/handle **+ fingerprint**. **KNOWN/VERIFIED contacts only — fail loud;** never render an unverified contact as encryptable.
- **Mode toggle:** `Encrypt | Decrypt`.
- **Encrypt:** plaintext textarea → `[Encrypt]` → `encryptToContact(...)` → armored block (`-----BEGIN SVRNTY MSG-----` … `-----END SVRNTY MSG-----`) + **`[Copy ciphertext]`** button. Label the output **"Encrypted for [contact] · not sent"**.
- **Decrypt:** paste armored block → `[Decrypt]` → `decryptFromContact(...)` → plaintext + sender status:
  - `senderVerified === true` → **"Verified from [contact] · [fingerprint]"**
  - else → **"sender NOT cryptographically verified"** (the `senderFingerprint` is only the CLAIMED sender — trust it only when verified).
- **Errors:** clear, non-leaky, FIXED strings for bad/garbled ciphertext, wrong-recipient, decrypt failure. Never render key material / raw secrets.

### Constraints
- Use the hooks above; do NOT reimplement or fork crypto in the UI (thin wrapper).
- ML-KEM params derive from the contact's STORED key length (never hardcode 1024) — owned by the crypto.
- **NO WIRE:** zero network calls; manual copy-paste only.
- **Verb is "Copy ciphertext", NEVER "Send"** (a send-shaped affordance that doesn't send is a claim-honesty trap).

### Non-goals (defer)
- No transport/relay/dead-drop. No new key management (existing contacts only). No auto send/receive.
- **Group / multiple recipients:** NOT in this task — it's a fast-follow (fan-out: loop `encryptToContact` per selected contact into a `{v, recipients:[{fp, armored}]}` bundle + multi-select UI). Ship single-contact first.

### Acceptance
Encrypt to a contact → copy the armored ciphertext → paste into Decrypt (as the recipient, with the sender's card in contacts) → recover the **exact** plaintext with `senderVerified === true`. Round-trips PQ-hybrid; nothing touches the wire.

## 3. Verify in the Galaxy (social graph) + guided fingerprint-compare  [render-glass]

**Problem** (Peter, 2026-09-30, from live first-contact): a KNOWN contact shows as a **dashed line** in the Galaxy / social graph, but **Verify is only reachable from the Living Address Book** (`ContactManagement.tsx:1761` wires `onOwnerVerify`; `TrustMapGalaxy.tsx` wires NOTHING) — no way to verify from the graph. And today's verify is a bare provenance tap (`in_person`/`other_channel`); it should be a **guided fingerprint match** so "Verify" means "I actually compared the key," not "I clicked a label."

**Trust model — DO NOT CHANGE** (`src/lib/trust/trust-recipe.ts`): Know (card in book) → **Verify (private, THIS device — "you are sure this key is the person you mean")** → Trust (mutual, or it isn't). Verify is NEVER a public badge; owner-local only; it is the prerequisite for Trust. Dashed edge = KNOWN; solid = VERIFIED (local only); solid + mutual = TRUSTED.

### Hooks (stable — wire, don't modify)
- **`onOwnerVerify(edge, method: 'in_person' | 'other_channel')`** — already on `TrustMap.tsx`; the address book calls it. Wire the SAME hook into the Galaxy. It handles the owner-local persist (`ownerVerifyPersistPatch` → `owner_verify {owner_verified_at, method}`).
- **`formatFingerprintForVerify(fp)`** (trust-recipe.ts) — formats the canonical 64-hex into 4-char groups for compare-aloud / QR footer. **This IS the compare primitive.**
- **`ownerHasVerified(edge)`** — current verified state (drives dashed→solid). **`canGrantTrust(edge)`** — the need-verify gate (Trust requires verify first).
- Reuse the shipped **camera QR-scan** (task #1 / PR #96) for the in-person scan path. Do NOT fork it.
- Copy strings already exist in `TRUST_RECIPE_COPY`: `verifyWhy`, `verifyPrivate`, `verifyInPerson`, `verifyOtherChannel`, `verifyConfirm`, `verifiedHere`. Use them verbatim.

### ★ WIRING GATE (Flint-style — get right first-render)
- The fingerprint shown/compared MUST be the contact's **canonical 64-hex** (`formatFingerprintForVerify(edge.fingerprint)`) — the id that binds all 4 keys (sign‖enc‖kem‖sig). NEVER a truncated display id or the name. A compare against a truncated id is false security.
- **In-person QR path: the scanned fingerprint MUST byte-equal the stored contact fingerprint before the confirm is enabled. MISMATCH → fail LOUD** ("this isn't the key you have for [name] — do not verify"), never silently pass.
- Verify stays **PRIVATE**: no public badge, no wire, no network. Only the local dashed→solid transition. (`stripOwnerLocalForPublish` already enforces the wire side — don't touch it.)

### UI
- **Galaxy (`TrustMapGalaxy.tsx`):** a focused KNOWN (dashed) star/edge gets a **"Verify"** action that opens the SAME verify sheet as the address book (extract a shared `VerifySheet` or reuse TrustMap's verify flow). After verify → the edge renders **solid** locally.
- **Verify sheet (guided compare) — shared by Galaxy + address book:**
  1. Show the contact's fingerprint LARGE + grouped (`formatFingerprintForVerify`), labeled with `verifyWhy` ("Anyone can use my name. They can't forge this key.").
  2. Two compare paths:
     - **In person** (`verifyInPerson`) → "Scan their QR" (reuse #96 camera) → scanned fp === stored fp → match enables confirm (`verifyConfirm`: "Yes — I scanned this from their phone, it's them").
     - **Another channel** (`verifyOtherChannel`) → show the 64-hex to read aloud / paste-compare over a trusted channel; user ticks "the code matches."
  3. On confirmed match → `onOwnerVerify(edge, method)`. Then show `verifiedHere` ("You verified this key on this device. Nobody else sees that. Trust still needs them to verify you too.").
- Honest private copy throughout (`verifyPrivate`): only you see whom you verified; it's a prerequisite for Trust; they must verify you too.

### Constraints
- Wire the hooks; do NOT modify trust plumbing / crypto. Verify = owner-local metadata via the hook; never a wire message or a public badge.
- The compare is fingerprint-based (safety-number style) — **no new crypto**, no new key material.
- Reuse the #96 camera for in-person scan.

### Non-goals (defer)
- Mutual **Trust** flow (Verify is the prerequisite; Trust needs both sides verified + mutual intent) — next task.
- Changing the fingerprint format or the trust tiers.
- The Gate/Galaxy **poll-latency** (Peter saw ~1 min + a refresh to Gate, ~30 s to Galaxy) — that's a live-event/subscription item for the core team, NOT this render task.

### Acceptance
From the Galaxy, focus a KNOWN (dashed) contact → **Verify** → guided compare (QR in-person OR code another-channel) → on match, `onOwnerVerify` records `owner_verify{method}` → edge renders **solid** locally + privately (no public badge, nothing on the wire). The SAME sheet is reachable from the address book. A **mismatched QR fails loud** and cannot verify. `ownerHasVerified` returns true after; `canGrantTrust` no longer blocks on need-verify.

## 4. Peer-chord legend — consent-explicit anti-surveillance clause (#106 fast-follow)  [render-glass]

_Non-urgent (the peer-mesh is dormant / go-live-gated — nothing renders live). Completes PR #170: the tooltip copy is already Hypatia-GREEN; this is the 2nd half of her spec. Prefer amending the existing draft **PR #170**; else a tiny follow-up PR._

**Task (copy-only):** append ONE clause to the peer-mesh legend string `peerMeshLegend` (`src/lib/trust/trust-recipe.ts`, rendered in `TrustMap.tsx`) so the legend carries the explicit anti-surveillance negation, not just the positive consent.

Current legend: "…both disclosed they know each other (gold) or trust each other (white-gold). Dashed gold is a group you named — not a bond."
→ Append: **"These lines are disclosures, not observations — svrnty never infers who knows whom."**
(Phrase-equivalent OK IF it preserves BOTH halves: disclosures-not-observations AND never-infers/observes.)

### Why (Hypatia claims-render gate · Archie constitution-signed ✅)
For the DV/survivor population this copy protects, the surveillance fear ("could svrnty also be watching / inferring my OTHER ties?") must be foreclosed EXPLICITLY. TRUE BY CONSTRUCTION: the mesh renders only consented `disclosed_circle` edges + svrnty's design (blind relay, consent-gated discovery) forecloses relationship-inference. No over-claim — an anti-capability statement backed by the architecture. (The dev comment "Glass never invents either layer from tags" already says this internally; this surfaces it to the user.)

### Scope / gate
- Copy-only. **NO crypto / data-source change** (already fixed to `disclosed_circle` in 22fd5164). Update the `peerMeshLegend` string + its test assertion.
- Gate: Hypatia re-greens the legend copy → Athena undraft + merge → #106 fully closed (both halves).
