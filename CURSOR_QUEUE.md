# svrnty — frontend build queue

Work top-down: the top task first, then the next. Build to spec. Open **ONE PR per task**. Copy/code that makes a security / recovery / trust **CLAIM** needs review before merge — do **not** self-merge crypto/claim surfaces. See `.cursor/rules`.

**Cursor = RENDER-GLASS ONLY** (UI/render). Crypto / keys / PSI / relay-logic / migration-logic = TEAM (Athena/Flint/Apollo). "You render the glass, the team holds the locks." Build ✅ items top-down, one PR each. ⏳ items at the bottom are NOT actionable until their spec lands — do not start them (a missing spec would be confabulated).

*Recently completed: Camera QR-scan (#96), Mint-Build Recipe v2 KERI (#112).*

## 1. Encrypt / Decrypt tab — ✅ READY · no-wire PQ-hybrid contact messaging · render-glass

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
