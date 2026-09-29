# Encrypt / Decrypt tab

Render-glass for no-wire contact messaging (CURSOR_QUEUE item 1). Ciphertext is copy-pasted by the user. This tab does not send, does not call the relay, and does not reimplement crypto.

## Files
- `EncryptDecryptTab.tsx` — Solar Ember UI (mode toggle, contact picker, encrypt / decrypt / copy)
- `encrypt-decrypt-copy.ts` — fixed, non-leaky strings
- `encrypt-decrypt-contacts.ts` — encryptable-contact filter (SVRNTY + PQ pubs; skip classical / blocked)
- `encrypt-decrypt-keys.ts` — assemble `SenderKeys` / `MyKeys` via fleet `extractRawSign` / `extractRawEnc` / `deriveCanonicalFingerprintHex`
- `encrypt-decrypt-actions.ts` — thin call to `encryptToContact` / `decryptFromContact`
- `load-owner-message-keys.ts` — IndexedDB load of the unlocked identity

## Wiring (must stay true)
`me.myFingerprint` and `sender.senderFingerprint` are **recomputed** with `deriveCanonicalFingerprintHex` over the owner's live keys. A stored card fingerprint is never used as a placeholder.

## Copy (claim-honesty)
User-facing copy does **not** say post-quantum, end-to-end, or Send. Encrypt output is labeled `Encrypted for [contact] · not sent`. Decrypt shows `Verified from [contact] · [fingerprint]` only when `senderVerified === true`; otherwise `sender NOT cryptographically verified`.

Armor headers come from the fleet hook (`BEGIN SVRNTY ENCRYPTED MESSAGE`), not a UI rewrite.

## Bundler seam
`next.config.ts` rewrites in-repo Node ESM `.js` specifiers to `.ts` (webpack `NormalModuleReplacementPlugin`) so the tab can CALL `encryptToContact` / `decryptFromContact` without forking crypto. Fleet files are untouched.
- Encryptable = Known **or** Trusted SVRNTY contacts that already store PQ kem+sig pubs (those pubs are only persisted from a signature-verified card).
- Decrypt looks up the claimed sender in that encryptable book after open; the picker is encrypt-only.
- Did not flip `isPQEncapLive()` / `isPQSignLive()` — those gates still describe other paths. Ask the fleet before claiming PQ on this surface.

## Open questions
1. Should `isPQEncapLive()` flip now that this tab calls `encryptToContact` → `sealToMailbox` (X25519 + ML-KEM)? We did not flip it or advertise PQ.
2. Queue mentioned `BEGIN SVRNTY MSG`; the merged hook emits `BEGIN SVRNTY ENCRYPTED MESSAGE`. UI displays the hook output.
3. Is Known (not only Trusted) the right encryptable set, given “KNOWN/VERIFIED contacts only”?
