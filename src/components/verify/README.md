# Guided verify sheet

Render-glass for queue item 3: Verify from the Galaxy (and the same sheet from the address book). Crypto / persist stay behind `onOwnerVerify` + `formatFingerprintForVerify` / `ownerHasVerified` — this folder does not modify trust plumbing.

## Files
- `VerifySheet.tsx` — Solar Ember dialog: large grouped fingerprint, in-person scan / another-channel tick, fail-loud mismatch
- `fingerprint-from-scan.ts` — extract a 40- or 64-hex fingerprint from QR text; byte-equal compare
- `verify-copy.ts` — mismatch line (bounded name only) + chrome labels; recipe strings stay in `TRUST_RECIPE_COPY`
- `../scan/QrScanCamera.tsx` — shared camera chrome used by Scan-to-join and this sheet (`decodeQrFrame`)

## Wiring
- In-person: scan must byte-equal the **stored** contact fingerprint before Confirm is enabled. Mismatch → `this isn't the key you have for [name] — do not verify`. Scanned text is never shown or logged.
- Another channel: show `formatFingerprintForVerify`; user ticks `the code matches.` Optional paste must match if filled.
- Confirm calls the existing `onOwnerVerify(edge, method)` hook. No network. No public badge.

## Honest limits
Your Card / Share QR still encodes a short-link, not the 64-hex. Scanning that link fails loud (no fingerprint in the payload). In-person match works when the QR *is* the fingerprint (raw, grouped, JSON, or `?fp=`). A fingerprint-only QR on Your Card is a follow-on — not this PR.

The Galaxy tab is `TrustMap.tsx` (the lattice users tap). `TrustMapGalaxy.tsx` is an unmounted canvas; this PR wires the focus sheet on TrustMap.

## Open questions
1. Should Your Card grow a fingerprint-only QR so in-person scan matches without a custom payload?
2. Sample-circle fingerprints are 40-hex stand-ins; live cards are 64-hex. Compare is length-strict either way.
