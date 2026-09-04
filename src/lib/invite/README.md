# Invite parse + QR scan (receive)

**Render-glass only.** One parser (`parseInviteUrl`) feeds the existing `<JoinerCeremony>`. No crypto, no second join path, no relay changes.

| File | Role |
|------|------|
| `parseInviteUrl.ts` | INV-4 untrusted-input boundary — total, host-pinned |
| `scanInvite.ts` | Scanned text → `parseInviteUrl`; FIXED errors; `stopMediaStream` |
| `decodeQrFrame.ts` | BarcodeDetector first, jsQR fallback; in-memory frames only |
| `ScanToJoin.tsx` | Camera UI, mounted only after Scan tap |
| `JoinByCode.tsx` | Paste fallback + Scan button; mounts the same ceremony |

## Invariants
- Camera permission is requested **on Scan tap**, not when the Join dialog opens.
- Stream stops on close / success / error / unmount.
- Frames are never uploaded or persisted (`getImageData` stays in RAM).
- Key fragment (URL `#` hash) is never logged, echoed, displayed, sent, or persisted by the scan path. Error text is a compile-time constant (INV-5).
- A decoded QR is not a trust act (INV-2) — the human still commits inside the ceremony.

## Assumptions
- Invite QRs encode the same short-link the give-side already generates (`shareUrl` = `https://…/c/<code>#<key>`).
- `jsqr` is the fallback decoder when `BarcodeDetector` is missing or throws.

## Questions
- **Flint:** please confirm INV-5 on this path — no fragment in DOM / logs / errors from ScanToJoin.
- **Hypatia:** scan copy is operational ("Point the camera…", paste-instead errors). No encryption / verified / end-to-end claim. Confirm that's honest enough.

## Verify
```bash
npx tsx --test src/lib/invite/scanInvite.test.ts src/lib/invite/decodeQrFrame.test.ts src/lib/invite/parseInviteUrl.test.ts
npx playwright test e2e/scan-to-join.spec.ts
```
