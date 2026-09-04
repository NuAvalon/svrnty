# svrnty — frontend build queue

The top unchecked item below is the task. Build UI to spec (render-glass) — the crypto / gate / PSI / trust plumbing lives behind stable hooks maintained by the core team; wire the UI to those hooks, never modify them. Open ONE PR into the canonical branch.

## 1. Camera QR-scan — receive side  [render-glass, no crypto]
On-demand "Scan" button → `getUserMedia` + a QR decoder (BarcodeDetector where available, jsQR fallback) → feed the decoded link into the EXISTING invite parser (`parseInviteUrl`) → the existing inline join ceremony.
- Reuse `parseInviteUrl` (the single invite parser) — do NOT create a second join path.
- Request camera permission only on tap; stop the stream on close/success/error; NEVER upload or persist frames.
- The key fragment (the part of an invite link after `#`) is key material — NEVER log, echo, display, send, or persist it. Error text = a FIXED string with no input interpolation (a scan handler is a leak-site).
- Already built (don't touch): paste-code join + QR generation. This task is ONLY the scan/receive side.

