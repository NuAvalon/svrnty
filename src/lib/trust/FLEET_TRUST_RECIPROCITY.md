# Fleet note — trust reciprocity probe + method delivery acks

**Audience:** Flint (crypto / relay-auth) · Apollo (disclosure) · Archie (constitution)  
**From:** Cursor glass (Living Address Book / Trust Map)  
**Date:** 2026-08-30  
**Scope:** UI already renders these *phases*. Wire behavior below is **fleet-owned** — do not implement in Cursor.

## Product intent (Peter)

1. **Both known / linked** → state change; only then can they communicate (methods / updates).
2. **I trust them** ≠ **mutual trust**. Outbound trust should be visible as “trust sent / awaiting mutual.”
3. When I trust, the client should **probe their relay for reciprocity**. If reciprocity is not ack’d, something happens on the **relay side** (retry, hold, notify, expire — fleet design). Same shape when **they** trust us (inbound).
4. **Method updates** need end-to-end **acks**. If an update does not propagate / is not acked, the glass shows **undelivered / awaiting-ack** (already stubbed in metadata).

## Glass phases (already drawn)

| Phase | Meaning on device |
| --- | --- |
| `connection: pending` | One-way / intro — not linked |
| `connection: linked` + `canCommunicate` | Both known/accepted — communicate allowed |
| `trust: outbound` | I trusted; `mutual.reciprocal` false |
| `trust: inbound` | `they_trust_me` and I have not trusted |
| `trust: mutual` | `mutual.reciprocal` |
| `method_delivery: awaiting-ack \| acked \| undelivered` | Local stub / future wire receipts |

See `src/lib/trust/living-edge-status.ts`.

## Ask for Flint

### A. Trust outbound → reciprocity probe
On local `trust` grant:
1. Persist outbound trust locally (glass does this today).
2. **Fleet:** deposit a trust signal toward peer’s relay / mailbox.
3. **Probe** for reciprocal trust signal (or PSI mutual bit).
4. Outcomes to surface back to glass (suggested):
   - `trust_probe: pending` — in flight
   - `trust_probe: reciprocal` → set `mutual.reciprocal` (+ crystallize UI)
   - `trust_probe: no-ack` — signal sent, no reciprocity yet (glass shows “Trust signal sent · no reciprocity ack yet”)
   - Relay-side policy on repeated no-ack (hold / soft-expire / notify) — **your call**; glass will only render the phase you write.

Inbound (they trust us first): same state machine mirrored — glass already has `trust: inbound`.

### B. Method update delivery receipts
When `sendContactMethodUpdate` is live:
1. Per-peer encrypt + deposit (existing CUR-1 seam).
2. Record **awaiting-ack** per recipient.
3. On peer apply / explicit ack envelope → **acked**.
4. Timeout / bounce / unreachable → **undelivered** (glass already has copy for this).

Stub today returns `stub-queued` and does not write receipts — replace without changing claim-honesty of the undelivered copy.

## Constitutional constraints
- Do not invent mutual from tags or co-membership.
- Do not claim delivery without an ack field.
- Tags / blocked stay device-local (Apollo §2).

## UI hooks waiting on you
- Trust Map: outbound glow ≠ mutual double-ring; crystallize toast on reciprocal flip.
- Address book rows: status chips (`Trust sent` / `Mutual` / `Linked` / ack lines).
- Method revise dialog: can attach receipt status once the seam writes `metadata.method_delivery`.
