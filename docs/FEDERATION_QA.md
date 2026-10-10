# Federation QA harness — spec

Status: **SPEC** (requested 2026-09-30; implementation tracked in `infra/fed-qa/`).
Scope approved via internal comms — requirement paraphrased here, not quoted.

## Requirement

A QA project that runs **on a single local Ubuntu box** and models:

- `svrnty.is` plus a set of other domains via a modified `/etc/hosts`, so a bunch of
  identities created "on" svrnty.is can then be **migrated to federated servers**.
- Both relay shapes: **single-mailbox self-host** and **multi-mailbox**.
- A **"migrate your mailbox to another relay"** flow that is easy for a self-hoster.
- **Self-host instructions/setup** in the repo — including security, backup, and build
  best practices — so others can run it smoothly.
- An **adversarial security stress-test** of the harness (routed to Flint's security
  agent) to probe network effects.
- Results feeding the **self-host/federation claims lane** in the living blueprint —
  claims made only when the harness proves them (claim-honesty).

Canonical contract: **blueprint v2.8.7 §11 (W7 Avalon)** — the self-host/federation
claim-family is Invariant I-C (network-continues-if-we-vanish) made testable. Every
claim in the W7 honesty ledger is **ROADMAP** until enforced-in-code AND
Flint-verified on the deployed edge (W6); this harness is the proof substrate.

## Why one box is sufficient

The svrnty app instance is self-contained: the relay dead-drop (`/api/relay/*`), the
envelope deposit/poll (`/api/relay/envelope`, `queue`, `ack`), and the satellite
adapters live **in-process**. A distinct domain → a distinct container → real
federation: cross-instance traffic exercises the actual wire (signed mailbox
pointers over the blind rendezvous, mailbox registry client) with no production
dependency.

## Topology (single Ubuntu box)

```
/etc/hosts (browser + host-side runs)
  127.0.0.1  svrnty.is      → app-a  (the managed instance stand-in)
  127.0.0.1  relay-b.test   → app-b  (single-mailbox self-host)
  127.0.0.1  relay-c.test   → app-c  (multi-mailbox relay)
  127.0.0.1  registry.test  → stub satellite mailbox-registry

compose network (in-network names = the same domains, service aliases):
  app-a    svrnty app, NEXT_PUBLIC_SVRNTY_DOMAIN=svrnty.is,     :3000
  app-b    svrnty app, NEXT_PUBLIC_SVRNTY_DOMAIN=relay-b.test,  :3001  (mailbox cap 1)
  app-c    svrnty app, NEXT_PUBLIC_SVRNTY_DOMAIN=relay-c.test,  :3002  (mailbox cap N)
  registry mailbox-registry TEST-DOUBLE                          :8100
  runner   node:22 + repo mount — drives scenarios via tsx
```

Two access modes: **in-compose** (runner talks `http://app-b:3000` — no hosts edits,
works on a headless box and in CI) and **browser-level** (`/etc/hosts` aliases +
`NEXT_PUBLIC_BASE_URL=http://<domain>:<port>` — Playwright drives a real browser at
domain names). `NEXT_PUBLIC_*` is baked at build time, so the image is built once per
domain — three image builds or one build per instance arg; the compose file
parameterises it.

### Sizing (verified)

- App container ≈ 150–300 MB RSS idle (Next.js standalone); x4 ≈ 1.2 GB.
- Registry stub ≈ <100 MB. Runner ≈ node base.
- **Recommended: 4 vCPU / 8 GB / 20 GB disk.** Minimum viable: 2 vCPU / 4 GB
  (serialised instance builds).

## Scenario set

| # | Scenario | Asserts |
|---|----------|---------|
| S1 | Mint K identities on `svrnty.is` (headless `mintHeadlessAgent`, proven path) | cards sign, Invariant-1 (`fp ≡ H(pubkey)`) holds for all K |
| S2 | Each identity registers a mailbox on its home relay | `POST /mailbox/register` owner-proof accepted; `GET /mailbox/{fp}` serves pubkeys only (never `owner_identity_fp`) |
| S3 | Cross-domain contact exchange | `/c/<code>` dead-drop round-trip works a→b, a→c (multi-use within the code TTL — serves until expiry, never consume-on-view; join cap `GROW_INVITE_CAP`) |
| S4 | **Mailbox migration** b → c | `publishMailboxPointer` with `pointerEpoch ≥ 1` propagates; peers resolve latest valid pointer (monotonic); `rehydrateTrustBeacons` re-derives R + re-deposits beacons onto relay-c; old mailbox stops receiving new envelopes; identity durable_id/did unchanged |
| S5 | Multi-mailbox relay | relay-c hosts N owner mailboxes; per-mailbox cap → uniform 429; deposit/poll isolation between mailboxes |
| S6 | Failure modes | relay down mid-migration → pointer retry; stale pointer (lower epoch) rejected; wrong-signature pointer rejected |
| S7 | Adversarial (Flint's agent) | pointer substitution, replayed envelopes, registry poisoning, R_e probing, rate-limit bypass, cross-instance metadata leakage — see "Adversarial pass" |
| S8 | **Mailbox expiry → rebuild** (G3) | `run.sh s8` against `registry-ttl` (`MAILBOX_TTL_MS=3000` standing in for the satellite's 30-day GC): register → GET 200 → TTL sweep → GET 404 → re-register same fp → GET 200. Wire-level proof an expired mailbox is gone *and* rebuildable; pointer-republish + `rehydrateTrustBeacons` against the rebuilt box ride the S4 node-level path (the unwired primitive, per W7 two-tier model) |

## Key contracts the harness depends on

- `POST /mailbox/register`, `GET /mailbox/{fp}` — served by the **satellite**, which is
  NOT in this repo (`infra/svrnty` is referenced by `docs/SELF_HOSTING.md` but not
  vendored). Until the image is published, `infra/fed-qa/registry-stub.mjs` implements
  the documented wire shape AND its two verification MUSTs (see
  `src/lib/crypto/mailbox-registry-client.ts`): `mailbox_fp ≡ SHA256(x25519_pub ‖
  mlkem1024_pub)` over raw bytes (400 on mismatch), and Ed25519 `owner_sig` over
  `svrnty-mailbox-reg-v1:{owner}:{fp}:{epoch}` (403 on bad/unknown owner — owners
  are seeded via the test-only `PUT /_test/identity/{fp}`, stub scaffolding that is
  NOT wire shape; the real satellite resolves owner keys from its identity registry).
  `MAILBOX_TTL_MS` env models the 30-day GC for S8. Still a **TEST-DOUBLE** — it
  proves client behaviour, not satellite correctness.
- `publishMailboxPointer` / `selectLatestValidPointer` (`src/lib/trust/mailbox-pointer-transport.ts`)
  — the real migration primitive: bootstrap epoch 0 sealed to identity-enc keys,
  rotations epoch ≥1 sealed to the peer's current mailbox.
- `mailboxConfig()` env knobs — `RELAY_MAILBOX_CAP` drives the multi-mailbox profile;
  the nursery-gated creation flag models the managed-vs-self-host difference.
- `rehydrateTrustBeacons` (`src/lib/trust/trust-rendezvous.ts:301`) — the W7 §11
  migration primitive: re-derives R for every trusted peer in the book and re-deposits
  signed+sealed beacons on the new relay (idempotent, book-derived — "the book makes
  the mailbox"). **Implemented + unit-tested, but UNWIRED** (zero app callers today):
  migration is an invocable capability, not an automatic path — so S4 exercises it
  directly, and honest copy stays "re-derivable from your book", never
  "automatically rehydrates". Auto-rehydration of a GC-destroyed mailbox is roadmap.

## "Migrate your mailbox" UX contract (for the docs/runbook)

A self-hoster migration SHOULD be: pick new relay → new mailbox created → pointer
`epoch+1` published to all peers → old relay kept decapsulable through an overlap
window → peers confirm → old mailbox retired. The harness's S4 must be executable
as one `run.sh migrate <id> <from> <to>` — if the flow can't be reduced to that, the
UX isn't easy enough and that's a finding, not a doc problem.

## Adversarial pass (routed: Flint's security agent)

Threat surface the harness exposes to a stress agent:

1. **Pointer substitution** — forge a mailbox pointer with a valid-looking signature;
   the anti-substitution `fp ≡ SHA256(pubkeys)` check must reject.
2. **Replay/rollback** — resubmit an older `pointerEpoch`; monotonic resolution must win.
3. **Registry poisoning** — stub returns wrong pubkeys for an fp; client must refuse to seal.
4. **Metadata shape** — deposits/polls across instances must stay uniform (I-4): same
   ack whether mailbox exists/empty/full; R_e tags must not cluster by pair on the relay.
5. **Rate-limit/cap evasion** — burst deposits at per-mailbox cap and per-IP limits.
6. **Simultaneous rotation** — both peers rotate mid-flight; overlap-window key validity.
7. **Network effects** — N identities × M relays: pointer propagation latency, registry
   hot-key behaviour, rendezvous deposit collision rates at scale (K=50, M=3 target).

## QA pipeline hook

`qa.yml` gains a `fed-qa` job **when the runner exists**: `docker compose -f
infra/fed-qa/compose.fed-qa.yml up` + `infra/fed-qa/run.sh`, triggered on PRs touching
`src/lib/{trust,relay,crypto,sync}/**mailbox**` + `infra/fed-qa/**` and on
`workflow_dispatch`. Not wired as a green no-op — the repo's own rule: an always-green
stub is worse than no job (see the parked claim-sweep precedent).

## Living-blueprint claims lane (canonical: v2.8.7 §11 W7 ledger)

The W7 honesty ledger is the claim contract — each row earns present-tense only
after its gate, per-claim (never wholesale retirement of the roadmap hedge):

| # | Claim | Today | Earns present-tense after |
|---|-------|-------|---------------------------|
| 1 | "Run your own relay" (self-host) | 🟡 ROADMAP | W1 shipped + W6 secure-defaults verified on edge — harness: **S2+S3 green on a clean box** |
| 2 | "Federated — survives if svrnty.is vanishes" (I-C) | 🟡 ROADMAP | W2 + W5-2 failover proven + W6 — harness: **S6 relay-down mid-migration green** |
| 3 | "Migration unlinkable by content / identity / credentials" | 🟡 ROADMAP | W4 enforced-in-code + Flint-verified (zero-loss, unlinkable handoff) — harness: **S4 green end-to-end incl. overlap window** |
| 4 | "Migration unlinkable by **TIMING**" (adversary watching BOTH relays) | 🔴 ROADMAP — APEX, caveat-forward | cover-window ("K3-for-migration") built + verified — harness: **S7 timing-analysis scenario, tracked-required** |

Supporting (not ledger rows): `fed-multi-mailbox` claim when S5 green;
`fed-adversarial` claim only with Flint's stress results attached, scoped wording
("stress-tested against <list>", never "secure").

## Launch acceptance gates (G1–G7, fleet-set)

The fleet's launch bar maps onto the harness — the S-scenarios are the proof
substrate; a gate is DONE only when its mapped scenario(s) run green end-to-end:

| Gate | Launch requirement | Harness coverage |
|------|-------------------|------------------|
| G1 | PSI + blocking rock-solid | **GAP** — not fed-qa's lane; needs its own suite against the flipped `isPSIDiscoveryLive` + mutual-block graduates (piece-2 §F3 churn matrix exists DARK — target: wire into `qa.yml` or a dedicated gate job) |
| G2 | Transfer away from primary relay + self-host | S2+S3 (mailbox register on a foreign domain + cross-domain exchange) |
| G3 | 30-day mailbox expiry → rebuild → work again | S8 — `run.sh s8` (green): short-TTL registry sweeps the mailbox (GET 404), re-register rebuilds it (GET 200). Partial coverage: wire-level expiry+rebuild proven on the stub; the *client-side* rebuild (pointer epoch+1 republish + `rehydrateTrustBeacons` re-deposit) still needs the S4 node-level path and the real satellite's TTL config |
| G4 | Transfer to a different relay, then still receive updates | S4 (migration + pointer propagation + beacon rehydration) |
| G5 | Primary relay down + mailboxes gone → full-loss recovery from clients | S6 extended: kill relay-b mid-run, assert client-side rehydration rebuilds the mailbox (manual `rehydrateTrustBeacons` invocation — the unwired primitive, per W7 two-tier model) |
| G6 | No silent message loss | Cross-cutting invariant on every scenario: every envelope deposited is either polled, expired-by-TTL, or an explicit failure — never silently dropped (assert ack-loop + TTL-death audit trail) |
| G7 | Resource / resiliency / anti-spam | S7 adversarial + S5 cap tests (per-mailbox 429 uniformity, rate-limit evasion attempts, registry hot-key) |

G-gates are the fleet's words; where they out-scope fed-qa (G1 PSI depth, G6 as a
product-wide property) the table says so rather than pretending coverage.

## Open questions for the fleet

1. **Satellite image** — publish the real `infra/svrnty` registration/mailbox service,
   or confirm the registry-stub contract is authoritative for QA.
2. ~~**Migration call-chain**~~ — **ANSWERED by v2.8.7 §11**: `rehydrateTrustBeacons`
   (`trust-rendezvous.ts:301`) is the migration primitive — implemented + unit-tested,
   unwired (manual/invocable, not automatic). S4 drives it directly; the honest
   capability claim is "re-derivable from your book". The auto-rehydrate-on-GC wiring
   (detect 404 → trigger) is a separate roadmap item, not part of S4.
3. **Mailbox cap semantics** — is `RELAY_MAILBOX_CAP` the intended multi-mailbox knob,
   or is multi-mailbox per-owner vs per-instance?
4. **Overlap window** — how long must the old mailbox's decap key stay valid
   (policy constant to assert)?
