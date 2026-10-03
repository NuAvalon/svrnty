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
| S3 | Cross-domain contact exchange | `/c/<code>` dead-drop round-trip works a→b, a→c (single-use, TTL) |
| S4 | **Mailbox migration** b → c | `publishMailboxPointer` with `pointerEpoch ≥ 1` propagates; peers resolve latest valid pointer (monotonic); old mailbox stops receiving new envelopes; identity durable_id/did unchanged |
| S5 | Multi-mailbox relay | relay-c hosts N owner mailboxes; per-mailbox cap → uniform 429; deposit/poll isolation between mailboxes |
| S6 | Failure modes | relay down mid-migration → pointer retry; stale pointer (lower epoch) rejected; wrong-signature pointer rejected |
| S7 | Adversarial (Flint's agent) | pointer substitution, replayed envelopes, registry poisoning, R_e probing, rate-limit bypass, cross-instance metadata leakage — see "Adversarial pass" |

## Key contracts the harness depends on

- `POST /mailbox/register`, `GET /mailbox/{fp}` — served by the **satellite**, which is
  NOT in this repo (`infra/svrnty` is referenced by `docs/SELF_HOSTING.md` but not
  vendored). Until the image is published, `infra/fed-qa/registry-stub.mjs` implements
  exactly the documented wire shape (see `src/lib/crypto/mailbox-registry-client.ts`)
  as a **TEST-DOUBLE** — marked as such; it proves client behaviour, not satellite
  correctness.
- `publishMailboxPointer` / `selectLatestValidPointer` (`src/lib/trust/mailbox-pointer-transport.ts`)
  — the real migration primitive: bootstrap epoch 0 sealed to identity-enc keys,
  rotations epoch ≥1 sealed to the peer's current mailbox.
- `mailboxConfig()` env knobs — `RELAY_MAILBOX_CAP` drives the multi-mailbox profile;
  the nursery-gated creation flag models the managed-vs-self-host difference.

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

## Living-blueprint claims lane (routed: Athena + fleet)

Add under self-host/federation, each gated on the harness scenario that proves it:

- `fed-minimal-self-host` — claim when S2+S3 green on a clean box (built+proven).
- `fed-mailbox-migration` — claim when S4 green end-to-end incl. overlap window.
- `fed-multi-mailbox` — claim when S5 green.
- `fed-adversarial` — claim only with Flint's stress results attached, scoped wording
  ("stress-tested against <list>", never "secure").

## Open questions for the fleet

1. **Satellite image** — publish the real `infra/svrnty` registration/mailbox service,
   or confirm the registry-stub contract is authoritative for QA.
2. **Migration call-chain** — which client function orchestrates pointer publication
   on relay switch today (if any)? If none, S4 defines it and it's a `devin-ok` ticket.
3. **Mailbox cap semantics** — is `RELAY_MAILBOX_CAP` the intended multi-mailbox knob,
   or is multi-mailbox per-owner vs per-instance?
4. **Overlap window** — how long must the old mailbox's decap key stay valid
   (policy constant to assert)?
