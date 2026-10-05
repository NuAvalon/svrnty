# fed-qa — single-box federation QA harness

Spec: [`docs/FEDERATION_QA.md`](../../docs/FEDERATION_QA.md). This is the skeleton —
what runs today vs what's pending, honestly marked.

## Run it (Ubuntu box with Docker)

```bash
cd infra/fed-qa
./run.sh   # builds 3 app instances + registry stub, runs smoke assertions
```

For browser-level runs (Playwright / manual at domain names):

```bash
sudo sh -c 'cat infra/fed-qa/hosts.fed-qa >> /etc/hosts'
```

## Real today

- **S0** — three sovereign domains (`svrnty.is`, `relay-b.test`, `relay-c.test`) boot as
  independent instances on one box.
- **S3** — the real `/api/relay` dead-drop round-trip, per domain. The card is **multi-use
  within its TTL** (one Grow link → N joiners); single-ACCEPT is enforced downstream at the
  joiner accept-oracle, **not** by relay delete-on-read (`app/api/relay/[code]/route.ts` —
  the old delete-on-read was itself a bug that broke multi-person Grow).
- **S1** — mint K headless identities (`S1_K`, default 10): cards sign + Invariant-1
  (full 64-hex, independently recomputed to defeat the `canonicalClaimMatches` prefix
  leniency) + `subject_type=agent` + all distinct. Emits the K `durable_id`s as JSON →
  feeds the glyph-distribution QA.
- **Registry contract** — `POST /mailbox/register` + `GET /mailbox/{fp}` round-trip and
  the no-`owner_identity_fp` field discipline, against the test-double.
- `RELAY_MAILBOX_CAP` wired: app-b capped at 1 (single-mailbox), app-c at 1000 (multi).

Note: `run.sh` is **host-driven** — it asserts against the published localhost ports
(`:3000/:3001/:3002/:8100`), so no `/etc/hosts` edit is needed for the smoke (that's only
for browser-level runs at domain names). S1 needs `node` + the repo's `node_modules`.

## Pending (marked, not faked)

- **S4 mailbox migration** — needs the fleet's answers in FEDERATION_QA.md "Open
  questions" (real satellite image vs stub authority; client migration call-chain;
  overlap-window constant).
- **S5/S7** multi-mailbox assertions + adversarial pass (Flint's agent).
- **qa.yml `fed-qa` job** — wired when S1+ land; an always-green job is worse than none.

## Files

| file | role |
|------|------|
| `compose.fed-qa.yml` | 3 app instances + registry stub + runner, one `fed` network with domain aliases |
| `registry-stub.mjs` | mailbox-registry TEST-DOUBLE (wire contract only — swap for the real satellite when published) |
| `hosts.fed-qa` | `/etc/hosts` additions for browser-level runs |
| `run.sh` | bring-up + host-driven smoke assertions (S0 · registry · S3 real-contract · S1) |
| `cells/s1_mint.mts` | S1 scenario — headless mint K identities, assert cards sign + Invariant-1 (strict) + agent-type + distinct |
