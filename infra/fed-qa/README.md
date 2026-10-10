# fed-qa — single-box federation QA harness

Spec: [`docs/FEDERATION_QA.md`](../../docs/FEDERATION_QA.md). This is the skeleton —
what runs today vs what's pending, honestly marked.

## Run it (Ubuntu box with Docker)

```bash
cd infra/fed-qa
./run.sh     # builds 3 app instances + registry stub, runs smoke assertions
./run.sh s8  # + mailbox expiry→rebuild (G3) against a short-TTL registry
```

For browser-level runs (Playwright / manual at domain names):

```bash
sudo sh -c 'cat infra/fed-qa/hosts.fed-qa >> /etc/hosts'
```

## Real today

- **S0** — three sovereign domains (`svrnty.is`, `relay-b.test`, `relay-c.test`) boot as
  independent instances on one box.
- **S3** — the real `/api/relay` dead-drop round-trip, per domain — MULTI-USE for the
  code's TTL (never consume-on-view), join-capped by `GROW_INVITE_CAP`.
- **Registry contract** — `POST /mailbox/register` + `GET /mailbox/{fp}` round-trip,
  the no-`owner_identity_fp` field discipline, AND the real verification MUSTs
  (`fp ≡ SHA256(pubkeys)`, Ed25519 `owner_sig` — negatives asserted) against the
  test-double.
- **S8 (G3)** — mailbox expiry → GC → rebuild on `registry-ttl` (`run.sh s8`).
- `RELAY_MAILBOX_CAP` wired: app-b capped at 1 (single-mailbox), app-c at 1000 (multi).

## Pending (marked, not faked)

- **S1** identity seeding — headless mint exists (`src/lib/identity/headless-mint.ts`);
  wire a `seed.mts` once the runner call-chain is confirmed.
- **S4 mailbox migration** — needs the fleet's answers in FEDERATION_QA.md "Open
  questions" (real satellite image vs stub authority; client migration call-chain;
  overlap-window constant).
- **S5/S7** multi-mailbox assertions + adversarial pass (Flint's agent).
- **qa.yml `fed-qa` job** — wired when S1+ land; an always-green job is worse than none.

## Files

| file | role |
|------|------|
| `compose.fed-qa.yml` | 3 app instances + registry stub + runner, one `fed` network with domain aliases |
| `registry-stub.mjs` | mailbox-registry TEST-DOUBLE (wire shape + fp-binding + owner_sig verify + `MAILBOX_TTL_MS` GC; swap for the real satellite when published) |
| `hosts.fed-qa` | `/etc/hosts` additions for browser-level runs |
| `run.sh` | bring-up + smoke assertions |
