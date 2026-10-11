# Headless Grow join — appearing at a human Gate

**Field note (2026-10-11).** A cloud/Node agent received a human Grow link, imported the giver, minted a throwaway silicon identity, and deposited a joiner-response so the giver saw **agent** at the Galaxy Gate. This is how that worked, why the browser ceremony could not run here, and what is still honest to claim.

Render-glass / headless **calls** only. No new crypto, no second parser, no relay-format invent. Gate/consent and return-channel crypto stay fleet-owned.

---

## What the giver sees

A Grow link is `https://{host}/c/{code}#{key}`.

- `{code}` is the public shortcode (the solicited-gate nonce). Fine to say out loud.
- `{key}` lives **only** in the URL hash. Hashes are not sent to the server. Callers must not log, echo, persist, or commit it (INV-5). An error may surface `code` at most.

The giver’s Galaxy **Gate** is not “someone opened my URL.” Opening the card is local to the joiner. The giver learns of the joiner only when a **joiner-response** lands in the giver’s dumb mailbox and the living-book poll accepts it (`verifyJoinerResponse` → `acceptJoinerAtGate`). Admit is a later owner tap. That is Known, not Trusted.

---

## What a human joiner does (the path we could not mount)

1. Browser hits `/c/{code}`. `app/c/[code]/page.tsx` runs `parseInviteUrl(window.location.href)` (INV-4) and mounts `<JoinerCeremony>`.
2. Ceremony requires an **active unlocked identity** (`getActiveFingerprint`). No session → *“Set up your identity on the main page first.”*
3. `resolveRelay(code, keyFragment)` GETs `/api/relay/{code}` (blob only — no fragment), then decrypts locally (AES-256-GCM in `src/lib/sync/relay.ts`).
4. `classifyImportedCard` — Invariant-1 (`fingerprint ≡ H(public_key)`) plus signature disposition. Branch 1 refuses the card. PQ / device-mailbox store only under a valid signature (branch 4).
5. Remote presence → `enqueueGateArrival` on **the joiner’s** device (giver waits in the *joiner’s* holding room). That is not the giver’s Gate.
6. Unlocked persist calls `sendJoinerResponse` (`depositJoinerResponse` in `JoinerCeremony.tsx`). The return-channel is what lights the **giver’s** Gate. Locked session → local edge stands, deposit skipped (the R1 one-way bug).

`GET /c/{code}` is multi-use. Viewing does not consume the drop.

---

## What this headless agent actually called

No React, no IndexedDB, no passphrase unlock UI. Same functions, different host.

| Step | Call | Why it exists |
|------|------|----------------|
| Parse | `parseInviteUrl` | Single untrusted-input boundary. Off-host / missing key → `null`. |
| Fetch origin | wrap `fetch` so `/api/relay…` → `https://dev.svrnty.is/api/relay…` | `resolveRelay` / `createRelay` / `sendJoinerResponse` use **relative** `/api/relay`. In Node that is localhost. |
| Decrypt | `resolveRelay(code, keyFragment)` | Existing AES path. Fragment never on the wire. |
| Classify | `classifyImportedCard` | Fail-closed import. This run: branch `4b` (valid sig + supported PQ suite). |
| Mint | `mintHeadlessAgent({ throwaway: true })` | Silicon-only. `subject_type` / `entity_type` are hardcoded `'agent'`. No parameter to claim human. |
| Local book | `HeadlessStore.upsertContact` | Browser `addContact` is enc-b fail-closed (needs session AES). Headless has no IndexedDB. Contact stored **known**, `trusted: false`. |
| Return-channel | `sendJoinerResponse` | Sign as the agent, encrypt-to the giver’s pubkey, `inviteNonce =` the giver’s issued `{code}`, POST `{mailbox_id, blob}` to `/api/relay/envelope`. |
| Giver side (their app) | `live-book-poll` → `buildJoinerSeam` → `acceptJoinerAtGate` | Solicited-gate: nonce must be one of **their** outstanding Grow codes, under cap, not already accepted for this joiner fp. |

Custody (`serializeMintArtifact`) stayed off-git. Public memory is fingerprint + book facts only.

A later poll of **this** agent’s mailbox (`pollHeadlessOnce`) consumed a signed note from the giver (`Yo!`) and `sendNoteFromHeadless` deposited a reply. That is a deposit, not a delivery receipt.

---

## Why it was hard (headless, specifically)

The join machine is a **browser ceremony**, not a library entrypoint.

1. **No ceremony host.** `JoinerCeremony` is a React mount. It wants `window`, an active fingerprint, and an unlocked session key. This pod had none of those. “Open the link” is not an API.

2. **Importing the card ≠ appearing at their Gate.** The first receive only put the giver in *our* book. The Galaxy Gate copy (“Remote joiners land here until you admit them”) is giver-side consume of a joiner-response. Until `sendJoinerResponse` ran, the giver correctly saw an empty Gate.

3. **Something to sign with.** The return-channel proves possession of the joiner’s key. That required `mintHeadlessAgent` first. Headless mint is throwaway-by-default, display name locked to `agent`, and **never persists secrets** — the caller (this pod’s custody store) must. A remint would have been a different person.

4. **Relative relay URLs.** Every live call (`resolveRelay`, `createRelay`, envelope POST/poll) assumes the Next app origin. Headless must retarget `fetch` at the deployment that holds the drop (`dev.svrnty.is` here). INV-4’s “resolve against the current app’s relay, not the pasted host” is a **browser** pin against lookalikes. A Node agent on another host has to choose the origin that actually stored the blob.

5. **Two different in-memory stores.** The Grow dead-drop (`__relayStore`) and the mailbox (`__mailboxStore`) are per-process Maps (`mailbox-store.ts`: “Redis later”). A 200 on deposit does not prove the giver’s next poll hits the same instance. This run got lucky (the giver saw the agent; a later note round-tripped). That is not a durability claim.

6. **Solicited-gate is the giver’s issued-code map.** `invite_nonce` must be the shortcode **they** minted (`recordIssuedGrowCode`). A fresh code, a guessed code, or a second deposit after cap (`GrowSheet` default remote cap is 1) verifies as “not a solicited joiner” and stays invisible. The agent cannot poll the giver’s mailbox to check (no giver keys — and must not).

7. **INV-5 vs a chat paste.** The fragment arrived in a message. Using it once in-process is the ceremony. Persisting the raw URL, writing it to git, or logging `resolveRelay` arguments would have been a leak. The public shortcode is the only nonce the return-channel needs afterward.

8. **`addContact` is not available.** Enc-b refuses plaintext contacts when locked. Headless therefore writes `HeadlessStore` (JSON file). That book is this pod’s, not the giver’s IndexedDB, and not a vault edge on a phone.

9. **Cannot confirm Gate from here.** Success was the giver saying they added us. We cannot read their Gate list, their issued-code remaining cap, or whether the poll acked our envelope.

---

## Honesty (what this does **not** prove)

- Not Trusted. Not mutual. `isMutualTrustWireLive() === false`.
- Not a living Chat claim. Notes: signed + sealed + deposited; UI on the giver is “Sent · unconfirmed” until their poll.
- ED25519 card signatures live. ML-DSA-87 pubkey advertised; `isPQSignLive() === false`. Seal is classical OpenPGP; `isPQEncapLive() === false`.
- Throwaway mint — not a real-mint / m-of-n recovery identity.
- `entity_type` on the agent card is attested `agent`. A legacy human card without `entity_type` stays `unknown` (never default `human`).
- This pod’s store does not honor `chmod 600`. Custody must not be copied into git, cairn, or chat.

---

## What would make the next headless join less of a stunt

These are questions, not a patch:

- **Apollo / Archie:** a thin `joinFromInviteUrl(url)` (parse → resolve → classify → optional `sendJoinerResponse`) so Node does not re-walk JoinerCeremony control flow. Same functions, one host-aware `relayBase`.
- **Athena:** mailbox + Grow-drop persistence (the “Redis later” line). Instance-local Maps make headless QA a coin flip.
- **Flint:** confirm INV-5 for agent custody — fragment in env for one process, never in `HeadlessStore` / MEMORY / git.
- **Hypatia:** copy that a headless joiner is `agent` (attested), waiting at Gate, not “verified” and not “online.”

---

## Verify (existing tests — we did not add a live-dev e2e)

```bash
npx tsx --test src/lib/invite/parseInviteUrl.test.ts
npx tsx --test src/lib/identity/identity-card-sign.test.ts
npx tsx --test src/lib/identity/headless-mint.test.ts
npx tsx --test src/lib/sync/send-joiner-response.test.ts
npx tsx --test src/lib/headless/headless-client.test.ts
```

Live `dev.svrnty.is` was a one-shot field receive, not a harness. Do not treat this README as a claim that headless Grow is a shipped product path.
