# Phase 3.2 — Notes store architecture

**Companion to** `docs/MESSAGING_PRIOR_ART.md`.  
**Claim:** this is the **notes** store — not the messaging brand.

## Separation rule

- **Book / vault DB** (`svrnty`): identity, keys, contacts, trust — permanent relationship objects.
- **Notes DB** (`svrnty-notes`): conversation material — **ephemeral-by-default**, own retention/TTL, own export rules.

Do not add a `messages` object store to `svrnty`. Cross-link by `peer_fingerprint` / `thread_id` only.

## Schema (v1)

**Database:** `svrnty-notes`, version `1`

| Store | Key | Value (at rest) |
|-------|-----|-----------------|
| `threads` | `thread_id` | metadata (participants, kind, retention, last_activity) — AES-GCM under notes session key |
| `notes` | `note_id` | ciphertext body + headers (thread_id, sent_at, direction) — AES-GCM |
| `ring_channels` | `channel_id` | local membership + wrapped content-key slots (never uploaded as roster) |
| `settings` | string | salt / retention defaults |

### Thread kinds

```ts
type ThreadKind = 'direct' | 'ring';
type ParticipantKind = 'human' | 'agent';
```

- **direct:** exactly one peer (human or trusted agent).
- **ring:** group via ring-channel (3.4) — local roster only; relay sees K opaque mailbox deposits.

### Retention (defaults)

| Policy | Default |
|--------|---------|
| Thread TTL | `null` (keep until user deletes) — product may later default to 30d |
| Per-note TTL | optional `expires_at` |
| Delete | user-ruled; deleting a thread deletes child notes |

Book stays permanent when notes burn.

## Wire object (notes v0 — pre-ratchet)

Honest classical seal (OpenPGP to admitted peer pubkey), typed payload:

```ts
{
  type: 'svrnty-note-v0',
  note_id, thread_id, from_fingerprint, sent_at,
  body,                    // plaintext inside seal only
  participant_kind,        // human | agent (sender’s claim; receiver already admitted key)
}
```

Signed with `DOMAIN_NOTE` (lives in `src/lib/messaging/domains.ts` until Archie promotes into `format/envelope.ts`).

**Not included in v0:** ratchet headers, sealed-sender tokens, read receipts, server group IDs.

## Transport

Same dumb relay as contact.update:

1. Seal note → opaque blob  
2. `POST /api/relay/envelope` `{ mailbox_id, blob }`  
3. Recipient polls owner-auth queue, decrypts, **drops if `from` ∉ admitted contacts**  
4. Persist into `svrnty-notes`, ack

Discriminator is **inside** the decrypted payload (`type: svrnty-note-v0`), not a new HTTP route. Relay stays dumb.

## PWA surface

- Route: `/msg` (reserved in middleware; never a slug)
- Host story: `svrnty.is/msg` or future `peter.svrnty.is/msg` — **separate from** dumb-relay URL aesthetics; relay stays mailbox-only
- UI copy: **Notes** — never “Messages” / “Chat” until 3.3

## Agents

Trusted agents are contacts with `participant_kind: 'agent'` (or identity_type on the edge). Same admit-to-speak rule: no key in book → no note in UI. Group rings may mix humans and agents; rotation rules identical.
