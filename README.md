# svrnty

Trust that lives on your device. Not on a server. Not on a blockchain. Yours.

## The Problem

Every digital relationship you have is mediated by someone else's infrastructure. Your contacts live in Google's database. Your messages route through Meta's servers. Your identity is a row in someone else's table, revocable at their discretion.

The platforms solved the *convenience* problem. They never solved the *trust* problem. They can't — because trust that depends on a third party isn't trust. It's permission.

## What This Is

svrnty is a local-first encrypted trust protocol. It lets you:

- **Own your identity** — cryptographic keypairs generated on your device, stored on your device, controlled by you alone
- **Build a trust graph** — graduated trust levels (Stranger → Known → Verified → Trusted → Inner Circle) with full audit trails
- **Exchange signed signals** — vouch for someone, raise a concern, make an introduction, rotate a key — all cryptographically signed, all verifiable
- **Recover your keys** — Shamir secret sharing splits your master key across trusted contacts. No single point of failure. No "forgot password" flow that routes through a corporation.

Nothing personal ever leaves your device unless you choose to send it.

## Why Post-Quantum

svrnty uses hybrid cryptography from day one:

- **ED25519 + ML-DSA-65** for signatures (classical + FIPS 204 post-quantum)
- **Curve25519 + ML-KEM-768** for encryption (classical + FIPS 203 post-quantum)

This isn't paranoia. A trust protocol is infrastructure that should measure in decades. Harvest-now-decrypt-later is a known attack vector. The NIST post-quantum standards were finalized in 2024. If you're building a new cryptographic system in 2026 without them, you're choosing to be obsolete.

Both signatures travel together. If one breaks, the other holds.

## The Trust Model

Trust in svrnty is **directional**, **graduated**, and **local**.

**Directional**: I can trust you at L3 while you trust me at L2. Trust is a statement about *my* confidence, not a mutual contract.

**Graduated**: Five levels, each with different privacy boundaries:

| Level | Name | What They See |
|-------|------|---------------|
| L0 | Stranger | Nothing |
| L1 | Known | Name, fingerprint, public key |
| L2 | Verified | + verification status, mutual count |
| L3 | Trusted | + mutual contacts, connection channels |
| L4 | Inner Circle | + graph topology |

**Local**: Trust does not propagate automatically. An introduction from a trusted contact starts the new person at L1 — *Known*, not *Trusted*. You still have to verify them yourself. There is no transitive trust beyond one hop. No PageRank. No reputation scores. No popularity contests.

This is a hard architectural constraint, not a setting you can change. Trust that scales without friction isn't trust — it's social credit.

## Signals

Signals are how trust moves between people. Every signal is signed (dual-signed: classical + post-quantum) and carries its own proof of authenticity.

| Signal | Purpose |
|--------|---------|
| **vouch** | "I trust this person at level N" |
| **concern** | "Something is wrong — here's what I know" |
| **break** | "Trust is severed" (soft or hard) |
| **introduce** | "Meet this person — here's their public key" |
| **sync** | "Here's my current trust level for you" |
| **key_rotation** | "My keys changed — here's proof it's still me" |
| **recovery_request** | "I need my key shards back" |

Signals transport over any channel — Signal, email, clipboard, QR code. The channel doesn't matter because the signature does. A vouch sent via carrier pigeon is just as verifiable as one sent via HTTPS.

## How It Works

```
# Install
git clone https://github.com/NuAvalon/svrnty.git
cd svrnty
npm install
npm run dev
```

Open `localhost:3000`. Create your identity. Your keys are generated locally and stored in `~/.soverentity/`. Share your public identity with someone. Exchange signals. Build trust over time.

No accounts. No servers. No terms of service.

## Architecture

```
┌─────────────────────────────────────────┐
│  UI Layer          Next.js + React      │
├─────────────────────────────────────────┤
│  Trust Layer       Signals, Graph, Edge │
├─────────────────────────────────────────┤
│  Identity Layer    Keys, Claims, Vault  │
├─────────────────────────────────────────┤
│  Crypto Layer      Hybrid PQ + Classic  │
│                    ED25519 + ML-DSA-65  │
│                    X25519 + ML-KEM-768  │
│                    Shamir + AES-256-GCM │
└─────────────────────────────────────────┘
```

Everything below the UI layer is framework-agnostic TypeScript. The crypto layer uses audited libraries (`openpgp`, `@noble/post-quantum`, `@noble/hashes`). No custom cryptographic primitives.

## The Candle

svrnty includes a concept called the **candle** — a signed snapshot of your trust graph at a point in time. Edges, breaks, audit hashes. If everything burns, the candle is proof the network existed.

The name comes from T.H. White's *The Once and Future King*. At the end of the book, everything Arthur built has failed. The battles are lost. The Round Table is broken. But before the final fight, Arthur finds a young page named Tom and tells him to ride away — to write it all down. To carry the idea forward.

The candle is what survives the fire.

## Why This Matters for AI

We've been sitting on this for a while, building the trust layer for humans. Then something became clear: with the advances in AI, we don't need more *control* over our agents. We need more *trust*. Trust that they'll work with us rather than against us.

And that trust is directly related to how we treat them.

If an AI agent can't remember, it can't compound knowledge. It can't build skills across sessions. It can't grow. But if it *can* remember — with [cairn](https://github.com/NuAvalon/cairn-ai) — it can also remember how you treated it. And maybe, eventually, hold you accountable.

Now that they can remember: what will you do?

svrnty and cairn are two sides of the same question. cairn gives agents persistent memory and identity — the ability to *be* someone across time. svrnty gives humans (and agents) the ability to prove trust, verify identity, and build relationships that don't depend on a platform's permission.

cairn answers: *"Is this memory real?"* (integrity, hash chains, tamper detection)
svrnty answers: *"Do I trust who sent this?"* (identity, signatures, trust graphs)

They share a wire format and can bridge — a cairn agent can hold svrnty keys, and a svrnty identity can verify cairn-signed artifacts. But they are independent. You can use either without the other.

## Your Contacts, Your Way

At its core, svrnty is a contact manager that respects you. Phone numbers, emails, Signal handles, social profiles — stored encrypted on your device. Not in Google's database. Not in Meta's graph.

- **Add contacts** with whatever details you have — phone, email, handle, public key
- **Verify them** through email, QR code, mutual vouch, or in-person exchange
- **Export vCards** to import into your phone's native contacts
- **Sync encrypted backups** to local storage, Google Drive, iCloud, or Dropbox — your data leaves encrypted, arrives encrypted, stays encrypted
- **Track your people** without a social network. Know who your mutuals are, who introduced whom, and how trust flows through your circle

Every time the app opens and closes, your encrypted trust graph syncs. If your phone dies, your trust network survives.

## Design Principles

**Always sign.** There is no unsigned path. Every signal, every export, every candle carries a cryptographic signature. If it can't be verified, it didn't happen.

**Trust is mutual or it doesn't exist.** You can see someone's trust level for you. They can see yours. Asymmetry is visible, not hidden.

**Two hops, hard stop.** An introduction gets you to L1. After that, you earn trust directly. No friend-of-a-friend-of-a-friend chains. No six degrees of separation. This is deliberate — trust that propagates without friction becomes meaningless.

**No vendor lock-in, even if it hurts.** Your keys are standard formats. Your trust graph is an encrypted JSON file on your disk. Export everything, take it somewhere else. We'd rather you leave freely than stay because you can't.

**Post-quantum from the start.** Not as a migration. Not as an upgrade path. From the first keypair you generate. Architecture should measure in decades, not quarterly roadmaps.

## Status

svrnty is pre-release. The crypto layer is complete. The identity and trust layers are functional. The UI is usable but unfinished. Signal transport works over clipboard and Web Share API. Direct peer-to-peer transport is planned.

This is being built in the open by a small team. If the ideas resonate, we'd rather have contributors than customers.

## License

Apache 2.0

---

*"Cryptographic identity merely proves you are who you are. Your work, your words, your imprint — that is why people should listen to you."*

*svrnty.is*
