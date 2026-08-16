# svrnty

Trust that lives on your device. Not on a server. Not on a blockchain. Yours.

## The Problem

Every digital relationship you have is mediated by someone else's infrastructure. Your contacts live in Google's database. Your messages route through Meta's servers. Your identity is a row in someone else's table, revocable at their discretion.

The platforms solved the *convenience* problem. They never solved the *trust* problem. They can't — because trust that depends on a third party isn't trust. It's permission.

## What This Is

svrnty is a local-first encrypted trust protocol. It lets you:

- **Own your identity** — cryptographic keypairs generated on your device, stored on your device, controlled by you alone
- **Build a trust graph** — binary trust (Known / Trusted) with decay, vouching, and full audit trails. No tiers to climb. No popularity contests.
- **Exchange signed signals** — vouch for someone, break trust visibly, raise a concern privately, make an introduction, rotate a key — all cryptographically signed, all verifiable
- **Back up your vault** — encrypted `.svrnty` vault files (AES-256-GCM, PBKDF2 600K iterations). Export to a local file you control. Cloud sync (Google Drive, Dropbox, iCloud, WebDAV) is on the roadmap; when it lands, the file is encrypted before it leaves your device and the cloud sees a binary blob, nothing more.
- **Recover your keys** — Shamir secret sharing splits your master key across trusted contacts. No single point of failure. No "forgot password" flow that routes through a corporation.

Nothing personal ever leaves your device unless you choose to send it.

## Why Post-Quantum

svrnty uses hybrid cryptography from day one:

- **ED25519 + ML-DSA-87** for signatures (classical + FIPS 204 post-quantum, Cat 5)
- **Curve25519 + ML-KEM-1024** for encryption (classical + FIPS 203 post-quantum, Cat 5)

This isn't paranoia. A trust protocol is infrastructure that should measure in decades. Harvest-now-decrypt-later is a known attack vector. The NIST post-quantum standards were finalized in 2024. If you're building a new cryptographic system in 2026 without them, you're choosing to be obsolete.

Both signatures travel together. If one breaks, the other holds.

## The Trust Model

Trust in svrnty is **binary**, **visible**, and **local**.

**Binary**: You either know someone or you trust them. Two states. Known means you've exchanged keys. Trusted means you vouch for them. There are no tiers to climb, no levels to unlock, no reputation scores. Inner circles exist by nature of who you share what with — not as a feature toggle.

**Visible**: Trust is mutual or it doesn't exist. You can see someone's trust state for you. They can see yours. Breaking trust is visible to both sides — it forces the conversation. Concerns are shared privately with people you trust, not broadcast.

**Local**: Trust does not propagate automatically. An introduction from a trusted contact starts the new person as Known. You still have to verify them yourself. There is no transitive trust beyond one hop. No PageRank. No reputation scores. No popularity contests.

**Decay**: Trust decays over time (2 years by default, customizable per edge). Like a rotating PGP key — if you haven't re-verified someone in two years, the system nudges you. Reverify or let it fade.

This is a hard architectural constraint, not a setting you can change. Trust that scales without friction isn't trust — it's social credit.

## Signals

Signals are how trust moves between people. Every signal is signed (dual-signed: classical + post-quantum) and carries its own proof of authenticity.

| Signal | Purpose |
|--------|---------|
| **vouch** | "I trust this person" |
| **concern** | "Something is wrong — here's what I know" (private, shared only with people you trust) |
| **break** | "Trust is severed" (visible to both sides, optional reason) |
| **introduce** | "Meet this person — here's their public key" |
| **sync** | "Here's my current trust state for you" |
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

Open `localhost:3000`. Create your identity. Your keys are generated locally and stored encrypted in your browser (IndexedDB) — no server, no filesystem key store. Share your public identity with someone. Exchange signals. Build trust over time.

No accounts. No server can read your data. No terms of service.

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
│                    ED25519 + ML-DSA-87  │
│                    X25519 + ML-KEM-1024 │
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
- **Export encrypted backups** to a local file today — your data leaves encrypted, arrives encrypted, stays encrypted (cloud sync to Google Drive, iCloud, Dropbox is on the roadmap)
- **Stay connected** without a social network. See who your mutuals are, who introduced whom, and how trust flows through your circle

Your encrypted trust graph lives in your browser and exports to a local `.svrnty` file you control. (Automatic cloud sync — so a lost or dead phone can't cost you your network — is on the roadmap.)

## Design Principles

**Sign what moves trust.** Trust signals are dual-signed (classical + post-quantum) and independently verifiable; vault exports are authenticated-encrypted.

**Trust is mutual or it doesn't exist.** You can see someone's trust level for you. They can see yours. Asymmetry is visible, not hidden.

**Two hops, hard stop.** An introduction makes you Known. After that, you earn trust directly. No friend-of-a-friend-of-a-friend chains. No six degrees of separation. This is deliberate — trust that propagates without friction becomes meaningless.

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
