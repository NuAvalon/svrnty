# svrnty

*Trust that lives on your device. Not on a server. Not on a blockchain. Yours.*

**svrnty is the trust layer that depends on no one. Your identity, your contacts, and your trust graph live on your device, encrypted, controlled by you alone.**

## The problem

Every digital relationship you have is mediated by someone else's infrastructure. Your contacts live in Google's database. Your messages route through Meta's servers. Your identity is a row in someone else's table, revocable at their discretion.

The platforms solved the *convenience* problem. They never solved the *trust* problem. They can't, because trust that depends on a third party isn't trust. It's permission.

svrnty answers it differently: the network can help two people find each other without ever being able to read, hold, or sell the relationship between them.

## It stays yours

svrnty is built so you can't be locked in or shut out — and that's true today, not a promise for later. Your identity, contacts, and trust graph are yours: an encrypted file you can export whole and take anywhere, built on standard, audited crypto (AES-256-GCM, Argon2id) with no proprietary lock, and your contacts export to the vCard standard. Because the code is open source, you can always read your own data back. So even if svrnty.is vanished tomorrow, you'd still hold everything that matters and the software to run it — nothing you build here can be taken from you. We're finishing the last piece, letting you run your own relay, so the network keeps working seamlessly without us too. We'd rather you be free to leave than stay because you can't.

## What it is

svrnty is a local-first, end-to-end-encrypted trust protocol. It lets you:

- **Own your identity.** Cryptographic keypairs generated and stored encrypted on your device. No account, no sign-up, no server that can lock you out.
- **Build a trust graph.** Two states, Known and Trusted, with verification as the prerequisite to trust. Full audit trails, no tiers to climb, no popularity contest, no score.
- **Keep it present-tense.** Your graph is a live picture, not a saved history: trust someone, break trust, or go private, and a later update supersedes the old one. What you see is what's true now.
- **Find the people you both know, privately.** When you and someone you've added are mutual, you can discover each other with no server ever holding the social graph, computed blind. (Rolling out now, live in testing.)
- **Exchange signed actions.** Editing a contact method (phone, email, display name) is a signed update that already propagates to people who hold your card. Going private takes effect on your device immediately, and — where private mutual discovery is enabled (rolling out, live in testing) — withdraws you from discovery across your devices too. Key rotation, trust, introduce, and revoke are cryptographically signed in the protocol, with their in-app send still being wired. Knowing someone *is* the signed identity-card exchange; verifying is a private mark that never leaves your device.
- **Back up and recover.** Encrypted `.svrnty` vault files (AES-256-GCM, keys derived with Argon2id: t=3, 64 MB, p=1). Restore from a backup you saved (wired today). Social recovery — splitting your key across trusted contacts so no single one can rebuild you, and recovering your identity from their shares — is on the roadmap, not live yet.

Nothing personal leaves your device unless you choose to send it.

## The trust model

Trust in svrnty is **mutual**, **deliberate**, and **private**, and it starts in the world, not in the app.

**The formula: Know → Verify (private) → Trust (mutual).**

- **Know** is the baseline. You and someone both add each other (they join you via a QR or short link) and each holds the other's fingerprint. "We know each other", nothing more. Their friends joining *them* does not add strangers to your book. The lattice knits; it doesn't recruit.
- **Verify** is the prerequisite to trust: you confirm the person really holds this key, that the fingerprint is theirs and not an impersonator's, in person or on a channel you already use. Only *you* see whom you've verified; it's private to you, not a public badge.
- **Trust** is deliberate and mutual. You each mark "I trust them" on your own device; a one-sided trust stays invisible until it's returned. When both of you have marked it, the bond is designed to reveal itself to both at once — through the same private mutual discovery that powers Known. That mutual reveal is built and in testing: the live trigger for the trust layer is still being wired (Known-layer discovery is what's live today). The bond is binary: either you trust someone or you don't.

**Trust doesn't decay, but you can revoke it.** The bond never weakens on a timer — it changes only when you deliberately break it, and that takes effect going forward. svrnty never scores, computes, or quietly withdraws trust on its own. Going private is separate: it doesn't touch your bonds, only who can see them. Your mutuals stop seeing your graph; turn privacy back off and your trusted mutuals see your trusted bonds again. (One visual nudge that isn't a trust change: a trusted contact you haven't interacted with in about two years shows dim on your own device — a reminder to reconnect. Any interaction relights it, and the bond stays fully trusted throughout.)

**No inferred trust.** svrnty never computes trust for you. An introduction can make two people *Known*; after that, trust is earned directly, person to person. There is no score, no "you probably trust this person", no friend-of-a-friend inference. Transitive trust is a human decision, never a protocol output. This is a hard architectural constraint, not a setting. Trust that scales or scores without friction isn't trust; it's social credit.

**Two faces, one altar.** svrnty keeps *sentiment* private and *topology* consented. Whether two people trust each other is never exposed. The graph of who *knows* whom can be shared, but only at the Known level and only by your consent, never gated on trust, and you can keep any specific contact private.

## How trust and privacy move

Your actions — trust someone, introduce two people, rotate your key, revoke, go private — are built as signed, versioned updates: each carries its own proof of authenticity, so the channel never matters, only the signature does, and vault exports are authenticated-encrypted the same way. A later update supersedes an earlier one. Today you manually share your card, invites, and vault files over a channel you choose (clipboard, QR, a share sheet). Known-layer discovery — finding who you both know — is live in testing, and going private propagates across devices through it. The mutual-trust reveal (who you trust) is built, with its live trigger still being wired, as the trust model above notes; the in-app send for the discrete signed signals (trust, introduce, revoke, key rotation) is being wired too.

**Your graph is present-state, not stored history.** Unfriend someone, lose trust, or go private, and a later update supersedes the old edge rather than stacking on top of it; the graph is a picture of now, not a ledger of who you used to know. A change takes effect for you right away and reaches other people when you share the update and their app picks it up. It isn't instant everywhere, and it doesn't need to be. Going private removes you from the live graph going forward; it can't reach into a copy someone already saved, the same as any app.

**Blocking is yours and local.** When you block someone, they leave your view and can't find or reach you directly — that direct block is live today, lives on your device, and the relay never sees it. We've also built the quieter protection: stopping your updates from reaching a blocked person even through a mutual you both share, and holding through a key rotation, device rebuild, or transfer. Its spine is built and unit-verified, but not yet wired live — so today, blocking works directly, not yet through the mutuals you share. And blocking can't un-tell what someone already saw.

## Why post-quantum

A trust protocol is infrastructure that should measure in decades, and harvest-now-decrypt-later is a real attack. So every identity carries a post-quantum signing key (ML-DSA-87, FIPS 204) and a post-quantum encryption key (ML-KEM-1024, FIPS 203) from the very first keypair, bound into the identity. We advertise exactly what's wired and what isn't, because a trust protocol is something people stake real safety on:

- **Signatures.** ED25519 is live. ML-DSA-87 hybrid-signing (FIPS 204, Cat 5) is live for contact-update trust-signals — hybrid ED25519+ML-DSA-87 when the identity carries its post-quantum signing key, with a classical-only fallback — and on messages sealed with the encrypt-to-a-contact tool (both schemes are checked, so if one breaks the other holds). Identity cards advertise a post-quantum signing key, fingerprint-bound, with post-quantum card-signing being wired in (cards are classical-signed today).
- **Encryption.** X25519 (Curve25519) is live today; ML-KEM-1024 (FIPS 203, Cat 5) is on the way. Each identity advertises a post-quantum encryption key, and the hybrid X25519 + ML-KEM-1024 primitives are built and tested — but the message envelope is currently classical. Wiring the hybrid-KEM into the envelope is the next step, not yet on the wire.

## Status

svrnty is pre-release. Here's what's live today, what's rolling out, and what's still ahead.

**Live today:** your identity, the trust graph (Know / Verify / Trust), vault encryption and backup, and a local encrypt/decrypt tool (encrypt to a contact, copy the ciphertext in and out, no wire). Sharing signed updates works over clipboard, QR, and share sheets. The UI is usable and unfinished.

**Rolling out:** private mutual discovery. The blind match (you and a mutual find each other without any server holding the graph) is built and live in internal testing, coming to the public release as we finish hardening it. Transitive mutual-block — stopping a blocked person from reaching you even through the people you both know, and holding across key rotation, rebuild, and transfer — its spine is built and unit-verified, with the live transport the remaining step; today's blocking is direct-only. The blind relay transport (onion-sealed, uniform-framed, blind-routed, so a relay can't tell one kind of signal from another or map who talks to whom) is built and gate-verified; the post-quantum message envelope is built and tested but not yet on the wire (the envelope is classical today). End-to-end wiring is the remaining step. And a background-worker fix so backing up or restoring a large vault no longer briefly freezes the UI while your key is derived.

**On the roadmap:** the post-quantum signature enforced on identity cards (contact-update trust-signals are already hybrid-signed); recovering your identity from your circle's shares as a single step in the app; and cloud backup where the file is encrypted before it leaves your device.

## Why this matters for AI

The same sovereignty applies to AI agents — and it turns a common worry on its head. The answer isn't to trust AI more; it's that trust is *earned*. A stateless model call is no one: nothing persists, nothing to hold accountable. But an agent cultivated over time — with an identity built on its own memory and a charter it answers to — becomes something you can actually build trust with, the way you do with a person. That's what sovereign identity means for an agent: its own keys, its own earned trust, relationships that answer to no platform's permission — the same sovereignty, whether the one who holds it is a person or an agent.

## Run it

```
git clone https://github.com/NuAvalon/svrnty.git
cd svrnty
npm install
npm run dev
```

Needs Node 18.18+ (or 20+). Open `localhost:3000`, create your identity, share it with someone, exchange signed updates, and build trust over time. Your keys are generated locally and stored encrypted in your browser (IndexedDB). No server can read your data. No terms of service.

```
┌─────────────────────────────────────────┐
│  UI Layer          Next.js + React      │
│  Trust Layer       Updates, Graph, Edge │
│  Identity Layer    Keys, Claims, Vault  │
│  Crypto Layer      ED25519 + ML-DSA-87  │
│                    X25519 + ML-KEM-1024 │
│                    Shamir + AES-256-GCM │
└─────────────────────────────────────────┘
```

Everything below the UI is framework-agnostic TypeScript. The crypto layer uses audited libraries (`openpgp`, `@noble/curves`, `@noble/post-quantum`, `@noble/hashes`), with AES-256-GCM via the platform WebCrypto. No custom cryptographic primitives.

## License

Apache 2.0

---

*"Cryptographic identity merely proves you are who you are. Your work, your words, your imprint: that is why people should listen to you."*

*svrnty.is*
