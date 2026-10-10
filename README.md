# svrnty

*Trust that lives on your device. Not on a server. Not on a blockchain. Yours.*

**svrnty is the trust layer that depends on no one. Your identity, your contacts, and your trust graph live on your device, encrypted, controlled by you alone.**

Read the [Manifesto](./MANIFESTO.md).

## The problem

Every digital relationship you have is mediated by someone else's infrastructure. Your contacts live in Google's database. Your messages route through Meta's servers. Your identity is a row in someone else's table, revocable at their discretion.

The platforms solved the *convenience* problem. They never solved the *trust* problem. They can't, because trust that depends on a third party isn't trust. It's permission.

svrnty answers it differently: the network can help two people find each other without ever being able to read, hold, or sell the relationship between them.

## It stays yours

svrnty is built so you can't be locked in or shut out — and that's true today, not a promise for later. Your identity, contacts, and trust graph are yours: an encrypted file you can export whole and take anywhere, built on standard, audited crypto (AES-256-GCM, Argon2id) with no proprietary lock, and your contacts export to the vCard standard. Because the code is open source, you can always read your own data back. So even if svrnty.is vanished tomorrow, you'd still hold everything that matters and the software to run it — nothing you build here can be taken from you. And you can already run the whole thing yourself — point one line of config at your own domain and bring it up — so the network keeps working for you and the people you reach on your own infrastructure, not ours. We'd rather you be free to leave than stay because you can't.

## What it is

svrnty is a local-first, end-to-end-encrypted trust protocol. It lets you:

- **Own your identity.** Cryptographic keypairs generated and stored encrypted on your device. No account, no sign-up, no server that can lock you out.
- **Build a trust graph.** Two states, Known and Trusted, with verification as the prerequisite to trust. Every change is signed and verifiable — no tiers to climb, no popularity contest, no score.
- **Keep it present-tense.** Your graph is a live picture, not a saved history: trust someone, break trust, or go private, and a later update supersedes the old one. What you see is what's true now.
- **Find the people you both know, privately.** When you and someone you've added are mutual, you can discover each other with no server ever holding the social graph, computed blind. (Rolling out now, live in testing.)
- **Exchange signed actions.** Editing a contact method (phone, email, display name) is a signed update that already propagates to people who hold your card. Going private takes effect on your device immediately, and — where private mutual discovery is enabled (rolling out, live in testing) — withdraws you from discovery across your devices too. Key rotation, trust, introduce, and revoke are cryptographically signed in the protocol, with their in-app send still being wired. Knowing someone *is* the signed identity-card exchange; verifying is a private mark that never leaves your device.
- **Back up and recover.** Encrypted `.svrnty` vault files (AES-256-GCM, keys derived with Argon2id: t=3, 64 MB, p=1). Restore from a backup you saved (wired today). Social recovery — splitting your key across trusted contacts so no single one can rebuild you, and recovering your identity from their shares — is on the roadmap, not live yet.

Nothing personal leaves your device unless you choose to send it.

## Your living address book

Underneath the protocol, svrnty is something a person actually opens: your address book. Not a frozen list of names, but a living picture of the people in your life and where you stand with each — who you know, who you've verified, who you trust. It's the human face of everything above: the trust graph, as you actually experience it.

It's there today: you add contacts, hold each person's card, and organize them with your own groups — and you can see the whole web as a map, the Galaxy: your relationships rendered as a living constellation rather than a list. (Your groups are labels kept on your own device, not shared or synced.) It's *living* the way the rest of svrnty is — present-state, not stored history: a contact who changes how to reach them sends a signed update, and your book shows what's true now, not a log of what used to be.

## The trust model

Trust in svrnty is **mutual**, **deliberate**, and **private**, and it starts in the world, not in the app.

**The formula: Know → Verify (private) → Trust (mutual).**

- **Know** is the baseline. You and someone both add each other (they join you via a QR or short link) and each holds the other's fingerprint. "We know each other", nothing more. Their friends joining *them* does not add strangers to your book. The lattice knits; it doesn't recruit.
- **Verify** is the prerequisite to trust: you confirm the person really holds this key, that the fingerprint is theirs and not an impersonator's, in person or on a channel you already use. Only *you* see whom you've verified; it's private to you, not a public badge.
- **Trust** is deliberate and mutual. You each mark "I trust them" on your own device; a one-sided trust stays invisible until it's returned. When both of you have marked it, the bond is designed to reveal itself to both at once — through the same private mutual discovery that powers Known. That mutual reveal is built and in testing: the live trigger for the trust layer is still being wired (Known-layer discovery is what's live today). The bond is binary: either you trust someone or you don't.

**What trust actually asks of you.** svrnty never computes trust, so it's worth saying plainly what you're really asking when you decide to trust someone — three questions:

1. **Will they do what they say?** Do their words line up with their actions, over time? Trust is integrity in motion: a protocol can't vouch for character, but it can make every claim only as strong as the signed act behind it — so the cost of faking it is the cost of meaning it.
2. **Are they morally aligned with you where it matters?** Not on everything — on the things that count in the context you share. Reliability alone isn't trust; a reliable adversary is still an adversary. It's aligned ends you can stand beside, where it counts.
3. **Do they know their own edges?** Do they know where they're qualified and where they aren't — so they won't take on what they can't commit to? Knowing the boundary of your own competence is what keeps a promise honest; someone who over-commits past what they can deliver can't be relied on, even when they mean well.

Those are judgments you make about a person — which is why trust here is binary: you weigh them and decide, yes or no, and the system never scores it for you.

**Trust doesn't decay, but you can revoke it.** The bond never weakens on a timer — it changes only when you deliberately break it, and that takes effect going forward. svrnty never scores, computes, or quietly withdraws trust on its own. Going private is separate: it doesn't touch your bonds, only who can see them. Your mutuals stop seeing your graph; turn privacy back off and your trusted mutuals see your trusted bonds again. (One visual nudge that isn't a trust change: a trusted contact you haven't interacted with in about two years shows dim on your own device — a reminder to reconnect. Any interaction relights it, and the bond stays fully trusted throughout.)

**No inferred trust.** svrnty never computes trust for you. An introduction can make two people *Known*; after that, trust is earned directly, person to person. There is no score, no "you probably trust this person", no friend-of-a-friend inference. Transitive trust is a human decision, never a protocol output. This is a hard architectural constraint, not a setting. Trust that scales or scores without friction isn't trust; it's social credit.

**Two faces, one altar.** svrnty keeps *sentiment* private and *topology* consented. Whether two people trust each other is never exposed. The graph of who *knows* whom can be shared, but only at the Known level and only by your consent, never gated on trust, and you can keep any specific contact private.

## How trust and privacy move

Your actions — trust someone, introduce two people, rotate your key, revoke, go private — are built as signed, versioned updates: each carries its own proof of authenticity, so the channel never matters, only the signature does, and vault exports are authenticated-encrypted the same way. A later update supersedes an earlier one. Today you manually share your card, invites, and vault files over a channel you choose (clipboard, QR, a share sheet). Known-layer discovery — finding who you both know — is live in testing, and going private propagates across devices through it. The mutual-trust reveal (who you trust) is built, with its live trigger still being wired, as the trust model above notes; the in-app send for the discrete signed signals (trust, introduce, revoke, key rotation) is being wired too.

**Your graph is present-state, not stored history.** Unfriend someone, lose trust, or go private, and a later update supersedes the old edge rather than stacking on top of it; the graph is a picture of now, not a ledger of who you used to know. A change takes effect for you right away and reaches other people when you share the update and their app picks it up. It isn't instant everywhere, and it doesn't need to be. Going private removes you from the live graph going forward; it can't reach into a copy someone already saved, the same as any app.

**Blocking is yours and local.** When you block someone, they leave your view and can't find or reach you directly — that direct block is live today, lives on your device, and the relay never sees it. We've also built the quieter protection: stopping your updates from reaching a blocked person even through a mutual you both share, and holding through a key rotation, device rebuild, or transfer. Its spine is built and unit-verified, but not yet wired live — so today, blocking works directly, not yet through the mutuals you share. And blocking can't un-tell what someone already saw.

## How svrnty reaches people

svrnty's relays are deliberately dumb: they move sealed, opaque blobs and never learn who you are or what you say. (Hiding the *pattern* of who talks to whom from the relay itself is the blind-relay transport below — built, not yet live.)

- **Sharing your card (live).** Your card rides a dead-drop — an encrypted blob behind a short 6-character code that expires in 7 days, and the key to open it lives only in the link you share, never on the server. Anyone you give the link to can join from it.
- **Receiving updates (live, in testing).** Your mailbox takes sealed blobs addressed to you; the relay sees only opaque ciphertext — no sender attached, and it keeps no list of your contacts. The sender's identity and signature travel *inside* the sealed message and are checked by you, the recipient, never by the relay. Today this runs single-node (one server, in-memory); making it durable across many servers is next.
- **Hiding the metadata too (coming).** The blind-relay transport — onion-sealed and uniform-framed, so a relay can't tell one kind of message from another or map who talks to whom — is built and unit-tested but not yet wired live. Until it's on, we don't claim metadata privacy.

**Run your own relay (live, as of today).** You can host the whole thing — copy the example config, set your own domain in it, then bring it up (`cp .env.example .env`, point `NEXT_PUBLIC_SVRNTY_DOMAIN` at your domain, then `docker compose up -d --build`). That stands up the app, automatic HTTPS, and the backend, with your share-links pointing at your domain — no code fork. Setting your domain is required, not optional polish: it's compiled in at build, so if you leave the default your links point back at svrnty.is and won't resolve for the people you send them to (change it later and you rebuild). The only piece that stays with svrnty.is is the global vanity-name registry, and it degrades gracefully without it. "Delete us, fork it, run your own" is shipped fact now, not a promise — the last piece of "it stays yours."

**Moving relays is yours.** Your identity lives in your keys, not in any relay — so you can switch to another relay, or your own, without becoming someone new. Today you share your updated card the way you first connected (a fresh link or QR); having your contacts pick up your new address automatically when you move is on the roadmap.

## When something goes wrong

A trust layer has to have honest answers for the bad days — a lost device, a compromised key, a contact who turns hostile — and be equally honest about which answers are wired yet.

**Share your recovery with people you trust (live).** You can split your recovery into pieces (Shamir shares) and hand them to people you trust, so no single one of them can rebuild you but a chosen few together can. Handing out the shares is live today. Collecting them back to rebuild your identity in one step is built but not yet wired into the app — on the near roadmap, as is changing who holds your pieces.

**If a contact turns hostile (live).** You can break trust and block, right on your device, effective going forward: a de-trusted or blocked person stops receiving your updates. That direct protection is live today. (The quieter protection — stopping a blocked person from reaching you even through the people you both know — is built and unit-verified but not yet wired live, as the trust model notes.)

**If a key is compromised (coming).** Rotating a compromised key or seed is built and cryptographically signed in the protocol, but its in-app send isn't wired yet — so today you can't complete a rotation end-to-end. We say so plainly, because a rotation you believe worked but didn't is worse than knowing it isn't ready.

We don't print protections we haven't wired.

## Why post-quantum

A trust protocol is infrastructure that should measure in decades, and harvest-now-decrypt-later is a real attack. So every identity carries a post-quantum signing key (ML-DSA-87, FIPS 204) and a post-quantum encryption key (ML-KEM-1024, FIPS 203) from the very first keypair, bound into the identity. We advertise exactly what's wired and what isn't, because a trust protocol is something people stake real safety on:

- **Signatures.** ED25519 is live. ML-DSA-87 hybrid-signing (FIPS 204, Cat 5) is live for contact-update trust-signals — hybrid ED25519+ML-DSA-87 when the identity carries its post-quantum signing key, with a classical-only fallback — and on messages sealed with the encrypt-to-a-contact tool (both schemes are checked, so if one breaks the other holds). Identity cards advertise a post-quantum signing key, fingerprint-bound, with post-quantum card-signing being wired in (cards are classical-signed today).
- **Encryption.** X25519 (Curve25519) is live today; ML-KEM-1024 (FIPS 203, Cat 5) is on the way. Each identity advertises a post-quantum encryption key, and the hybrid X25519 + ML-KEM-1024 primitives are built and tested — but the message envelope is currently classical. Wiring the hybrid-KEM into the envelope is the next step, not yet on the wire.

## Status

svrnty is pre-release. Here's what's live today, what's rolling out, and what's still ahead.

**Live today:** your identity; the trust graph (Know / Verify / Trust); your living address book — contacts, device-local groups, and the Galaxy view; vault encryption and backup; a local encrypt/decrypt tool (encrypt to a contact, copy the ciphertext in and out, no wire); card sharing via dead-drop and your single-node mailbox; splitting your recovery across trusted contacts (Shamir shares); direct blocking; and **running your own relay** (turnkey — a one-line domain config, then `docker compose up`). Sharing signed updates works over clipboard, QR, and share sheets. The UI is usable and unfinished.

**Rolling out:** private mutual discovery — the blind match (you and a mutual find each other without any server holding the graph) is built and live in internal testing, hardening for public release. Transitive mutual-block — stopping a blocked person from reaching you even through the people you both know, and holding across key rotation, rebuild, and transfer — its spine is built and unit-verified, with the live transport the remaining step; today's blocking is direct-only. The blind relay transport (onion-sealed, uniform-framed, blind-routed, so a relay can't tell one kind of signal from another or map who talks to whom) is built and gate-verified; the post-quantum message envelope is built and tested but not yet on the wire (the envelope is classical today). End-to-end wiring is the remaining step. And a background-worker fix so backing up or restoring a large vault no longer briefly freezes the UI while your key is derived.

**On the roadmap:** recovering your identity from your circle's shares as a single step in the app (and rotating who holds them); rotating a compromised key or seed end-to-end in-app; having your contacts pick up your new address automatically when you move relays; the post-quantum signature enforced on identity cards (contact-update trust-signals are already hybrid-signed); and cloud backup where the file is encrypted before it leaves your device.

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

To run your own relay for yourself or others:

```
cp .env.example .env
# REQUIRED: set NEXT_PUBLIC_SVRNTY_DOMAIN to your own domain (baked in at build; leave the default and your share-links point back at svrnty.is)
docker compose up -d --build
```

This stands up the app, automatic HTTPS, and the backend; with your domain set, your share-links point at it, no code fork. (The domain is baked in at build — change it later and rebuild.)

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
