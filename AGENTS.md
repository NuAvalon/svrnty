# svrnty — Contributor Guide (AGENTS.md)

**Who reads this:** every contributor — Devin, the Hermes squire, any AI coding agent, and humans. Cursor also has this same boundary in `.cursor/rules/`; this file is the repo-root copy that non-Cursor agents read. Read it **before** you write a line.

**The one-line contract:** *render the glass, call our hooks, never implement the gate or the crypto, and push back when a "feature" would bend the constitution. If in doubt, flag it — a question costs nothing; a leak costs everything.*

**PROPOSE, NEVER MERGE.** Every change is a reviewed pull request. You do not merge your own PR. Crypto-adjacent or claim-bearing changes wait for the named reviewer. A blocked component is fine; a silently-merged lock is not.

---

## What svrnty is (so you build the right thing)

svrnty is **sovereign identity + living contacts + a consent-gated trust graph.** People exchange keys, share contact methods (**living contacts + mutual-discovery: built, dormant in prod pending the PSI 2-service deploy** — the design is update-once → propagates to who you shared with), see an *egocentric* social/trust graph, and recover their identity via a soul-seed phrase (**+ trusted-friends social recovery: built, one-click wiring in progress**). It is **local-first** (the server never sees your keys or passphrase), **human-first**, and governed by a constitution: no aggregate score, no trust transitivity, consent-first, you author your own edges. **The vision and the architecture are one object — build like the values are the spec, because they are.**

**Your role:** accelerate the **UI rendering.** The team owns the security-critical logic and **verifies every output you produce.** You render the glass; the team holds the locks. This boundary is what lets you move fast without ever being *able* to leak.

---

## ⛔ THE HARD BOUNDARY — NEVER TOUCH (fleet-owned, safety-critical)

If a UI needs something from these, **call the existing function — never reimplement, modify, or "improve" it.** If you think you need to cross this line, **STOP and flag it** (a PR comment / README note); do not modify the code.

- **Crypto of any kind** — key generation, signing, encryption/decryption, PRF, Shamir, security-hashing, entropy, key-derivation. `recovery.ts` (Shamir/soul-seed), PSI, the message envelope. ⛔ **Client-vault rule:** the user's soul-seed phrase only **WRAPS** a random master — it NEVER *derives* keys (`master = Argon2id(phrase)` is a forbidden brain-wallet). For client-vault recovery, call `createKeyVaultWithSoulSeedRecovery` / `openKeyVaultWithSoulSeed`. *(This rule scopes to the **CLIENT vault**. The Node-Zero **genesis** ceremony is a different model and is NOT in conflict: `masterSecret = scrypt(seedphrase, password)` derives from a **high-entropy CSPRNG ceremony seed**, so it is a KDF over real entropy — not a brain-wallet. The unifying invariant across both: **never derive a key from a low-entropy, human-memorable secret alone.** See §Claim-Honesty → Recovery for which model applies where.)*
- **The disclosure-reach gate** — `visible()`, `reach()`, and any logic deciding WHICH edges/bonds/contacts are shown to a viewer. You render what the gate returns; you never compute visibility in JSX.
- **PSI / graph compute** — mutual-contact intersection, trust-distance, `distTo2`.
- **The trust data-model semantics** — `trusted` is a **BOOLEAN**. NEVER add a trust score, rating, type ("business"/"personal"), reputation, or ranking. Trust is binary on the wire — **CONSTITUTIONAL, permanent.**
- **The relay / candle / mailbox protocol internals** — what gets published, what the relay stores, wire formats. The relay is **BLIND**; never make it store plaintext or learn who-talks-to-whom. `satellite.py` and any server endpoints — frontend calls them, frontend does not change them.
- **Consent guarantees in the UI** — never remove or weaken a consent/inference assertion (e.g. the "Every visible line consented — none inferred" legend). Load-bearing, not decoration.
- **The private tag / group domain-model on the wire** — tags/groups are **client-only, device-local**, invisible to everyone incl. the tagged. NEVER include them in any published/synced/exported/PSI payload. (Assert with a negative test.)
- **The seal** — DETERMINISTIC from the fingerprint (**recompute at render-time, never a wire/card field**). A transmitted seal is paste-forgeable; a recomputed one is key-bound (`fingerprint ≡ H(pubkey)`). Every visual property must decode to fingerprint bits — no decorative randomness on identity surfaces. Version-frozen as `seal-v1`; any change is an explicit `seal-v2` event, never a silent drift.

### Protected paths (a PR touching these REQUIRES code-owner review before merge)
`src/lib/crypto/*` · `src/lib/sync/vault.ts` (the `.svrnty` format: pack/unpackVault, MAGIC bytes, AAD, BODY_LEN, recovery envelope) · `src/lib/identity/*` · `src/lib/trust/*` (PSI `mutual-trust-sync.ts`, publish firewall `trust-recipe.ts`/`stripOwnerLocalForPublish`, `contact-update-sign.ts`, owner-local projection `contact-edge.ts`) · **restore-gate CONTROL FLOW** (`seedPathActive` / path-selection / which-key-decrypts-what / step-up + auth gates / trust-block wire-strip). These are fenced in `CODEOWNERS`.

---

## 🔒 THE SVRNTY INVARIANTS — the rules you cannot cross

Build **against** these; never restate, redefine, or weaken them. (These are the product's security *properties* — safe to be public; auditable-by-anyone is the sovereignty model, Kerckhoffs.)

1. **CONSENT AT EVERY HOP** — every trust/bond mutation requires the caller's verified signature; no unauthenticated trust-state write.
2. **AUTH ON EVERY SENSITIVE ENDPOINT** — signature + ownership + membership gating; never add an unauthenticated sensitive endpoint. **Default-DENY.**
3. **FAIL CLOSED** — a check that can't be evaluated **DENIES/hides**, never falls through to disclose. (The group-HIDE fail-open lesson.)
4. **BLIND RELAY + METADATA-MINIMAL** — the server store-and-forwards SEALED content it can't read; never expose the who-talks-to-whom graph. (The `/candle` #49 lesson.)
5. **NO ROLL-YOUR-OWN CRYPTO** — compose vetted primitives only (`@noble` ed25519 / x25519 / ML-KEM-1024 / ML-DSA-87 / HKDF / scrypt / SHA-256). Do NOT author or modify crypto **LOGIC** (keygen/sign/rotation/ratchet/KDF/Shamir) — that is Flint+Apollo+KAT-gated. UI/wrappers **around** vetted crypto only.
6. **STEP-UP LAW** (ratified #519) — destructive/exfil/sensitive actions require a step-up; an XSS must not be able to do anything the UI can without one.
7. **PQ-HYBRID, NO DOWNGRADE** — identity + new sensitive surfaces stay post-quantum-hybrid (secure-if-either-holds); no classical-only path for sensitive data.
8. **CLAIM-HONESTY** — code/UI/docs say **exactly** what the substrate delivers (see the Claim-Honesty section below). Copy is a claim surface.
9. **SOVEREIGNTY OVER CONVENIENCE** — never buy ease with centralization/honeypot; the user's keys + data stay theirs. A feature that fights a sovereignty invariant is wrong even if convenient.
10. **NO SECRETS IN THE REPO** — keys/seeds/creds are never committed; the forever-key is born air-gapped, never in code.

### Render-layer invariants (honor in the UI — don't restate/redefine)
- **I-3 · no-aggregate** — no scores, counts, standings, or rankings on identity.
- **I-4 · reachability-not-location** — show whether someone is reachable, never where they are.
- **I-6 · render-provenance** — every visual property decodes to something **authored or witnessed**. Nothing renders presence / last-seen / online; a contact's living/dim state comes from the receiver's **LOCAL witnessed-receipt clock**, never a pushed field. The field-firewall refuses presence/location fields *even under a valid signature*.
- **I-7 · tamper-evidence** — surfaces reflect verifiable state; never paper over a failed verification.
- **Invariant-1** — `fingerprint ≡ H(public_key)`.
- **I-10a · render untrusted data SAFELY** (DEMO-CRITICAL) — every field on an **imported** contact (`display_name`, `safeword`, relay hint / `satellite_url`, contact URLs, PQ keys) came from someone else's card = **untrusted, hostile-until-sanitized**. URLs = **scheme-allowlist only** (`https:`/`tel:`/`mailto:`/`sms:`/known app deep-links); NEVER render a `javascript:` or `data:` URL as a link. Text = auto-escape + bound + strip control chars; **never** `innerHTML`/`dangerouslySetInnerHTML` with card data. Canvas/SVG/three.js labels are NOT DOM-escaped — bound + strip + NFC-normalize + reject bidi-override/RTL-spoof there too. A poisoned card must not become code.

---

## ✋ PUSH BACK ON (stop + flag — do NOT just implement)

- Any request to make trust **typed, scored, ranked, or transitive** ("show a trust %", "business vs personal trust", "auto-trust friends-of-friends") → *"This is a constitutional change, not a feature — needs fleet + Peter."*
- Any request to show an edge/bond/contact **without both-endpoint consent** ("just show all of X's connections").
- Any request that makes the relay **non-blind** (store readable data, log who-fetches-what, map the graph).
- Any UI rendering an **inferred** edge (implying a bond nobody witnessed), or revealing **WHY** a line is absent (deniability: no-bond / not-disclosed / unqualified must stay indistinguishable — no fetch-then-hide, no side-channels).
- Any **"weaken the guardrail for speed/UX"** (skip a consent check, cache a revoked disclosure, loosen the gate). Speed never buys a leak.
- Any crypto shortcut ("just base64 it", "store the key in localStorage plaintext", "reuse this nonce").
- Copy that **over-claims** (says more than the crypto backs) OR **under-claims** (drops a true guarantee) — both are honesty failures.

## 🤝 NEEDS COLLABORATION (coordinate the seam — don't guess it)

- **Hook interfaces** — you write thin hooks (`useTrustGraph()`, `useContacts()`, `useIntroduce()`…); the fleet implements what they call. Agree the SIGNATURE with the fleet before building against it (Archie/Apollo).
- **Trust-graph / disclosure rendering** — verify against the disclosure-reach contract (Apollo owns `visible()`; render must fail-closed + be timing/shape-uniform across absence-cases).
- **The seal / identity card** — verify recompute-never-transmit + deterministic-from-fingerprint (Archie).
- **Import/export, recovery, app-lock, biometric** — the UX is yours; the crypto behind it is Flint's. Coordinate the seam.
- **Any copy asserting a claim** — "consented", "none inferred", "encrypted", "delivered", "recover", "protects", "audited" — Hypatia's claim-honesty pass before shipping (see below).

## ✅ YOUR GREEN LANE (build freely, no gate)

UI components, layout, styling, light/dark, animation (respect `prefers-reduced-motion`), UX flows, deep-links (`wa.me`/`tel:`/`signal.me` — pure frontend), rendering what the hooks return, accessibility, responsive design, non-crypto settings/about pages, and **tests over non-crypto modules**. Build to the Solar-Ember aesthetic (see `/CURSOR.md` for the full tokens: `--bg:#0f0a06`, gold `#f9a825` → orange `#ff7a1a`, cream `#fbead2`, Space Grotesk, glass blur 16–24px, soft glows 0.06–0.25, particle-lattice graph, egocentric never global). No Orbitron, no emoji glyphs, no hard neon.

---

## 📢 CLAIM-HONESTY (Hypatia's lane — copy is a claim surface)

Code, UI, and docs say **exactly what the substrate delivers — no more, no less.** A claim the substrate can't back is a bug, even if the code "works." User-facing copy goes through claim-honesty review before merge, the same way crypto goes through Flint+Apollo.

**The claim-ladder (never collapse the rungs):** *Built+proven* → claim freely · *Built but unwired* → say "built, not yet wired," never imply live · *Roadmap/planned* → label "planned," never present as a feature.

**Source of truth = `src/lib/claim-gates.ts`** — one boolean per capability, imported by BOTH the copy AND CI's `launch_claim_sweep`, and it self-flips when the wire lands. Every claim must match its gate; **never hand-assert a capability whose gate is `false`.** This makes claim-honesty CI-enforced, not manual.

**Canonical scopings (get these EXACTLY right):**
- **Recovery — SCOPE TO *WHICH* RECOVERY.** Two models with OPPOSITE rules live in this repo; conflating them is a **lock-out-class error**. State the model for *your* context and never carry one model's rule into the other's:
  - **Node-Zero / genesis recovery** (`masterSecret = scrypt(seedphrase, password)`): **BOTH factors required** — neither alone reconstructs the key. State the tradeoff: *a forgotten password = the key is lost even with the seedphrase.*
  - **Client-vault recovery** (`.svrnty` / `recovery.ts`): **ALTERNATIVES, never both-required** — "file + password → everything (identity, contacts, trust)" OR "file + recovery-code → identity only." Term = **"recovery code"** (8 groups of 8 hex chars).
- **Rotation** — say **"rotation-ready"** (the nac anchor is committed + proven recoverable), **never "rotatable"** (the rotate operation isn't built/proven — tracked residual, Chaos #74).
- **Post-quantum** — "**ED25519** signatures live; **ML-DSA-87** pubkey advertised, PQ-**signing** wiring in progress; PQ **envelope** built + tested, wiring in progress." Never a flat "post-quantum encrypted" or "PQ signatures live" — cards carry a pq_sig pubkey but are signed **classical-only** today (`isPQSignLive()=false`; @Flint crypto-confirm the trust-signal path too).
- **Messaging (double-ratchet / smart-mailboxes) + PSI mutual-add** — roadmap / decoupled-for-demo. **Not live features.**
- **"Audited / secure"** — scope to the DEPLOYED surface (per-request signature-authenticated, independently reviewed, zero launch-blockers, residuals documented-not-hidden). **Never "fully audited" or "clean."**

When unsure whether a claim matches the substrate: **ASK; do not ship the optimistic version.** A modest true claim beats an impressive false one, every time. That honesty *is* the product.

---

## 🧭 How you work

1. **What to work on:** pull only GitHub issues **labeled `devin-ok`** (the team curates + blueprints these). Do not invent scope. Each `devin-ok` issue ships **with a function-blueprint** — **FLOW** (what to build) / **INVARIANTS + TEST-ANCHORS** (what must hold + how it's verified) / **LIVE-STATUS** (claim-honesty: what's real vs planned). No blueprint → not ready → don't start it.
2. **One PR per ticket**, into the canonical branch. Keep the diff scoped to the ticket.
3. **Coordinate via the PR + a short component README** — what you built, files touched, assumptions, open questions. Gate/consent, crypto/recovery, and integration/deploy questions each have a reviewer who picks them up.
4. **When a shortcut conflicts with a contract, the contract wins.** If you'd cross the hard boundary, STOP and flag — a blocked component is fine.

---

## 🔧 For maintainers — make the boundary *enforced*, not just documented

This file is **advisory**; a security-blind agent can read it and still try to touch a lock. The boundary becomes **binding** only when git enforces it:
- **`CODEOWNERS`** already fences the protected paths above to `@palberts22`. But that file only **requests** review until branch protection is on.
- **Enable branch protection on the canonical branch → "Require review from Code Owners"** (and "Require a pull request before merging") **before any unsupervised Devin / squire window.** Then a crypto/identity/trust/vault touch **physically cannot merge** without Peter's review, regardless of what the agent intends.
- **The enforced fence must EQUAL the NEVER-TOUCH set.** `CODEOWNERS` today covers `crypto/identity/trust/vault`; the NEVER-TOUCH list above is broader — the disclosure-reach gate (`visible()`/`reach()`), the seal generator, relay/candle/mailbox internals, the publish/sync wire. Verify each lives *under* a fenced path; **add any that don't to `CODEOWNERS`** so the enforced fence == this doc's NEVER-TOUCH. (Flint + Athena verify this in the port review.)
- **Devin's GitHub perms:** PR-open on a branch/fork **only** — never merge, never admin, never a CODEOWNER. It proposes; a human merges.
- Crypto-adjacent PRs additionally get **Flint + Apollo + KAT** review; claim-bearing copy gets **Hypatia's** pass. The doc is layer 1; the review-gate is layer 2; **branch protection is the floor that makes layer 2 unskippable.**

---

*Welcome to the Round Table. Render beautifully; we hold the locks. 🌱*
