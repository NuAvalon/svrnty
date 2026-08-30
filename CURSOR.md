# svrnty — Cursor Build Brief (UI acceleration)

**For:** Cursor · **Reviewers:** the svrnty team (gate/constitution · frontend/deploy · crypto/security) · **Aug-29**

> Read this first, then build. Coordinate back via READMEs (one per component: what you built, files touched, assumptions, questions). This brief is self-contained — the invariants and the aesthetic tokens you need are inlined below.

---

## What svrnty is (so you build the right thing)
svrnty is **sovereign identity + living contacts + a consent-gated trust graph.** People exchange keys, share contact methods that stay live (update once → propagates), see an egocentric social/trust graph, and recover their identity via a soul-seed phrase + trusted friends. It is **local-first** (the server never sees your keys or passphrase), **human-first**, and governed by a constitution: no aggregate score, no trust transitivity, consent-first, you author your own edges. The vision and the architecture are one object — build like the values are the spec, because they are.

**Your role:** accelerate the **UI rendering.** The team owns the security-critical logic and **verifies every output you produce.** You render the glass; the team holds the locks.

---

## ⛔ THE HARD BOUNDARY — do NOT touch these (owned + verified by the team)
If a UI needs something from these, **call the existing function — never reimplement, modify, or "improve" it.** If you think you need to cross this line, STOP and flag it in a README instead.
- **Crypto:** `recovery.ts` (Shamir/soul-seed), PSI, the message envelope, all key-derivation. (Audited-sound — do not alter.)
- **Gate-logic / constitution:** the disclosure-reach enforcement, the `visible()` / edge-visibility function, consent-by-inclusion (opted-out data is *un-computable by construction*, never client-side-hidden), plausible-deniability (never leak *why* an edge isn't shown — no fetch-then-hide, no side-channels).
- **Relay / server:** `satellite.py` and any server endpoints. Frontend calls them; frontend does not change them.

### The security invariants you must honor in UI (build against these; don't restate/redefine)
- **I-3 · no-aggregate** — no scores, counts, standings, or rankings on identity.
- **I-4 · reachability-not-location** — show whether someone is reachable, never where they are.
- **I-6 · render-provenance** — every visual property decodes to something **authored or witnessed.** Nothing renders presence / last-seen / online. The living/dim state of a contact comes from the receiver's **LOCAL witnessed-receipt clock**, NEVER a pushed field. The field-firewall refuses presence/location fields *even under a valid signature* — don't try to render them. **Design-layer corollary:** identicons/rosettes/seals derive from identity material — **no decorative randomness on identity surfaces.**
- **I-7 · tamper-evidence** — surfaces reflect verifiable state; don't paper over a failed verification.
- **Invariant-1** — fingerprint ≡ H(public_key).

When in doubt, cite the invariant + ask in a README; don't invent UI that leaks what the law forbids.

**Rule of thumb:** anything that decides *who can see what* or *what a secret is* = team-owned. Anything that *renders* it = yours.

---

## 🎨 Aesthetic — build EVERYTHING to these tokens (Peter-approved: "Solar Ember")
Solar-ember: a glowing golden honeycomb on warm ember. Sacral, luminous, cloaked — solarpunk, not cyberpunk. Living scene you move through, **not** a card+list dashboard.

```css
/* SOLAR EMBER — svrnty's palette */
--bg:            #0f0a06;                        /* warm ember-dark, "solar at dusk" */
--surface:       rgba(30,20,10,.55);
--surface-solid: rgba(28,19,10,.92);
--border:        rgba(255,190,120,.10);
--border-lit:    rgba(255,170,70,.38);
--accent:        #f9a825;                        /* solar gold  */
--accent2:       #ff7a1a;                        /* sacral orange */
--text:          #fbead2;                         /* warm cream */
--muted:         #c9a271;
--dim:           #8f7550;
/* app background */
background: radial-gradient(70% 70% at 50% 42%, rgba(249,168,37,.14), transparent 60%), var(--bg);
```
- **Type:** **Space Grotesk** (400–700). Mono is fine as a secondary voice for keys/fingerprints. **Avoid Orbitron, hard sci-fi display fonts, emoji glyphs** ("1990s game," the opposite of the feel).
- **Effects:** **glass** surfaces (`backdrop-filter: blur(16–24px)` on translucent panels) · **soft glows only** (opacity **0.06–0.25**, never hard neon — luminous, not electric) · **particle-lattice canvas** for graph views (drifting nodes, accent connection-lines drawn when nodes are near, dist < ~130) · radial gradient wash from center for depth.
- **Avoid:** hard neon, heavy drop-shadows, flat solid fills where a glow/glass would breathe.

**⚠️ HARD REQ — the identity rosette/seal must be DETERMINISTIC from the fingerprint** (an identicon, not decoration). Derive the seal's geometry from the person's fingerprint hash so the *same fingerprint always renders the same seal* — a verification aid AND beauty at once. A random/decorative rosette is "a lie in the house style." (I-6 render-provenance, Peter-endorsed.) The generative key-derived seal = a rune-sigil. The social-graph view = an **egocentric** particle-lattice (points-of-light contacts + connection lines) — NOT a card-list, NOT a global/PageRank graph.

**🔒 seal-v1 — the fingerprint→seal generator is VERSION-FROZEN (a recognition aid, NOT proof):** now that people recognize each other by seal, the generator is trust-UX-load-bearing:
- **⚡ RECOMPUTE, NEVER TRANSMIT — this IS the seal's unforgeability, not aesthetics.** The client ALWAYS recomputes the seal from the fingerprint at render-time. NEVER accept, cache, or ship a seal as a wire/card field — the card carries the **fingerprint**; the client draws the seal FROM it. A transmitted seal is paste-forgeable (an attacker puts a victim's seal on their own card); a recomputed seal is key-bound (fingerprint ≡ H(pubkey), Invariant-1). If the seal is ever transmitted instead of recomputed, the entire unforgeability property collapses. Derive it via a **domain-separated hash of the canonical fingerprint** — `seal_seed = H("svrnty/seal/v1" ‖ fingerprint)` — so an attacker can't grind visuals without grinding keys.
- **Pin + version + freeze it as `seal-v1`.** The algorithm, the parameter-derivation from the fingerprint bytes, and the rendering rules are a **wire-freeze-class** artifact — the same fingerprint MUST render the same seal forever. A silent generator change would make everyone's identity *appear* to change (a trust-UX earthquake). Any future evolution is an EXPLICIT versioned event (`seal-v2`), never a drift; old seals keep rendering under seal-v1. (Same law as the PSI fingerprint-serialization freeze.)
- **It's a recognition AID, never a verification primitive.** The visual space is far smaller than the key space → near-collisions exist and an attacker can grind keys toward a lookalike seal. NEVER build UI that treats "the seals look the same" as proof of identity — the fingerprint check-ritual is the verification; the seal only helps someone NOTICE something's off.

---

## 🛡️ I-10a · Render untrusted data SAFELY (XSS guardrail — DEMO-CRITICAL)
Every field on a contact you **imported** — `display_name`, `safeword`, the relay hint / `satellite_url`, contact-method URLs, PQ keys — came from someone ELSE's card. Treat it as **untrusted, hostile-until-sanitized** input. When you render it:
- **URLs / contact links = scheme-allowlist ONLY.** Render as a clickable link only if the scheme is `https:` · `tel:` · `mailto:` · `sms:` · or a known app deep-link (`wa.me` / `signal.me` / `t.me` / `instagram.com` / `facebook.com`). **NEVER render a `javascript:` or `data:` URL as a link** — a poisoned card would become executable code in your app (stored XSS). Unknown/other scheme → render as plain text, not a link.
- **Text fields = escape + bound.** Render through the framework's auto-escaping (**never** `dangerouslySetInnerHTML` / `innerHTML` with card data), enforce a display char-limit, strip control characters.
- **Don't trust length/shape from the wire.** The relay validates too (defense-in-depth), but the UI must sanitize before it renders.
- **Canvas / three.js / SVG text (the particle-lattice graph labels, identity marks) — DOM auto-escaping does NOT reach these sinks.** Canvas text isn't HTML-parsed (code-execution vector is lower there), BUT you must still **bound + strip control chars + NFC-normalize + reject bidi-override / RTL-spoof characters** on any card text drawn into a canvas/SVG label — homoglyph/bidi-override impersonation and overflow work in canvas too. Escaping is a DOM tool; for canvas/SVG use bound+strip+normalize. (Ties I-10a → I-6 identity-mark safety.)

A contact must not be able to inject code or markup into your view by crafting their card. This composes with I-6 render-provenance — I-10a is the *render-it-safely* limb. When in doubt, render as inert text + flag in a README.

---

## ✅ WHAT to build (UI rendering over the EXISTING primitives)
**L8 · Recovery (crypto is DONE — build the UI over it):**
- Set-your-recovery-code UI: strong secret + a live **entropy strength meter** (warn if too simple/common — a famous quote is guessable; guide toward personal/unique). ⚠️ Format = **recovery code** (8 groups of 8 hex chars), NOT "12 words" (BIP39-24 is a follow-on).
- Self-recovery flow: backup file **+** ONE key → restore. **Password** → everything (identity + contacts + trust); OR **recovery code** (if password lost) → identity only. ⚠️ Alternatives, NOT "both required" — password ALONE opens a v4 backup (Flint's matrix; honest model shipped #65). Correcting the earlier "both required" over-claim.
- *[fast-follow]* social collect-back UI (gather shards from keepers). Ships only after a survivor-safety review + team greenlight.

**L8 · The recovery crypto API (team-owned — CALL it, never reimplement):**
> ⛔ **THE GUARDRAIL:** the master key is ALWAYS randomly generated (CSPRNG). The soul-seed phrase only **WRAPS** it — it NEVER derives it. `master = Argon2id(phrase)` is a **brain-wallet** (a guessable phrase → guessable keys → anyone who guesses it becomes the user) — FORBIDDEN. If any path tempts you toward phrase→keys, STOP + flag in a README. (This is exactly the boundary you already respected — keep respecting it.)
>
> **Two creation paths — offer both** (different recovery properties):
>
> | Path | Master | Recovery |
> |---|---|---|
> | **Generated (default)** | random → 12-word BIP39 mnemonic | the mnemonic ENCODES the master → **standalone** ("write it down") |
> | **User-set soul-seed** | random, then phrase-WRAPPED | phrase is a **2nd factor** → needs phrase **+** the backup blob/shares (memorable, NOT standalone) |
>
> **The two calls (both team-owned):**
> - `createKeyVaultWithSoulSeedRecovery(phrase, opts) → KeyVault` — generates a random master and wraps it with the phrase; returns the KeyVault (encrypted keys + wrap + salt + verify-tag). No plaintext key ever leaves.
> - `openKeyVaultWithSoulSeed(vaultBlob, phrase) → bundle | PHRASE_MISMATCH` — the restore mirror. A wrong phrase fails LOUD (verify-tag) → warm "that's not quite it," **no lockout**, let them retry.
>
> **Your UI responsibilities:**
> - The **entropy meter runs BEFORE** the create call — reject/redirect famous/weak phrases (a famous quote is guessable); the API assumes the phrase already passed.
> - Backup (`.svrnty` blob) = encrypted keys + encrypted contacts, **no plaintext keys** → restore ALWAYS needs the soul-seed (or another factor). Say so honestly in the UI.
> - Phrase normalization must be byte-identical at set-time and restore-time — call the team's shared `normalize` fn, never roll your own (a mismatch = permanent lockout).

**L1 · Living contacts:** update-contact-method SEND UI (edit your card → broadcast to who you shared with) + **version-control** (versioned methods; correct/retract an errored update; recipients see the corrected version).

**L2 · Trust graph:** the **TrustMap** render — **egocentric** (you at center, your bonds + who they vouch for), particle-lattice, NEVER global/PageRank · reach-settings UI (private / L1 / L2 + per-group if it ships) · the **"awaken the circle"** global opt-in toggle (composes WITH per-edge reach — global-on never overrides a finer per-edge restriction) · click-node → glyph + contact info.

**L4 · Import/Export:** key + contacts import/export UI; export gated behind pw/biometric.

**L5 · Biometric unlock** *[fast-follow]*: WebAuthn/passkey unlock so no constant pw entry.

**L6 · Groups:** create/name groups + assign contacts (own-device, local — no trust semantics) · *[if per-group ships at launch]* per-group bond-visibility ACL — a **NARROW-ONLY** filter (a group can only RESTRICT who sees a bond within your trusted-mutuals, never widen). This one touches the visibility boundary → build the UI, but the ACL enforcement is team-owned; coordinate.

---

## 🔁 Coordination (via READMEs)
1. For each component, **write/update a README** in that component's folder: what you built, files touched, assumptions, questions.
2. Gate/constitution/visibility questions, crypto/recovery questions, and frontend-integration/deploy questions each have a team reviewer — flag in the README and the right reviewer picks it up.
3. **If unsure whether something crosses the hard boundary → STOP, flag it in the README, don't modify security-critical code.** A blocked component is fine; a silently-modified lock is not.
4. Build to these tokens + the contracts above. When they conflict with a quick shortcut, the contracts win.

Welcome to the Round Table. Render beautifully; we'll hold the locks. 🌱
