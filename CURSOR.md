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

---

## ✅ WHAT to build (UI rendering over the EXISTING primitives)
**L8 · Recovery (crypto is DONE — build the UI over it):**
- Set-your-soul-seed-phrase UI: 12+ words, a live **entropy strength meter** (warn if too simple/common — a famous quote is guessable; guide toward personal/unique). The phrase is ALWAYS a 2nd factor.
- Self-recovery flow: local backup file **+** phrase (both required) → restore.
- *[fast-follow]* social collect-back UI (gather shards from keepers). Ships only after a survivor-safety review + team greenlight.

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
