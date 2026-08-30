# Master Address Book + Social Graph (UI pass)

## What changed
- **Share identity** lives on the **Identity** card (not Contacts).
- **Contacts** is the **Master Address Book** — flat list, **no living/resting** chrome.
- Filters: **Classical** · **SVRNTY** (Known / Trusted). Blocked is under **⋯** — not a primary tab.
- Contact card: Reach / Card tabs + **Actions** menu (trust, edit, give a piece, block, remove).
- **Groups** button (book + Social Graph) opens a quiet panel to filter / select / rename / remove local tags — not a primary tab.
- **Select multiple** works on every scope. Bulk Trust / Revoke apply to SVRNTY rows in the selection; Block / Delete / **Add to group** apply to all selected.
- Top tab label: **Trust Map → Social Graph** (same `TrustMap` component + CUR-5 actions).
- Social Graph: **Lattice** (egocentric particle field + trust glow overlay) + **Browse** (organic group neighborhoods); camera zoom/pan/pinch; **Select** + floating bar; **fullscreen**.
- Sample circle (~20 peers): denser PSI-mutual (reciprocal with you) + overlapping owner groups so Orbit/Browse read as a web — still no inferred peer↔peer trust edges.
- **My card as they see it** for a peer/group (disclosure preview — not a send receipt).
- Revise contact method: notify **Trusted** or a **local group** chip.

### Classical vs SVRNTY (this pass)
- **Classical:** edit name / email / phones / urls / handles / notes. **No trust / revoke.** Invite or **Link to SVRNTY** (paste living fp+key) → leaves Classical, lands SVRNTY as **pending**.
- **SVRNTY:** profile edit locked. Can **trust / untrust**, toggle local **share/visibility** intent, assign **groups**. **Pending** = they have not added you yet (no pulse). Classical channels kept as **additional information** on the card after link.
- **Peer↔peer mutual trust** (two people you trust who trust each other under open visibility) — UI will render fleet PSI results when present; **never invents** peer edges. See team asks.
- **Account menu** (header): Lock / log out, switch identity, passphrase-gated **Delete local copy**.

## ★ Team asks (need fleet answers — not review comments)
1. **Invite → response special setting** — Peter asked for invites that allow a response with a special setting. What is the wire/consent model (pending joiner, reach ACL, one-shot reply envelope)? Cursor only ships send chrome + reuse of signed share short-link until this exists.
2. **Introduce / resync / privacy bulk actions** — UI stubs list them; confirm which are local-only vs relay-auth (Flint) before wiring.
3. **Groups on classical vs SVRN** — confirm tags stay owner-local + stripped on wire (Apollo) when assigning from multi-select.
4. **Hypatia** — claim-honesty pass on “Master Address Book” / “Classical” / “SVRN contacts” / “Pending” / “What you share” wording.
5. **Living book** — intentionally removed from Contacts; should Social Graph keep any living/dim freshness, or is that retired?
6. **PSI peer↔peer mutual** — when two trusted contacts trust each other and all have open visibility, glass should show that mutual. Confirm Apollo PSI payload shape + `visible()` gate so UI stays fail-closed (no inferred bonds).
7. **Share / visibility toggles** — local intent is on the card; which fields map to fleet reach/disclosure wire (CUR-10), and which stay owner-local forever?
8. **Pending lifecycle** — what flips pending → active (reciprocal card, PSI sync, explicit accept)? Should pending live under SVRNTY, Classical, or a holding area?

## Boundary
No crypto / `visible()` / relay changes. Invite payload = existing signed card → `createRelay` URL.
Groups remain owner-local private tags (never a server roster). Browse shows witnessed trust/mutual on YOUR edges only — no inferred peer↔peer bonds.
Link-to-SVRNTY stores fp+key locally and marks pending; reciprocal confirmation is fleet-owned.
