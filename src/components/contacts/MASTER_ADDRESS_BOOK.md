# Master Address Book + Social Graph (UI pass)

## What changed
- **Share identity** lives on the **Identity** card (not Contacts). E2E: `e2e/share-qr.spec.ts` opens via Identity tab + `share-identity-from-card`.
- **Contacts** is the **Master Address Book** — flat list, **no living/resting** chrome.
- Filters: **All** (default) · **Classical** · **SVRNTY** (Known / Trusted). Blocked is under **⋯** — not a primary tab.
- Rows keep `data-testid="contact-row"` + `data-live="push"` on live-apply (demo-arc beat-4 hinge). Living/resting chrome stays retired.
- Contact card: Reach / Card tabs + **Actions** menu (trust, edit, give a piece, block, remove).
- **Groups** button (book + Social Graph) opens a quiet panel to filter / select / rename / remove local tags — not a primary tab.
- **Select multiple** works on every scope. Bulk Trust / Revoke apply to SVRNTY rows in the selection; Block / Delete / **Add to group** apply to all selected.
- Top tab label: **Trust Map → Social Graph** (same `TrustMap` component + CUR-5 actions).
- Social Graph: canvas **galaxy** (lamp a person → constellation of groups you named + fleet-disclosed circle). Trust is glow. Search + camera zoom. Ember filaments = open-visibility peer trust (Peter’s spec), never inferred from tags.
- Classical contacts: **Add field** (phone, address, org, title, birthday, custom…) and re-export as a clean vCard.
- Sample circle (~20 peers, revision 5): **10 living SVRNTY** (Ada, Grace, … frozen public keys, fingerprint ≡ H(key)) + **10 classical** (Lynn, Tesla, Hypatia, … keyless — **no fingerprint**). Glow vs hollow on the graph. Open-visibility clique (`they_trust` stand-in) so Ada↔Grace filaments appear — still no inferred bonds from co-membership.
- **Your identity card:** add fields (phone, Instagram, …) and **lenses** (Business vs Festival) with a preferred channel. Same QR/link is still you; extra methods are local intent until the living card schema carries them.
- **My card as they see it** for a peer/group (disclosure preview — not a send receipt).
- Revise contact method: notify **Trusted** or a **local group** chip.

### Classical vs SVRNTY (this pass)
- **Classical contacts do not have fingerprints.** Fingerprint ≡ H(public_key) (Invariant-1). A keyless vCard has no commitment to hash. The card says so; the graph draws a hollow node, never a seal from a fake hex string.
- **Classical:** edit name / email / phones / urls / handles / notes. **No trust / revoke.** Invite or **Link to SVRNTY** (paste living fp+key) → leaves Classical, lands SVRNTY as **pending**.
- **SVRNTY:** profile edit locked. Can **trust / untrust**, toggle local **share/visibility** intent, assign **groups**. **Pending** = they have not added you yet (no pulse). Classical channels kept as **additional information** on the card after link.
- **Peer↔peer mutual trust** (two people you trust who trust each other under open visibility) — UI renders fleet PSI `they_trust` when the open-visibility predicate holds; **never invents** from tags. See team asks.
- **Account menu** (header): Lock / log out, switch identity, passphrase-gated **Delete local copy**.

## ★ Team asks (need fleet answers — not review comments)
1. **Invite → response special setting** — Peter asked for invites that allow a response with a special setting. What is the wire/consent model (pending joiner, reach ACL, one-shot reply envelope)? Cursor only ships send chrome + reuse of signed share short-link until this exists.
2. **Introduce / resync / privacy bulk actions** — UI stubs list them; confirm which are local-only vs relay-auth (Flint) before wiring.
3. **Groups on classical vs SVRN** — confirm tags stay owner-local + stripped on wire (Apollo) when assigning from multi-select.
4. **Hypatia** — claim-honesty pass on “Master Address Book” / “Classical” / “SVRN contacts” / “Pending” / “What you share” wording.
5. **Living book** — intentionally removed from Contacts; should Social Graph keep any living/dim freshness, or is that retired?
6. **PSI peer↔peer mutual** — glass now draws witnessed chords from `they_trust` under Peter’s predicate (reciprocal + open vis both ways). Confirm Apollo PSI payload shape + `visible()` gate so live (non-demo) books stay fail-closed.
7. **Share / visibility toggles** — local intent is on the card; which fields map to fleet reach/disclosure wire (CUR-10), and which stay owner-local forever?
8. **Pending lifecycle** — what flips pending → active (reciprocal card, PSI sync, explicit accept)? Should pending live under SVRNTY, Classical, or a holding area?
9. **Owner lenses / extra card methods** — glass stores named faces (method subset + preferred) on-device. Signed identity-exchange envelope still only carries name + keys + email. Fleet: when can a lens ride the living card without becoming a second identity?

## Boundary
No crypto / `visible()` / relay changes. Invite payload = existing signed card → `createRelay` URL.
Groups remain owner-local private tags (never a server roster). Browse hulls are owner groups. Galaxy ember filaments are open-visibility peer trust only when `they_trust` is witnessed — never inferred from tags.
Link-to-SVRNTY stores fp+key locally and marks pending; reciprocal confirmation is fleet-owned.
