# Living Address Book + Social Graph (UI pass)

## What changed
- **Share identity** lives on the **Identity** card (not Contacts). E2E: `e2e/share-qr.spec.ts` opens via Identity tab + `share-identity-from-card`.
- **Contacts** is the **Living Address Book** — flat list, **no living/resting pulse** chrome. (Name = the book; not I-6 freshness.)
- Filters: **All** (default) · **Classical** · **SVRNTY** (Known / Trusted). Blocked is under **⋯** — not a primary tab.
- Rows keep `data-testid="contact-row"` + `data-live="push"` on live-apply (demo-arc beat-4 hinge). Living/resting chrome stays retired.
- Contact card: Reach / Card tabs + **Actions** menu (trust, edit, invite / link to SVRNTY, give a piece, block, remove).
- **Bring a classical contact onto SVRNTY:**
  - **Invite to SVRNTY** (Reach tab + Actions) — sends *your* signed card (same share link). ★ Fleet: joining from that invite should attach to *this* row. Glass cannot bind that yet.
  - **Link to SVRNTY** (Reach tab + Actions) — paste their fingerprint + public key once you have them. They leave Classical, land SVRNTY as pending. Classical numbers stay as additional information.
- **Groups** button (book + Social Graph) opens a quiet panel to filter / select / rename / remove local tags — not a primary tab.
- **Select multiple** works on every scope. Bulk Trust / Revoke apply to SVRNTY rows in the selection; Block / Delete / **Add to group** apply to all selected.
- Top tab label: **Trust Map → Social Graph** (same `TrustMap` component + CUR-5 actions).
- Social Graph: canvas **galaxy** (lamp a person → constellation of groups you named + fleet-disclosed circle). Trust is glow. Search + camera zoom. Ember filaments = open-visibility peer trust (Peter’s spec), never inferred from tags.
- Classical contacts: **Add field** (phone, address, org, title, birthday, custom…) and re-export as a clean vCard.
- **vCard export** is a **phone book**: Contacts → More → **Export all as vCard (phone book)** — name, emails, phones, urls, org/title/address, notes, handles. **Stripped:** trust, fingerprint, public key, owner-local group tags, they_trust, share settings. JSON export is the full local dump (auth-gated) — not the phone-book path. E2E: wait for sample seed to finish (`Refresh demo circle`) before asserting classical rows — sequential IndexedDB writes can race a mid-seed Contacts mount.
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
1. **Invite → join should link this classical row** — Peter: when they join from *your* invite, that person should become this contact (keyed), not a second gray. Glass only sends the signed share short-link today; no join correlation. Wire/consent model (pending joiner, reach ACL, one-shot reply envelope)?
2. **Introduce / resync / privacy bulk actions** — UI stubs list them; confirm which are local-only vs relay-auth (Flint) before wiring.
3. **Groups on classical vs SVRN** — confirm tags stay owner-local + stripped on wire (Apollo) when assigning from multi-select. vCard export now strips tags (negative test).
4. **Hypatia** — claim-honesty pass on “Living Address Book” / “Classical” / “SVRNTY” / “Pending” / “What you share” / invite-join wording.
5. **Living/dim freshness** — living/resting pulse chrome stays retired. “Living Address Book” is the Contacts surface name, not I-6 last-seen. Confirm Social Graph stays reachability-not-presence.
6. **PSI peer↔peer mutual** — glass now draws witnessed chords from `they_trust` under Peter’s predicate (reciprocal + open vis both ways). Confirm Apollo PSI payload shape + `visible()` gate so live (non-demo) books stay fail-closed.
7. **Share / visibility toggles** — local intent is on the card; which fields map to fleet reach/disclosure wire (CUR-10), and which stay owner-local forever?
8. **Pending lifecycle** — what flips pending → active (reciprocal card, PSI sync, explicit accept)? Should pending live under SVRNTY, Classical, or a holding area?
9. **Owner lenses / extra card methods** — glass stores named faces (method subset + preferred) on-device. Signed identity-exchange envelope still only carries name + keys + email. Fleet: when can a lens ride the living card without becoming a second identity?

## Boundary
No crypto / `visible()` / relay changes. Invite payload = existing signed card → `createRelay` URL.
Groups remain owner-local private tags (never a server roster). Browse hulls are owner groups. Galaxy ember filaments are open-visibility peer trust only when `they_trust` is witnessed — never inferred from tags.
Link-to-SVRNTY stores fp+key locally and marks pending; reciprocal confirmation is fleet-owned.
vCard export is phone-book fields only (tags/fingerprint/trust stripped).

