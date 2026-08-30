# Master Address Book + Social Graph (UI pass)

## What changed
- **Share identity** lives on the **Identity** card (not Contacts).
- **Contacts** is the **Master Address Book** — flat list, **no living/resting** chrome.
- Filters: All · Classical (VCF/keyless) · **SVRN contacts** (Known / Trusted) + multi-select actions.
- **Select multiple** works on every scope (not only SVRN). Bulk Trust / Revoke apply to SVRN rows in the selection; Block / Delete / **Add to group** apply to all selected.
- **Groups** = owner-local private tags (`metadata.tags`), same model as Social Graph — inline label + reuse chips; tags render on list rows. Never published (strip-on-wire).
- Classical contacts: editable; **SVRN network contacts: edit locked** (key-bound).
- Detail: Call / Text / WhatsApp / Signal / Email chips (CUR-3 allowlist) + **Invite to SVRNTY** (link or QR).
- Top tab label: **Trust Map → Social Graph** (same `TrustMap` component + CUR-5 actions).

## ★ Team asks (need fleet answers — not review comments)
1. **Invite → response special setting** — Peter asked for invites that allow a response with a special setting. What is the wire/consent model (pending joiner, reach ACL, one-shot reply envelope)? Cursor only ships send chrome + reuse of signed share short-link until this exists.
2. **Introduce / resync / privacy bulk actions** — UI stubs list them; confirm which are local-only vs relay-auth (Flint) before wiring.
3. **Groups on classical vs SVRN** — confirm tags stay owner-local + stripped on wire (Apollo) when assigning from multi-select.
4. **Hypatia** — claim-honesty pass on “Master Address Book” / “Classical” / “SVRN contacts” wording.
5. **Living book** — intentionally removed from Contacts; should Social Graph keep any living/dim freshness, or is that retired?

## Boundary
No crypto / `visible()` / relay changes. Invite payload = existing signed card → `createRelay` URL.
