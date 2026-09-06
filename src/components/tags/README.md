# Tags — CUR-8 L6 tag-management UI

**Brief:** `CURSOR_QUEUE.md` CUR-8 · Aesthetic: Solar Ember  
**Hard boundary:** tags are **owner-authored, local-only** private labels. Never implement strip-on-wire here — call fleet publish APIs that already strip; do not invent a wire format that carries tags.

## What shipped (UI glass)
- **Private tags** dialog on Your circle (`ContactManagement` → Tags)
- Create / rename / remove tags; assign / unassign contacts
- Contact detail shows private tags with honesty line (“On this device only — never shared.”)
- Trust Map already clusters by owner-authored tags (`onAssignGroup`) — unchanged; this dialog is the full manage surface

## Files
- `local-tags.ts` — pure helpers (normalize / assign / rename / remove / catalog / persist patch)
- `local-tags.test.ts` — unit tests
- `strip-on-wire.test.ts` — Apollo §2 / KB#87571 **negative** tests (publish / PSI / export)
- `TagManagementDialog.tsx` — Solar Ember manage UI
- Wired from `ContactManagement.tsx`
- `src/lib/contacts/vcard.ts` — book export **stops** emitting `CATEGORIES` from tags

## Persistence shape (local IndexedDB only)
`updateContact(id, { tags, metadata: { …, tags } })` — dual-write so `contact-edge` projection and older metadata readers stay aligned. **This patch must never be fed into a peer/relay publish path.**

## Strip-on-wire (asserted — do not weaken)
Negative tests cover:
1. **Export** — `toVCard` / `toVCardFile` never emit `CATEGORIES`, tag labels, or `blocked`
2. **Publish** — `identityCardSigningInput` drops smuggled `tags`/`blocked` (IdentityCard allowlist)
3. **PSI** — sync input is fingerprint strings only; blinded body never echoes tag labels
4. **Local persist** — `tagPersistPatch` stays IndexedDB-shaped (not an IdentityCard)

Overlaps gap VCF PR (#77) on the book-export strip — same Apollo invariant.

## ⛔ Apollo seam (fleet still owns)
- contact.update / mailbox / any additional outbound path beyond identity-card + PSI + vCard
- Empty/orphan tag catalog (tags with zero members) is session-UI only until first assign — OK?

## Claim-honesty (Hypatia)
- Copy says private / this device / never shared with contacts or the relay
- Does **not** claim server-side groups, shared tribes, or trust semantics
- Local member counts (“1 person”) are owner-private organization, not I-3 public standings — confirm wording

## Assumptions
- Tag rename is case-insensitive match; display casing follows the rename input
- Max 32 chars / tag, 24 tags / contact (UI bound)
- Trust Map “Add to group” remains a quick-assign path; full CRUD lives here

## Questions for fleet (please answer in the PR description / merge notes — not as review comments)
1. **Apollo:** Confirm vCard strip (no CATEGORIES) is correct for own-device book export too (gap-freeze says yes — please sign).
2. **Apollo:** Any additional strip-on-wire audit needed beyond identity-card + PSI fps + vCard (e.g. contact.update delta allowlist)?
3. **Hypatia:** Is “Private tags / never shared with contacts or the relay” claim-honest?
4. **Athena:** Prefer Tags button placement (circle toolbar vs Trust Map chrome) for launch?
