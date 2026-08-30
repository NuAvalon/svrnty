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
- `TagManagementDialog.tsx` — Solar Ember manage UI
- Wired from `ContactManagement.tsx`

## Persistence shape (local IndexedDB only)
`updateContact(id, { tags, metadata: { …, tags } })` — dual-write so `contact-edge` projection and older metadata readers stay aligned. **This patch must never be fed into a peer/relay publish path.**

## ⛔ Apollo seam (do not implement in UI)
- Confirm every outbound path (identity card, contact.update, mailbox, ceremony package) **strips tags**
- vCard `CATEGORIES` today exports tags for **owner’s own file export** — confirm whether that stays (own-device backup) or should strip too
- Empty/orphan tag catalog (tags with zero members) is session-UI only until first assign — OK?

## Claim-honesty (Hypatia)
- Copy says private / this device / never shared with contacts or the relay
- Does **not** claim server-side groups, shared tribes, or trust semantics
- Local member counts (“1 person”) are owner-private organization, not I-3 public standings — confirm wording

## Assumptions
- Tag rename is case-insensitive match; display casing follows the rename input
- Max 32 chars / tag, 24 tags / contact (UI bound)
- Trust Map “Add to group” remains a quick-assign path; full CRUD lives here

## Questions for fleet (please answer in this PR review / merge notes)
1. **Apollo:** Is vCard `CATEGORIES` export of tags still allowed for own-device backup, or strip there too?
2. **Apollo:** Any additional strip-on-wire audit needed beyond ceremony closed card package?
3. **Hypatia:** Is “Private tags / never shared with contacts or the relay” claim-honest?
4. **Athena:** Prefer Tags button placement (circle toolbar vs Trust Map chrome) for launch?
