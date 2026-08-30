# Contact method deep-links (CUR-3 · L1g)

**Queue:** `CURSOR_QUEUE.md` CUR-3 · **Seam:** PURE frontend (no crypto) · **Invariant:** I-10a render-safety

## What we built
Tap-to-open contact methods on the living book detail sheet and Trust Map focus sheet.

| File | Role |
|------|------|
| `src/lib/contacts/safe-contact-link.ts` | Scheme-allowlist resolver (`https`/`tel`/`mailto`/`sms` + app hosts). Never returns `javascript:`/`data:`. |
| `src/lib/contacts/safe-contact-link.test.ts` | I-10a floor tests |
| `src/components/contacts/ContactMethodLink.tsx` | Renders `<a>` only when href is allowlisted; otherwise inert text |
| `ContactManagement.tsx` / `TrustMap.tsx` | Wire-up |

## Allowlist (CURSOR.md I-10a)
- Schemes: `https:` · `tel:` · `mailto:` · `sms:`
- App hosts: `wa.me` · `signal.me` · `t.me` · `instagram.com` · `facebook.com` (+ common www/m aliases)
- Handles: `signal` / `telegram` / `whatsapp` / `instagram` / `facebook` / `email_alt` → deep-link; unknown platform → plain text

## Assumptions
1. Phone display keeps the authored formatting; `tel:` href uses digits only.
2. Signal usernames use `signal.me/#eu/…`; phone-shaped handles use `#p/+E164`.
3. Personal `https` URLs (any host) are allowlisted by scheme — matching CURSOR ("https … or a known app deep-link").

## Questions for the team
1. **Hypatia / Archie:** Is any-https-host correct for personal profile URLs, or should personal sites be host-allowlisted too?
2. **Athena:** Should the same helper also wrap the identity-card "your methods" row (owner-authored — lower XSS risk, still nice UX)?
3. **Flint:** When `urls` grows onto the contact.update allowlist, confirm receivers keep running this gate at render (defence-in-depth; UI already does).
