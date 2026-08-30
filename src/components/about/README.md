# About page (CUR-11)

**Queue:** `CURSOR_QUEUE.md` CUR-11 · **Seam:** copy source (Hypatia) → Cursor renders · **Pure UI**

## What we built
In-app About surface at `/about`, linked from the home header.

| File | Role |
|------|------|
| `src/components/about/copy.ts` | All user-facing strings (swap here when Hypatia source lands) |
| `src/components/about/AboutPage.tsx` | Solar Ember layout — brand-first, glass sections, reduced-motion |
| `app/about/page.tsx` | Next.js route + metadata |
| `app/page.tsx` | Header "About" link |

## Assumptions
1. **Hypatia copy was not in the repo** when this shipped. Provisional copy under-claims from README / CURSOR.md constitution language and shows a dashed banner until Hypatia replaces `ABOUT_COPY` (set `provisionalBanner: null` when final).
2. Route is public (`/about`) — no identity required. Safe for locked / gate states.
3. No crypto, gate, or relay claims beyond what constitution + shipped README already say. PQ / recovery specifics intentionally omitted (under-claim > over-claim).
4. "None inferred" / binary trust / no-aggregate wording mirrors constitution axes already on Trust Map — still needs Hypatia claim-honesty pass.

## Questions for the team (also in the PR body)
1. **Hypatia:** Where is the canonical about-page copy source? Drop a file path / paste final strings — we will swap `copy.ts` and remove the provisional banner.
2. **Hypatia:** Keep / drop / rewrite the "Held as law" principles block?
3. **Hypatia:** Tiny Landlords manifesto (#56) — link from About once merged, or keep About shorter?
4. **Athena:** Header link placement OK, or also footer / HelpGuide step?
5. **Archie:** Any constitution line we under- or over-stated?
