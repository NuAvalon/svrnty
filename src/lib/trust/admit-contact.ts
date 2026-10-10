// src/lib/trust/admit-contact.ts
// INBOUND admission predicate (the "FALSE-MUTUAL gate") — the single chokepoint deciding whether an
// inbound note / trust-affirmation from a sender is ADMITTED (persisted / allowed to flip trust).
//
// Historically admission was `contact != null` (in-book EXISTS). That let a BLOCKED sender's signed
// note/affirmation through (Codex P1 #2): blocking that does not block = the exact harm svrnty exists
// to refuse. Admission now requires in-book AND not-blocked.
//
// INBOUND semantics: `blocked` is the flag on MY record for THEM — a sender I blocked. This is
// admission, NOT authentication: a forged/unsigned/misaddressed blob is still rejected upstream
// (verifyNoteSender / verifyTrustAffirmSender) BEFORE admit; admitContact cannot rescue a forgery and
// a `true` here never authenticates anything.
//
// Pure + structural (no store import) so it wires IDENTICALLY at every isAdmitted site — the human
// live-book-poll note + affirm seams and the headless-client — and works for any contact store shape.
//
// BLOCKED-ness mirrors the canonical isContactBlocked (trust-actions.ts): the flag lives top-level
// `blocked` OR in `metadata.blocked` (device-local), so BOTH must be checked — a contact blocked via
// metadata alone must still be refused (checking only `.blocked` would be a silently-inert fix). It is
// REPLICATED here (not imported) on purpose: isContactBlocked lives in src/components, and src/lib —
// especially the headless client (must stay browser-dependency-free) — must not import a component.
// Param is `unknown` on purpose: it wires at every store without a per-store type — the browser
// ContactRecord (metadata: any) and the HeadlessContact (index signature `[key: string]: unknown`,
// which would reject a specific-shape param) both pass, as do null/undefined (a stranger). Narrowed +
// coerced-by-truthiness internally; a non-object (or null) is NOT admitted.
export function admitContact(contact: unknown): boolean {
  if (contact == null || typeof contact !== 'object') return false;
  const c = contact as { blocked?: unknown; metadata?: unknown };
  const meta = c.metadata != null && typeof c.metadata === 'object'
    ? (c.metadata as { blocked?: unknown })
    : null;
  return !(c.blocked || (meta != null && meta.blocked));
}
