// src/lib/contacts/method-send-delta.ts
// Method-grow #125128 — the SEND-side delta builder: map ONE revised contact method (kind, value)
// onto the contact.update `delta` the owner signs + sends (Flint's sendContactUpdate). Lives here (not
// in the crypto) because it is UI-shaped: the dialog revises one method and we translate that edit into
// the wire delta. Flint's boundary (#125143): "buildDelta stays in the dialog — it needs the card."
//
// TWO delta shapes, matching the apply-side (apply-contact-update.ts FIELD_MAP):
//   • MERGE fields — the messaging-app handles map. A revise carries ONLY the changed sub-key so apply
//     merges it in without wiping the others (data-loss guard, Flint #125132). Clearing a handle sends
//     the EMPTY STRING '' as the delete sentinel — NOT null (canonicalize forbids null in the signed
//     form, so a null could never be signed; Flint #125153).
//   • REPLACE fields — email / phone / website(url) are flat lists the send-UI always sends whole.
//
// The curated handle-key set is the SHARED CONTACT_HANDLE_KEYS (single source with verify + apply —
// no drift): a kind IN that set routes to `handles`, everything else to its list field.

import { CONTACT_HANDLE_KEYS } from '../trust/contact-update';

/** The delta a single method revise produces — one allowlisted field, shaped for apply's FIELD_MAP. */
export type MethodDelta = Record<string, unknown>;

/**
 * Build the contact.update delta for revising one method to `value`.
 *
 * @param kind  a MethodKind — a handle-key (signal/whatsapp/telegram/discord/matrix/instagram/facebook)
 *              routes to the `handles` MERGE map; email/phone/site route to their REPLACE list.
 * @param value the new value; an EMPTY string clears the method — for a handle that is the '' delete
 *              sentinel (apply deletes the key); for a list field it is an empty list.
 * @throws on an unknown kind (fail loud — never silently produce an empty/mis-shaped delta).
 */
export function buildMethodDelta(kind: string, value: string): MethodDelta {
  const v = value.trim();

  // Handle-kinds MERGE into `handles` — carry ONLY the changed sub-key. Empty ⇒ '' delete sentinel.
  if (CONTACT_HANDLE_KEYS.has(kind)) {
    return { handles: { [kind]: v } };
  }

  // List fields REPLACE — a bounded flat list, sent whole. Empty value ⇒ empty list (clears the field).
  switch (kind) {
    case 'email':
      return { emails: v ? [v] : [] };
    case 'phone':
      return { phones: v ? [v] : [] };
    case 'site': // 'site' is the existing MethodKind name for the website URL
    case 'website':
      return { urls: v ? [v] : [] };
    default:
      throw new Error(`buildMethodDelta: unknown method kind '${kind}'`);
  }
}
