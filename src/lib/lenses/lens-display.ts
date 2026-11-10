// src/lib/lenses/lens-display.ts
/**
 * Lenses v1.3 — RECEIVE-side display projection for `contact_info.lens_methods` (review-1 item 5).
 *
 * A lens value is authenticated by a classical pair-MAC only, so it NEVER lands in a primary field
 * and is never shown as simply the contact's own. This projection hands the view, per stored lens
 * method, the row it renders: the given value plus, when the signed path already holds a DIFFERENT
 * value for that slot, the held value — so the view shows the contract's changed-copy ("{name}'s
 * {method} changed… check some other way, not through the new one" + "Was: {old}") instead of
 * trusting the new one. Pure; the component renders what it gets.
 */

import { CONTACT_HANDLE_KEYS } from '../trust/contact-update';
import type { LensMethodWire } from './lens-wire';

/** The minimal contact shape the projection reads — any stored/contact-card model satisfies it. */
export interface LensContactLike {
  email?: unknown;
  emails?: unknown;
  phone?: unknown;
  phones?: unknown;
  contact_info?: unknown;
}

export interface LensDisplayRow {
  /** The lens_methods map key (kind + separator + label). */
  key: string;
  method: LensMethodWire;
  /** The signed-path value held for this slot when it DIFFERS from the lens value; null when the
   *  slot holds nothing or already holds this exact value (then the row is just "gave you this"). */
  heldValue: string | null;
}

function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.length > 0) : [];
}

/**
 * The values the SIGNED path delivered for a method's slot — the "one you hold" the changed-copy
 * compares against. Slot mapping:
 *   email            → contact.email + contact.emails + contact_info.emails
 *   phone            → contact.phone + contact.phones + contact_info.phones
 *   site/url/website → contact_info.urls
 *   a handle kind    → contact_info.handles[kind]
 *   anything else    → no signed home — the value can only ever be "given", never "changed".
 */
export function heldValuesForKind(contact: LensContactLike, kind: string): string[] {
  const ci = typeof contact.contact_info === 'object' && contact.contact_info !== null
    ? (contact.contact_info as Record<string, unknown>)
    : {};
  if (kind === 'email') {
    return [...new Set([contact.email, ...strList(contact.emails), ...strList(ci.emails)].filter((x): x is string => typeof x === 'string' && x.length > 0))];
  }
  if (kind === 'phone') {
    return [...new Set([contact.phone, ...strList(contact.phones), ...strList(ci.phones)].filter((x): x is string => typeof x === 'string' && x.length > 0))];
  }
  if (kind === 'site' || kind === 'url' || kind === 'website') {
    return [...new Set(strList(ci.urls))];
  }
  if (CONTACT_HANDLE_KEYS.has(kind)) {
    const handles = typeof ci.handles === 'object' && ci.handles !== null ? (ci.handles as Record<string, unknown>) : {};
    const v = handles[kind];
    return typeof v === 'string' && v.length > 0 ? [v] : [];
  }
  return [];
}

/** One display row per stored lens method — the view renders these, never the raw map. */
export function lensDisplayRows(contact: LensContactLike): LensDisplayRow[] {
  const ci = typeof contact.contact_info === 'object' && contact.contact_info !== null
    ? (contact.contact_info as Record<string, unknown>)
    : {};
  const map = typeof ci.lens_methods === 'object' && ci.lens_methods !== null
    ? (ci.lens_methods as Record<string, LensMethodWire>)
    : {};
  const rows: LensDisplayRow[] = [];
  for (const [key, m] of Object.entries(map)) {
    if (!m || typeof m.kind !== 'string' || typeof m.value !== 'string') continue;
    const held = heldValuesForKind(contact, m.kind);
    rows.push({ key, method: m, heldValue: held.length > 0 && !held.includes(m.value) ? held[0] : null });
  }
  return rows;
}
