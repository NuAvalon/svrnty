// src/lib/lenses/lens-display.ts
/**
 * Lenses v1.7 — RECEIVE-side display projection for `contact_info.lens_methods`.
 *
 * A lens value is authenticated by a classical pair-MAC only, so it NEVER lands in a primary field
 * and is never shown as simply the contact's own. This projection hands the view, per stored lens
 * method, the row it renders.
 *
 * R6a: a changed value shows as CHANGED for every method, including kinds with no signed home —
 *   the apply path keeps the previous lens value on the entry (`was`) so "Was:" can name it.
 * R6b: "changed" is shown only when the SAME slot (kind+label) held a different value before —
 *   a value under a NEW slot shows as GIVEN beside what is held and never marks an existing value
 *   as replaced. Signed-path values sit in unlabelled slots, so only an UNLABELLED lens value can
 *   ever compare against them. The relabel-swap (a new slot whose kind dropped a held value this
 *   payload did not carry) is marked at apply time with `wasKind` — the changed line then names
 *   the KIND, not the new label.
 * Pure; the component renders what it gets.
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
  /** The value the "Was:" line names when this row is CHANGED; null when the row shows as GIVEN. */
  heldValue: string | null;
  /** R6b: true when the change is a relabel-swap — the changed line names the KIND (the label
   *  changed), not this method's own label. */
  kindChanged: boolean;
}

function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.length > 0) : [];
}

/**
 * The values the SIGNED path delivered for a method's kind — the "one you hold" the changed-copy
 * compares against. Signed values carry no labels: they occupy the kind's UNLABELLED slot, so this
 * list is consulted only for unlabelled lens methods (R6b's same-slot rule). Slot mapping:
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
    ? (ci.lens_methods as Record<string, LensMethodWire & { was?: string; wasKind?: boolean }>)
    : {};
  const rows: LensDisplayRow[] = [];
  for (const [key, m] of Object.entries(map)) {
    if (!m || typeof m.kind !== 'string' || typeof m.value !== 'string') continue;
    if (typeof m.was === 'string') {
      // R6a/R6b: a change the apply path already witnessed — "Was:" names the previous lens value
      // (same slot) or the dropped held value (relabel-swap, kind-named).
      rows.push({ key, method: m, heldValue: m.was, kindChanged: m.wasKind === true });
      continue;
    }
    // R6b same-slot rule: the signed home is an UNLABELLED slot — only an unlabelled lens value
    // may compare against it; a labelled one is a new slot and shows as given.
    const held = m.label === undefined || m.label === '' ? heldValuesForKind(contact, m.kind) : [];
    rows.push({ key, method: m, heldValue: held.length > 0 && !held.includes(m.value) ? held[0] : null, kindChanged: false });
  }
  return rows;
}
