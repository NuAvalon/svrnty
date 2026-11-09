// src/lib/trust/delivery-receipt-setting.ts
//
// The Delivery receipt setting: whether this device tells a sender that their note arrived (and so, roughly, when we were online).
//   global default  = a sealed per-owner record (client-store.ts: `delivery_receipts:<owner>`), values on | off | unknown
//   per contact     = ContactRecord.delivery_receipts, 'on' | 'off', absent = follow the global
// Read AT SEND, never at accept: turning it off between the two must stop the receipt. Off means nothing leaves; it never means "later".
// Pure: no storage, no clock. The record itself is read and written in client-store.ts.
//
// Fail-closed: an unreadable record is not a choice, so nothing is sent. An ABSENT record is migrated before it is read (client-store.ts), so by
// the time a send asks it is either a real value or 'unknown' (a restore: the owner is asked once, and no receipts go out until they answer).

export type DeliveryValue = 'on' | 'off';
export type DeliveryDefaultValue = DeliveryValue | 'unknown';
export interface DeliveryDefault {
  v: 1;
  value: DeliveryDefaultValue;
  /** Set when the app switched this on for an existing user: the owner is told once, then it is cleared. */
  notice_pending?: boolean;
}
export type DeliveryDefaultRead =
  | { state: 'ok'; rec: DeliveryDefault }
  | { state: 'absent' }
  | { state: 'unreadable' };

const VALUES: ReadonlySet<unknown> = new Set(['on', 'off', 'unknown']);

/** Exact shape or nothing: any other value (wrong version, a value outside the three, a non-boolean notice flag, extra types) is unreadable. */
export function parseDeliveryDefault(raw: unknown): DeliveryDefaultRead {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return { state: 'unreadable' };
  const r = raw as Record<string, unknown>;
  if (r.v !== 1 || !VALUES.has(r.value)) return { state: 'unreadable' };
  if ('notice_pending' in r && typeof r.notice_pending !== 'boolean') return { state: 'unreadable' };
  const rec: DeliveryDefault = { v: 1, value: r.value as DeliveryDefaultValue };
  if (r.notice_pending === true) rec.notice_pending = true;
  return { state: 'ok', rec };
}

/** The one rule. `perContact` is whatever the contact row holds (anything but exactly 'on' or 'off' is ignored). */
export function mayEmitReceipt(i: { admitted: boolean; perContact: unknown; global: DeliveryDefaultRead }): boolean {
  if (!i.admitted) return false;
  if (i.global.state === 'unreadable') return false; // an unreadable record is not a choice
  if (i.perContact === 'off') return false;
  if (i.perContact === 'on') return true; // a per-contact choice wins over the global
  return i.global.state === 'ok' && i.global.rec.value === 'on';
}

/** What an UNTRUSTED source (a plaintext backup file) may set: only a tightening. Anything else is dropped. */
export function restrictOnly(v: unknown): DeliveryValue | undefined {
  return v === 'off' ? 'off' : undefined;
}
