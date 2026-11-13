// What the Delivery UI may do, in one place, so the glass has no rules of its own.
// The record and the per-contact field are R2a's (client-store.ts); the send-time rule is delivery-receipt-setting.ts. Nothing here decides a send.
//
// The panel state comes from readDeliveryDefaultMigrating (the same read a send uses), so opening Settings before the first send still gets an upgrade
// flagged `notice_pending` or a restore marked 'unknown'. An unreadable record is shown as unreadable and offers no switch: a write would be a guess.

import type { DeliveryDefaultRead, DeliveryValue } from '@/lib/trust/delivery-receipt-setting';

export type DeliveryPanel =
  | { kind: 'unreadable' }
  | { kind: 'ask' } // restored: the owner is asked once, no receipts until answered
  | { kind: 'choice'; value: DeliveryValue; notice: boolean };

export interface DeliveryIO {
  read(owner: string): Promise<DeliveryDefaultRead>;
  write(owner: string, rec: { v: 1; value: DeliveryValue }): Promise<void>;
}

export function panelFromRead(r: DeliveryDefaultRead): DeliveryPanel {
  if (r.state !== 'ok') return { kind: 'unreadable' }; // 'absent' cannot survive the migrating read; if it does, say nothing is known
  if (r.rec.value === 'unknown') return { kind: 'ask' };
  return { kind: 'choice', value: r.rec.value, notice: r.rec.notice_pending === true };
}

export async function loadDeliveryPanel(io: DeliveryIO, owner: string): Promise<DeliveryPanel> {
  return panelFromRead(await io.read(owner));
}

/** The owner's own choice (the Settings switch, or Yes/No on the restore ask). Writing a value also ends any pending notice. */
export async function chooseDelivery(io: DeliveryIO, owner: string, value: DeliveryValue): Promise<DeliveryPanel> {
  await io.write(owner, { v: 1, value });
  return loadDeliveryPanel(io, owner);
}

/** Seen the one-time notice: keep the value, clear the flag. Does nothing unless a real value with a pending notice is there. */
export async function dismissDeliveryNotice(io: DeliveryIO, owner: string): Promise<DeliveryPanel> {
  const r = await io.read(owner);
  if (r.state === 'ok' && r.rec.value !== 'unknown' && r.rec.notice_pending) {
    await io.write(owner, { v: 1, value: r.rec.value });
  }
  return loadDeliveryPanel(io, owner);
}

/** Per-contact choice: 'on' | 'off' set it, 'follow' removes it so the contact follows the global setting. */
export type ContactDeliveryChoice = DeliveryValue | 'follow';

// `held` is the record the write is applied to (updateContact hands it to the updater): the choice does not depend on it, but the write is shaped
// like every other one in ContactManagement (a patch built from the held record, never from the screen's copy; see contact-update-fresh-read.test.ts).
export function contactDeliveryPatch(_held: unknown, choice: ContactDeliveryChoice): { delivery_receipts: DeliveryValue | undefined } {
  return { delivery_receipts: choice === 'follow' ? undefined : choice };
}

/** What the contact row holds, as the three choices (anything but exactly 'on' or 'off' is 'follow', as the send-time rule reads it). */
export function contactDeliveryChoice(stored: unknown): ContactDeliveryChoice {
  return stored === 'on' || stored === 'off' ? stored : 'follow';
}
