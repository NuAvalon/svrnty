// src/lib/sync/receipt-allowed.ts
//
// The decision a queued delivery receipt asks AT THE MOMENT IT WOULD LEAVE (task #714 R2a, spec G2 + G3): is the sender still admitted (in the
// book, not blocked), and does the Delivery setting allow it now. The contact row and the global default are both read here, every time:
// nothing is carried over from the accept, so a block or an Off that lands in between stops the receipt. A reader that throws means NO.
import { admitContact } from '@/lib/trust/admit-contact';
import { mayEmitReceipt, type DeliveryDefaultRead } from '@/lib/trust/delivery-receipt-setting';

export interface ReceiptAllowedIo {
  getContact: (ownerFingerprint: string, senderFingerprint: string) => Promise<{ delivery_receipts?: unknown } | null | undefined>;
  readGlobal: (ownerFingerprint: string) => Promise<DeliveryDefaultRead>;
}

/** Production readers: the encrypted book and the sealed per-owner record (an absent record is migrated to 'on' once, see client-store.ts). */
async function realIo(): Promise<ReceiptAllowedIo> {
  const { getContactByFingerprint, readDeliveryDefaultMigrating } = await import('@/lib/identity/client-store');
  return { getContact: (o, f) => getContactByFingerprint(o, f) as never, readGlobal: readDeliveryDefaultMigrating };
}

export async function receiptAllowedNow(ownerFingerprint: string, senderFingerprint: string, io?: ReceiptAllowedIo): Promise<boolean> {
  try {
    const r = io ?? (await realIo());
    const contact = await r.getContact(ownerFingerprint, senderFingerprint);
    const global = await r.readGlobal(ownerFingerprint);
    return mayEmitReceipt({ admitted: admitContact(contact), perContact: contact?.delivery_receipts, global });
  } catch {
    return false; // can't tell => don't send
  }
}
