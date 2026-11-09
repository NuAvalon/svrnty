// src/lib/sync/receipt-allowed.test.ts
// Run: npx tsx --test src/lib/sync/receipt-allowed.test.ts
// The SEND-TIME decision for a delivery receipt (task #714 R2a): is the sender still admitted, and does the Delivery setting (per contact over the
// global) allow it NOW. Readers are injected, so this runs without IndexedDB.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { receiptAllowedNow, type ReceiptAllowedIo } from './receipt-allowed';
import type { DeliveryDefaultRead } from '@/lib/trust/delivery-receipt-setting';

const OWNER = 'ab'.repeat(32);
const FP = 'cd'.repeat(32);
const ok = (value: 'on' | 'off' | 'unknown'): DeliveryDefaultRead => ({ state: 'ok', rec: { v: 1, value } });
const io = (contact: unknown, global: DeliveryDefaultRead | Error): ReceiptAllowedIo => ({
  getContact: async () => (contact === 'throw' ? Promise.reject(new Error('contacts locked')) : (contact as never)),
  readGlobal: async () => (global instanceof Error ? Promise.reject(global) : global),
});
// a minimal admitted contact row (the real rule is admitContact: in the book, not blocked)
const admitted = { trust_level: 'known', fingerprint: FP };
const blocked = { trust_level: 'known', fingerprint: FP, blocked: true };

test('A1 an admitted contact with the global On gets a receipt; with the global Off, or unknown, or absent, does not', async () => {
  assert.equal(await receiptAllowedNow(OWNER, FP, io(admitted, ok('on'))), true);
  for (const g of [ok('off'), ok('unknown'), { state: 'absent' } as DeliveryDefaultRead]) assert.equal(await receiptAllowedNow(OWNER, FP, io(admitted, g)), false);
});
test('A2 a per-contact value wins over the global, both ways', async () => {
  assert.equal(await receiptAllowedNow(OWNER, FP, io({ ...admitted, delivery_receipts: 'off' }, ok('on'))), false);
  assert.equal(await receiptAllowedNow(OWNER, FP, io({ ...admitted, delivery_receipts: 'on' }, ok('off'))), true);
});
test('A3 a blocked or missing contact never gets a receipt, whatever the settings say', async () => {
  assert.equal(await receiptAllowedNow(OWNER, FP, io(blocked, ok('on'))), false);
  assert.equal(await receiptAllowedNow(OWNER, FP, io({ ...blocked, delivery_receipts: 'on' }, ok('on'))), false);
  assert.equal(await receiptAllowedNow(OWNER, FP, io(null, ok('on'))), false);
});
test('A4 a reader that THROWS, or an unreadable global, means no send (never a rejection)', async () => {
  assert.equal(await receiptAllowedNow(OWNER, FP, io('throw', ok('on'))), false);
  assert.equal(await receiptAllowedNow(OWNER, FP, io(admitted, new Error('locked'))), false);
  assert.equal(await receiptAllowedNow(OWNER, FP, io({ ...admitted, delivery_receipts: 'on' }, { state: 'unreadable' })), false);
});
test('A5 it asks the global with the OWNER and the contact with the owner and the sender, and reads both each time (nothing cached between calls)', async () => {
  const seen: string[] = [];
  const probe: ReceiptAllowedIo = {
    getContact: async (o, f) => { seen.push(`contact:${o}:${f}`); return admitted as never; },
    readGlobal: async (o) => { seen.push(`global:${o}`); return ok('on'); },
  };
  await receiptAllowedNow(OWNER, FP, probe);
  await receiptAllowedNow(OWNER, FP, probe);
  assert.deepEqual(seen, [`contact:${OWNER}:${FP}`, `global:${OWNER}`, `contact:${OWNER}:${FP}`, `global:${OWNER}`]);
});
