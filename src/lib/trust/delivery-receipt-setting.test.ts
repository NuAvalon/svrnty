// src/lib/trust/delivery-receipt-setting.test.ts
// Run: npx tsx --test src/lib/trust/delivery-receipt-setting.test.ts
// The Delivery receipt setting (task #714 R2a): one global default (a sealed per-owner record) and an optional per-contact override.
// Pure decision + record parsing; the storage itself is in client-store.ts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mayEmitReceipt, parseDeliveryDefault, restrictOnly, type DeliveryDefaultRead } from './delivery-receipt-setting';

const ok = (value: 'on' | 'off' | 'unknown'): DeliveryDefaultRead => ({ state: 'ok', rec: { v: 1, value } });
const absent: DeliveryDefaultRead = { state: 'absent' };
const unreadable: DeliveryDefaultRead = { state: 'unreadable' };

test('D1 the global default decides when the contact has no setting: on sends; off, unknown, absent and unreadable do not', () => {
  assert.equal(mayEmitReceipt({ admitted: true, perContact: undefined, global: ok('on') }), true);
  for (const g of [ok('off'), ok('unknown'), absent, unreadable]) assert.equal(mayEmitReceipt({ admitted: true, perContact: undefined, global: g }), false);
});
test('D2 a per-contact setting WINS over the global, both ways', () => {
  assert.equal(mayEmitReceipt({ admitted: true, perContact: 'off', global: ok('on') }), false);
  assert.equal(mayEmitReceipt({ admitted: true, perContact: 'on', global: ok('off') }), true);
  assert.equal(mayEmitReceipt({ admitted: true, perContact: 'on', global: ok('unknown') }), true, 'an explicit per-contact choice stands while the global is unanswered');
});
test('D3 an UNREADABLE global means no send, even when the contact says on (a record that cannot be read is not a choice)', () => {
  assert.equal(mayEmitReceipt({ admitted: true, perContact: 'on', global: unreadable }), false);
});
test('D4 a contact that is not admitted never gets a receipt, whatever the settings say', () => {
  for (const g of [ok('on'), ok('off'), absent]) assert.equal(mayEmitReceipt({ admitted: false, perContact: 'on', global: g }), false);
});
test('D5 a per-contact value that is not exactly "on" or "off" is ignored (falls back to the global), never read as a choice', () => {
  for (const bad of ['ON', 'true', 1, null, {}, '']) assert.equal(mayEmitReceipt({ admitted: true, perContact: bad as never, global: ok('off') }), false, String(bad));
  for (const bad of ['ON', 'true', 1, null, {}, '']) assert.equal(mayEmitReceipt({ admitted: true, perContact: bad as never, global: ok('on') }), true, String(bad));
});
test('D6 parseDeliveryDefault accepts only the exact record shape; anything else is unreadable', () => {
  assert.deepEqual(parseDeliveryDefault({ v: 1, value: 'on' }), { state: 'ok', rec: { v: 1, value: 'on' } });
  assert.deepEqual(parseDeliveryDefault({ v: 1, value: 'unknown', notice_pending: true }), { state: 'ok', rec: { v: 1, value: 'unknown', notice_pending: true } });
  for (const bad of [null, undefined, 'on', 1, {}, { v: 2, value: 'on' }, { v: 1, value: 'yes' }, { v: 1 }, { v: 1, value: 'on', notice_pending: 'yes' }, []]) {
    assert.deepEqual(parseDeliveryDefault(bad), { state: 'unreadable' }, JSON.stringify(bad));
  }
});
test('D7 restrictOnly: an UNTRUSTED source may only tighten. "off" is accepted, "on", "unknown" and junk are dropped', () => {
  assert.equal(restrictOnly('off'), 'off');
  for (const v of ['on', 'unknown', 'ON', '', null, undefined, 1, {}]) assert.equal(restrictOnly(v), undefined, String(v));
});
