import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { chooseDelivery, contactDeliveryChoice, contactDeliveryPatch, dismissDeliveryNotice, loadDeliveryPanel, panelFromRead, type DeliveryIO } from './delivery-actions';
import type { DeliveryDefault, DeliveryDefaultRead } from '@/lib/trust/delivery-receipt-setting';

function fakeIO(start: DeliveryDefaultRead) {
  let cur = start;
  const writes: DeliveryDefault[] = [];
  const io: DeliveryIO = {
    read: async () => cur,
    write: async (_o, rec) => { writes.push(rec); cur = { state: 'ok', rec }; },
  };
  return { io, writes };
}
const ok = (value: DeliveryDefault['value'], notice_pending?: boolean): DeliveryDefaultRead =>
  ({ state: 'ok', rec: notice_pending ? { v: 1, value, notice_pending } : { v: 1, value } });

describe('Delivery UI actions', () => {
  it('A1 maps each stored state to one panel', () => {
    assert.deepEqual(panelFromRead(ok('on')), { kind: 'choice', value: 'on', notice: false });
    assert.deepEqual(panelFromRead(ok('off')), { kind: 'choice', value: 'off', notice: false });
    assert.deepEqual(panelFromRead(ok('on', true)), { kind: 'choice', value: 'on', notice: true });
    assert.deepEqual(panelFromRead(ok('unknown')), { kind: 'ask' });
  });
  it('A2 unreadable and absent offer no switch', () => {
    assert.deepEqual(panelFromRead({ state: 'unreadable' }), { kind: 'unreadable' });
    assert.deepEqual(panelFromRead({ state: 'absent' }), { kind: 'unreadable' });
  });
  it('A3 Yes/No on the restore ask writes on/off and leaves no notice', async () => {
    for (const v of ['on', 'off'] as const) {
      const { io, writes } = fakeIO(ok('unknown'));
      assert.deepEqual(await chooseDelivery(io, 'o', v), { kind: 'choice', value: v, notice: false });
      assert.deepEqual(writes, [{ v: 1, value: v }]);
    }
  });
  it('A4 choosing a value clears a pending notice', async () => {
    const { io } = fakeIO(ok('on', true));
    assert.deepEqual(await chooseDelivery(io, 'o', 'off'), { kind: 'choice', value: 'off', notice: false });
  });
  it('A5 dismissing the notice keeps the value and clears the flag', async () => {
    const { io, writes } = fakeIO(ok('on', true));
    assert.deepEqual(await dismissDeliveryNotice(io, 'o'), { kind: 'choice', value: 'on', notice: false });
    assert.deepEqual(writes, [{ v: 1, value: 'on' }]);
  });
  it('A6 dismissing writes nothing when there is no pending notice, an unknown value, or an unreadable record', async () => {
    for (const s of [ok('on'), ok('unknown'), { state: 'unreadable' } as DeliveryDefaultRead]) {
      const { io, writes } = fakeIO(s);
      await dismissDeliveryNotice(io, 'o');
      assert.equal(writes.length, 0);
    }
  });
  it('A7 loadDeliveryPanel reads through the io', async () => {
    const { io } = fakeIO(ok('off'));
    assert.deepEqual(await loadDeliveryPanel(io, 'o'), { kind: 'choice', value: 'off', notice: false });
  });
  it('A8 per-contact patch: on/off set the field, follow clears it, and the held record is not read', () => {
    assert.deepEqual(contactDeliveryPatch(null, 'on'), { delivery_receipts: 'on' });
    assert.deepEqual(contactDeliveryPatch({ delivery_receipts: 'off' }, 'off'), { delivery_receipts: 'off' });
    assert.deepEqual(contactDeliveryPatch({ delivery_receipts: 'on' }, 'follow'), { delivery_receipts: undefined });
  });
  it('A9 the stored field reads back as one of three choices; anything else is follow', () => {
    assert.equal(contactDeliveryChoice('on'), 'on');
    assert.equal(contactDeliveryChoice('off'), 'off');
    for (const v of [undefined, null, 'ON', 1, {}, 'unknown']) assert.equal(contactDeliveryChoice(v), 'follow');
  });
});
