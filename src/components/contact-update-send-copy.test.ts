// Run: npx tsx --test src/components/contact-update-send-copy.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { contactUpdateSendMessage } from './contact-update-send-copy';

const skip = (reason: 'no-pq-kem' | 'no-public-key') => ({ fingerprint: 'fp', reason }) as never;

test('S14: a no-pq-kem skip names the updated-card remedy (security upgrade), NOT "no key"', () => {
  const r = contactUpdateSendMessage({ deposited: ['m1'], skipped: [skip('no-pq-kem'), skip('no-pq-kem')], failed: [] });
  assert.equal(r.ok, true);
  assert.match(r.message, /2 contacts need to share an updated contact card \(security upgrade\) \(not sent\)/);
  assert.doesNotMatch(r.message, /no key/i);
});

test('a real missing key is still "no key", and the two causes are counted separately', () => {
  const r = contactUpdateSendMessage({ deposited: ['m1'], skipped: [skip('no-pq-kem'), skip('no-public-key')], failed: [{ mailbox_id: 'x', status: 503 }] });
  assert.match(r.message, /1 contact needs to share an updated contact card \(security upgrade\) \(not sent\)/);
  assert.match(r.message, /1 skipped \(no key yet\)/);
  assert.match(r.message, /1 failed \(retry\)/);
});

test('nothing delivered: not ok, reasons listed, saved-locally line kept', () => {
  const r = contactUpdateSendMessage({ deposited: [], skipped: [skip('no-pq-kem')], failed: [] });
  assert.equal(r.ok, false);
  assert.match(r.message, /^Couldn't deliver: 1 contact needs to share an updated contact card \(security upgrade\)\. Saved locally/);
});

test('claim-safe wording: never quantum-safe / PQ-secure before the Nov-5 gate', () => {
  const r = contactUpdateSendMessage({ deposited: [], skipped: [skip('no-pq-kem')], failed: [] });
  assert.doesNotMatch(r.message, /quantum|PQ-secure|post-quantum/i);
});


test('a blocked skip is never described as a missing key', () => {
  const r = contactUpdateSendMessage({ deposited: ['m'], skipped: [{ fingerprint: 'F', reason: 'blocked' }], failed: [] });
  assert.equal(r.ok, true);
  assert.equal(r.message, 'Sent to 1 contact, 1 blocked or removed (not sent).');
});

test('blocked and missing keys are counted separately', () => {
  const r = contactUpdateSendMessage({ deposited: ['m'], skipped: [{ fingerprint: 'F', reason: 'blocked' }, { fingerprint: 'G', reason: 'no-public-key' }], failed: [] });
  assert.equal(r.message, 'Sent to 1 contact, 1 blocked or removed (not sent), 1 skipped (no key yet).');
});

test('nothing sent because everyone was blocked: no advice to try again', () => {
  const r = contactUpdateSendMessage({ deposited: [], skipped: [{ fingerprint: 'F', reason: 'blocked' }], failed: [] });
  assert.equal(r.ok, false);
  assert.equal(r.message, 'Not sent: 1 contact is blocked or removed.');
});

test('nothing sent with mixed causes keeps the retry line and names the blocked count', () => {
  const r = contactUpdateSendMessage({ deposited: [], skipped: [{ fingerprint: 'F', reason: 'blocked' }], failed: [{ mailbox_id: 'm', status: 500 }] });
  assert.equal(r.ok, false);
  assert.equal(r.message, "Couldn't deliver: 1 blocked or removed, 1 failed. Saved locally — try Send again later for the 1 that failed.");
});

test('the retry line counts only the ones that failed, because a blocked contact is refused every time', () => {
  const r = contactUpdateSendMessage({
    deposited: [],
    skipped: [{ fingerprint: 'F', reason: 'blocked' }, { fingerprint: 'G', reason: 'blocked' }],
    failed: [{ mailbox_id: 'm', status: 500 }],
  });
  assert.equal(r.message, "Couldn't deliver: 2 blocked or removed, 1 failed. Saved locally — try Send again later for the 1 that failed.");
});

test('when nothing is blocked the retry line stays as it was', () => {
  const r = contactUpdateSendMessage({ deposited: [], skipped: [], failed: [{ mailbox_id: 'm', status: 500 }] });
  assert.equal(r.message, "Couldn't deliver: 1 failed. Saved locally — try Send again later.");
});
