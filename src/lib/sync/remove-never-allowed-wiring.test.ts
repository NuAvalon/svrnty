// A SOURCE-SHAPE pin (not a behaviour test: the behaviour is run in a real browser by e2e/remove-never-allowed.spec.ts and in the hook tests): the Remove handler reads the contact's consent BEFORE the record is
// removed, and sends the satellite nothing unless that consent had a row. Run: npx tsx --test src/lib/sync/remove-never-allowed-wiring.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const SRC = readFileSync('src/components/ContactManagement.tsx', 'utf8');
const body = (): string => {
  const at = SRC.indexOf('const handleDeleteContact = async (contactId: string) => {');
  assert.ok(at >= 0, 'the Remove handler is found');
  const end = SRC.indexOf('const handleToggleTrust', at);
  assert.ok(end > at, 'and its end');
  return SRC.slice(at, end);
};

test('RW1 the Remove handler reads the contact\'s record INSIDE the safety lock and IMMEDIATELY BEFORE the removal (a read outside the lock can go stale before the lock is taken, and then Remove skips a revoke it owes), and hands its consent to the removal reconcile', () => {
  const b = body();
  const lock = b.indexOf('withSafetyWrite(contactId, async () => {');
  assert.ok(lock >= 0, 'the removal runs inside one safety-lock callback that returns the consent');
  const cb = b.slice(lock, b.indexOf('});', lock));
  const read = cb.indexOf('await getContact(contactId)');
  const remove = cb.indexOf('await removeContactWithLatch(');
  assert.ok(read >= 0 && remove >= 0, 'both calls are INSIDE that callback');
  assert.ok(read < remove, 'the record is read before it is removed');
  assert.match(cb.slice(read, remove), /consentFromRecord\(recordBefore\)/, 'the consent is derived from that record before the removal');
  assert.match(cb, /return consent;/, 'and handed out of the lock');
  assert.equal((b.match(/getContact\(contactId\)/g) ?? []).length, 1, 'the handler reads the record in exactly one place, so no read outside the lock');
  assert.match(b, /const consentBefore = await withSafetyWrite\(/, 'the outer consentBefore is what the lock returned');
  assert.match(b, /reconcileAllowedOnRemove\(\{[\s\S]*?\bconsentBefore,\s*\}\)/, 'and is handed to the removal reconcile');
});

test('RW2 the Remove handler no longer uses the unconditional "peer gone" reconcile (that sends a DELETE for a person who never had a row)', () => {
  const b = body();
  assert.doesNotMatch(b, /reconcileAllowedOnConsentChange\s*\(/);
  assert.doesNotMatch(b, /NO_CONSENT/);
  // CONTROL: the other handlers in the file still use it, so this pin is looking at a name that is really in use
  assert.ok((SRC.match(/reconcileAllowedOnConsentChange\s*\(\{/g) ?? []).length >= 3, 'control: the block / contact-gone / sharing handlers still call it');
  // and the old shape would have matched: the pattern can fail
  assert.match('void reconcileAllowedOnConsentChange({ ownerFp: fingerprint, senderFp: removedFp, consent: NO_CONSENT });', /reconcileAllowedOnConsentChange\s*\(/);
});
