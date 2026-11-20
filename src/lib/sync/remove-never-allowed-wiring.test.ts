// A SOURCE-SHAPE pin (not a behaviour test: the behaviour is run in a real browser by e2e/allowed-revoke.spec.ts and in the hook tests): the Remove handler reads NO consent: the owner's allowed set (#959)
// decides whether the satellite may hold a row, so a contact that was never added sends the satellite nothing. Run: npx tsx --test src/lib/sync/remove-never-allowed-wiring.test.ts
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

test('RW1 the Remove handler reads NO consent and hands the removal reconcile only the owner and the peer: the allowed set, not a read made before the removal, decides whether a row may exist; the removal still runs inside the contact lock', () => {
  const b = body();
  assert.match(b, /await withSafetyWrite\(contactId, \(\) => removeContactWithLatch\(fingerprint, contactId, removedFp\)\);/, 'the removal runs inside the contact lock');
  assert.doesNotMatch(b, /getContact\(/, 'the handler reads no record');
  assert.doesNotMatch(b, /consentFromRecord|consentBefore/, 'and derives no consent');
  const call = /reconcileAllowedOnRemove\(\{([^}]*)\}\)/.exec(b);
  assert.ok(call, 'the removal reconcile is called');
  assert.match(call![1], /ownerFp:\s*fingerprint/);
  assert.match(call![1], /senderFp:\s*removedFp/);
  assert.equal(call![1].split(',').filter((x) => x.trim()).length, 2, 'and is handed nothing else');
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

test('RW3 the contacts screen asks the satellite what it still lists, at app-open and BEFORE the PSI session work starts, whether or not that work manages to start', () => {
  const effect = SRC.slice(SRC.indexOf('// KNOW-layer PSI: bind the raw sign key'));
  const tick = effect.indexOf('void runAllowedRevokeTick(fingerprint);');
  const psi = effect.indexOf('void startPsiDiscovery(');
  assert.ok(tick > 0 && psi > 0, 'both are in the start-up effect');
  assert.ok(tick < psi, 'the revoke check is not behind the PSI start');
});
