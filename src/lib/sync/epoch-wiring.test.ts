// The epoch seam's hook-up in the poll and its place in the consume pipeline. The poll needs the real database to run, so these are SOURCE PINS: they
// read the text and say what it must contain. The behaviour of the seam itself is run in epoch-seam.test.ts and consume-mailbox-epoch.test.ts.
// Run: npx tsx --test src/lib/sync/epoch-wiring.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const code = (s: string) => s.replace(/^\s*(\/\/|\*|\/\*).*$/gm, '');

test('PIN: the epoch seam is installed ONLY through the gate on the receive switch, read from the flags and never fixed on', () => {
  const lbp = code(read('./live-book-poll.ts'));
  assert.match(lbp, /const epochFlags = readPsiEpochFlags\(\);/);
  assert.match(lbp, /epoch: installEpochSeam\(epochFlags\.receive, \(\) =>\s*buildEpochSeam\(\{/);
  assert.match(lbp, /receiveOn: epochFlags\.receive,/);
  assert.doesNotMatch(lbp, /receiveOn:\s*true/);
  assert.doesNotMatch(lbp, /epoch: buildEpochSeam\(/, 'no unconditional install');
});

test('PIN: the seam is supplied the shared memory-only cache, the store\'s epoch writer, the reviewed hybrid opener (through the cycle-ended-aware wrapper), and a COPY of the seed from this cycle\'s one unlock', () => {
  const lbp = code(read('./live-book-poll.ts'));
  assert.match(lbp, /cache: epochPairSecretCache,/);
  assert.match(lbp, /adopt: adoptPsiEpoch,/);
  assert.match(lbp, /openPackage: \(blob\) => openEpochPackage\(blob, \{ asPackage: asMailboxEnvelopePackage, open: hybrid \? openHybridForCycle\(owner, hybrid\) : async \(\) => null \}\),/);
  assert.match(lbp, /ownerSeed: ownerSeedFromCycle\(cycle\),/);
  assert.match(code(read('./epoch-seam.ts')), /extractRawSign\(await cycle\.key\(\)\)\.seed\.slice\(\)/);
});

test('PIN: the poll never zeroes the unlocked key\'s own seed (it is the buffer the rest of the cycle signs with); only the seam\'s copy is zeroed', () => {
  const lbp = code(read('./live-book-poll.ts'));
  assert.doesNotMatch(lbp, /extractRawSign\([^)]*\)[^;]*\.fill\(0\)/);
  const seam = code(read('./epoch-seam.ts'));
  assert.match(seam, /seed\?\.fill\(0\)/);
});

test('PIN: a locked or ended cycle gives no seed (cannot verify), it does not throw out of the seam', () => {
  const lbp = code(read('./live-book-poll.ts'));
  assert.match(code(read('./epoch-seam.ts')), /return async \(\) => \{\s*try \{\s*return extractRawSign\(await cycle\.key\(\)\)\.seed\.slice\(\);\s*\} catch \{\s*return null;/);
});

test('PIN: in the consume pipeline the epoch seam sits AFTER the receipt seam and BEFORE the contact-update decrypt, so it cannot eat or be eaten', () => {
  const cm = read('./consume-mailbox.ts');
  const receipt = cm.indexOf('if (deps.receipt) {');
  const epoch = cm.indexOf('if (deps.epoch) {');
  const decrypt = cm.indexOf('// decrypt — an undecryptable blob is not-for-us');
  assert.ok(receipt > 0 && epoch > receipt && decrypt > epoch, `receipt ${receipt} < epoch ${epoch} < decrypt ${decrypt}`);
});

test('PIN: the poll\'s build variable for the receive switch has its full name where it is read, and nothing else turns the receive path on', () => {
  assert.match(read('../trust/psi-epoch-config.ts'), /process\.env\.NEXT_PUBLIC_PSI_EPOCH_RECEIVE\b/);
  const lbp = code(read('./live-book-poll.ts'));
  assert.doesNotMatch(lbp, /NEXT_PUBLIC_PSI_EPOCH/);
});
