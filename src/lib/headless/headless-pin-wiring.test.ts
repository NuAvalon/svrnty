// A headless agent keeps the pin a signature-verified joiner response carried, and sends its OWN pin when it joins. The behaviour was run through the
// CLI (two minted agents: grow, join, poll, admit-gate); these [static] tests pin the two edits that make it true, like join-cli-wiring.test.ts.
//   npx tsx --test src/lib/headless/headless-pin-wiring.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const cli = readFileSync('scripts/devin-comm.ts', 'utf8');

test('H1 [static] join sends the agent\'s OWN pin in the signed response, canonical only', () => {
  assert.match(cli, /import \{ canonicalAuthorityPin \} from '\.\.\/src\/lib\/identity\/authority-pin';/);
  const join = cli.slice(cli.indexOf("if (cmd === 'join')"), cli.indexOf("if (cmd === 'admit-gate')"));
  assert.match(join, /canonicalAuthorityPin\(myId\.next_authority_commitment\) \? \{ nextAuthorityCommitment: canonicalAuthorityPin\(myId\.next_authority_commitment\)! \} : \{\}/);
});
test('H2 [static] admit-gate copies the pin the arrival carried onto the contact (the arrival already holds only a canonical one)', () => {
  const gate = cli.slice(cli.indexOf("if (cmd === 'admit-gate')"), cli.indexOf("if (cmd === 'send-tr')"));
  assert.match(gate, /\.\.\.\(pinToStore \? \{ next_authority_commitment: pinToStore \} : \{\}\)/);
});
test('H2b [static] admit-gate keeps a pin the row already holds (upsertContact replaces the row): the held pin wins over the arrival\'s', () => {
  const gate = cli.slice(cli.indexOf("if (cmd === 'admit-gate')"), cli.indexOf("if (cmd === 'send-tr')"));
  assert.match(gate, /const heldPin = canonicalAuthorityPin\(store\.getContactByFingerprint\(arrival\.fingerprint\)\?\.next_authority_commitment\);/);
  assert.match(gate, /const pinToStore = heldPin \?\? rec\.next_authority_commitment;/);
});
test('H3 [static] the headless join does NOT store the GIVER\'s pin: it verifies the fingerprint binding only, not the card signature (a pin needs a verified signature)', () => {
  const join = cli.slice(cli.indexOf("if (cmd === 'join')"), cli.indexOf("if (cmd === 'admit-gate')"));
  assert.doesNotMatch(join, /next_authority_commitment: [a-z]*(card|giver|target|contact)/i);
  const link = readFileSync('src/lib/headless/join-grow-link.ts', 'utf8');
  assert.doesNotMatch(link, /next_authority_commitment|authorityPin/);
});
