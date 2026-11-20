// beacon-key-replace-screens: who may show a key replacement, and what each screen hands it. Static guards over the source, each with a control that proves it can fire.
// Run: npx tsx --test src/lib/trust/beacon-key-replace-screens.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

function walk(dir: string, out: Array<{ path: string; text: string }> = []): Array<{ path: string; text: string }> {
  for (const n of readdirSync(dir)) {
    if (n === 'node_modules' || n.startsWith('.')) continue;
    const p = join(dir, n); const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (/\.(ts|tsx)$/.test(n) && !/\.test\.tsx?$/.test(n)) out.push({ path: p, text: readFileSync(p, 'utf8') });
  }
  return out;
}
const SRC = walk(join(process.cwd(), 'src'));
const codeOnly = (t: string) => t.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).map((l) => l.replace(/\/\/.*$/, '')).join('\n');
const rel = (p: string) => p.replace(/\\/g, '/').split('/src/').pop()!;
const namersOf = (files: Array<{ path: string; text: string }>, re: RegExp) => files.filter((f) => re.test(codeOnly(f.text))).map((f) => rel(f.path)).sort();
const text = (r: string) => codeOnly(SRC.find((f) => rel(f.path) === r)!.text);

const SCREENS = ['components/ContactManagement.tsx', 'components/JoinerCeremony.tsx'];
// the views an in-person exchange renders, some of them to the OTHER person: none may show a key replacement
const EXCHANGE_VIEWS = ['components/Ceremony.tsx', 'components/GrowSheet.tsx', 'components/GrowSurface.tsx', 'components/GrowGatePanel.tsx', 'components/verify/VerifySheet.tsx'];

test('KS1 only the two intake screens import the key replacement and its words: a new importer fails here until it is reviewed (the guard FIRES on a synthetic one)', () => {
  const RE = /beacon-key-intake-real|beacon-key-replace-copy/;
  assert.deepEqual(namersOf([{ path: '/x/src/components/NewView.tsx', text: "import { replaceNotice } from '@/lib/trust/beacon-key-replace-copy';" }], RE), ['components/NewView.tsx']);
  assert.deepEqual(namersOf(SRC, RE), SCREENS);
});

test('KS2 NO LINE in an in-person exchange view: none of the views an exchange renders (some to the OTHER person) imports the key replacement or its words (CONTROL: the files exist, so the check is not vacuous)', () => {
  for (const v of EXCHANGE_VIEWS) {
    assert.ok(existsSync(join(process.cwd(), 'src', v)), `${v} exists`);
    assert.doesNotMatch(text(v), /beacon-key-intake|beacon-key-replace|replaceNotice|replaceContactBeaconKey/, `${v} must not show a key replacement`);
  }
});

test('KS3 the Contacts import replaces only the contact looked up by the card\'s VERIFIED fingerprint, and names the BOOK\'s contact, never the card\'s display name', () => {
  const t = text('components/ContactManagement.tsx');
  assert.match(t, /const existing = await getContactByFingerprint\(fingerprint, contactIdentity\.fingerprint\);/, 'existing is looked up by the card\'s fingerprint, after the binding check refused a mismatch');
  const start = t.indexOf("beaconIntake.verdict === 'replace' && beaconIntake.replace");
  assert.ok(start > 0, 'the replace branch was found');
  const branch = t.slice(start, t.indexOf('} else {', start));                 // the replace clause only: its sibling message (the back-fill result) legitimately names the card
  assert.match(branch, /replaceContactBeaconKey\(fingerprint, \{ contact: existing, next: beaconIntake\.replace \}\)/, 'the replace targets `existing`, nothing else');
  assert.match(branch, /replaceNotice\(replaced, existing\.name\)/, 'the words name the book\'s contact');
  assert.doesNotMatch(branch, /displayName|contactIdentity\.(name|display_name)|card\./, 'never the name the card carries');
  assert.doesNotMatch(branch, /beacon_public_key|beacon_key_generation/, 'and the replace branch itself never names the key fields');
  // ONE back-fill write, and it comes BEFORE the replace (fields are empty for a replace, so it cannot carry the key)
  const whole = t.slice(t.indexOf('backfillsKeyMaterial ||'), t.indexOf('You already have'));
  assert.equal((whole.match(/await updateContact\(/g) ?? []).length, 1, 'one object-form back-fill write');
  assert.ok(whole.indexOf('await updateContact(') < whole.indexOf('replaceContactBeaconKey('), 'the back-fill runs before the replace');
});

test('KS4 the Grow ceremony replaces only the contact looked up by the peer\'s verified fingerprint, names the book\'s contact, and shows the line only on this device\'s own done screen', () => {
  const t = text('components/JoinerCeremony.tsx');
  assert.match(t, /const existing = peer\.fingerprint\s*\?\s*await getContactByFingerprint\(ownerFp, peer\.fingerprint\)/);
  assert.match(t, /replaceNotice\(await replaceContactBeaconKey\(ownerFp, \{ contact: existing, next: beaconIntake\.replace \}\), existing\.name\)/);
  assert.match(t, /\{keyNotice && <p style=\{subStyle\}>\{keyNotice\}<\/p>\}/, 'the line is a paragraph of the done screen');
  assert.equal((t.match(/keyNotice/g) ?? []).length, 3, 'the value: declared once and rendered once (a guard and the text), nowhere else');
  assert.equal((t.match(/setKeyNotice/g) ?? []).length, 2, 'the setter: declared once and called once, in the replace branch');
  const done = t.slice(t.indexOf("phase === 'done'"));
  assert.ok(done.includes('keyNotice'), 'it renders inside the done phase only');
});
