// "My QR": a QR that holds the owner's fingerprint and nothing else, so a real card can be checked in person by the Verify sheet.
// The payload is tested as data; the component and its wiring are source-shape pins (it must send nothing, and the dialog must give it the owner's
// own fingerprint). Run: npx tsx --test src/components/verify/my-fingerprint-qr.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { MY_QR_LABEL, MY_QR_LINE, myQrPayload } from './my-fingerprint-qr';
import { extractFingerprintFromScan, fingerprintsMatch } from './fingerprint-from-scan';

const FP = 'ab12'.repeat(16);
const OTHER = 'cd34'.repeat(16);
const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const WHOLE_LINE_COMMENT = /^\s*(?:\/\/|\/\*(?:(?!\*\/).)*\*\/\s*$|\/\*(?!.*\*\/)|\*(?!\/)|\*\/\s*$)/;
const code = (rel: string) => read(rel).split('\n').filter((l) => !WHOLE_LINE_COMMENT.test(l)).join('\n');

test('the payload is the fingerprint and nothing else: 64 lowercase hex', () => {
  assert.equal(myQrPayload(FP), FP);
  assert.equal(myQrPayload(FP.toUpperCase()), FP, 'lowercased');
  assert.equal(myQrPayload(`  ${FP}\n`), FP, 'trimmed');
  assert.match(myQrPayload(FP) as string, /^[0-9a-f]{64}$/);
});

test('anything that is not a 64-hex fingerprint makes no QR (fail closed): a short stand-in, a wrong length, groups, a link, JSON, a non-string', () => {
  for (const bad of [
    'ab12'.repeat(10), 'ab12'.repeat(16).slice(1), FP + 'a', FP.replace(/^ab/, 'zz'),
    'ab12 '.repeat(15) + 'ab12', `https://svrnty.example/c/${FP}`, `{"fingerprint":"${FP}"}`, `?fp=${FP}`, '', '   ', undefined, null, 42, {}, [FP],
  ] as unknown[]) {
    assert.equal(myQrPayload(bad), null, `must refuse: ${JSON.stringify(bad)}`);
  }
});

test('the payload round-trips through the Verify sheet\'s own scan reader and matches the stored contact, and only that one', () => {
  const payload = myQrPayload(FP) as string;
  assert.equal(extractFingerprintFromScan(payload), FP, 'the sheet reads it back as the same fingerprint');
  assert.equal(fingerprintsMatch(FP, extractFingerprintFromScan(payload)), true, 'a stored contact with this fingerprint matches');
  assert.equal(fingerprintsMatch(FP.toUpperCase(), extractFingerprintFromScan(payload)), true, 'case does not matter');
  assert.equal(fingerprintsMatch(OTHER, extractFingerprintFromScan(payload)), false, 'another contact does not');
});

test('the two strings are exactly the ones the wording review settled', () => {
  assert.equal(MY_QR_LABEL, 'My QR');
  assert.equal(MY_QR_LINE, "This is only your fingerprint. Share it in person, or anywhere they'll know it's really you.");
});

test('NEG: the module and the component send nothing and keep nothing: no request, no storage, no device API', () => {
  const FORBIDDEN = /\b(?:fetch|XMLHttpRequest|sendBeacon|WebSocket|EventSource|localStorage|sessionStorage|indexedDB|navigator|document\.cookie)\b|new\s+Image\b/;
  for (const rel of ['./my-fingerprint-qr.ts', './MyFingerprintQr.tsx']) {
    const src = code(rel);
    assert.ok(src.length > 100, `${rel} is read`);
    assert.doesNotMatch(src, FORBIDDEN, rel);
  }
  assert.match('await fetch("/x")', /\bfetch\b/, 'control: the pattern sees a request');
  assert.match('new Image()', /new\s+Image\b/, 'control: and an image beacon');
});

test('the component draws the payload and the line, and only through the existing QR component', () => {
  const src = code('./MyFingerprintQr.tsx');
  assert.match(src, /myQrPayload\(fingerprint\)/);
  assert.match(src, /<SimpleQRCode value=\{payload\}/);
  assert.match(src, /\{MY_QR_LINE\}/);
  assert.deepEqual([...src.matchAll(/from '([^']+)'/g)].map((m) => m[1]).sort(), ['./my-fingerprint-qr', '@/components/SimpleQRCode', 'react']);
});

test('the share dialog shows it: its own tab, labelled from the one constant, given the OWNER\'s own fingerprint prop', () => {
  const src = code('../ContactShareDialog.tsx');
  assert.match(src, /<TabsTrigger[^>]*value="myqr"/);
  assert.match(src, /\{MY_QR_LABEL\}/);
  assert.match(src, /<TabsContent value="myqr"[^>]*>[\s\S]*?<MyFingerprintQr fingerprint=\{fingerprint\} \/>/);
  assert.match(src, /grid-cols-5/);
});
