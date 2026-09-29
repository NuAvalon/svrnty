// src/lib/invite/scanInvite.test.ts
// INV-5 leak-site + INV-4 single-parser tests for the QR-scan join handler.
// Run: npx tsx --test src/lib/invite/scanInvite.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SCAN_ERROR_CAMERA,
  SCAN_ERROR_NOT_INVITE,
  SCAN_ERROR_PERMISSION,
  classifyCameraError,
  inviteFromScannedText,
  stopMediaStream,
} from './scanInvite';

const SECRET = 'supersecretkeyfragmentXYZ';
const VALID = `https://svrnty.is/c/abc123#${SECRET}`;

test('valid invite QR text parses through parseInviteUrl (single join path)', () => {
  const r = inviteFromScannedText(VALID);
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.invite.code, 'abc123');
    assert.equal(r.invite.keyFragment, SECRET);
  }
});

test('malformed / off-host / missing-key scans fail closed with the FIXED error', () => {
  const bad = [
    '',
    'not a url',
    'https://evil.example/c/abc123#' + SECRET,
    'javascript:alert(1)',
    'https://svrnty.is/c/abc123', // no key
    42,
    null,
    { href: VALID },
  ];
  for (const input of bad) {
    const r = inviteFromScannedText(input);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.error, SCAN_ERROR_NOT_INVITE);
  }
});

test('INV-5: error text never interpolates the raw scan or the key fragment', () => {
  const poisoned = `https://evil.example/c/abc#${SECRET}`;
  const r = inviteFromScannedText(poisoned);
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.equal(r.error, SCAN_ERROR_NOT_INVITE);
    assert.equal(r.error.includes(SECRET), false);
    assert.equal(r.error.includes(poisoned), false);
    assert.equal(r.error.includes('evil.example'), false);
  }
});

test('classifyCameraError maps permission vs unavailable without echoing err.message', () => {
  const denied = classifyCameraError({ name: 'NotAllowedError', message: SECRET });
  assert.equal(denied, SCAN_ERROR_PERMISSION);
  assert.equal(denied.includes(SECRET), false);

  const alsoDenied = classifyCameraError({ name: 'PermissionDeniedError', message: SECRET });
  assert.equal(alsoDenied, SCAN_ERROR_PERMISSION);

  const missing = classifyCameraError({ name: 'NotFoundError', message: SECRET });
  assert.equal(missing, SCAN_ERROR_CAMERA);
  assert.equal(missing.includes(SECRET), false);

  const unknown = classifyCameraError('weird ' + SECRET);
  assert.equal(unknown, SCAN_ERROR_CAMERA);
  assert.equal(unknown.includes(SECRET), false);
});

test('stopMediaStream stops every track and is null-safe', () => {
  let stopped = 0;
  const stream = {
    getTracks: () => [
      { stop: () => { stopped += 1; } },
      { stop: () => { stopped += 1; } },
    ],
  };
  stopMediaStream(stream as unknown as MediaStream);
  assert.equal(stopped, 2);
  stopMediaStream(null);
  stopMediaStream(undefined);
  assert.equal(stopped, 2);
});

test('scan sources never fetch, persist frames, or console-log (INV-5 leak-site)', () => {
  const dir = dirname(fileURLToPath(import.meta.url));
  const files = [
    join(dir, 'scanInvite.ts'),
    join(dir, 'decodeQrFrame.ts'),
    join(dir, '../../components/ScanToJoin.tsx'),
  ];
  const forbidden = [
    /\bfetch\s*\(/,
    /\blocalStorage\b/,
    /\bindexedDB\b/,
    /\bXMLHttpRequest\b/,
    /\bsendBeacon\b/,
    /\.toDataURL\s*\(/,
    /\.toBlob\s*\(/,
    /console\.(log|info|debug|warn|error)/,
  ];
  for (const file of files) {
    const src = readFileSync(file, 'utf8');
    for (const re of forbidden) {
      assert.equal(
        re.test(src),
        false,
        `${file} matches ${re} — scan path must not upload, persist, or log frames/payloads`,
      );
    }
  }
});
