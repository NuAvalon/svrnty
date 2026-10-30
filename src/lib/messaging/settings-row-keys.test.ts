// src/lib/messaging/settings-row-keys.test.ts + static guards for the encrypted-settings helpers in store.ts (#720).
// The repo has no Node-side IndexedDB harness, so the store functions themselves are proven in a real browser (see the PR); these pin
// the rules that keep them from reaching the plaintext salt row and keep the rollback-safe schema version.
// Run: npx tsx --test src/lib/messaging/settings-row-keys.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SETTINGS_ROW_PREFIXES, isAllowedSettingsPrefix, isAllowedSettingsRowKey } from './settings-row-keys';

const storeSrc = () => readFileSync(new URL('./store.ts', import.meta.url), 'utf8');
const fnBody = (src: string, signature: string) => {
  const start = src.indexOf(signature);
  assert.ok(start >= 0, `${signature} not found`);
  const next = src.indexOf('\nexport ', start + 1);
  return src.slice(start, next === -1 ? src.length : next);
};

test('K1 a row key is an allowed prefix plus at least one more character, plain charset, bounded length', () => {
  assert.equal(isAllowedSettingsRowKey('dead_letter:3f2b8c1e-5a4d-4e8b-9c1a-0d2e3f4a5b6c'), true);
  assert.equal(isAllowedSettingsRowKey('dead_letter:x'), true);
  for (const bad of ['dead_letter:', 'dead_letter', 'notes_encryption_salt', 'notes_encryption_salt:x', '', ' dead_letter:x', 'DEAD_LETTER:x',
    'dead_letter:a/b', 'dead_letter:a b', 'dead_letter:\u0000', 'dead_letter:é', `dead_letter:${'x'.repeat(200)}`, 42, null, undefined, {}]) {
    assert.equal(isAllowedSettingsRowKey(bad), false, JSON.stringify(bad));
  }
  assert.equal(isAllowedSettingsRowKey(`dead_letter:${'x'.repeat(188)}`), true, 'exactly 200 chars is the limit');
  assert.equal(isAllowedSettingsRowKey(`dead_letter:${'x'.repeat(189)}`), false);
});

test('K2 a LIST prefix must be exactly an allowed prefix, so a list can never reach the salt row', () => {
  assert.equal(isAllowedSettingsPrefix('dead_letter:'), true);
  for (const bad of ['', 'dead_', 'dead_letter', 'dead_letter:x', 'notes_', 'notes_encryption_salt', 'n', undefined, null, 7]) {
    assert.equal(isAllowedSettingsPrefix(bad), false, JSON.stringify(bad));
  }
  assert.deepEqual([...SETTINGS_ROW_PREFIXES], ['dead_letter:'], 'a new prefix is a deliberate edit of this test');
});

test('K3 static: every encrypted-settings entry point checks the key/prefix BEFORE touching the store', () => {
  const src = storeSrc();
  for (const [sig, check] of [
    ['export async function putEncryptedSetting(', 'requireRowKey(key);'],
    ['export async function getEncryptedSetting<', 'requireRowKey(key);'],
    ['export async function deleteEncryptedSetting(', 'requireRowKey(key);'],
    ['export async function listEncryptedSettings<', 'isAllowedSettingsPrefix(prefix)'],
  ] as const) {
    const body = fnBody(src, sig);
    assert.ok(body.includes(check), `${sig} must call ${check}`);
    assert.ok(body.indexOf(check) < Math.min(...['txPut(', 'txGet(', 'txDelete(', 'openDb(', 'encryptJson('].map((m) => (body.indexOf(m) === -1 ? Infinity : body.indexOf(m)))), `${sig}: the check must come first`);
  }
});

test('K4 static: put encrypts with the notes key (encryptJson), reads/lists throw while locked, nothing writes plaintext into a row', () => {
  const src = storeSrc();
  assert.match(fnBody(src, 'export async function putEncryptedSetting('), /encryptJson\(value\)/);
  assert.match(fnBody(src, 'export async function getEncryptedSetting<'), /requireUnlocked\(\);/);
  assert.match(fnBody(src, 'export async function listEncryptedSettings<'), /requireUnlocked\(\);/);
  assert.doesNotMatch(fnBody(src, 'export async function putEncryptedSetting('), /txPut\('settings', \{ key, value/);
});

test('K5 static ROLLBACK SAFETY: the notes DB stays at schema version 2 (a bump would lock a rolled-back v2 build out of its own notes)', () => {
  assert.match(storeSrc(), /const DB_VERSION = 2;/);
  assert.doesNotMatch(storeSrc(), /createObjectStore\('dead_letters?'/);
});

test('K6 static: the plaintext salt row is only ever written by initNotesStore, never by the encrypted-row helpers', () => {
  const src = storeSrc();
  const helpers = [
    'export async function putEncryptedSetting(',
    'export async function getEncryptedSetting<',
    'export async function listEncryptedSettings<',
    'export async function deleteEncryptedSetting(',
  ].map((s) => fnBody(src, s)).join('\n');
  assert.doesNotMatch(helpers, /notes_encryption_salt/);
});
