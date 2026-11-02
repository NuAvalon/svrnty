// The legacy plaintext key item is removed on every page load, and nothing else is. The boot test runs the real script text that the layout ships,
// against a fake localStorage, so a typo in the shipped string is caught and not only the helper.
//
// Run: npx tsx --test src/lib/identity/legacy-keys.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import vm from 'node:vm';
import { clearLegacyChatKeys, LEGACY_CHAT_KEYS_BOOT_SCRIPT, LEGACY_CHAT_KEYS_ITEM } from './legacy-keys';
import { UI_PREFS_KEY } from '@/components/recovery/solar-ember';

class FakeStorage {
  private m = new Map<string, string>();
  removed: string[] = [];
  cleared = 0;
  constructor(init: Record<string, string> = {}) { for (const [k, v] of Object.entries(init)) this.m.set(k, v); }
  getItem(k: string) { return this.m.has(k) ? this.m.get(k)! : null; }
  setItem(k: string, v: string) { this.m.set(k, v); }
  removeItem(k: string) { this.removed.push(k); this.m.delete(k); }
  clear() { this.cleared++; this.m.clear(); }
  snapshot() { return JSON.stringify([...this.m.entries()].sort()); }
}

const LEGACY = JSON.stringify({ sign_sk: 'a', mlkem_sk: 'b', x25519_sk: 'c' });
// items the app and near-miss names the cleanup must not touch
const OTHERS: Record<string, string> = {
  [UI_PREFS_KEY]: '{"appearance":"light"}',
  svrnty_keys_backup: 'keep',
  svrnty_key: 'keep',
  'svrnty-keys': 'keep',
  SVRNTY_KEYS: 'keep',
  x_svrnty_keys: 'keep',
  relay_pref: 'keep',
};

const runBoot = (storage: unknown) => vm.runInNewContext(LEGACY_CHAT_KEYS_BOOT_SCRIPT, { localStorage: storage });

test('the item name is the one the old page wrote', () => {
  assert.equal(LEGACY_CHAT_KEYS_ITEM, 'svrnty_keys');
});

test('boot script: the legacy item is removed', () => {
  const s = new FakeStorage({ ...OTHERS, svrnty_keys: LEGACY });
  runBoot(s);
  assert.equal(s.getItem('svrnty_keys'), null);
});

test('boot script: every other item is byte-identical before and after, and nothing else is removed or cleared', () => {
  const s = new FakeStorage({ ...OTHERS, svrnty_keys: LEGACY });
  const before = new FakeStorage(OTHERS).snapshot();
  runBoot(s);
  assert.equal(s.snapshot(), before);
  assert.deepEqual(s.removed, ['svrnty_keys']);
  assert.equal(s.cleared, 0);
});

test('boot script: nothing to remove is a no-op that changes nothing', () => {
  const s = new FakeStorage(OTHERS);
  const before = s.snapshot();
  runBoot(s);
  assert.equal(s.snapshot(), before);
});

test('boot script: a storage that throws, or is missing, does not throw out of the script', () => {
  assert.doesNotThrow(() => runBoot({ removeItem() { throw new Error('blocked'); } }));
  assert.doesNotThrow(() => vm.runInNewContext(LEGACY_CHAT_KEYS_BOOT_SCRIPT, {}));
});

test('helper: removes only the legacy item and reports success', () => {
  const s = new FakeStorage({ ...OTHERS, svrnty_keys: LEGACY });
  assert.equal(clearLegacyChatKeys(s), true);
  assert.equal(s.snapshot(), new FakeStorage(OTHERS).snapshot());
  assert.deepEqual(s.removed, ['svrnty_keys']);
});

test('helper: a throwing or missing storage is reported, never thrown', () => {
  assert.equal(clearLegacyChatKeys({ removeItem() { throw new Error('blocked'); } }), false);
  assert.equal(clearLegacyChatKeys(null), false);
  assert.equal(clearLegacyChatKeys(undefined), false);
});

test('GUARD: the root layout ships the removal script in the head, and the appearance script is still there', () => {
  const layout = readFileSync(new URL('../../../app/layout.tsx', import.meta.url), 'utf8');
  const head = layout.slice(layout.indexOf('<head>'), layout.indexOf('</head>'));
  assert.match(head, /dangerouslySetInnerHTML=\{\{ __html: LEGACY_CHAT_KEYS_BOOT_SCRIPT \}\}/, 'the removal script is in the head');
  assert.match(head, /__html: appearanceBoot/, 'the appearance script is still shipped');
  assert.match(layout, /import \{ LEGACY_CHAT_KEYS_BOOT_SCRIPT \} from '@\/lib\/identity\/legacy-keys'/, 'it imports the shipped script');
});

test('GUARD: no app code outside this module names the legacy item (it is removed, never used)', () => {
  const root = new URL('../../../', import.meta.url);
  const hits: string[] = [];
  const walk = (dir: URL) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const u = new URL(e.name + (e.isDirectory() ? '/' : ''), dir);
      if (e.isDirectory()) { walk(u); continue; }
      if (!/\.(ts|tsx)$/.test(e.name) || /legacy-keys(\.test)?\.ts$/.test(e.name)) continue;
      if (readFileSync(u, 'utf8').includes("'svrnty_keys'")) hits.push(u.pathname);
    }
  };
  walk(new URL('app/', root));
  walk(new URL('src/', root));
  assert.deepEqual(hits, [], 'a use elsewhere makes clearing it a behaviour change');
});
