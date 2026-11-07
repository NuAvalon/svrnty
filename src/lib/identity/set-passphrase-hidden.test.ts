// "Set Passphrase" is switched off until the re-key fix ships (a passphrase change re-stores only the identity keys and strands the contacts, the recovery vault,
// the shards and the device mailbox under the old passphrase). The card-menu item is the only UI entry point; these pins keep it that way: the item is behind
// the off switch, nothing else opens the dialog, and nothing else calls the handler.
// Run: npx tsx --test src/lib/identity/set-passphrase-hidden.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const strip = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const frontend = strip(readFileSync(new URL('../../components/SoverentityFrontend.tsx', import.meta.url), 'utf8'));

test('the switch is off', () => {
  assert.match(frontend, /const SET_PASSPHRASE_ENTRY_ENABLED = false;/);
});

test('the card-menu item is rendered only behind the switch, and it is the ONLY place that opens the dialog', () => {
  const opens = frontend.match(/setShowPassphraseDialog\(true\)/g) ?? [];
  assert.equal(opens.length, 1, 'exactly one opener');
  const i = frontend.indexOf('setShowPassphraseDialog(true)');
  const guard = frontend.lastIndexOf('{SET_PASSPHRASE_ENTRY_ENABLED && (', i);
  assert.ok(guard > 0 && i - guard < 400, 'the opener sits inside the switched block');
  assert.equal((frontend.match(/SET_PASSPHRASE_ENTRY_ENABLED/g) ?? []).length, 2, 'declared once, used once');
});

test('the handler is called by the dialog button only, and the dialog renders only when something opened it', () => {
  assert.equal((frontend.match(/handleSetPassphrase/g) ?? []).length, 2, 'its definition and the dialog button, nothing else');
  assert.match(frontend, /onClick=\{handleSetPassphrase\}/);
  assert.match(frontend, /\{showPassphraseDialog && \(/);
  assert.doesNotMatch(frontend, /handleSetPassphrase\(/ , 'no call other than the definition');
});

test('no other source file opens the dialog or names the handler', () => {
  const hits: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (name === 'node_modules' || name.startsWith('.')) continue;
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else if (/\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name) && !p.endsWith('SoverentityFrontend.tsx')) {
        if (/handleSetPassphrase|setShowPassphraseDialog/.test(readFileSync(p, 'utf8'))) hits.push(p);
      }
    }
  };
  walk(new URL('../../', import.meta.url).pathname);
  walk(new URL('../../../app/', import.meta.url).pathname);
  assert.deepEqual(hits, []);
});
