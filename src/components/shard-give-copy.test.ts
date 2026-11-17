// Run: npx tsx --test src/components/shard-give-copy.test.ts
// The "give a recovery piece" dialog's two sentences (copy ledger rows 226a and 237) are pinned byte for byte here, apart from the module that holds them. The component is checked
// as source (the repo has no component renderer): it renders the constants, and the old phrases cannot come back anywhere in the source.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SHARD_LINK_NOTE, shardAllGivenLine, shardReadyLine } from './shard-give-copy';

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(HERE, '..');
const stripComments = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
const component = (): string => stripComments(readFileSync(join(HERE, 'ShardGiveDialog.tsx'), 'utf8'));
const LINK_NOTE = 'The piece is encrypted in your browser. The server only holds the encrypted copy; the key is in the link itself, so anyone with this link or QR code can open the piece. Send it only through a channel you trust.';

test('SG1 the link note is the copy owner\'s words byte for byte (row 226a): its hash matches the frozen one, it is pure ASCII, and the all-given line interpolates exactly (row 237)', () => {
  assert.equal(SHARD_LINK_NOTE, LINK_NOTE);
  assert.ok(createHash('sha256').update(SHARD_LINK_NOTE).digest('hex').startsWith('0308189eaab50474'));
  assert.ok(/^[\x20-\x7e]+$/.test(SHARD_LINK_NOTE), 'pure ASCII, no smart quotes or dashes');
  for (const [total, threshold] of [[5, 3], [3, 2], [10, 7], [2, 2]] as const) {
    assert.equal(
      shardAllGivenLine(total, threshold),
      `You've given out all ${total} of your pieces. Any ${threshold} of your keepers together hold enough to rebuild your recovery key. Collecting the pieces back isn't in the app yet.`,
    );
  }
});

test('SG2 THE COMPONENT imports the module, renders each constant once with the right arguments, and keeps no piece of either sentence inline', () => {
  const c = component();
  const once = (needle: string): void => assert.equal(c.split(needle).length - 1, 1, `exactly once in the component: ${needle}`);
  once("import { SHARD_LINK_NOTE, shardAllGivenLine, shardReadyLine } from './shard-give-copy';");
  once('{SHARD_LINK_NOTE}');
  once('{shardAllGivenLine(total, threshold)}');          // the arguments are pinned: swapping them would print the wrong numbers
  once('{shardReadyLine(remaining, total, threshold)}');
  for (const name of ['SHARD_LINK_NOTE', 'shardAllGivenLine', 'shardReadyLine']) {
    assert.equal(c.split(name).length - 1, 2, `${name} appears only in the import and the one use`);
  }
  // No retyped piece of either sentence: the pieces are taken from the module's own text (split at the numbers and at . ; ,), so any part of it is covered.
  const flat = (t: string): string => t.replace(/\s+/g, ' ');
  const pieces = [SHARD_LINK_NOTE, shardAllGivenLine(777, 555), shardReadyLine(333, 777, 555), shardReadyLine(1, 777, 555)]
    .flatMap((t) => t.split(/777|555|333|[.;,]/))
    .map((t) => flat(t).trim())
    .filter((t) => t.length >= 18);
  assert.ok(pieces.length >= 5, `expected several pieces to check, got ${pieces.length}`);
  const cf = flat(c);
  for (const piece of pieces) assert.ok(!cf.includes(piece), `the component must not retype "${piece}": it lives in the copy module only`);
});

test('SG3 THE OLD PHRASES CANNOT RETURN: nowhere in the non-test source', () => {
  const OLD = ['the server never sees the piece', 'never sees the piece', 'can help you restore', 'It\'s encrypted in your browser',
    'of your keepers restore you', 'lets any'];
  const hits: string[] = [];
  const walk = (dir: string): void => {
    for (const n of readdirSync(dir)) {
      const p = join(dir, n);
      if (statSync(p).isDirectory()) { if (n !== 'node_modules') walk(p); }
      else if (/\.(ts|tsx)$/.test(n) && !/\.(test|spec|selftest)\.tsx?$/.test(n)) {
        const t = stripComments(readFileSync(p, 'utf8')).replace(/\s+/g, ' ');
        for (const o of OLD) if (t.includes(o)) hits.push(`${p.slice(SRC.length + 1)}: ${o}`);
      }
    }
  };
  walk(SRC);
  assert.deepEqual(hits, []);
});

test('SG4 THE LINK NOTE STAYS TRUE (row 226c): it says the link and the QR code carry the key, and is never softened toward "one-time" or "the server cannot see it"', () => {
  assert.ok(SHARD_LINK_NOTE.includes('the key is in the link itself'));
  assert.ok(SHARD_LINK_NOTE.includes('anyone with this link or QR code can open the piece'));
  assert.ok(SHARD_LINK_NOTE.includes('Send it only through a channel you trust.'));
  for (const bad of ['once opened', 'first to open', 'whoever opens it first', 'one-time', 'only once', 'never sees', 'cannot see', 'can\'t see', 'no server', 'zero-knowledge']) {
    assert.ok(!SHARD_LINK_NOTE.toLowerCase().includes(bad), `the note must not say "${bad}"`);
  }
});

test('SG5 THE ALL-GIVEN LINE PROMISES NO RESTORE: it says the keepers together hold enough to rebuild the key and that collecting back is not built', () => {
  const line = shardAllGivenLine(5, 3);
  assert.ok(line.includes('together hold enough to rebuild your recovery key'));
  assert.ok(line.includes('Collecting the pieces back isn\'t in the app yet.'));
  for (const bad of ['restore', 'can help', 'recover your', 'get them back']) assert.ok(!line.toLowerCase().includes(bad), `the line must not say "${bad}"`);
});

test('SG6 the copy module is a leaf: no imports in any form', () => {
  const text = stripComments(readFileSync(join(HERE, 'shard-give-copy.ts'), 'utf8'));
  assert.ok(!/(?:^|[\s;])import\s+(?:[^'"()]*?\s+from\s+)?['"]/m.test(text), 'no import statement');
  assert.ok(!/\b(?:import|require)\s*\(/.test(text), 'no dynamic import or require');
});

test('SG7 the ready line is the copy owner\'s words byte for byte (row 249a): hashes, plain ASCII, exact interpolation, one form per count', () => {
  const sha = (t: string): string => createHash('sha256').update(t).digest('hex');
  const one = shardReadyLine(1, 5, 3);
  const many = shardReadyLine(5, 5, 3);
  assert.equal(one, "You hold 1 un-given piece of 5. Any 3 of your keepers together hold enough to rebuild your recovery key; no single piece can, not even theirs. Collecting the pieces back isn't in the app yet.");
  assert.equal(many, "You hold 5 un-given pieces of 5. Any 3 of your keepers together hold enough to rebuild your recovery key; no single piece can, not even theirs. Collecting the pieces back isn't in the app yet.");
  // the frozen hashes are of the TEMPLATE with its placeholders literal
  assert.ok(sha(one.replace('1 un-given piece of 5', '{remaining} un-given piece of {total}').replace('Any 3', 'Any {threshold}')).startsWith('cdedd700e20d8d8b'));
  assert.ok(sha(many.replace('5 un-given pieces of 5', '{remaining} un-given pieces of {total}').replace('Any 3', 'Any {threshold}')).startsWith('a66e2f17e5863486'));
  for (const [r, t, th] of [[2, 5, 3], [3, 3, 2], [4, 10, 7]] as const) {
    assert.equal(shardReadyLine(r, t, th), `You hold ${r} un-given pieces of ${t}. Any ${th} of your keepers together hold enough to rebuild your recovery key; no single piece can, not even theirs. Collecting the pieces back isn't in the app yet.`);
  }
  for (const t of [one, many]) assert.ok(/^[\x20-\x7e]+$/.test(t), 'pure ASCII');
});

test('SG8 THE THREE PLACES SAY THE SAME THING: the ready line and the all-given line share one clause about what the keepers hold, and neither promises a restore (row 237 drops its second sentence when collect-back ships)', () => {
  const clause = 'of your keepers together hold enough to rebuild your recovery key';
  assert.ok(shardReadyLine(5, 5, 3).includes(clause));
  assert.ok(shardAllGivenLine(5, 3).includes(clause));
  for (const t of [shardReadyLine(1, 5, 3), shardReadyLine(5, 5, 3)]) {
    assert.ok(t.includes("Collecting the pieces back isn't in the app yet."));
    for (const bad of ['restore', 'can help', 'recover your', 'get them back']) assert.ok(!t.toLowerCase().includes(bad), `the ready line must not say "${bad}"`);
  }
});
