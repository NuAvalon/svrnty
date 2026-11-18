// Run: npx tsx --test src/components/shard-give-copy.test.ts
// The "give a recovery piece" dialog's two sentences (copy ledger rows 226a and 237) are pinned byte for byte here, apart from the module that holds them. The component is checked
// as source (the repo has no component renderer): it renders the constants, and the old phrases cannot come back anywhere in the source.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SHARD_COUNT_MAX, SHARD_COUNT_UNUSABLE, SHARD_LINK_FAILED, SHARD_LINK_NOTE, SHARD_READ_FAILED, shardAllGivenLine, shardCountUsable, shardReadyLine } from './shard-give-copy';

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
  once("import { SHARD_COUNT_UNUSABLE, SHARD_LINK_FAILED, SHARD_LINK_NOTE, SHARD_READ_FAILED, shardAllGivenLine, shardCountUsable, shardReadyLine } from './shard-give-copy';");
  once('{SHARD_LINK_NOTE}');
  once('{shardAllGivenLine(total, threshold)}');          // the arguments are pinned: swapping them would print the wrong numbers
  once('{shardReadyLine(remaining, total, threshold)}');
  once('setError(SHARD_READ_FAILED);');
  once('setError(SHARD_LINK_FAILED);');
  for (const name of ['SHARD_LINK_NOTE', 'shardAllGivenLine', 'shardReadyLine', 'SHARD_READ_FAILED', 'SHARD_LINK_FAILED']) {
    assert.equal(c.split(name).length - 1, 2, `${name} appears only in the import and the one use`);
  }
  // No retyped piece of either sentence: the pieces are taken from the module's own text (split at the numbers and at . ; ,), so any part of it is covered.
  const flat = (t: string): string => t.replace(/\s+/g, ' ');
  const pieces = [SHARD_LINK_NOTE, shardAllGivenLine(777, 555), shardReadyLine(333, 777, 555), shardReadyLine(1, 777, 555), SHARD_READ_FAILED, SHARD_LINK_FAILED]
    .flatMap((t) => t.split(/777|555|333|[.;,]/))
    .map((t) => flat(t).trim())
    .filter((t) => t.length >= 18);
  assert.ok(pieces.length >= 5, `expected several pieces to check, got ${pieces.length}`);
  const cf = flat(c);
  for (const piece of pieces) assert.ok(!cf.includes(piece), `the component must not retype "${piece}": it lives in the copy module only`);
});

test('SG3 THE OLD PHRASES CANNOT RETURN: nowhere in the non-test source', () => {
  const OLD = ['the server never sees the piece', 'never sees the piece', 'can help you restore', 'It\'s encrypted in your browser',
    'Could not read your recovery shards', 'Failed to create the recovery link', 'of your keepers restore you', 'lets any'];
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

test('SG7 the two failure sentences are the copy owner\'s words byte for byte (row 249b): hashes and plain ASCII', () => {
  const sha = (t: string): string => createHash('sha256').update(t).digest('hex');
  assert.equal(SHARD_READ_FAILED, 'Your recovery pieces could not be read on this device.');
  assert.equal(SHARD_LINK_FAILED, 'The recovery link could not be created. Try again.');
  assert.ok(sha(SHARD_READ_FAILED).startsWith('87cec57c2e11733c'));
  assert.ok(sha(SHARD_LINK_FAILED).startsWith('9d75021f49626660'));
  for (const t of [SHARD_READ_FAILED, SHARD_LINK_FAILED]) assert.ok(/^[\x20-\x7e]+$/.test(t), 'pure ASCII');
});

test('SG8 THE DIALOG SHOWS NO ERROR TEXT: it reads no .message, and its two catches log by tag only and show the fixed sentence', () => {
  const c = component();
  assert.ok(!/\.message\b/.test(c), 'the dialog must not read an error\'s own text');
  assert.equal(c.split("console.error('Recovery pieces read failed:', errorTag(err));").length - 1, 1);
  assert.equal(c.split("console.error('Recovery link failed:', errorTag(err));").length - 1, 1);
  assert.equal(c.split("import { errorTag } from '@/lib/error-tag';").length - 1, 1);
});

test('SG9 the ready line is the copy owner\'s words byte for byte (row 249a): hashes, plain ASCII, exact interpolation, one form per count', () => {
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

test('SG10 THE THREE PLACES SAY THE SAME THING: the ready line and the all-given line share one clause about what the keepers hold, and neither promises a restore (row 237 drops its second sentence when collect-back ships)', () => {
  const clause = 'of your keepers together hold enough to rebuild your recovery key';
  assert.ok(shardReadyLine(5, 5, 3).includes(clause));
  assert.ok(shardAllGivenLine(5, 3).includes(clause));
  for (const t of [shardReadyLine(1, 5, 3), shardReadyLine(5, 5, 3)]) {
    assert.ok(t.includes("Collecting the pieces back isn't in the app yet."));
    for (const bad of ['restore', 'can help', 'recover your', 'get them back']) assert.ok(!t.toLowerCase().includes(bad), `the ready line must not say "${bad}"`);
  }
});

// ---- #893: the render-time guard (copy ledger row 258a). Pairs are [total, threshold]; the second list holds what a stored record could hold that the types say it cannot.
const UNUSABLE: Array<[unknown, unknown]> = [[5, 1], [5, 0], [5, -1], [5, 6], [5, 3.5], [5, NaN], [5, Infinity], [5, -Infinity], [5, '3'], [5, null], [5, undefined], [5, true], [5, [3]], [5, {}],
  [NaN, 3], [5.5, 3], ['5', 3], [undefined, 3], [null, 3], [Infinity, 3], [0, 0], [1, 1], [2, 3], [-5, 2], [undefined, undefined], [256, 3], [256, 256], [1e20, 3], [1000, 3]];
const USABLE: Array<[number, number]> = [[5, 3], [3, 2], [2, 2], [10, 10], [10, 2], [5, 5], [100, 51], [255, 3], [255, 255], [254, 3]];

test('SG11 THE FALLBACK SENTENCE is the copy owner\'s words byte for byte (row 258a): 189 plain-ASCII characters, the frozen hash, no digit, no "no single piece" clause, and the honest tail of row 237', () => {
  assert.equal(SHARD_COUNT_UNUSABLE, "This set of recovery pieces doesn't record a usable count, so this device can't tell how many keepers it takes to rebuild your recovery key. Collecting the pieces back isn't in the app yet.");
  assert.equal(SHARD_COUNT_UNUSABLE.length, 189);
  assert.ok(/^[\x20-\x7e]+$/.test(SHARD_COUNT_UNUSABLE), 'pure ASCII, no smart quotes or dashes');
  assert.ok(createHash('sha256').update(SHARD_COUNT_UNUSABLE).digest('hex').startsWith('084a0b2d3c97bb1f'));
  assert.ok(!/\d/.test(SHARD_COUNT_UNUSABLE), 'no number in it');
  assert.ok(!SHARD_COUNT_UNUSABLE.includes('no single piece'));
  assert.ok(!SHARD_COUNT_UNUSABLE.includes('together hold enough'), 'it makes no claim about what any number of keepers hold');
  assert.ok(SHARD_COUNT_UNUSABLE.endsWith("Collecting the pieces back isn't in the app yet."));
});

test('SG12 THE GUARD: a usable count is an integer threshold with 2 <= threshold <= total and an integer total; everything else is refused, including every shape a stored record could hold', () => {
  for (const [total, threshold] of USABLE) assert.equal(shardCountUsable(total, threshold), true, `usable: ${total} / ${threshold}`);
  for (const [total, threshold] of UNUSABLE) assert.equal(shardCountUsable(total as number, threshold as number), false, `unusable: ${String(total)} / ${String(threshold)}`);
  assert.equal(shardCountUsable(5, 6), false, 'one above the total');
  assert.equal(shardCountUsable(5, 5), true, 'exactly the total');
  assert.equal(shardCountUsable(5, 2), true, 'exactly 2');
  assert.equal(shardCountUsable(5, 1), false, 'one below 2');
});

test('SG13 BOTH LINES SHOW THE ONE SENTENCE when the count is unusable, whatever the number of pieces left, and it is the same bytes in both places', () => {
  for (const [total, threshold] of UNUSABLE) {
    for (const remaining of [0, 1, 3, 5, NaN]) {
      const ready = shardReadyLine(remaining, total as number, threshold as number);
      assert.equal(ready, SHARD_COUNT_UNUSABLE, `ready: ${String(total)} / ${String(threshold)} / ${remaining}`);
    }
    assert.equal(shardAllGivenLine(total as number, threshold as number), SHARD_COUNT_UNUSABLE, `all-given: ${String(total)} / ${String(threshold)}`);
  }
});

test('SG14 A USABLE RECORD IS UNCHANGED: a real 3 of 5 still shows its numbers and its own sentences, never the fallback', () => {
  for (const [total, threshold] of USABLE) {
    const all = shardAllGivenLine(total, threshold);
    const ready = shardReadyLine(2, total, threshold);
    assert.notEqual(all, SHARD_COUNT_UNUSABLE);
    assert.notEqual(ready, SHARD_COUNT_UNUSABLE);
    assert.ok(all.includes(`all ${total} of your pieces`) && all.includes(`Any ${threshold} of your keepers`), `numbers in the all-given line: ${total}/${threshold}`);
    assert.ok(ready.includes(`of ${total}.`) && ready.includes(`Any ${threshold} of your keepers`) && ready.includes('no single piece can'), `numbers in the ready line: ${total}/${threshold}`);
  }
});

test('SG15 THE GUARD IS PER RECORD (Archie #209178): the dialog takes ONE validity decision per render, every derived line asks it, and nothing in the dialog re-derives it or inlines the fallback', () => {
  const c = component();
  const count = (needle: string): number => c.split(needle).length - 1;
  assert.equal(count('const countUsable = shardCountUsable(total, threshold);'), 1, 'one decision, with the stored total and threshold in that order');
  assert.equal(count('shardCountUsable'), 2, 'shardCountUsable appears only in the import and that one call');
  assert.equal(count('{countUsable'), 2, 'the already-held line and the link screen ask the decision, and nothing else does');
  assert.equal(count(' already holds a piece of your recovery. {countUsable'), 1, 'the already-held line keeps its first sentence (who holds a piece), and only its second asks the decision');
  assert.equal(count("'One piece per contact keeps any single person below your restore threshold.'"), 1, 'the second sentence is unchanged, shown only for a usable record');
  assert.equal(count('SHARD_COUNT_UNUSABLE'), 3, 'the fallback appears only in the import and the two places the dialog shows it itself (already-held, link screen); the ready and all-given lines get it from the leaf');
  assert.ok(!c.includes('usable count'), 'the sentence is not inlined in the dialog');
  assert.ok(!/\b(?:threshold|total)\s*(?:<=?|>=?|===?|!==?)/.test(c) && !/Number\.isInteger/.test(c), 'the dialog does not compare or validate the stored numbers itself');
  assert.ok(!/Any \$\{/.test(c), 'the dialog does not interpolate a threshold into a sentence of its own');
});

test('SG16 WHICH SENTENCES THE GUARD SUPPRESSES (row 281): only the ones whose content comes from the record; the link screen keeps its safety instruction, the already-held line keeps who holds a piece', () => {
  const c = component().replace(/\s+/g, ' ');
  const count = (needle: string): number => c.split(needle).length - 1;
  // 281c: the safety instruction and the validity sentence are OUTSIDE the conditional; only the derived sentence is inside it, and the fallback follows it once
  assert.equal(count('Share this link only with {contact.name}. It stays valid for up to 7 days. {countUsable ? <>{contact.name} now holds 1 of your {total} pieces.</> : SHARD_COUNT_UNUSABLE}'), 1);
  assert.equal(count('Share this link only with'), 1, 'the safety instruction appears once and nowhere under the guard');
  assert.equal(count('It stays valid for up to 7 days.'), 1);
  assert.equal(count('now holds 1 of your {total} pieces.'), 1, 'the derived sentence is shown only for a usable record');
  // 281b: who holds a piece is kept; the threshold sentence is the guarded one
  assert.equal(count('{contact.name} already holds a piece of your recovery. {countUsable ? \'One piece per contact keeps any single person below your restore threshold.\' : SHARD_COUNT_UNUSABLE}'), 1);
  // 281a + all-given: the whole line comes from the leaf (SG13), and the dialog adds nothing around it
  assert.equal(count('{shardReadyLine(remaining, total, threshold)}'), 1);
  assert.equal(count('{shardAllGivenLine(total, threshold)}'), 1);
});

test('SG17 THE UPPER BOUND (row 286): a total above what createShards can make is unusable, the boundary is exact, and the constant is the one recovery.ts enforces', () => {
  assert.equal(SHARD_COUNT_MAX, 255);
  assert.equal(shardCountUsable(255, 3), true, 'exactly the maximum');
  assert.equal(shardCountUsable(255, 255), true);
  assert.equal(shardCountUsable(256, 3), false, 'one above');
  assert.equal(shardCountUsable(256, 256), false, 'threshold equal to an impossible total');
  assert.equal(shardCountUsable(1e20, 3), false, 'a corrupted or hand-edited total');
  assert.equal(shardCountUsable(254, 3), true);
  assert.equal(shardReadyLine(5, 256, 3), SHARD_COUNT_UNUSABLE);
  assert.equal(shardAllGivenLine(1e20, 3), SHARD_COUNT_UNUSABLE);
  const recovery = readFileSync(join(SRC, 'lib', 'crypto', 'recovery.ts'), 'utf8');
  assert.ok(recovery.includes(`if (totalShares > ${SHARD_COUNT_MAX}) throw`), 'the limit createShards enforces is the same number, so the two cannot drift apart unseen');
});
