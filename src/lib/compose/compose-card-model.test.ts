// Run: npx tsx --test src/lib/compose/compose-card-model.test.ts
// The sign card as data. Fixtures go through the REAL queue and validator, so a card is only ever built from something the app would really accept.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emptyQueue, enqueue, current, type QueueItem } from './compose-queue';
import { buildCardModel, segmentWithMarkers, type SignCardModel, type RefusedCardModel, type DeriveWords } from './compose-card-model';
import { CARD_COPY } from './compose-card-copy';

const T0 = new Date('2026-10-25T07:20:00.000Z');
const nonceN = (n: number) => n.toString(16).padStart(32, '0');
const base = { nonce: nonceN(1), issued_at: '2026-10-25T07:20:00.000Z', expires_at: '2026-10-25T07:25:00.000Z', origin: 'noosphere.nuavalon.com' };
const post = (over: Record<string, string> = {}) => ({ purpose: 'svrnty-loom-post-v1', fleet: 'autobots', thread: 'lane:ops', body: 'hello there', ...base, ...over });
const task = (over: Record<string, string> = {}) => ({ purpose: 'svrnty-loom-task-v1', fleet: 'autobots', thread: 'lane:orch', title: 'Fix the poller', body: 'It polls too often.', target: 'route', ...base, ...over });
const WORDS: DeriveWords = () => ['alpha', 'bravo', 'charlie', 'delta'];
function itemOf(raw: unknown): QueueItem {
  const { state, result } = enqueue(emptyQueue(), raw, T0);
  assert.equal(result.outcome, 'queued', JSON.stringify(result));
  const it = current(state, T0);
  assert.ok(it);
  return it;
}
// `null` means "no derivation function" (a default parameter would swallow `undefined` and silently substitute WORDS).
const sign = (raw: unknown, words: DeriveWords | null = WORDS, opts = {}) => buildCardModel(itemOf(raw), words ?? undefined, opts) as SignCardModel;
const allStrings = (m: object): string[] => Object.values(m).flatMap((v) => (typeof v === 'string' ? [v] : Array.isArray(v) ? v.flatMap((x) => (typeof x === 'object' && x ? Object.values(x).filter((y) => typeof y === 'string') : [])) : []));

test('POST card: every element is Hypatia\'s string; location is `<fleet> · <thread>`; the body is the request body EXACTLY; Approve exists', () => {
  const m = sign(post());
  assert.equal(m.mode, 'sign');
  assert.equal(m.kind, 'post');
  assert.equal(m.title, 'Sign a message for noosphere');
  assert.equal(m.intro, 'noosphere.nuavalon.com asks you to sign this message, as you, into:');
  assert.equal(m.location, 'autobots · lane:ops');
  assert.equal(m.body, 'hello there');
  assert.equal(m.wordsLine, 'Check these words match the portal: alpha bravo charlie delta');
  assert.equal(m.approve, 'Sign and post as me');
  assert.equal(m.decline, "Don't sign");
  assert.equal(m.footnote, 'Your signature makes this message yours. Only sign text you wrote and can see in full above.');
  assert.equal(m.toLine, null); assert.equal(m.taskTitle, null); assert.equal(m.linkedLine, null);
  assert.equal(m.weftNotice, null); assert.equal(m.noWordsNotice, null);
});

test('TASK card: its own strings; `To:` the agent or the orchestrator; the title and body exactly; `Linked to step` only when present', () => {
  const a = sign(task({ target: 'apollo' }));
  assert.equal(a.kind, 'task');
  assert.equal(a.title, 'Sign a task request for noosphere');
  assert.equal(a.intro, 'noosphere.nuavalon.com asks you to sign this request, as you:');
  assert.equal(a.toLine, 'To: apollo');
  assert.equal(a.taskTitle, 'Fix the poller');
  assert.equal(a.body, 'It polls too often.');
  assert.equal(a.linkedLine, null);
  assert.equal(a.location, null);
  assert.equal(a.approve, 'Sign the request as me');
  assert.equal(a.footnote, 'This posts a signed request. Nothing is assigned until an agent accepts it and creates the task.');
  assert.equal(sign(task({ target: 'route' })).toLine, 'To: the orchestrator, to route');
  assert.equal(sign(task({ dag_node: 'D-N12' })).linkedLine, 'Linked to step: D-N12');
});

test('WYSIWYS: the body is shown in FULL and unchanged: newlines, quotes, emoji (incl. an allowed ZWJ sequence), and a long body are never shortened or rewritten', () => {
  const hard = 'line one\nline "two" \\ back\n👨‍👩‍👧 family ❤️‍🔥 heat 👩🏽‍💻 dev\n  indented  and  double  spaces';
  assert.equal(sign(post({ body: hard })).body, hard);
  const long = 'x'.repeat(2800);
  assert.equal(sign(post({ body: long })).body, long);
  assert.equal(sign(task({ title: 'T "q" 👨‍👩‍👧', body: hard })).taskTitle, 'T "q" 👨‍👩‍👧');
});

test('FAIL CLOSED on the words: no function, a throwing function, and any answer that is not exactly four plain words -> NO Approve, no words line, a plain notice', () => {
  const cases: Array<[string, DeriveWords | null]> = [
    ['no function', null],
    ['throws', () => { throw new Error('boom'); }],
    ['three words', () => ['a', 'b', 'c']],
    ['five words', () => ['a', 'b', 'c', 'd', 'e']],
    ['empty word', () => ['a', 'b', '', 'd']],
    ['a word with a space', () => ['a', 'b c', 'd', 'e']],
    ['non-string word', () => ['a', 'b', 3 as unknown as string, 'd']],
    ['not an array', () => 'a b c d' as unknown as string[]],
  ];
  for (const [name, fn] of cases) {
    const m = sign(post(), fn);
    assert.equal(m.approve, null, `${name}: no Approve`);
    assert.equal(m.wordsLine, null, `${name}: no words line`);
    assert.equal(m.noWordsNotice, CARD_COPY.noWords, `${name}: the notice`);
    assert.equal(m.decline, "Don't sign", `${name}: Decline stays`);
  }
});

test('WEFT is view-only: the notice shows and there is NO Approve even with valid words; once the Weft side accepts, Approve returns and the notice goes', () => {
  const w = sign(post({ fleet: 'weft' }));
  assert.equal(w.weftNotice, 'View only: replying into the Weft needs their side to accept signed posts (not built yet).');
  assert.equal(w.approve, null);
  assert.equal(w.location, 'weft · lane:ops');
  const ok = sign(post({ fleet: 'weft' }), WORDS, { weftAccepted: true });
  assert.equal(ok.weftNotice, null);
  assert.equal(ok.approve, 'Sign and post as me');
  assert.equal(sign(post({ fleet: 'weft' }), WORDS, { weftAccepted: false }).approve, null);
});

test('REFUSED card (hidden characters): the notice, ONLY Close, no Approve of any kind; the offending text appears with [U+XXXX] markers and the character itself is never emitted', () => {
  const evil = 'pay‮now​ ok';
  const m = buildCardModel(itemOf(post({ body: evil })), WORDS) as RefusedCardModel;
  assert.equal(m.mode, 'refused');
  assert.equal(m.notice, "Can't sign this message: it contains hidden characters that can change how text looks (shown below as [U+202E] etc.). Write it again in the portal without them.");
  assert.equal(m.close, 'Close');
  assert.equal('approve' in m, false);
  assert.equal(m.field, 'body');
  const joined = m.segments.map((s) => s.text).join('');
  assert.equal(joined, 'pay[U+202E]now[U+200B] ok');
  assert.deepEqual(m.segments.filter((s) => s.marker).map((s) => s.text), ['[U+202E]', '[U+200B]']);
  assert.doesNotMatch(joined, /[‮​]/, 'the refused characters must not be in the output');
});

test('REFUSED task TITLE with a hidden character: a Close-only card, the field says `title`, the markers are in the title text', () => {
  const m = buildCardModel(itemOf(task({ title: 'Fix\u200Bit' })), WORDS) as RefusedCardModel;
  assert.equal(m.mode, 'refused');
  assert.equal(m.field, 'title');
  assert.equal(m.segments.map((s) => s.text).join(''), 'Fix[U+200B]it');
  assert.equal('approve' in m, false);
});

test('A THREAD id with a hidden character makes NO CARD at all: the thread-charset check drops it before the hidden-character check (so the doc row "Thread id shown literally with markers" is unreachable as built)', () => {
  const { state, result } = enqueue(emptyQueue(), post({ thread: 'lane:o\u200Bps' }), T0);
  assert.deepEqual(result, { outcome: 'dropped', code: 'bad-thread' });
  assert.deepEqual(state.pending, []);
});

test('a refusal whose text is unavailable still has the notice and Close, with no segments (never a guess)', () => {
  const it = itemOf(post({ body: 'a‮b' }));
  assert.equal(it.kind, 'refusal');
  const stripped = { ...it, shownText: undefined } as QueueItem;
  const m = buildCardModel(stripped, WORDS) as RefusedCardModel;
  assert.deepEqual(m.segments, []);
  assert.equal(m.close, 'Close');
});

test('segmentWithMarkers: indices are CODE POINTS (an emoji counts once), markers are uppercase hex padded to 4, astral/TAG characters keep their full hex', () => {
  assert.deepEqual(segmentWithMarkers('a😀b‮c', [3]), [{ text: 'a😀b', marker: false }, { text: '[U+202E]', marker: true }, { text: 'c', marker: false }]);
  assert.deepEqual(segmentWithMarkers('\u0007x', [0]), [{ text: '[U+0007]', marker: true }, { text: 'x', marker: false }]);
  assert.deepEqual(segmentWithMarkers('a\u{E0041}', [1]), [{ text: 'a', marker: false }, { text: '[U+E0041]', marker: true }]);
  assert.deepEqual(segmentWithMarkers('‮‭', [0, 1]).map((s) => s.text), ['[U+202E]', '[U+202D]']);
  assert.deepEqual(segmentWithMarkers('plain', []), [{ text: 'plain', marker: false }]);
  assert.deepEqual(segmentWithMarkers('', [0]), []);
});

test('the card never uses the words doc §5 forbids (sent, delivered, secure, verified, end-to-end, auto-approve, quantum) in any element', () => {
  const FORBIDDEN = /\b(sent|delivered|secure|verified|end-to-end|auto-approve|quantum)\b/i;
  for (const m of [sign(post()), sign(task()), sign(post({ fleet: 'weft' })), sign(post(), null), buildCardModel(itemOf(post({ body: 'a‮b' })), WORDS) as RefusedCardModel]) {
    for (const s of allStrings(m)) assert.doesNotMatch(s, FORBIDDEN, s);
  }
  assert.match('Delivered', /\b(sent|delivered)\b/i, 'control: the pattern is not dead');
});
