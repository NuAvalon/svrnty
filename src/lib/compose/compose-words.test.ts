// Run: npx tsx --test src/lib/compose/compose-words.test.ts
// compose-words v1 (Flint lane:portal #1465): words = SAS(request). The VECTORS below were computed by an INDEPENDENT Python reference (hashlib + a hand-rolled
// JCS, no TS imported), so this file proves the TS side reproduces numbers it did not produce. The portal pins the same vectors.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { composeWordIndices, composeWordsPreimage, deriveComposeWords, hasLoneSurrogate, wordListIsPinned, WORDS_DOMAIN } from './compose-words';
import { BIP39_ENGLISH, BIP39_ENGLISH_SHA256 } from './compose-wordlist';
import { buildCardModel } from './compose-card-model';
import { emptyQueue, enqueue, current } from './compose-queue';

const base = { nonce: '0'.repeat(31) + '1', issued_at: '2026-10-25T07:20:00.000Z', expires_at: '2026-10-25T07:25:00.000Z', origin: 'noosphere.nuavalon.com' };
const post = (o: Record<string, string> = {}): Record<string, string> => ({ purpose: 'svrnty-loom-post-v1', fleet: 'autobots', thread: 'lane:ops', body: 'hello there', ...base, ...o });
const task = (o: Record<string, string> = {}): Record<string, string> => ({ purpose: 'svrnty-loom-task-v1', fleet: 'autobots', thread: 'lane:orch', title: 'Fix the poller', body: 'It polls too often.', target: 'route', ...base, ...o });

const VEC: Record<string, { idx: number[]; words: string[]; digest: string }> = {
  "V1 plain post": { idx: [211, 1537, 863, 1577], words: ["bounce", "scan", "hip", "share"], digest: "1a7805afe291222a6283e7e26ec2ce26e713b266309b89ae1cebb9673a7855d3" },
  "V2 non-BMP+combining": { idx: [98, 175, 1238, 278], words: ["arrange", "bicycle", "onion", "carpet"], digest: "0c42be6b1162c0edeaaca8cd1c082c5a9d8e5f8faa294ffd81f2af9727726788" },
  "V3a NFC": { idx: [1523, 685, 2023, 826], words: ["salmon", "fiber", "woman", "guard"], digest: "be6ab7f3b3ac1edcf66a6ef915cd84d474603ea48aa7e280e419f8776e968abe" },
  "V3b NFD": { idx: [623, 1493, 255, 1267], words: ["evil", "rival", "cable", "oyster"], digest: "4df7547fcf3ee783d7ba4c41db26f55bf55a382fddc8ce8737ca6196f81def1d" },
  "V4 task": { idx: [1566, 912, 1140, 362], words: ["sense", "improve", "model", "coil"], digest: "c3ce423a16a50bf436ea078afca28a3e7919094525bfe8506acd3519594608f5" },};
const OBJ: Record<string, Record<string, string>> = {
  'V1 plain post': post(),
  'V2 non-BMP+combining': post({ body: 'café \u{1F600} \u{1D4B3} end' }),
  'V3a NFC': post({ body: 'café' }),
  'V3b NFD': post({ body: 'café' }),
  'V4 task': task({ dag_node: 'D-N12' }),
};

test('the pinned word list is the upstream BIP-39 English file: 2048 unique words, sha256 matches the pin, and the load-time check agrees', () => {
  assert.equal(BIP39_ENGLISH.length, 2048);
  assert.equal(new Set(BIP39_ENGLISH).size, 2048);
  assert.equal(BIP39_ENGLISH_SHA256, '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda');
  assert.equal(bytesToHex(sha256(utf8ToBytes(BIP39_ENGLISH.join('\n') + '\n'))), BIP39_ENGLISH_SHA256);
  assert.equal(BIP39_ENGLISH[0], 'abandon'); assert.equal(BIP39_ENGLISH[2047], 'zoo');
  assert.equal(wordListIsPinned(), true);
});

test('W1: the preimage is u16be(len(D)) || D || JCS(request), JCS last; the digest is its SHA-256', () => {
  const o = post();
  const pre = composeWordsPreimage(o);
  const D = utf8ToBytes(WORDS_DOMAIN);
  assert.equal(WORDS_DOMAIN, 'svrnty:compose-words:v1');
  assert.deepEqual([pre[0], pre[1]], [0, D.length]);
  assert.deepEqual(Array.from(pre.slice(2, 2 + D.length)), Array.from(D));
  const jcsText = new TextDecoder().decode(pre.slice(2 + D.length));
  assert.equal(jcsText, '{"body":"hello there","expires_at":"2026-10-25T07:25:00.000Z","fleet":"autobots","issued_at":"2026-10-25T07:20:00.000Z","nonce":"00000000000000000000000000000001","origin":"noosphere.nuavalon.com","purpose":"svrnty-loom-post-v1","thread":"lane:ops"}');
  assert.equal(bytesToHex(sha256(pre)), VEC['V1 plain post'].digest);
});

test('W2/W5 VECTORS (from the independent Python reference): digest, the four 11-bit indices and the four words, for a plain post, non-BMP + combining characters, and a task with dag_node', () => {
  for (const name of ['V1 plain post', 'V2 non-BMP+combining', 'V4 task']) {
    const v = VEC[name];
    assert.equal(bytesToHex(sha256(composeWordsPreimage(OBJ[name]))), v.digest, name + ' digest');
    assert.deepEqual(composeWordIndices(OBJ[name]), v.idx, name + ' indices');
    assert.deepEqual(deriveComposeWords(OBJ[name]), v.words, name + ' words');
  }
});

test('W5: JCS does NOT normalise Unicode: NFC and NFD of the same visible text give DIFFERENT words (fail-visible, correct), both pinned', () => {
  assert.deepEqual(deriveComposeWords(OBJ['V3a NFC']), VEC['V3a NFC'].words);
  assert.deepEqual(deriveComposeWords(OBJ['V3b NFD']), VEC['V3b NFD'].words);
  assert.notDeepEqual(VEC['V3a NFC'].words, VEC['V3b NFD'].words);
  assert.equal('café'.normalize('NFD'), 'café', 'precondition: they really are NFC/NFD of each other');
});

test('W5: the same fields in a DIFFERENT KEY ORDER give identical words (the hash is over the canonical form, not insertion order)', () => {
  const o = post();
  const rev = Object.fromEntries(Object.entries(o).reverse());
  assert.notDeepEqual(Object.keys(rev), Object.keys(o), 'precondition: the order really differs');
  assert.deepEqual(deriveComposeWords(rev), deriveComposeWords(o));
});

test('every field is bound: changing any one signed field (body, thread, nonce, a time, origin, fleet) changes the words', () => {
  const w0 = deriveComposeWords(post()).join(' ');
  for (const [k, v] of Object.entries({ body: 'hello there!', thread: 'lane:portal', nonce: '0'.repeat(31) + '2', issued_at: '2026-10-25T07:20:00.001Z', expires_at: '2026-10-25T07:25:00.001Z', fleet: 'weft', origin: 'noosphere.nuavalon.org' })) {
    assert.notEqual(deriveComposeWords(post({ [k]: v })).join(' '), w0, k + ' must be bound');
  }
});

test('W4 FAIL CLOSED: a lone surrogate in ANY field -> an EMPTY list (no words), never a throw; control: the same text with a valid pair gives words', () => {
  for (const bad of ['\ud800', 'a\udc00b', 'x\ud83dy', '\udc00\ud800']) {
    assert.equal(hasLoneSurrogate(bad), true, JSON.stringify(bad));
    assert.deepEqual(deriveComposeWords(post({ body: bad })), []);
    assert.deepEqual(deriveComposeWords(post({ thread: bad })), []);
  }
  assert.equal(hasLoneSurrogate('😀'), false);
  assert.equal(deriveComposeWords(post({ body: '😀' })).length, 4);
});

test('W4 FAIL CLOSED: a non-string value, a non-ASCII key, or a corrupted word list -> no words', () => {
  assert.deepEqual(deriveComposeWords({ ...post(), extra: 5 as unknown as string }), []);
  assert.deepEqual(deriveComposeWords({ ...post(), 'kéy': 'v' }), []);
  const broken = [...BIP39_ENGLISH]; broken[7] = 'tampered';
  assert.equal(wordListIsPinned(broken, BIP39_ENGLISH_SHA256), false, 'one changed word breaks the pin');
  assert.equal(wordListIsPinned(BIP39_ENGLISH.slice(0, 2047), BIP39_ENGLISH_SHA256), false);
});

test('the words are always 4 distinct-shape list words (lowercase a-z, 3-8 letters) over many requests, and every index is in range', () => {
  for (let n = 0; n < 300; n++) {
    const w = deriveComposeWords(post({ nonce: n.toString(16).padStart(32, '0') }));
    assert.equal(w.length, 4);
    for (const x of w) assert.match(x, /^[a-z]{3,8}$/);
    for (const i of composeWordIndices(post({ nonce: n.toString(16).padStart(32, '0') }))) assert.ok(i >= 0 && i < 2048);
  }
});

test('WIRED INTO THE CARD: the real derivation gives the card its words line and Approve; a corrupted derivation (empty list) leaves NO Approve', () => {
  const { state } = enqueue(emptyQueue(), post(), new Date('2026-10-25T07:20:00.000Z'));
  const item = current(state, new Date('2026-10-25T07:20:00.000Z'))!;
  const ok = buildCardModel(item, deriveComposeWords, { wordsConfirmed: true }) as { wordsLine: string | null; approve: string | null };
  assert.equal(ok.wordsLine, 'Check these words match the portal: ' + VEC['V1 plain post'].words.join(' '));
  assert.equal(ok.approve, 'Sign and post as me');
  const unconfirmed = buildCardModel(item, deriveComposeWords) as { approve: string | null };
  assert.equal(unconfirmed.approve, null, 'the production switch is off by default: perfect words, still no Approve');
  const closed = buildCardModel(item, () => [], { wordsConfirmed: true }) as { approve: string | null };
  assert.equal(closed.approve, null);
});
