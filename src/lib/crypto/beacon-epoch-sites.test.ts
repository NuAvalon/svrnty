// beacon-epoch-sites: every place that reads the client's idea of which epochs are open is CLASSIFIED, so a new one cannot appear without a decision.
// Run: npx tsx --test src/lib/crypto/beacon-epoch-sites.test.ts
//
// Two kinds of place, and they must not be mixed up:
//   - MARGIN sites decide how long to KEEP something that may still matter at the relay (drop a row, give up on a withdraw, release a seed, plan a withdraw).
//     They use relayDead / epochsToPlanAt: the relay's own clock rule PLUS its skew margin, so a device clock running ahead cannot act early.
//   - READ / MINT sites report or choose what the relay will honour NOW (is there a match, which epochs to poll, which epoch to deposit into). They must keep the
//     plain visible-epoch rule: with the margin, matchState would call a match live for an hour after the relay closed its epoch.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const read = (p: string) => readFileSync(join(process.cwd(), p), 'utf8');
/** Drop comments, so a comment that mentions a call is not counted as one. */
const strip = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"\\])\/\/[^\n]*/g, '$1');
/** The text of a function or method body, from the first `{` after its signature to the matching `}`; null if the signature is not found. */
const bodyOf = (src: string, signature: RegExp): string | null => {
  const m = signature.exec(src); if (!m) return null;
  const open = src.indexOf('{', m.index + m[0].length); if (open < 0) return null;
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(open, i + 1);
  }
  return null;
};

type Site = { name: string; file: 'client' | 'secrets'; signature: RegExp };
/** MARGIN: must use the margin predicate, and must not use the plain visible-epoch rule or a leftover `live` set. */
const MARGIN: Site[] = [
  { name: 'closeEpochs', file: 'client', signature: /async function closeEpochs\(/ },
  { name: 'removeCommitBody', file: 'client', signature: /const removeCommitBody = async/ },
  { name: 'drainQueuedWithdraws', file: 'client', signature: /const drainQueuedWithdraws = async/ },
  { name: 'drainPendingWithdraws', file: 'client', signature: /async drainPendingWithdraws\(/ },
  { name: 'planPairRows', file: 'secrets', signature: /async planPairRows\(/ },
];
/** READ / MINT: keep the plain visible-epoch rule, each with its reason. A new unlisted call must be added here ON PURPOSE, with a reason. */
const READ: Array<Site & { reason: string }> = [
  { name: 'matchState', file: 'client', signature: /async matchState\(/, reason: 'reports a match only for a row in an epoch the relay honours NOW; with the margin it would claim a live match for an hour after the relay closed its epoch' },
  { name: 'pollNow', file: 'client', signature: /async pollNow\(/, reason: 'polls only epochs the relay honours now; polling a closed epoch is wasted calls' },
  { name: 'newRow', file: 'secrets', signature: /async newRow\(/, reason: 'chooses which epoch to deposit into: a row must never be minted into an epoch the relay no longer accepts' },
];

const SRC = { client: strip(read('src/lib/crypto/beacon-client.ts')), secrets: strip(read('src/lib/trust/beacon-secrets.ts')) };
const CALL = /\bvisibleEpochs(?:At)?\(\s*now\(\)\s*\)/g;

/** Every plain visible-epoch call that sits OUTSIDE the listed read/mint functions: each is a site nobody has classified. */
function unclassifiedCalls(file: 'client' | 'secrets', src: string): string[] {
  const inside: Array<[number, number]> = [];
  for (const r of READ.filter((x) => x.file === file)) {
    const m = r.signature.exec(src); const b = bodyOf(src, r.signature);
    if (m && b) { const at = src.indexOf(b, m.index); inside.push([at, at + b.length]); }
  }
  const out: string[] = []; let m: RegExpExecArray | null; CALL.lastIndex = 0;
  while ((m = CALL.exec(src))) if (!inside.some(([a, z]) => m!.index >= a && m!.index < z)) out.push(`${file}: ${src.slice(m.index, m.index + 40).replace(/\s+/g, ' ')} at offset ${m.index}`);
  return out;
}

test('ES1 every site is found: each listed function has a real body (so no check below can pass by finding nothing)', () => {
  for (const s of [...MARGIN, ...READ]) {
    const b = bodyOf(SRC[s.file], s.signature);
    assert.ok(b && b.length > 80, `${s.name} (${s.file}) was not found or is empty`);
  }
});

test('ES2 no plain visible-epoch call exists outside the listed read/mint functions: a new unlisted call fails here', () => {
  assert.deepEqual(unclassifiedCalls('client', SRC.client), [], 'an unclassified visibleEpochs(now()) in beacon-client.ts: decide margin or read, and list it');
  assert.deepEqual(unclassifiedCalls('secrets', SRC.secrets), [], 'an unclassified visibleEpochsAt(now()) in beacon-secrets.ts: decide margin or read, and list it');
});

test('ES3 every MARGIN site uses the margin predicate and none of the plain rule: no visibleEpochs call, no leftover `live` set', () => {
  for (const s of MARGIN) {
    const b = bodyOf(SRC[s.file], s.signature)!;
    assert.match(b, /\brelayDead\(|\bepochsToPlanAt\(/, `${s.name}: must decide "closed" with relayDead / epochsToPlanAt`);
    assert.doesNotMatch(b, /\bvisibleEpochs(?:At)?\(/, `${s.name}: must not read the plain visible-epoch rule`);
    assert.doesNotMatch(b, /\blive\.has\(/, `${s.name}: a leftover \`live\` set is the plain rule by another name`);
  }
});

test('ES4 every READ/MINT site keeps the plain rule and does NOT get the margin (each with its reason)', () => {
  for (const s of READ) {
    const b = bodyOf(SRC[s.file], s.signature)!;
    assert.match(b, /\bvisibleEpochs(?:At)?\(\s*now\(\)\s*\)/, `${s.name}: reads the visible epochs (${s.reason})`);
    assert.doesNotMatch(b, /\brelayDead\(|\bepochsToPlanAt\(|RELAY_CLOSE_MARGIN/, `${s.name}: must NOT take the margin (${s.reason})`);
  }
});

test('ES5 the seed expiry is built on the shared instant, with no epoch/grace arithmetic of its own', () => {
  const e = strip(read('src/lib/identity/beacon-seed-expiry.ts'));
  assert.match(e, /relayDeadAtMs\(/);
  assert.doesNotMatch(e, /GRACE_SECONDS|EPOCH_SECONDS/);
});

test('ES6 the classifier can fail (control for ES2/ES3): a new unlisted call, and a leftover `live` set, are both reported', () => {
  const extra = SRC.client + '\n  async somethingNew() { const x = visibleEpochs(now()); return x; }\n';
  assert.equal(unclassifiedCalls('client', extra).length, unclassifiedCalls('client', SRC.client).length + 1, 'a new plain call outside the listed functions is counted');
  const margin = MARGIN.find((m) => m.name === 'removeCommitBody')!;
  const doctored = SRC.client.replace(/const removeCommitBody = async[^{]*\{/, (m) => m + ' const live = visibleEpochs(now()); if (!live.has("1")) {}');
  const b = bodyOf(doctored, margin.signature)!;
  assert.match(b, /\blive\.has\(/, 'the doctored margin site shows the leftover set that ES3 rejects');
});
