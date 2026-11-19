// Run: npx tsx --test src/components/settings/trust-map-setting.test.ts
// The "Show up in trust maps" setting: its words are the copy owner's byte for byte (ledger rows 323 and 326), it exists only inside the Lenses & vault panel, the writer has one caller, turning "show up" ON
// asks first, and the not-live line reads the one flag that also gates the emitter. Source scans over app/ and src/ (comments are not code).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import * as copy from './trust-map-copy';

const CWD = process.cwd();
const h = (s: string): string => createHash('sha256').update(s).digest('hex').slice(0, 16);
const codeOnly = (t: string): string => t.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
const read = (rel: string): string => readFileSync(join(CWD, rel), 'utf8');
function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) { if (name !== 'node_modules' && name !== '.next') sourceFiles(p, out); continue; }
    if (/\.(ts|tsx)$/.test(name) && !/\.test\.(ts|tsx)$/.test(name) && !/\.d\.ts$/.test(name)) out.push(p);
  }
  return out;
}
const filesWith = (needle: RegExp): string[] =>
  ['app', 'src'].flatMap((r) => (existsSync(join(CWD, r)) ? sourceFiles(join(CWD, r)) : [])).filter((f) => needle.test(codeOnly(readFileSync(f, 'utf8')))).map((f) => f.slice(CWD.length + 1)).sort();

const FRONTEND = 'src/components/SoverentityFrontend.tsx';
const PANEL = 'src/components/settings/TrustMapSettings.tsx';

test('TM1 every sentence is the copy owner\'s bytes (length + sha256 prefix) and plain ASCII', () => {
  const rows: Array<[string, string, number, string]> = [
    ['323a label', copy.TRUST_MAP_LABEL, 21, '6f0d114e6f1f20eb'],
    ['323b not live', copy.TRUST_MAP_NOT_LIVE, 103, 'a80fcf243966c8b8'],
    ['323c state on', copy.TRUST_MAP_STATE_ON, 74, '77ab3f0098270dc9'],
    ['323c state off', copy.TRUST_MAP_STATE_OFF, 52, 'cbfac985da6a671e'],
    ['323d confirm', copy.TRUST_MAP_CONFIRM, 76, 'f62f877112427fc0'],
    ['323d Show up', copy.TRUST_MAP_CONFIRM_YES, 7, 'b43e47255851dc59'],
    ['323d Cancel', copy.TRUST_MAP_CONFIRM_NO, 6, '19766ed6ccb2f4a3'],
    ['323f write failed', copy.TRUST_MAP_WRITE_FAILED, 56, '44a6df8051a158c0'],
    ['326a absent', copy.TRUST_MAP_ABSENT, 72, '93757b238368db05'],
    ['326b unreadable', copy.TRUST_MAP_UNREADABLE, 84, 'd82c4d582595ebe2'],
  ];
  for (const [name, text, len, sha] of rows) {
    assert.equal(text.length, len, `${name}: length`);
    assert.equal(h(text), sha, `${name}: sha256 prefix`);
    assert.ok(/^[\x20-\x7e]+$/.test(text), `${name}: ASCII`);
  }
  assert.equal(Object.keys(copy).length, rows.length, 'no other string is exported from the copy module');
});

test('TM2 while dark the words say what is SAVED and never a present effect: nothing about blocked people, a delay, or anyone being hidden now', () => {
  for (const v of Object.values(copy)) assert.doesNotMatch(String(v), /block|minute|currently|you're hidden|won't see|will see/i);
});

test('TM3 the panel spells no sentence of its own: it renders the copy constants only', () => {
  const src = codeOnly(read(PANEL));
  assert.doesNotMatch(src, />\s*[A-Za-z][^<>{}]*\s[^<>{}]*</, 'no literal text between tags');
  const lits = [...src.matchAll(/(['"`])((?:(?!\1).)*)\1/g)].map((m) => m[2]);
  assert.deepEqual(lits.filter((t) => /[A-Z][a-z]+( [a-z']+){2,}/.test(t)), [], 'no quoted sentence');
});

test('TM4 PLACEMENT: only the identity screen\'s Lenses & vault panel mounts it; the share dialog, the Identity face, the Galaxy and the ceremony never name the panel, its copy, its writer or its reader', () => {
  assert.deepEqual(filesWith(/\bTrustMapSettings\b/), [FRONTEND, PANEL].sort());
  assert.deepEqual(filesWith(/trust-map-copy/), [PANEL]);
  assert.deepEqual(filesWith(/\bsetOwnerGlobalVisibleForOwner\b/), [PANEL, 'src/lib/identity/client-store.ts'].sort());
  assert.deepEqual(filesWith(/\breadOwnerGlobalVisibility\b/), [PANEL, 'src/lib/identity/client-store.ts'].sort());
  const fe = codeOnly(read(FRONTEND));
  assert.equal([...fe.matchAll(/<TrustMapSettings\b/g)].length, 1, 'one mount');
  const at = fe.indexOf('<TrustMapSettings');
  const open = fe.lastIndexOf('<CardMorePanel', at);
  const close = fe.indexOf('</CardMorePanel>', at);
  assert.ok(open >= 0 && close > at, 'the mount sits inside a CardMorePanel');
  assert.match(fe.slice(open, at), /label="Lenses & vault"/, 'and that panel is Lenses & vault');
  assert.equal(fe.slice(open, close).includes('<CardMorePanel', open + 1) && fe.slice(open + 1, at).includes('<CardMorePanel'), false, 'with no other panel opened in between');
  const el = fe.slice(at, fe.indexOf('/>', at) + 2);
  assert.doesNotMatch(el, /\{\s*\.\.\./, 'no props spread into the mount');
});

test('TM5 ONE CALLER: the writer wrapper is called from the panel\'s choose() only, the pure writer from the store wrapper only', () => {
  assert.deepEqual(filesWith(/\bsetOwnerGlobalVisible\(/), ['src/lib/identity/client-store.ts', 'src/lib/trust/suppression-restore.ts'].sort());
  const panel = codeOnly(read(PANEL));
  assert.equal([...panel.matchAll(/\bsetOwnerGlobalVisibleForOwner\(/g)].length, 1, 'exactly one call in the panel');
  const a = panel.indexOf('const choose = useCallback');
  const b = panel.indexOf('}, [ownerFingerprint, load]);', a);
  assert.ok(a > 0 && b > a && panel.slice(a, b).includes('setOwnerGlobalVisibleForOwner('), 'and it is inside choose()');
});

test('TM6 turning "show up" ON asks first: the switch asks, only the confirm button writes it, Cancel writes nothing; turning it OFF does not ask', () => {
  const panel = codeOnly(read(PANEL));
  assert.match(panel, /onClick=\{\(\) => \(visible \? void choose\(false\) : setAsking\(true\)\)\}/, 'the switch: stay out writes at once, show up only asks');
  assert.equal([...panel.matchAll(/choose\(true\)/g)].length, 1, 'one way to write "show up"');
  assert.match(panel, /data-testid="trust-map-confirm-yes"[^>]*onClick=\{\(\) => void choose\(true\)\}/, 'and it is the confirm button');
  assert.match(panel, /data-testid="trust-map-confirm-no"[^>]*onClick=\{\(\) => setAsking\(false\)\}/, 'Cancel only closes the question');
});

test('TM7 the not-live line reads the ONE flag (isPiece2MutualBlockLive) and nothing else; no env, no storage, no second switch', () => {
  const panel = codeOnly(read(PANEL));
  assert.equal([...panel.matchAll(/isPiece2MutualBlockLive\(\)/g)].length, 1);
  assert.match(panel, /\{!isPiece2MutualBlockLive\(\) \? \(\s*<p data-testid="trust-map-not-live"[^>]*>\{TRUST_MAP_NOT_LIVE\}<\/p>\s*\) : null\}/, 'it renders iff the flag is false, in every state (outside the unreadable/choice branches)');
  assert.doesNotMatch(panel, /process\.env|localStorage|sessionStorage|NEXT_PUBLIC/, 'no second source');
});

test('TM9 absent and unreadable are TOLD APART all the way: the reader returns four states, the panel picks its sentence by state, neither shows a switch, and 325a (which said "couldn\'t be read" about a fine device) is gone', () => {
  const store = codeOnly(read('src/lib/identity/client-store.ts'));
  const a = store.indexOf('export async function readOwnerGlobalVisibility(');
  const body = store.slice(a, store.indexOf('\n}\n', a));
  assert.match(body, /Promise<'visible' \| 'hidden' \| 'absent' \| 'unreadable'>/, 'four states');
  assert.match(body, /if \(r\.state === 'absent'\) return 'absent';\s*if \(r\.state === 'unreadable'\) return 'unreadable';/, 'absent and unreadable are separate returns');
  const panel = codeOnly(read(PANEL));
  assert.match(panel, /stored === 'absent' \? \(\s*<p data-testid="trust-map-absent"[^>]*>\{TRUST_MAP_ABSENT\}<\/p>\s*\) : stored === 'unreadable' \? \(\s*<p data-testid="trust-map-unreadable"[^>]*>\{TRUST_MAP_UNREADABLE\}<\/p>\s*\) : \(/, 'each state shows its own sentence, and only the choice branch below has a switch');
  assert.equal([...panel.matchAll(/data-testid="trust-map-switch"/g)].length, 1, 'one switch, in the choice branch');
  assert.ok(panel.indexOf('data-testid="trust-map-switch"') > panel.indexOf('data-testid="trust-map-unreadable"'), 'after the absent and unreadable branches');
  assert.doesNotMatch(codeOnly(read('src/components/settings/trust-map-copy.ts')), /Nothing was changed/, 'the void sentence is not in the copy module (a comment saying why it is void is not the sentence)');
});

test('TM8 the stored state is shown, never the requested one: every write ends with a re-read', () => {
  const panel = codeOnly(read(PANEL));
  assert.match(panel, /\} finally \{\s*await load\(\);\s*setBusy\(false\);\s*\}/, 'choose() re-reads in finally, so a failed write shows what is stored');
});
