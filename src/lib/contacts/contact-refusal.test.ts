// src/lib/contacts/contact-refusal.test.ts
// Ledger row 233. A store REFUSAL keeps its own sentence at every catch that replaces an error's text; "didn't finish" never stands in for "refused".
//   A. the mapper, with the REAL classes the store throws (a lookalike object would pass while the real class drifted)
//   B. the matrix: every refusal x every contact-book site never yields that site's fixed fallback
//   C. text is never the key: a plain Error with the old message is not a refusal
//   D. the registry: a new Refus* class fails here until someone says where its sentence comes from
//   E. the update path throws typed refusals only, and the mapper stays a leaf
// Run: npx tsx --test src/lib/contacts/contact-refusal.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { contactRefusalMessage, CONTACT_REFUSAL_MESSAGES as M, type ContactRefusalContext } from './contact-refusal';
import { ContactRefused } from '@/lib/identity/client-store';
import { ContactUpdateRefused } from '@/lib/identity/contact-identity';
import { TrustRefusedError } from '@/lib/trust/apply-trust-transition';
import { CONTACT_FAILURE_MESSAGES, contactFailureMessage, type ContactFailureSite } from '@/components/contact-management-copy';

const SRC = resolve(__dirname, '..', '..');
const read = (rel: string) => readFileSync(join(SRC, rel), 'utf8');

type Case = { name: string; make: () => Error; expect: (ctx: ContactRefusalContext) => string };
const CASES: Case[] = [
  { name: 'ContactRefused binding', make: () => new ContactRefused('binding', 'x'), expect: (c) => (c === 'import' ? M.importBinding : c === 'add' ? M.addBinding : M.updateBinding) },
  { name: 'ContactRefused verify-before-trust', make: () => new ContactRefused('verify-before-trust', 'x'), expect: () => M.verifyBeforeTrust },
  { name: 'ContactUpdateRefused binding', make: () => new ContactUpdateRefused('binding', 'x'), expect: () => M.updateBinding },
  { name: 'ContactUpdateRefused verify-before-trust', make: () => new ContactUpdateRefused('verify-before-trust', 'x'), expect: () => M.verifyBeforeTrust },
  { name: 'ContactUpdateRefused identity-immutable', make: () => new ContactUpdateRefused('identity-immutable', 'x'), expect: () => M.identityImmutable },
  { name: 'TrustRefusedError blocked', make: () => new TrustRefusedError(), expect: () => M.blocked },
];

test('A1 each real refusal class maps to its ledgered sentence, by code and reason, in each context', () => {
  for (const c of CASES) for (const ctx of ['import', 'add', 'other'] as const) assert.equal(contactRefusalMessage(c.make(), ctx), c.expect(ctx), `${c.name} @ ${ctx}`);
});

test('A2 the sentences are the ledger row 233 words', () => {
  assert.equal(M.importBinding, 'This card could not be verified — its fingerprint does not match its key, so it was not imported. Ask them to send a fresh one.');
  assert.equal(M.addBinding, "This contact wasn't added: its fingerprint doesn't match its public key. Check both and try again.");
  assert.equal(M.updateBinding, "Nothing was saved: this contact's fingerprint doesn't match its public key.");
  assert.equal(M.verifyBeforeTrust, 'Verify this person in person or another way before you trust them. Nothing was changed.');
  assert.equal(M.identityImmutable, "Nothing was saved: a contact's fingerprint can't be changed. If they have a new key, add them as a new contact.");
  assert.equal(M.blocked, 'This contact is blocked. Unblock them before trusting them.');
  assert.equal(M.blocked, new TrustRefusedError().message, 'the blocked sentence is the one TrustRefusedError already carried');
  assert.equal(Object.values(M).length, new Set(Object.values(M)).size, 'no two refusals share a sentence');
});

test('B1 every refusal at every contact-book site shows the refusal, never that site\'s fallback', () => {
  const sites = Object.keys(CONTACT_FAILURE_MESSAGES) as ContactFailureSite[];
  assert.ok(sites.length >= 15, `the matrix covers every site (${sites.length})`);
  const quiet = console.error; console.error = () => {};
  try {
    for (const site of sites) for (const c of CASES) {
      const ctx = site === 'import' ? 'import' : site === 'add' ? 'add' : 'other';
      const got = contactFailureMessage(c.make(), site);
      assert.notEqual(got, CONTACT_FAILURE_MESSAGES[site], `${c.name} at ${site} fell to the generic sentence`);
      assert.equal(got, c.expect(ctx), `${c.name} at ${site}`);
    }
  } finally { console.error = quiet; }
});

test('C1 text is never the key: a plain Error carrying a refusal message is not a refusal, and an unknown reason is not either', () => {
  const quiet = console.error; console.error = () => {};
  try {
    for (const msg of ['fingerprint↔key binding failed — refusing to update a contact whose fingerprint does not match its public key', 'verify-before-trust: refusing to promote a contact', 'This contact is blocked. Unblock them before trusting them.']) {
      assert.equal(contactRefusalMessage(new Error(msg)), null);
      assert.equal(contactFailureMessage(new Error(msg), 'edit'), CONTACT_FAILURE_MESSAGES.edit);
    }
  } finally { console.error = quiet; }
  assert.equal(contactRefusalMessage({ code: 'contact-refused', reason: 'something-new' }), null);
  assert.equal(contactRefusalMessage({ code: 'contact-update-refused' }), null);
  assert.equal(contactRefusalMessage(null), null);
  assert.equal(contactRefusalMessage('contact-refused'), null);
});

// D. Every exported Refus* class in src, and where its sentence comes from. Adding one fails this test until it is classified.
const REGISTRY: Record<string, string> = {
  ContactRefused: 'contact-refusal',
  ContactUpdateRefused: 'contact-refusal',
  TrustRefusedError: 'contact-refusal',
  RestoreDomainRefused: 'restore-domain helper (restoreDomainRefusalMessage)',
  RestoreDurableRefused: 'RESTORE_DURABLE_MESSAGE, by code',
  ContactIoRefused: 'contact-io-errors helpers',
  SealedBookRefused: 'contact-io-errors helpers',
  EnvelopeRefused: 'contact-io-errors helpers',
  ArtifactRefused: 'no screen catch: no user outside its own file',
  ProverRefused: 'no screen catch: no user outside its own file',
  SatelliteEnvRefused: 'no screen catch: no user outside its own file',
};
function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) { if (n !== 'node_modules') walk(p, out); }
    else if (/\.(ts|tsx)$/.test(n) && !/\.(test|spec)\.tsx?$/.test(n)) out.push(p);
  }
  return out;
}
test('D1 every exported Refus* error class is in the registry, and the registry has no stale entry', () => {
  const found = new Set<string>();
  for (const f of walk(SRC)) for (const m of readFileSync(f, 'utf8').matchAll(/export class (\w*Refus\w*) extends Error/g)) found.add(m[1]);
  assert.deepEqual([...found].sort(), Object.keys(REGISTRY).sort(), 'a Refus* class was added or removed: say where its screen sentence comes from');
});

test('E1 the update path throws typed refusals only: no plain Error that says "refusing"', () => {
  const store = read('lib/identity/client-store.ts');
  const fn = store.slice(store.indexOf('export async function finalizeContactUpdate'), store.indexOf('Write `ops` in one transaction'));
  assert.ok(fn.length > 500, 'sliced the function');
  assert.equal((fn.match(/throw new ContactUpdateRefused\(/g) || []).length, 2);
  assert.match(fn, /throw new ContactUpdateRefused\('binding', 'fingerprint↔key binding failed/, 'the binding refusal carries the binding reason');
  assert.match(fn, /throw new ContactUpdateRefused\('verify-before-trust', 'verify-before-trust: refusing to promote/, 'the promotion refusal carries its reason');
  assert.doesNotMatch(fn, /throw new Error\(/, 'a plain Error here is a refusal a screen cannot recognise');
  const ident = read('lib/identity/contact-identity.ts');
  assert.match(ident, /throw new ContactUpdateRefused\('identity-immutable'/);
  assert.doesNotMatch(ident, /throw new Error\(/);
});

test('E2 the two add refusals carry their reason; the restore loop still only skips ContactRefused, never an update refusal', () => {
  const store = read('lib/identity/client-store.ts');
  assert.match(store, /throw new ContactRefused\('binding', 'fingerprint↔key binding failed/);
  assert.match(store, /throw new ContactRefused\('verify-before-trust', 'verify-before-trust: refusing to create/);
  assert.match(store, /if \(!\(e instanceof ContactRefused\)\) throw e;/);
  assert.equal(new ContactUpdateRefused('binding', 'x') instanceof ContactRefused, false);
});

test('E3 the mapper is a leaf: no import, so a public page can use it without loading the store', () => {
  assert.doesNotMatch(read('lib/contacts/contact-refusal.ts'), /^import /m);
});

test('E4 an update refusal inside the plaintext restore loop still STOPS the restore (static slice of the loop + the class relation; no IndexedDB is run here)', () => {
  const store = read('lib/identity/client-store.ts');
  const start = store.indexOf('export async function importPlaintextContacts(');
  const loop = store.slice(start, store.indexOf('export async function importAll(', start));
  assert.ok(loop.length > 800, 'sliced the loop');
  const tryBody = loop.slice(loop.indexOf('try {'), loop.indexOf('} catch (e) {'));
  assert.match(tryBody, /updateContactIf\(/, 'the same try also runs an update, which can refuse');
  assert.match(tryBody, /addContact\(/);
  assert.match(loop, /\} catch \(e\) \{[\s\S]*?if \(!\(e instanceof ContactRefused\)\) throw e;\s*skipped\+\+;/, 'only an add refusal is skipped and counted');
  const skips = (e: unknown) => e instanceof ContactRefused;
  assert.equal(skips(new ContactRefused('binding', 'x')), true);
  for (const reason of ['binding', 'verify-before-trust', 'identity-immutable'] as const) assert.equal(skips(new ContactUpdateRefused(reason, 'x')), false, `an update refusal (${reason}) must rethrow and stop the restore`);
});

test('E5 the paste import shows R1 from the shared constant when it refuses the card itself, and nowhere retypes the sentence', () => {
  const cm = read('components/ContactManagement.tsx');
  assert.equal((cm.match(/message: CONTACT_REFUSAL_MESSAGES\.importBinding/g) || []).length, 1);
  assert.doesNotMatch(cm, /could not be verified — its fingerprint/, 'the sentence lives in one place');
});
