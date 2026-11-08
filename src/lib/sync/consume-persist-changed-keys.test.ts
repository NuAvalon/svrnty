// A contact update is looked up, verified, applied and persisted. Verification takes real time, so anything else that changes the same record
// in between (another loop, a user action) must not be written back to its old value. The pipeline therefore persists ONLY the keys the update
// changed, and the store merges them into the record it holds at that moment.
//
// REAL here: consumeInboundContactUpdates, a genuinely signed contact update, its verification, applyVerifiedContactUpdate.
// MODELLED here: the store. `persist` applies the merge `{ ...existing, ...changes }` that the client store performs on an update, and the
// test can inject another write BEFORE the lookup, BETWEEN the lookup and the persist, or AFTER the persist. It is not run against IndexedDB.
//
// Each interleaving test asserts the property we want (the other write survives, the update is still applied). The CONTROL has no other writer.
//
// Run: npx tsx --test src/lib/sync/consume-persist-changed-keys.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { signWithEnvelope } from '@/lib/crypto/sign-envelope';
import { DOMAIN_CONTACT_UPDATE, contactUpdateSigningInput, type ContactUpdateEnvelope } from '@/lib/format/envelope';
import type { SignedContactUpdate, KnownContactIdentity } from '@/lib/trust/contact-update';
import type { StoredContact } from '@/lib/contacts/apply-contact-update';
import { consumeInboundContactUpdates, changedKeys, type ConsumeDeps, type KnownContact } from './consume-mailbox';

interface Identity { fingerprint: string; publicKey: string; privateKey: string; passphrase: string }

async function makeIdentity(name: string): Promise<Identity> {
  const passphrase = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart — 'ed25519' is valid at runtime (see core.ts).
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase,
    format: 'armored',
  });
  const fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  return { fingerprint, publicKey, privateKey, passphrase };
}

let alice: Identity;
let bob: Identity;
before(async () => {
  alice = await makeIdentity('alice');
  bob = await makeIdentity('bob');
});

interface UpdateSpec { changed_fields: string[]; delta: Record<string, unknown> }
const NAME_CHANGE: UpdateSpec = { changed_fields: ['display_name'], delta: { display_name: 'Bob (NEW name)' } };
const HANDLES_CHANGE: UpdateSpec = { changed_fields: ['handles'], delta: { handles: { signal: '@bob-new' } } };

async function signedUpdate(spec: UpdateSpec): Promise<SignedContactUpdate> {
  const env: ContactUpdateEnvelope = {
    fingerprint: bob.fingerprint, epoch: 0, version: 1, updated_at: '2026-08-19T00:00:00.000Z',
    changed_fields: spec.changed_fields, delta: spec.delta,
  };
  const signature = await signWithEnvelope(DOMAIN_CONTACT_UPDATE, contactUpdateSigningInput(env), bob.privateKey, bob.passphrase);
  return { envelope: env, signature };
}

function recordingFetch(): typeof fetch {
  return (async (url: string) => {
    if (String(url).includes('/queue')) {
      return new Response(JSON.stringify([{ envelope_id: 'e1', blob: 'BLOB1' }]), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify({ deleted: 1 }), { status: 200 });
  }) as unknown as typeof fetch;
}

/** The record as it sits in the book when the update is processed. */
function bobAtLookup(extra: Record<string, unknown> = {}): StoredContact {
  return {
    id: 'contact-bob', fingerprint: bob.fingerprint, name: 'Bob (old name)', email: 'bob@old.test', public_key: bob.publicKey,
    trust_level: 'trusted', trusted: true, blocked: false, added_at: '2026-01-01T00:00:00.000Z', version: 0,
    metadata: { share_settings: { open_visibility: true } },
    ...extra,
  };
}

type Db = Map<string, StoredContact>;
interface Run {
  /** another write lands BEFORE the lookup (the snapshot already has it) */
  beforeLookup?: (db: Db) => void;
  /** another write lands BETWEEN the lookup and the persist */
  inWindow?: (db: Db) => void;
  /** another write lands AFTER the persist */
  afterPersist?: (db: Db) => void;
  update?: UpdateSpec;
  seen?: StoredContact[];
  /** how many updates the consume pass should report applied (default 1) */
  applied?: number;
}

/** Consume one genuinely signed update for Bob; returns the book's record afterwards. */
async function consume(start: StoredContact, run: Run = {}): Promise<StoredContact> {
  const db: Db = new Map([[start.id, { ...start }]]);
  const known: KnownContactIdentity = { fingerprint: bob.fingerprint, epoch: 0, version: 0, classicalPublicKeyArmored: bob.publicKey };
  const signed = await signedUpdate(run.update ?? NAME_CHANGE);
  const store = {
    // lookup hands the consume path a snapshot (a copy) of the record, as the real adapter does.
    lookup: async (fp: string): Promise<KnownContact | null> => {
      if (fp !== bob.fingerprint) return null;
      run.beforeLookup?.(db);
      return { known, current: { ...(db.get('contact-bob') as StoredContact) } };
    },
    persist: async (id: string, changes: StoredContact) => {
      run.seen?.push(changes);
      run.inWindow?.(db); // the other write lands in the window
      const existing = db.get(id) as StoredContact;
      db.set(id, { ...existing, ...changes, id: existing.id }); // the client store's merge
      run.afterPersist?.(db);
    },
  };
  const deps: ConsumeDeps = {
    owner: { fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase },
    decrypt: async () => signed,
    store,
    relayBase: 'http://relay.test/api/relay',
    now: () => '2026-08-19T00:00:00.000Z',
    fetchImpl: recordingFetch(),
  };
  const summary = await consumeInboundContactUpdates(deps);
  assert.equal(summary.applied, run.applied ?? 1, 'the signed update must have been applied');
  return db.get('contact-bob') as StoredContact;
}

const setFlag = (db: Db) =>
  db.set('contact-bob', { ...(db.get('contact-bob') as StoredContact), blocked: true, trusted: false, trust_level: 'unverified' });

// ── the property, in every order ────────────────────────────────────────────────────────────────────────────

test('CONTROL: with no other writer, the update is applied and nothing else changes', async () => {
  const after = await consume(bobAtLookup());
  assert.equal(after.name, 'Bob (NEW name)');
  assert.equal(after.blocked, false);
  assert.equal(after.trust_level, 'trusted');
});

test('a flag and trust level set on the contact while its update is being verified are kept', async () => {
  const after = await consume(bobAtLookup(), { inWindow: setFlag });
  assert.equal(after.name, 'Bob (NEW name)', 'the verified update is still applied');
  assert.equal(after.blocked, true, 'the flag survives');
  assert.equal(after.trust_level, 'unverified', 'the trust change survives');
  assert.equal(after.trusted, false);
});

test('the same flag set BEFORE the lookup (the snapshot already has it) is kept, and the update is NOT applied: a blocked contact’s update changes nothing', async () => {
  const after = await consume(bobAtLookup(), { beforeLookup: setFlag, applied: 0 });
  assert.equal(after.name, 'Bob (old name)', 'the blocked contact’s update is dropped');
  assert.equal(after.blocked, true);
  assert.equal(after.trust_level, 'unverified');
});

test('the same flag set AFTER the persist is kept on top of the applied update', async () => {
  const after = await consume(bobAtLookup(), { afterPersist: setFlag });
  assert.equal(after.name, 'Bob (NEW name)');
  assert.equal(after.blocked, true);
  assert.equal(after.trust_level, 'unverified');
});

test('a flag set in the window is kept for an update that touches contact_info (a handles update), too', async () => {
  const start = bobAtLookup({ contact_info: { handles: { telegram: '@bob' }, phone: '+1 555 0100' } });
  const after = await consume(start, { inWindow: setFlag, update: HANDLES_CHANGE });
  assert.equal(after.blocked, true, 'the flag survives');
  assert.equal(after.trust_level, 'unverified');
  assert.deepEqual((after.contact_info as { handles: Record<string, string> }).handles, { telegram: '@bob', signal: '@bob-new' }, 'the handles update merged into the existing handles');
});

test('a visibility change (open_visibility true -> false) made in the window is kept', async () => {
  const after = await consume(bobAtLookup(), {
    inWindow: (db) => {
      const cur = db.get('contact-bob') as StoredContact;
      db.set('contact-bob', { ...cur, metadata: { ...(cur.metadata ?? {}), share_settings: { open_visibility: false } } });
    },
  });
  assert.equal(after.name, 'Bob (NEW name)');
  assert.equal((after.metadata?.share_settings as { open_visibility?: boolean }).open_visibility, false, 'the setting stays as the owner left it');
});

test('a session secret cleared in the window stays cleared', async () => {
  const after = await consume(bobAtLookup({ psi_session_id: 'sess-1', psi_sk_A: 'SECRET-SCALAR' }), {
    inWindow: (db) => {
      db.set('contact-bob', { ...(db.get('contact-bob') as StoredContact), psi_session_id: undefined, psi_sk_A: undefined }); // the sync loop completes and clears it
    },
  });
  assert.equal(after.name, 'Bob (NEW name)');
  assert.equal(after.psi_sk_A, undefined, 'a cleared session secret is not written back');
  assert.equal(after.psi_session_id, undefined);
});

// ── what is persisted ───────────────────────────────────────────────────────────────────────────────────────

test('what an applied update persists is exactly the keys it changed, not the record', async () => {
  const seen: StoredContact[] = [];
  await consume(bobAtLookup({ psi_session_id: 'sess-1' }), { seen });
  assert.equal(seen.length, 1);
  const keys = Object.keys(seen[0]);
  assert.ok(keys.includes('name') && keys.includes('version'), `the changed keys are sent: ${keys.join(',')}`);
  for (const untouched of ['id', 'fingerprint', 'email', 'public_key', 'blocked', 'trusted', 'trust_level', 'metadata', 'psi_session_id', 'added_at']) {
    assert.ok(!keys.includes(untouched), `${untouched} was not changed by the update and must not be sent`);
  }
});

test('NAMED LIMIT: a handles update sends the whole contact_info object (the comparison is per top-level key)', async () => {
  const seen: StoredContact[] = [];
  const start = bobAtLookup({ contact_info: { handles: { telegram: '@bob' }, phone: '+1 555 0100' } });
  await consume(start, { seen, update: HANDLES_CHANGE });
  const keys = Object.keys(seen[0]);
  assert.ok(keys.includes('contact_info'), 'contact_info is sent whole');
  for (const untouched of ['blocked', 'trusted', 'trust_level', 'metadata', 'name']) assert.ok(!keys.includes(untouched), `${untouched} must not be sent`);
  assert.deepEqual((seen[0].contact_info as { phone: string }).phone, '+1 555 0100', 'the other contact_info members ride along with it');
});

// ── changedKeys ─────────────────────────────────────────────────────────────────────────────────────────────

const rec = (o: Record<string, unknown>): StoredContact => ({ id: 'x', fingerprint: 'f', name: 'n', email: 'e', public_key: 'k', trust_level: 't', added_at: 'a', ...o });

test('changedKeys: unchanged keys are left out, changed and added keys are included', () => {
  const before = rec({ a: 1, b: 'same', c: true });
  const after = rec({ a: 2, b: 'same', c: true, d: 'new' });
  assert.deepEqual(changedKeys(before, after), { a: 2, d: 'new' });
  assert.deepEqual(changedKeys(before, { ...before }), {}, 'identical copies change nothing');
});

test('changedKeys: a removed key is reported as undefined, and null is not the same as missing', () => {
  const before = rec({ gone: 'x', n: null });
  const after = rec({ n: undefined });
  const out = changedKeys(before, after);
  assert.ok('gone' in out && out.gone === undefined);
  assert.ok('n' in out && out.n === undefined, 'null -> undefined is a change');
  assert.deepEqual(changedKeys(rec({ n: null }), rec({ n: null })), {});
});

test('changedKeys: nested values compare by content; a changed nested object is sent whole, an equal one is not', () => {
  const before = rec({ metadata: { tags: ['a'], share: { open: true } }, list: [1, 2] });
  const sameContent = rec({ metadata: { tags: ['a'], share: { open: true } }, list: [1, 2] });
  assert.deepEqual(changedKeys(before, sameContent), {});
  const changed = rec({ metadata: { tags: ['a'], share: { open: false } }, list: [1, 2] });
  assert.deepEqual(changedKeys(before, changed), { metadata: { tags: ['a'], share: { open: false } } });
  assert.deepEqual(changedKeys(before, rec({ metadata: before.metadata, list: [1, 2, 3] })), { list: [1, 2, 3] });
});

test('changedKeys never mutates its inputs and returns a new object', () => {
  const before = rec({ a: 1, m: { x: 1 } });
  const after = rec({ a: 2, m: { x: 1 } });
  const b0 = JSON.stringify(before);
  const a0 = JSON.stringify(after);
  const out = changedKeys(before, after);
  assert.equal(JSON.stringify(before), b0);
  assert.equal(JSON.stringify(after), a0);
  assert.notEqual(out, after);
});
