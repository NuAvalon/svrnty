// #724 BEHAVIOUR test for the PWA book: a contact row's fingerprint is its identity, so no update may replace it.
// P3 (contact-identity.test.ts) pins WHERE the rule sits by reading the source; this file proves WHAT it does. It runs the REAL compare-and-swap
// loop (casUpdateWith) with the REAL finalize step (finalizeContactUpdate) over an in-memory book of REAL identities (canonical fingerprints minted
// from real keys), once with each public writer's build shape. The decisive case is a swapped-in VALID pair (Y's fingerprint with Y's keys onto X's
// row): the fp<->key binding check passes it, so only the #724 rule stands between it and X's trust row.
// Real IndexedDB is NOT covered here (no fake in this repo); the routing of updateContact / updateContactIf through this io is pinned by P3.
//
// Run: npx tsx --test src/lib/identity/contact-identity-cas.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { mintCanonicalFingerprint } from '@/lib/identity/fingerprint';
import { generatePQKeypairBundle, uint8ToBase64 } from '@/lib/crypto/pq';
import { casUpdateWith, type CasIO, type Expect, type PutOp } from './contact-cas';
import { finalizeContactUpdate, mergeContactUpdate, type ContactRecord } from './client-store';

async function identity(name: string): Promise<ContactRecord> {
  const passphrase = `pw-${name}`;
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'ed25519Legacy', userIDs: [{ name, email: `${name}@t.test` }], passphrase, format: 'armored' });
  const decrypted = await decryptKey({ privateKey: await readPrivateKey({ armoredKey: privateKey }), passphrase });
  const pq = generatePQKeypairBundle();
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: decrypted, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  return {
    id: `c-${name}`, owner_fingerprint: 'owner', fingerprint, name, email: `${name}@t.test`, public_key: publicKey, trust_level: 'unverified', added_at: '2026-01-01T00:00:00.000Z',
    pq_kem_public_key: uint8ToBase64(pq.kem.publicKey), pq_sig_public_key: uint8ToBase64(pq.signing.publicKey),
  } as ContactRecord;
}

/** The stored row minus its iv (the stand-in for the encrypted envelope). */
function unseal(raw: Record<string, unknown>): ContactRecord {
  const r = { ...raw };
  delete r.iv;
  return r as unknown as ContactRecord;
}

/** An in-memory book behind the CAS seam. finalize is the store's REAL finalize; "encryption" is JSON; commits are counted. */
function book(...rows: ContactRecord[]) {
  const contacts = new Map<string, Record<string, unknown>>(rows.map((r) => [r.id, { ...r, iv: `iv-${r.id}-0` }]));
  let ivs = 0;
  const state = { commits: 0 };
  const io: CasIO<ContactRecord> = {
    readRaw: async (id) => contacts.get(id) ?? null,
    manifestKey: () => 'contact_manifest:owner',
    readManifest: async () => null,
    decrypt: async (raw) => unseal(raw),
    finalize: finalizeContactUpdate,
    encrypt: async (next) => ({ ...next, iv: `iv-${next.id}-${++ivs}` }),
    manifestOp: async () => ({ store: 'settings', value: { key: 'contact_manifest:owner', value: 'm' } }),
    commit: async (_expects: Expect[], ops: PutOp[]) => {
      for (const op of ops) if (op.store === 'contacts' && 'value' in op) contacts.set((op.value as { id: string }).id, op.value as Record<string, unknown>);
      state.commits++;
      return true;
    },
  };
  const row = (id: string) => unseal(contacts.get(id)!);
  return { io, state, row };
}

// The two public writers' build shapes, as client-store.ts builds them (P3 pins that both route through contactCasIO).
const WRITERS = {
  updateContact: (patch: Partial<ContactRecord>) => (e: ContactRecord) => mergeContactUpdate(e, patch),
  updateContactIf: (patch: Partial<ContactRecord>) => (e: ContactRecord) => { const p: Partial<ContactRecord> | null = patch; return p === null ? null : mergeContactUpdate(e, p); },
} as const;

let ann: ContactRecord;
let bob: ContactRecord;
before(async () => { [ann, bob] = await Promise.all([identity('ann'), identity('bob')]); });

for (const [writer, build] of Object.entries(WRITERS)) {
  test(`${writer}: a VALID foreign pair (bob's fingerprint + bob's keys) onto ann's row is refused and nothing is committed`, async () => {
    const b = book(ann);
    const swap = { fingerprint: bob.fingerprint, public_key: bob.public_key, pq_kem_public_key: bob.pq_kem_public_key, pq_sig_public_key: bob.pq_sig_public_key };
    await assert.rejects(() => casUpdateWith(b.io, ann.id, build(swap)), /fingerprint/i);
    assert.equal(b.state.commits, 0);
    assert.deepEqual(b.row(ann.id), ann, "ann's row is untouched");
  });

  test(`${writer}: a fingerprint-only change is refused and nothing is committed`, async () => {
    const b = book(ann);
    await assert.rejects(() => casUpdateWith(b.io, ann.id, build({ fingerprint: bob.fingerprint })), /fingerprint/i);
    assert.equal(b.state.commits, 0);
    assert.deepEqual(b.row(ann.id), ann);
  });

  test(`${writer}: a key that does not match the row's fingerprint (bob's KEM key on ann) is refused and nothing is committed`, async () => {
    const b = book(ann);
    await assert.rejects(() => casUpdateWith(b.io, ann.id, build({ pq_kem_public_key: bob.pq_kem_public_key })), /binding failed/);
    assert.equal(b.state.commits, 0);
    assert.deepEqual(b.row(ann.id), ann);
  });

  test(`${writer}: non-regression, an ordinary edit (and a repeat of the row's own fingerprint) commits`, async () => {
    const b = book(ann);
    const r = await casUpdateWith(b.io, ann.id, build({ name: 'Ann B', fingerprint: ann.fingerprint }));
    assert.deepEqual(r, { applied: true, attempts: 1 });
    assert.equal(b.state.commits, 1);
    assert.equal(b.row(ann.id).name, 'Ann B');
    assert.equal(b.row(ann.id).fingerprint, ann.fingerprint);
  });
}
