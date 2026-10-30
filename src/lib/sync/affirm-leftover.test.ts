// src/lib/sync/affirm-leftover.test.ts
//
// Flint #690/#701 (B gate): while dev ran f75e74e (~15:47Z to 21:59Z, Oct 24) it deposited 'svrnty-trust-affirm-v0'
// envelopes that can still sit in relay mailboxes until the 7-day TTL (~Oct 31). This build (#593) removed the
// affirm wire and its module. Such an envelope must be TERMINAL here: dropped, acked (deleted from the mailbox),
// NEVER applied, NEVER shown, NEVER re-deposited, with no trust-state change.
//
// The fixture is built the way f75e74e built it (canonical preimage, signed under the old domain tag, sealed hybrid or
// classical), with ONLY primitives that survive this build, because trust-affirm.ts is deleted. The signature must be
// VALID: a forged one would be dropped as "forged" by any future recognizer and this pin would stay green while a
// recognizer that APPLIES valid affirms came back. Validity of this exact helper was checked against dev, where the old
// seam still exists (it flipped they_trust_me and acked); that control cannot run on this branch.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMessage, encrypt, readKey } from 'openpgp';
import { mintHeadlessAgent } from '../identity/headless-mint';
import { uint8ToBase64 } from '../crypto/pq';
import { signWithEnvelope } from '../crypto/sign-envelope';
import { sealLivingBookHybrid } from '../crypto/living-book-sleeve';
import { canonicalize } from '../format/canonical';
import { HeadlessStore, type HeadlessContact } from '../headless/headless-store';
import { buildHeadlessConsumeDeps, type HeadlessOwner } from '../headless/headless-client';
import { consumeInboundContactUpdates } from './consume-mailbox';

// Frozen v0 constants of the deleted module (kept as literals ON PURPOSE: nothing in this build may import or know them).
const AFFIRM_WIRE_TYPE = 'svrnty-trust-affirm-v0';
const DOMAIN_TRUST_AFFIRM = 'svrnty:trust-affirm:v0';
const RELAY = 'http://relay.test/api/relay';

type Id = { fp: string; pub: string; priv: string; kpass: string; kem: string; kemSec: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return { fp: id.fingerprint, pub: id.public_key, priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass,
    kem: id.pq_kem_public_key, kemSec: uint8ToBase64(a.secret_material.mlkem1024Sec), sig: id.pq_sig_public_key };
}
const ownerOf = (id: Id, over: Partial<HeadlessOwner> = {}): HeadlessOwner => ({
  fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass,
  kemPublicKey: id.kem, kemSecretKey: id.kemSec, sigPublicKey: id.sig, ...over });
const contactOf = (id: Id): HeadlessContact => ({
  id: 'c_' + id.fp.slice(0, 8), fingerprint: id.fp, public_key: id.pub, pq_sig_public_key: id.sig, pq_kem_public_key: id.kem,
  trusted: true, trust_level: 'trusted', mutual: { they_trust_me: false, last_sync: null, reciprocal: false } });

/** A genuine, validly-signed affirm exactly as f75e74e produced it (canonical-sender form), as sealed plaintext JSON. */
async function oldBuildAffirmJson(from: Id, toFp: string): Promise<string> {
  const wire = { type: AFFIRM_WIRE_TYPE, affirm_id: 'aff_leftover_1', from_fingerprint: from.fp, to_fingerprint: toFp, trusts: true, sent_at: '2026-10-24T16:00:00.000Z' };
  const signature = await signWithEnvelope(DOMAIN_TRUST_AFFIRM,
    canonicalize(wire, { exclude: ['signature', 'public_key', 'pq_kem_public_key', 'pq_sig_public_key'] }), from.priv, from.kpass);
  return JSON.stringify({ ...wire, public_key: from.pub, signature, pq_kem_public_key: from.kem, pq_sig_public_key: from.sig });
}
async function sealHybrid(json: string, to: Id): Promise<string> {
  return sealLivingBookHybrid(new TextEncoder().encode(json), to.pub, to.kem);
}
async function sealClassical(json: string, to: Id): Promise<string> {
  const encryptionKeys = await readKey({ armoredKey: to.pub });
  return (await encrypt({ message: await createMessage({ text: json }), encryptionKeys })) as string;
}

async function consumeLeftover(opts: { hybrid: boolean; ownerSecretMissing?: boolean }) {
  const [A, B] = [await mint(), await mint()];                      // A (in B's book, trusted) sent the leftover affirm to owner B
  const dir = mkdtempSync(join(tmpdir(), 'affleft-'));
  try {
    const store = new HeadlessStore({ path: join(dir, 'store.json'), lockDir: dir });
    store.upsertContact(contactOf(A));
    const before = JSON.stringify(store.getContactByFingerprint(A.fp));
    const json = await oldBuildAffirmJson(A, B.fp);
    const blob = opts.hybrid ? await sealHybrid(json, B) : await sealClassical(json, B);
    const acks: string[] = [];
    const posts: string[] = [];
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET';
      if (method === 'GET' && String(url).includes('/queue')) return new Response(JSON.stringify([{ envelope_id: 'env_affirm_leftover', blob }]), { status: 200 });
      if (method === 'POST' && String(url).endsWith('/ack')) acks.push(String(init?.body));
      else posts.push(`${method} ${url}`);
      return new Response('{"ok":true}', { status: 200 });
    }) as typeof fetch;
    const owner = ownerOf(B);
    if (opts.ownerSecretMissing) delete (owner as { kemSecretKey?: string }).kemSecretKey;   // advertises a kem, cannot derive its secret
    const deps = await buildHeadlessConsumeDeps(owner, store, { relayBase: RELAY, fetchImpl });
    const summary = await consumeInboundContactUpdates(deps);
    const after = JSON.stringify(store.getContactByFingerprint(A.fp));
    return { summary, before, after, acks, posts, notes: store.listNotes().length, threads: store.listThreads().length, contact: store.getContactByFingerprint(A.fp) as HeadlessContact };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

function assertNothingApplied(r: Awaited<ReturnType<typeof consumeLeftover>>) {
  assert.equal(r.summary.polled, 1);
  assert.equal(r.summary.dropped, 1, 'counted as dropped');
  assert.equal(r.summary.applied, 0);
  assert.equal(r.summary.ignited, 0);
  assert.equal(r.summary.notes, 0);
  assert.ok(!('affirmed' in r.summary), 'this build has no affirm outcome at all');
  assert.equal(r.after, r.before, 'the contact record is BYTE-IDENTICAL: no trust-state change');
  assert.equal(r.contact.mutual?.they_trust_me, false, 'they_trust_me did NOT flip');
  assert.equal(r.contact.mutual?.reciprocal, false);
  assert.equal(r.notes, 0, 'nothing shown / stored in the inbox');
  assert.equal(r.threads, 0);
  assert.deepEqual(r.posts, [], 'nothing re-deposited (no outbound request other than the poll and the ack)');
}

test('leftover affirm, HYBRID-sealed, normal owner → dropped + ACKED (deleted from the mailbox), no trust-state change', async () => {
  const r = await consumeLeftover({ hybrid: true });
  assertNothingApplied(r);
  assert.equal(r.summary.acked, 1);
  assert.equal(r.acks.length, 1);
  assert.match(r.acks[0], /env_affirm_leftover/);
});

test('leftover affirm, CLASSICAL-sealed, normal owner → dropped + ACKED, no trust-state change', async () => {
  const r = await consumeLeftover({ hybrid: false });
  assertNothingApplied(r);
  assert.equal(r.summary.acked, 1);
  assert.equal(r.acks.length, 1);
});

test('leftover hybrid affirm, owner advertises a kem but its ML-KEM secret is NOT derivable → left for retry (NOT acked), still no trust-state change', async () => {
  // Deliberate protect-real-mail behaviour (an unopenable hybrid blob is never acked-unseen). Flint #701: acceptable for the
  // security property "never applied, never shown"; it is ciphertext on the relay for <=7 days and is re-counted as dropped each poll.
  const r = await consumeLeftover({ hybrid: true, ownerSecretMissing: true });
  assertNothingApplied(r);
  assert.equal(r.summary.acked, 0);
  assert.deepEqual(r.acks, [], 'left in the mailbox: no ack request was sent');
});

test('no non-test source recognises the affirm kind: the module, the wire type and the accept functions are gone from CODE (comments excluded)', () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');           // .../src
  const hits: string[] = [];
  const re = /trust-affirm|TrustAffirm|svrnty-trust-affirm|acceptTrustAffirm|affirmShouldApply|TRUST_AFFIRM/;
  for (const rel of readdirSync(root, { recursive: true }) as string[]) {
    if (!/\.(ts|tsx)$/.test(rel) || /\.test\.|\.exp\.ts$/.test(rel)) continue;
    const code = readFileSync(join(root, rel), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')                                               // block comments
      .replace(/(^|[^:])\/\/[^\n]*/g, '$1');                                          // line comments
    const m = re.exec(code);
    if (m) hits.push(`${rel}: ${m[0]}`);
  }
  assert.deepEqual(hits, [], 'a code path recognises the affirm kind again; Flint #690 requires it only be DROPPED, never recognised');
});
