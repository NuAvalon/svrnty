// src/components/trust-map-refresh-opened.test.ts
// Apollo's verify tests for PR #325 vs copy v4 (lane #2435; added per Archie #2437): what the Galaxy note says over the REAL
// pollLiveBookOnce -> consume path, with an envelope that is genuinely OPENED and STORED (a signed contact.update from Bob). V2 is the only
// test that kills the "drop acked < polled" mutant on that path: opened + stored + ack 500 must say the v4 line, never "Caught up.".
//
// Run: npx tsx --test src/components/trust-map-refresh-opened.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { signWithEnvelope } from '@/lib/crypto/sign-envelope';
import { DOMAIN_CONTACT_UPDATE, contactUpdateSigningInput, type ContactUpdateEnvelope } from '@/lib/format/envelope';
import type { SignedContactUpdate, KnownContactIdentity } from '@/lib/trust/contact-update';
import type { StoredContact } from '@/lib/contacts/apply-contact-update';
import { makeUnlockCycle } from '@/lib/crypto/unlock-cycle';
import type { ConsumeDeps, KnownContact } from '@/lib/sync/consume-mailbox';
import { pollLiveBookOnce } from '@/lib/sync/live-book-poll';
import { refreshNoteFor } from './trust-map-refresh-note';

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
  return { fingerprint: (await readKey({ armoredKey: publicKey })).getFingerprint(), publicKey, privateKey, passphrase };
}
let alice: Identity, bob: Identity;
before(async () => { alice = await makeIdentity('alice'); bob = await makeIdentity('bob'); });

const CAUGHT = 'Caught up.', WAITING = 'Checked. Some messages are still on the relay.', FAILED = 'Could not check right now.', LOCKED = 'Unlock to check for messages.';
const HYBRID = JSON.stringify({ v: 1, alg: 'X25519+ML-KEM-1024/HKDF-SHA256/AES-256-GCM', mailbox_fp: 'ab'.repeat(32), epk: 'e', kem_ct: 'k', nonce: 'n', ct: 'c' });

function relay(opts: { queue: unknown; queueStatus?: number; ackStatus?: number }): typeof fetch {
  return (async (url: string) => {
    if (String(url).includes('/queue')) return new Response(JSON.stringify(opts.queue), { status: opts.queueStatus ?? 200 });
    if (String(url).includes('/ack')) return new Response('{}', { status: opts.ackStatus ?? 200 });
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
}
const known = (): KnownContact => {
  const k: KnownContactIdentity = { fingerprint: bob.fingerprint, epoch: 0, version: 0, classicalPublicKeyArmored: bob.publicKey };
  const current: StoredContact = { id: 'contact-bob', fingerprint: bob.fingerprint, name: 'Bob (old)', email: 'b@x.test', public_key: bob.publicKey, trust_level: 'verified', added_at: '2026-01-01T00:00:00.000Z', version: 0 };
  return { known: k, current };
};
async function signedUpdate(): Promise<SignedContactUpdate> {
  const env: ContactUpdateEnvelope = { fingerprint: bob.fingerprint, epoch: 0, version: 1, updated_at: '2026-08-19T00:00:00.000Z', changed_fields: ['display_name'], delta: { display_name: 'Bob (NEW)' } };
  return { envelope: env, signature: await signWithEnvelope(DOMAIN_CONTACT_UPDATE, contactUpdateSigningInput(env), bob.privateKey, bob.passphrase) };
}
async function run(f: typeof fetch, extra: Partial<ConsumeDeps> = {}, persisted: unknown[] = []) {
  const signed = await signedUpdate();
  const kc = known();
  const status = await pollLiveBookOnce({}, { buildDeps: async () => ({
    owner: { fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase },
    decrypt: async () => signed,
    store: { lookup: async (fp: string) => (fp === bob.fingerprint ? kc : null), persist: async (_id: string, next: StoredContact) => { persisted.push(next); } },
    relayBase: 'http://relay.test/api/relay', now: () => '2026-08-19T00:00:00.000Z', fetchImpl: f, ...extra,
  }) });
  return { status, note: refreshNoteFor(status) };
}

test('V1 control: one envelope OPENED, STORED and ACKED (200) -> Caught up.', async () => {
  const persisted: unknown[] = [];
  const r = await run(relay({ queue: [{ envelope_id: 'e1', blob: 'B' }] }), {}, persisted);
  assert.equal(persisted.length, 1, 'it really was applied and stored'); assert.equal(r.note, CAUGHT);
});
test('V2 Flint\'s open gap: an envelope that OPENED and was STORED, ack returns 500 -> the v4 line (not Caught up., not "couldn\'t be opened")', async () => {
  const persisted: unknown[] = [];
  const r = await run(relay({ queue: [{ envelope_id: 'e1', blob: 'B' }], ackStatus: 500 }), {}, persisted);
  assert.equal(persisted.length, 1, 'it really was applied and stored'); assert.equal(r.status, 'checked-waiting'); assert.equal(r.note, WAITING);
  assert.doesNotMatch(r.note, /opened/);
});
test('V3 one HELD envelope (no kem secret) -> the v4 line', async () => {
  const r = await run(relay({ queue: [{ envelope_id: 'h1', blob: HYBRID }] }), { hybridSecretMissing: true });
  assert.equal(r.note, WAITING);
});
test('V4 two envelopes, one acked, one held -> the v4 line (acked < polled and held)', async () => {
  const r = await run(relay({ queue: [{ envelope_id: 'e1', blob: 'B' }, { envelope_id: 'h1', blob: HYBRID }] }), { hybridSecretMissing: async () => true });
  assert.equal(r.note, WAITING);
});
test('V5 empty list -> Caught up.; malformed 200 ({} / null / "x" / 7) -> Could not check right now.; refused 401/403/500/503 -> same', async () => {
  assert.equal((await run(relay({ queue: [] }))).note, CAUGHT);
  for (const b of [{}, null, 'x', 7]) { const r = await run(relay({ queue: b })); assert.equal(r.note, FAILED, JSON.stringify(b)); assert.equal(r.status, 'unreadable'); }
  for (const s of [401, 403, 500, 503]) { const r = await run(relay({ queue: {}, queueStatus: s })); assert.equal(r.note, FAILED, String(s)); assert.equal(r.status, 'rejected'); }
});
test('V6 locked (no deps) -> Unlock...; a lock landing MID-poll (cycle ended) -> Unlock..., never Caught up.', async () => {
  assert.equal(refreshNoteFor(await pollLiveBookOnce({}, { buildDeps: async () => null })), LOCKED);
  const cycle = makeUnlockCycle(alice.privateKey, alice.passphrase);
  const r = await run(relay({ queue: [{ envelope_id: 'e1', blob: 'B' }, { envelope_id: 'e2', blob: 'B2' }] }),
    { owner: { fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase, cycle }, decrypt: async () => { cycle.drop(); return null; } });
  assert.equal(r.note, LOCKED); assert.notEqual(r.note, CAUGHT);
});
