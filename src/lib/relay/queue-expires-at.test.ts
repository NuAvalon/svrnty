// src/lib/relay/queue-expires-at.test.ts
// #720 kept-line date (Archie #1955, Athena #1956): the owner's poll reports, per envelope, the moment the RELAY will delete it.
// A client that only knows its own first-poll time would promise "first_seen + 7 d", which is later than the real expiry for a message
// deposited before that first poll. The relay already stores expires_at (the column its sweep deletes on); this pins that the poll returns
// THAT value, additively, and nothing else new.
//
// Run: npx tsx --test src/lib/relay/queue-expires-at.test.ts

process.env.RELAY_DB_PATH = ':memory:'; // in-memory SQLite (the runner sets no NODE_ENV)
import { test, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle, uint8ToBase64 } from '@/lib/crypto/pq';
import { mintCanonicalFingerprint } from '@/lib/identity/fingerprint';
import { depositEnvelope, pollMailbox, resetMailboxStore } from './mailbox-store';
import { deriveMailboxId, signMailboxPollRequest } from './mailbox-auth';

const DAY = 24 * 60 * 60 * 1000;
const TTL = 7 * DAY;

interface Canon { fp: string; pub: string; priv: string; pass: string; kemB64: string; sigB64: string }

async function mkCanon(name: string): Promise<Canon> {
  const pass = `pw-${name}`;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime.
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase: pass,
    format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: pass });
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  return { fp: fingerprint, pub: publicKey, priv: privateKey, pass, kemB64: uint8ToBase64(pq.kem.publicKey), sigB64: uint8ToBase64(pq.signing.publicKey) };
}

let OWNER: Canon;
before(async () => {
  OWNER = await mkCanon('owner');
});
beforeEach(() => {
  resetMailboxStore();
  delete process.env.RELAY_ENVELOPE_TTL_MS;
  delete process.env.INVITE_REQUIRED;
});

async function routePoll(authed: boolean): Promise<{ status: number; body: unknown }> {
  const { GET } = await import('../../../app/api/relay/queue/route');
  const mailboxId = deriveMailboxId(OWNER.fp);
  const headers = authed
    ? await signMailboxPollRequest({ mailboxId, fingerprint: OWNER.fp, publicKeyArmored: OWNER.pub, privateKeyArmored: OWNER.priv, passphrase: OWNER.pass, now: Date.now(), kemPublicKey: OWNER.kemB64, sigPublicKey: OWNER.sigB64 })
    : {};
  const res = await GET(new Request(`http://r.test/api/relay/queue?mailbox_id=${encodeURIComponent(mailboxId)}`, { headers }));
  return { status: res.status, body: await res.json() };
}

test('E1 store: each polled envelope carries ITS OWN stored expiry (deposit time + TTL), not a poll-time guess', () => {
  const t0 = 10 * DAY;
  depositEnvelope('mbx', 'OLD', t0);            // deposited 3 days before the poll below
  depositEnvelope('mbx', 'NEW', t0 + 3 * DAY);  // deposited at the poll
  const list = pollMailbox('mbx', t0 + 3 * DAY);
  assert.deepEqual(list.map((e) => e.blob), ['OLD', 'NEW']);
  assert.equal(list[0].expires_at, t0 + TTL, 'OLD expires 4 days after the poll, not 7');
  assert.equal(list[1].expires_at, t0 + 3 * DAY + TTL);
  assert.equal(list[0].expires_at - (t0 + 3 * DAY), 4 * DAY);
});

test('E2 store: the expiry follows the configured TTL', () => {
  process.env.RELAY_ENVELOPE_TTL_MS = String(2 * DAY);
  depositEnvelope('mbx', 'X', 1000);
  assert.equal(pollMailbox('mbx', 1000)[0].expires_at, 1000 + 2 * DAY);
});

test('E3 store: the reported expiry IS the sweep boundary: present the instant before it, gone at it', () => {
  depositEnvelope('mbx', 'X', 5000);
  const exp = pollMailbox('mbx', 5000)[0].expires_at;
  assert.equal(pollMailbox('mbx', exp - 1).length, 1, 'still there 1 ms before the reported expiry');
  assert.equal(pollMailbox('mbx', exp).length, 0, 'deleted at the reported expiry');
});

test('E4 route: the owner poll returns ISO expires_at equal to the stored value, for a message deposited 3 days ago', async () => {
  const before = Date.now();
  depositEnvelope(deriveMailboxId(OWNER.fp), 'OLDBLOB', before - 3 * DAY);
  const { status, body } = await routePoll(true);
  assert.equal(status, 200);
  const list = body as Array<{ envelope_id: string; blob: string; expires_at: string }>;
  assert.equal(list.length, 1);
  const exp = Date.parse(list[0].expires_at);
  assert.equal(list[0].expires_at, new Date(before - 3 * DAY + TTL).toISOString(), 'exactly deposit + TTL');
  const daysOut = (exp - Date.now()) / DAY;
  assert.ok(daysOut > 3.99 && daysOut < 4.01, `about 4 days out, not 7 (got ${daysOut})`);
});

test('E5 route: the wire item has exactly {envelope_id, blob, expires_at}: no separate deposit time, nothing else new', async () => {
  depositEnvelope(deriveMailboxId(OWNER.fp), 'B', Date.now());
  const { body } = await routePoll(true);
  assert.deepEqual(Object.keys((body as object[])[0]).sort(), ['blob', 'envelope_id', 'expires_at']);
});

test('E6 route: a non-owner still gets the uniform 401 and no expiry (anti-oracle unchanged)', async () => {
  depositEnvelope(deriveMailboxId(OWNER.fp), 'SECRET', Date.now());
  const { status, body } = await routePoll(false);
  assert.equal(status, 401);
  assert.deepEqual(body, { error: 'unauthorized' });
});
