// S14 on N10 (Flint #179187, item 1): the hybrid leg must have the lifetime of the poll TICK, like the unlock cycle.
//   • a dead cycle (lock/switch/drop) opens NOTHING on the hybrid leg (openHybridForCycle),
//   • dropping the cycle zeroes the hybrid secrets (cycleDroppingHybrid), so they never outlive the tick,
//   • lock mid-poll with a hybrid blob in flight → nothing persisted, nothing acked (retryable).
// Run: npx tsx --test src/lib/sync/hybrid-cycle-scope.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { signWithEnvelope } from '@/lib/crypto/sign-envelope';
import { DOMAIN_CONTACT_UPDATE, contactUpdateSigningInput, type ContactUpdateEnvelope } from '@/lib/format/envelope';
import type { SignedContactUpdate, KnownContactIdentity } from '@/lib/trust/contact-update';
import type { StoredContact } from '@/lib/contacts/apply-contact-update';
import { makeUnlockCycle } from '@/lib/crypto/unlock-cycle';
import { lockSession } from '@/lib/identity/client-store';
import { consumeInboundContactUpdates, type ConsumeDeps, type KnownContact } from './consume-mailbox';
import { encryptContactUpdateTo, openpgpEnvelopeDecryptor, parseContactUpdateWire } from './contact-update-envelope';
import { makeHybridOpener, dualReadOpener, asMailboxEnvelopePackage } from './hybrid-dual-read';
import { cycleDroppingHybrid, openHybridForCycle } from './live-book-poll';
import { mintHybridRecipient, type HybridRecipient } from './hybrid-test-fixture';

let alice: HybridRecipient; // the mailbox owner: classical OpenPGP + ML-KEM
let bob: { fingerprint: string; publicKey: string; privateKey: string; passphrase: string }; // the sender (classical signer)
let blob: string; // Bob's signed contact-update, sealed PQ-hybrid to Alice

async function makeBob() {
  const passphrase = 'pw-bob';
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart — 'ed25519' is valid at runtime (see core.ts).
    curve: 'ed25519',
    userIDs: [{ name: 'bob', email: 'bob@x.test' }],
    passphrase,
    format: 'armored',
  });
  return { fingerprint: (await readKey({ armoredKey: publicKey })).getFingerprint(), publicKey, privateKey, passphrase };
}

const ENV = (fp: string): ContactUpdateEnvelope => ({
  fingerprint: fp, epoch: 0, version: 1, updated_at: '2026-08-19T00:00:00.000Z',
  changed_fields: ['display_name'], delta: { display_name: 'Bob (NEW name)' },
});

// Bob's signed update, sealed PQ-hybrid to `to`.
async function sealFor(to: HybridRecipient): Promise<string> {
  const env = ENV(bob.fingerprint);
  const signature = await signWithEnvelope(DOMAIN_CONTACT_UPDATE, contactUpdateSigningInput(env), bob.privateKey, bob.passphrase);
  const signed: SignedContactUpdate = { envelope: env, signature };
  const b = await encryptContactUpdateTo(signed, to.publicKeyArmored, to.pqKemPublicKey);
  assert.ok(asMailboxEnvelopePackage(b), 'precondition: the in-flight blob is a hybrid MailboxEnvelopePackage');
  return b;
}

before(async () => {
  alice = await mintHybridRecipient();
  bob = await makeBob();
  blob = await sealFor(alice);
});

const freshCycle = () => makeUnlockCycle(alice.privateKeyArmored, alice.passphrase);

test('openHybridForCycle: a LIVE cycle opens the hybrid blob', async () => {
  const cycle = freshCycle();
  const open = openHybridForCycle({ cycle }, alice.hybrid);
  const inner = await open(asMailboxEnvelopePackage(blob)!);
  assert.ok(inner, 'hybrid leg opens while the cycle is live');
  cycle.drop();
});

test('openHybridForCycle: after a session lock the SAME blob opens NOTHING (hybrid leg obeys the cycle)', async () => {
  const cycle = freshCycle();
  const open = openHybridForCycle({ cycle }, alice.hybrid);
  lockSession();
  assert.equal(cycle.ended, true);
  assert.equal(await open(asMailboxEnvelopePackage(blob)!), null, 'dead cycle => no hybrid open');
});

test('openHybridForCycle: after drop() the blob opens NOTHING', async () => {
  const cycle = freshCycle();
  const open = openHybridForCycle({ cycle }, alice.hybrid);
  cycle.drop();
  assert.equal(await open(asMailboxEnvelopePackage(blob)!), null);
});

test('cycleDroppingHybrid: drop() zeroes the hybrid secrets (tick lifetime, not session) and ends the cycle', async () => {
  const mine = await mintHybridRecipient(); // own copy: we zero it
  const sec = mine.hybrid.secrets;
  const nonZero = (a: Uint8Array) => a.some((b) => b !== 0);
  assert.ok(nonZero(sec.x25519Sec) && nonZero(sec.mlkem1024Sec), 'control: secrets are real before drop');
  const cycle = cycleDroppingHybrid(makeUnlockCycle(mine.privateKeyArmored, mine.passphrase), () => mine.hybrid);
  assert.equal(cycle.ended, false);
  cycle.drop();
  assert.equal(cycle.ended, true);
  assert.equal(nonZero(sec.x25519Sec), false, 'x25519 secret zeroed');
  assert.equal(nonZero(sec.mlkem1024Sec), false, 'ML-KEM secret zeroed');
  cycle.drop(); // idempotent
});

// ── consume-level: a hybrid blob in flight when the lock lands ──
function recordingFetch(ackLog: string[][], theBlob: string): typeof fetch {
  return (async (url: string, init?: RequestInit) => {
    if (String(url).includes('/queue')) {
      return new Response(JSON.stringify([{ envelope_id: 'e1', blob: theBlob }]), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (String(url).includes('/ack')) {
      ackLog.push(JSON.parse(String(init?.body ?? '{}')).envelope_ids);
      return new Response(JSON.stringify({ deleted: 1 }), { status: 200 });
    }
    return new Response('not found', { status: 404 });
  }) as unknown as typeof fetch;
}

function bobKnown(): KnownContact {
  const known: KnownContactIdentity = { fingerprint: bob.fingerprint, epoch: 0, version: 0, classicalPublicKeyArmored: bob.publicKey };
  const current: StoredContact = {
    id: 'contact-bob', fingerprint: bob.fingerprint, name: 'Bob (old name)', email: 'bob@old.test', public_key: bob.publicKey,
    trust_level: 'verified', added_at: '2026-01-01T00:00:00.000Z', version: 0,
  };
  return { known, current };
}

// Each consume-level test gets its OWN recipient + blob: dropping the cycle ZEROES the hybrid secrets (that is the
// point), so a shared recipient would be dead for the next test.
async function setup(lockDuringLookup: boolean) {
  const alice = await mintHybridRecipient();
  const blob = await sealFor(alice);
  const persisted: StoredContact[] = [];
  const ackLog: string[][] = [];
  const cycle = cycleDroppingHybrid(freshCycle(), () => alice.hybrid);
  const owner = { cycle };
  const deps: ConsumeDeps = {
    owner: {
      fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKeyArmored,
      privateKeyArmored: alice.privateKeyArmored, passphrase: alice.passphrase, cycle,
    },
    decrypt: dualReadOpener(
      makeHybridOpener(openHybridForCycle(owner, alice.hybrid), parseContactUpdateWire),
      openpgpEnvelopeDecryptor(alice.privateKeyArmored, alice.passphrase, cycle),
    ),
    store: {
      // the hybrid open has already resolved when lookup runs: this is "lock lands after decrypt, before persist"
      lookup: async (fp: string) => { if (lockDuringLookup) lockSession(); return fp === bob.fingerprint ? bobKnown() : null; },
      persist: async (_id: string, next: StoredContact) => { persisted.push(next); },
    },
    relayBase: 'http://relay.test/api/relay',
    now: () => '2026-08-19T00:00:00.000Z',
    fetchImpl: recordingFetch(ackLog, blob),
  };
  return { deps, persisted, ackLog, cycle };
}

test('hybrid blob in flight, lock lands after the hybrid open and before persist → nothing persisted, nothing acked', async () => {
  const { deps, persisted, ackLog, cycle } = await setup(true);
  const summary = await consumeInboundContactUpdates(deps);
  assert.equal(persisted.length, 0, 'NOTHING persisted after the lock');
  assert.deepEqual(ackLog, [], 'retryable: the envelope stays in the mailbox (no ack-delete)');
  assert.equal(summary.applied, 0);
  cycle.drop();
});

test('control: the same hybrid blob with NO lock is opened, persisted and acked (the guard only fires on a dead cycle)', async () => {
  const { deps, persisted, ackLog, cycle } = await setup(false);
  const summary = await consumeInboundContactUpdates(deps);
  assert.equal(persisted.length, 1);
  assert.equal(persisted[0].name, 'Bob (NEW name)');
  assert.deepEqual(ackLog, [['e1']]);
  assert.equal(summary.applied, 1);
  cycle.drop();
});
