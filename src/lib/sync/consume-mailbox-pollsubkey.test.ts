// src/lib/sync/consume-mailbox-pollsubkey.test.ts
// N12 (#703) through the REAL consumer: idle polls with `pollSubkey: true` carry only the poll header and cost no identity-key
// unlock (spy via makeUnlockCycle opts.onUnlock); the default path is unchanged (one unlock per poll cycle); acks still use the
// identity key; an old relay's 401 is reported, never silently downgraded to v1; a lock forces a NEW key.
// Run: npx tsx --test src/lib/sync/consume-mailbox-pollsubkey.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { makeUnlockCycle } from '@/lib/crypto/unlock-cycle';
import { lockSession } from '@/lib/identity/client-store';
import { OWNER_AUTH_HEADER, POLL_AUTH_HEADER } from '@/lib/relay/mailbox-auth';
import { dropPollKey, pollKeyState } from '@/lib/relay/poll-subkey';
import { consumeInboundContactUpdates, type ConsumeDeps } from './consume-mailbox';

interface Identity { fingerprint: string; publicKey: string; privateKey: string; passphrase: string }
let alice: Identity;

before(async () => {
  const passphrase = 'pw-alice';
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime (see core.ts).
    curve: 'ed25519',
    userIDs: [{ name: 'alice', email: 'alice@x.test' }],
    passphrase,
    format: 'armored',
  });
  alice = { fingerprint: (await readKey({ armoredKey: publicKey })).getFingerprint(), publicKey, privateKey, passphrase };
});

interface Seen { url: string; headers: Record<string, string> }
function recordingFetch(seen: Seen[], envelopes: Array<{ envelope_id: string; blob: string }> = [], queueStatus = 200): typeof fetch {
  return (async (url: string, init?: RequestInit) => {
    seen.push({ url: String(url), headers: { ...(init?.headers as Record<string, string> | undefined) } });
    if (String(url).includes('/queue')) {
      return queueStatus === 200
        ? new Response(JSON.stringify(envelopes), { status: 200, headers: { 'content-type': 'application/json' } })
        : new Response('unauthorized', { status: queueStatus });
    }
    if (String(url).includes('/ack')) return new Response(JSON.stringify({ deleted: 1 }), { status: 200 });
    return new Response('not found', { status: 404 });
  }) as unknown as typeof fetch;
}

const emptyStore = { lookup: async () => null, persist: async () => {} };

function deps(over: Partial<ConsumeDeps> & { fetchImpl: typeof fetch; cycle: ReturnType<typeof makeUnlockCycle> }): ConsumeDeps {
  const { cycle, ...rest } = over;
  return {
    owner: { fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase, cycle },
    decrypt: async () => null,
    store: emptyStore,
    ...rest,
  } as ConsumeDeps;
}

async function pollOnce(opts: { pollSubkey?: boolean; seen: Seen[]; unlocks: { n: number }; envelopes?: Array<{ envelope_id: string; blob: string }>; queueStatus?: number }) {
  const cycle = makeUnlockCycle(alice.privateKey, alice.passphrase, { onUnlock: () => { opts.unlocks.n++; } });
  try {
    return await consumeInboundContactUpdates(deps({ fetchImpl: recordingFetch(opts.seen, opts.envelopes, opts.queueStatus), cycle, pollSubkey: opts.pollSubkey }));
  } finally {
    cycle.drop();
  }
}

test('NEGATIVE BASELINE on the real consumer (default path): every idle poll cycle unlocks the identity key and sends only the owner header', async () => {
  dropPollKey();
  const seen: Seen[] = []; const unlocks = { n: 0 };
  for (let i = 0; i < 5; i++) await pollOnce({ seen, unlocks });
  assert.equal(unlocks.n, 5, 'one unlock per idle poll today (this is what N12 removes)');
  const queue = seen.filter((s) => s.url.includes('/queue'));
  assert.equal(queue.length, 5);
  for (const q of queue) {
    assert.ok(q.headers[OWNER_AUTH_HEADER], 'owner header present');
    assert.equal(q.headers[POLL_AUTH_HEADER], undefined, 'no v2 header on the default path');
  }
  assert.deepEqual(pollKeyState(), { held: false }, 'the default path never mints a poll key');
});

test('done_when (P3) on the real consumer: with pollSubkey, 5 idle polls cost ONE unlock (the mint) and carry ONLY the poll header', async () => {
  dropPollKey();
  const seen: Seen[] = []; const unlocks = { n: 0 };
  for (let i = 0; i < 5; i++) await pollOnce({ pollSubkey: true, seen, unlocks });
  assert.equal(unlocks.n, 1, '1 per cert mint, 0 per idle poll');
  const queue = seen.filter((s) => s.url.includes('/queue'));
  assert.equal(queue.length, 5);
  for (const q of queue) {
    assert.ok(q.headers[POLL_AUTH_HEADER], 'v2 header present');
    assert.equal(q.headers[OWNER_AUTH_HEADER], undefined, 'the identity-key header is NOT sent on an idle poll');
  }
  assert.equal(pollKeyState().held, true);
  dropPollKey();
});

test('an old relay that does not know the v2 header answers 401: the consumer REPORTS it (rejected=401) and makes NO second request (no silent downgrade to v1)', async () => {
  dropPollKey();
  const seen: Seen[] = []; const unlocks = { n: 0 };
  const summary = await pollOnce({ pollSubkey: true, seen, unlocks, queueStatus: 401 });
  assert.equal(summary.rejected, 401);
  assert.equal(seen.length, 1, 'exactly one request: no retry with the owner header');
  assert.equal(seen[0].headers[OWNER_AUTH_HEADER], undefined);
  dropPollKey();
});

test('after a lock the next consumer poll mints a NEW key (a different poll_pub) and unlocks again; the old key is gone', async () => {
  dropPollKey();
  const seen: Seen[] = []; const unlocks = { n: 0 };
  await pollOnce({ pollSubkey: true, seen, unlocks });
  const first = pollKeyState().pollPub;
  assert.ok(first);
  lockSession();
  assert.deepEqual(pollKeyState(), { held: false });
  await pollOnce({ pollSubkey: true, seen, unlocks });
  assert.notEqual(pollKeyState().pollPub, first);
  assert.equal(unlocks.n, 2, 'one mint before the lock, one after');
  dropPollKey();
});

test('the poll header is the only thing that changed on the wire: same URL and mailbox_id query on both paths', async () => {
  dropPollKey();
  const a: Seen[] = []; const b: Seen[] = []; const u = { n: 0 };
  await pollOnce({ seen: a, unlocks: u });
  await pollOnce({ pollSubkey: true, seen: b, unlocks: u });
  assert.equal(a[0].url, b[0].url);
  assert.match(a[0].url, /\/queue\?mailbox_id=mbx_[0-9a-f]{64}$/);
  dropPollKey();
});

test('the consumer wires the opt-in without changing ack: ack signing still goes through signMailboxAckRequest (identity key)', async () => {
  const { readFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const src = readFileSync(join(__dirname, 'consume-mailbox.ts'), 'utf8');
  assert.match(src, /signMailboxAckRequest\(/);
  assert.equal((src.match(/pollSubkeyHeaders\(/g) ?? []).length, 1, 'the poll subkey is used for the POLL only');
  const ackStart = src.indexOf('signMailboxAckRequest({');
  assert.doesNotMatch(src.slice(ackStart, ackStart + 600), /pollSubkey/);
});
