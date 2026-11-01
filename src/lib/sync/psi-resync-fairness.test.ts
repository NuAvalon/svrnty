// src/lib/sync/psi-resync-fairness.test.ts
// The PSI resync queue over many ticks: K=1 request per tick, so WHO goes first decides who is ever reached. This drives the real loop in the
// order the app runs it (completion pass, sync tick, save the initiated sessions, mark who was attempted), with a store that applies its updates,
// the real overlay deps, and a relay stub that can refuse or ignore chosen peers.
//   - a peer whose request errors, or whose session expires unanswered, must not stay first: peers behind it are reached.
//   - a completed exchange stamps mutual.last_sync, so the peer is not re-queued for 24 h; an unanswered or errored attempt never does.
//
// Run: npx tsx --test src/lib/sync/psi-resync-fairness.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys, mailboxFpOf } from '@/lib/crypto/mailbox-keys';
import { openPsiFromSatellite } from '@/lib/crypto/psi-wire-seal';
import type { MailboxEnvelopePackage } from '@/lib/crypto/mailbox-envelope';
import type { ContactRecord } from '@/lib/identity/client-store';
import type { PSISyncOptions } from '@/lib/trust/mutual-trust-sync';
import { ResyncSlotSource } from '@/lib/trust/psi-resync-slot';
import {
  buildKnowOverlayDeps,
  markPsiAttempted,
  runKnowLayerSyncTick,
  runPsiCompletionPass,
  savePsiInitiated,
  type CompleteTrustSyncFn,
  type KnowOverlayStore,
} from './know-layer-sync';

const OWNER = 'ab'.repeat(32);
const sat = generateMailboxKeypair();
const fpN = (i: number) => i.toString(16).padStart(64, '0');
const TICK_MS = 5 * 60 * 1000;
const READY = { mutualFingerprints: [], totalChecked: 0, sessionId: 's', role: 'initiator' };

/** A device: `n` trusted, consented contacts; the relay refuses `refuse` and the completion answers only `answer`. */
function device(n: number, opts: { refuse?: Set<string>; answer?: Set<string> } = {}) {
  const contacts: ContactRecord[] = Array.from({ length: n }, (_, i) => ({
    id: `c${i + 1}`, fingerprint: fpN(i + 1), name: `Peer ${i + 1}`, email: '', public_key: 'pk', trust_level: 'trusted',
    added_at: new Date().toISOString(), trusted: true, open_visibility: true,
  }) as ContactRecord);
  const store: KnowOverlayStore = {
    getAllContacts: async () => contacts,
    updateContact: async (id, updates) => {
      const i = contacts.findIndex((c) => c.id === id);
      contacts[i] = { ...contacts[i], ...updates } as ContactRecord;
    },
  };
  let clock = Date.UTC(2026, 10, 1, 9, 0, 0);
  const slots = new ResyncSlotSource(toPublicKeys(sat), () => clock);
  const options: PSISyncOptions = {
    satelliteUrl: 'http://sat.test', myFingerprint: OWNER, signFn: () => new Uint8Array(64), pqWrap: { satelliteKeys: toPublicKeys(sat) }, slots,
  };
  const attemptedLog: string[] = []; // every real request the relay saw, in order, refused or not
  const completeFn: CompleteTrustSyncFn = (async (_d: unknown, _sid: string, peerFp: string) =>
    (opts.answer?.has(peerFp) ? READY : { error: 'Session not ready or not found' })) as unknown as CompleteTrustSyncFn;
  const realFetch = globalThis.fetch;
  let seq = 0;
  const install = () => {
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
      const u = String(url);
      if (init?.method === 'POST' && u.endsWith('/trust/psi/initiate')) {
        const body = (await openPsiFromSatellite(JSON.parse(String(init.body)) as MailboxEnvelopePackage, toSecretKeys(sat), mailboxFpOf(sat))) as Record<string, unknown>;
        if (body.cover === true) return new Response(JSON.stringify({ session_id: 'cover' }), { status: 200 });
        const peer = body.responder_fingerprint as string;
        attemptedLog.push(peer);
        if (opts.refuse?.has(peer)) return new Response(JSON.stringify({ detail: 'refused' }), { status: 429 });
        return new Response(JSON.stringify({ session_id: `s${++seq}` }), { status: 200 });
      }
      if (u.includes('/trust/psi/pending/')) return new Response(JSON.stringify({ sessions: [] }), { status: 200 });
      return new Response('unexpected', { status: 500 });
    }) as typeof fetch;
  };
  const restore = () => { globalThis.fetch = realFetch; };
  /** One tick, in the order startKnowLayerSync runs it. */
  const tick = async () => {
    const deps = buildKnowOverlayDeps(OWNER, store);
    await runPsiCompletionPass(store, OWNER, deps, options, completeFn);
    const r = await runKnowLayerSyncTick(deps, options);
    await savePsiInitiated(store, OWNER, r.initiated);
    await markPsiAttempted(store, OWNER, r.attempted);
    clock += TICK_MS;
    return r;
  };
  const lastSync = (i: number) => (contacts[i - 1].mutual as { last_sync?: string | null } | undefined)?.last_sync ?? null;
  return { contacts, store, tick, install, restore, attemptedLog, lastSync };
}

/** Run `ticks` ticks with the relay stub installed. */
async function run(d: ReturnType<typeof device>, ticks: number) {
  d.install();
  try { for (let t = 0; t < ticks; t++) await d.tick(); } finally { d.restore(); }
}

// ── Head of the queue ───────────────────────────────────────────────────────────────────────────────

test('15 contacts, the first 12 refused by the relay: the 13th is reached within 15 ticks', async () => {
  const refuse = new Set(Array.from({ length: 12 }, (_, i) => fpN(i + 1)));
  const d = device(15, { refuse });
  await run(d, 15);
  assert.ok(d.attemptedLog.includes(fpN(13)), `the 13th contact was never attempted; attempts: ${d.attemptedLog.map((f) => parseInt(f, 16)).join(',')}`);
  assert.ok(d.attemptedLog.indexOf(fpN(13)) < 15);
});

test('15 contacts, the first 12 never answer: the 13th is reached within 15 ticks, completes, and only it is stamped', async () => {
  const d = device(15, { answer: new Set([fpN(13), fpN(14), fpN(15)]) });
  await run(d, 17);
  assert.ok(d.attemptedLog.indexOf(fpN(13)) >= 0 && d.attemptedLog.indexOf(fpN(13)) < 15, `13th attempted at index ${d.attemptedLog.indexOf(fpN(13))}`);
  assert.ok(d.lastSync(13), 'the completed exchange stamped mutual.last_sync');
  assert.ok(Number.isFinite(Date.parse(d.lastSync(13)!)), 'as an ISO time');
  for (let i = 1; i <= 12; i++) assert.equal(d.lastSync(i), null, `an unanswered attempt to contact ${i} must not look like a sync`);
});

test('30 contacts, the first 20 never answer: the 21st is still reached (within 25 ticks) although expired sessions keep coming back due', async () => {
  // With one request per tick, a session lives about 13 ticks. From tick 14 the earliest sessions have expired and are due again. In book order each
  // expired peer is first again, so only about the first 13 peers are ever served and the 21st never is. With rotation the peers never tried go first
  // (in book order), so the 21st is reached at tick 21. (The literal 15-contact case above is served by tick 13 either way.)
  const d = device(30, { answer: new Set(Array.from({ length: 10 }, (_, i) => fpN(21 + i))) });
  await run(d, 26);
  const at = d.attemptedLog.indexOf(fpN(21));
  assert.ok(at >= 0 && at < 25, `the 21st contact was attempted at index ${at}; attempts: ${d.attemptedLog.map((f) => parseInt(f, 16)).join(',')}`);
  assert.ok(d.lastSync(21), 'and its completed exchange stamped last_sync');
  for (let i = 1; i <= 20; i++) assert.equal(d.lastSync(i), null);
});

test('an attempt that errors does not stamp last_sync either', async () => {
  const d = device(3, { refuse: new Set([fpN(1), fpN(2), fpN(3)]) });
  await run(d, 6);
  for (let i = 1; i <= 3; i++) assert.equal(d.lastSync(i), null);
});

// ── After a completed exchange ──────────────────────────────────────────────────────────────────────

test('a completed peer is not asked again for 24 h: five answering peers are each initiated exactly once over 30 ticks', async () => {
  const peers = [1, 2, 3, 4, 5].map(fpN);
  const d = device(5, { answer: new Set(peers) });
  await run(d, 30);
  for (const p of peers) assert.equal(d.attemptedLog.filter((x) => x === p).length, 1, `contact ${parseInt(p, 16)} initiated ${d.attemptedLog.filter((x) => x === p).length} times`);
  for (let i = 1; i <= 5; i++) assert.ok(d.lastSync(i));
});

test('stamping last_sync keeps what was already in mutual and adds no trust claim', async () => {
  const d = device(1, { answer: new Set([fpN(1)]) });
  d.contacts[0] = { ...d.contacts[0], mutual: { they_trust_me: true, reciprocal: true, last_sync: null } } as ContactRecord;
  await run(d, 4);
  const m = d.contacts[0].mutual as Record<string, unknown>;
  assert.ok(m.last_sync);
  assert.equal(m.they_trust_me, true, 'existing fields are kept as they were');
  assert.equal(m.reciprocal, true);
  const fresh = device(1, { answer: new Set([fpN(1)]) });
  await run(fresh, 4);
  const fm = fresh.contacts[0].mutual as Record<string, unknown>;
  assert.equal(fm.they_trust_me, null, 'a record with no mutual gets the benign default, not a trust claim');
  assert.equal(fm.reciprocal, false);
});

// ── markPsiAttempted on its own ─────────────────────────────────────────────────────────────────────

test('markPsiAttempted numbers attempts in order, after the largest on the book, ignores unknown peers, and never touches last_sync', async () => {
  const d = device(3);
  d.contacts[1] = { ...d.contacts[1], psi_try_seq: 7 } as ContactRecord;
  await markPsiAttempted(d.store, OWNER, [fpN(3), 'ff'.repeat(32), fpN(1)]);
  assert.equal(d.contacts[2].psi_try_seq, 8);
  assert.equal(d.contacts[0].psi_try_seq, 9);
  assert.equal(d.contacts[1].psi_try_seq, 7, 'a contact not named is left as it was');
  assert.equal(d.contacts.some((c) => c.mutual && (c.mutual as { last_sync?: unknown }).last_sync), false);
  await markPsiAttempted(d.store, OWNER, undefined);
  await markPsiAttempted(d.store, OWNER, []);
  assert.equal(d.contacts[0].psi_try_seq, 9, 'nothing attempted: nothing written');
});
