// src/lib/connect/add-logic.test.ts
// Anchors for the Connect-UX add-logic seam (CURSOR_QUEUE.md #3).
// Every dependency is mocked — these tests pin the CONTRACT, not the plumbing.
/* eslint-disable @typescript-eslint/no-explicit-any */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  createConnectAddLogic,
  type ConnectDeps,
  type ConnectLinkCard,
} from './add-logic';

const FP =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

function makeDeps(over: Partial<ConnectDeps> = {}) {
  const calls = { enqueued: [] as any[], admitted: [] as any[], resolved: 0 };
  const deps: ConnectDeps = {
    resolveRelay: async () => {
      calls.resolved++;
      return JSON.stringify({
        identity: {
          fingerprint: FP,
          display_name: 'Ada',
          entity_type: 'human',
          public_key: 'PUB',
        },
      });
    },
    classifyImportedCard: async () => ({
      importClassical: true,
      pq: { pq_kem_public_key: 'KEM', pq_sig_public_key: 'SIG' },
      alarm: 'quiet',
      branch: '4b',
      deviceMailbox: null,
    }),
    enqueueGateArrival: async (_o: string, a: any) => {
      calls.enqueued.push(a);
    },
    getContactByFingerprint: async () => null,
    getGateArrival: async () => null,
    admitGateArrival: async (_o: string, _a: any) => {
      calls.admitted.push(_a);
      return { id: 'c1' } as any;
    },
    ...over,
  };
  return { deps, calls };
}

const CARD: ConnectLinkCard = {
  fingerprint: FP,
  displayName: 'Ada',
  entityType: 'human',
  publicKeyArmored: 'PUB',
  inviteNonce: 'abc123',
};

describe('parseConnectLink', () => {
  const l = createConnectAddLogic(makeDeps().deps);

  it('accepts a full https invite link with fragment', () => {
    assert.deepEqual(l.parseConnectLink('https://svrnty.is/c/abc123#keymaterial'), {
      code: 'abc123',
      keyFragment: 'keymaterial',
    });
  });

  it('accepts a scheme-less link', () => {
    const p = l.parseConnectLink('svrnty.is/c/x1#frag');
    assert.equal(p?.code, 'x1');
    assert.equal(p?.keyFragment, 'frag');
  });

  it('accepts a fragment-less link (post-flip shape is a parse OK, resolve refuses)', () => {
    assert.deepEqual(l.parseConnectLink('https://svrnty.is/c/abc123'), { code: 'abc123' });
  });

  it('accepts the bare code', () => {
    assert.deepEqual(l.parseConnectLink('abc123'), { code: 'abc123' });
  });

  it('rejects wrong host, wrong path, whitespace, non-strings — TOTAL, never throws', () => {
    assert.equal(l.parseConnectLink('https://evil.example/c/abc#k'), null);
    assert.equal(l.parseConnectLink('https://svrnty.is/x/abc#k'), null);
    assert.equal(l.parseConnectLink('  '), null);
    assert.equal(l.parseConnectLink(''), null);
    assert.equal(l.parseConnectLink(undefined), null);
    assert.equal(l.parseConnectLink(42), null);
    assert.equal(l.parseConnectLink('https://svrnty.is/c/a b#k'), null);
  });
});

describe('resolve', () => {
  it('fragment-less link refuses "unwired" — the post-flip format is not live', async () => {
    const { deps, calls } = makeDeps();
    const l = createConnectAddLogic(deps);
    const r = await l.resolve({ code: 'abc123' });
    assert.deepEqual(r, { ok: false, refusal: 'unwired' });
    assert.equal(calls.resolved, 0); // no network spent on an unwired shape
  });

  it('bad code refuses "bad-link" before any network', async () => {
    const { deps, calls } = makeDeps();
    const l = createConnectAddLogic(deps);
    const r = await l.resolve({ code: '!!', keyFragment: 'k' });
    assert.equal(r.ok, false);
    assert.equal((r as any).refusal, 'bad-link');
    assert.equal(calls.resolved, 0);
  });

  it('a relay failure refuses "resolve-failed"', async () => {
    const { deps } = makeDeps({
      resolveRelay: async () => {
        throw new Error('404');
      },
    });
    const l = createConnectAddLogic(deps);
    const r = await l.resolve({ code: 'abc', keyFragment: 'k' });
    assert.equal(r.ok, false);
    assert.equal((r as any).refusal, 'resolve-failed');
  });

  it('unreadable blob refuses "resolve-failed"', async () => {
    const { deps } = makeDeps({ resolveRelay: async () => 'not-json{' });
    const l = createConnectAddLogic(deps);
    const r = await l.resolve({ code: 'abc', keyFragment: 'k' });
    assert.equal(r.ok, false);
    assert.equal((r as any).refusal, 'resolve-failed');
  });

  it('a non-card payload (shard-shaped) refuses "not-a-card" — honest, never a verify failure', async () => {
    const { deps } = makeDeps({
      resolveRelay: async () =>
        JSON.stringify({ type: 'svrnty-shard-custody', shard: { data: 'x' } }),
    });
    const l = createConnectAddLogic(deps);
    const r = await l.resolve({ code: 'abc', keyFragment: 'k' });
    assert.deepEqual(r, { ok: false, refusal: 'not-a-card' });
  });

  it('fp↔key mismatch refuses "unverified-card" (anti-spoof — never imported)', async () => {
    const { deps } = makeDeps({
      classifyImportedCard: async () => ({
        importClassical: false,
        pq: null,
        alarm: 'reject',
        branch: 1,
        deviceMailbox: null,
      }),
    });
    const l = createConnectAddLogic(deps);
    const r = await l.resolve({ code: 'abc', keyFragment: 'k' });
    assert.deepEqual(r, { ok: false, refusal: 'unverified-card' });
  });

  it('a verified card yields name, canonical fp, pq legs, and attested entity type', async () => {
    const { deps } = makeDeps();
    const l = createConnectAddLogic(deps);
    const r = await l.resolve({ code: 'abc', keyFragment: 'k' });
    assert.equal(r.ok, true);
    const card = (r as any).card as ConnectLinkCard;
    assert.equal(card.fingerprint, FP);
    assert.equal(card.displayName, 'Ada');
    assert.equal(card.entityType, 'human');
    assert.equal(card.pqKemPublicKey, 'KEM');
    assert.equal(card.pqSigPublicKey, 'SIG');
    assert.equal(card.inviteNonce, 'abc');
  });

  it('an absent entity_type resolves to "unknown" — not-yet-attested, never guessed', async () => {
    const { deps } = makeDeps({
      resolveRelay: async () =>
        JSON.stringify({ identity: { fingerprint: FP, display_name: 'A', public_key: 'P' } }),
    });
    const l = createConnectAddLogic(deps);
    const r = await l.resolve({ code: 'abc', keyFragment: 'k' });
    assert.equal((r as any).card.entityType, 'unknown');
  });

  it('a fingerprintless card can never resolve ok:true', async () => {
    const { deps } = makeDeps({
      resolveRelay: async () =>
        JSON.stringify({ identity: { display_name: 'A', public_key: 'P' } }),
    });
    const l = createConnectAddLogic(deps);
    const r = await l.resolve({ code: 'abc', keyFragment: 'k' });
    assert.deepEqual(r, { ok: false, refusal: 'unverified-card' });
  });
});

describe('landInGate — invariant 1: arrival is Gate, never Known', () => {
  it('enqueues a GateArrival (remote, scanned_giver) — writes NO contact', async () => {
    const { deps, calls } = makeDeps();
    const l = createConnectAddLogic(deps);
    const r = await l.landInGate('owner', CARD);
    assert.equal(r.kind, 'landed');
    assert.equal(calls.enqueued.length, 1);
    const a = calls.enqueued[0];
    assert.equal(a.fingerprint, FP);
    assert.equal(a.mintChannel, 'remote');
    assert.equal(a.direction, 'scanned_giver');
    assert.equal(a.inviteNonce, 'abc123');
    assert.equal(calls.admitted.length, 0); // never promoted by landing
  });

  it('carries pq legs onto the arrival so admit binds the canonical fp', async () => {
    const { deps, calls } = makeDeps();
    const l = createConnectAddLogic(deps);
    await l.landInGate('owner', { ...CARD, pqKemPublicKey: 'K', pqSigPublicKey: 'S' });
    assert.equal(calls.enqueued[0].pqKemPublicKey, 'K');
    assert.equal(calls.enqueued[0].pqSigPublicKey, 'S');
  });

  it('is idempotent: already-gated fp lands as already-gate, no rewrite', async () => {
    const { deps, calls } = makeDeps({ getGateArrival: async () => ({}) as any });
    const l = createConnectAddLogic(deps);
    const r = await l.landInGate('owner', CARD);
    assert.equal(r.kind, 'already-gate');
    assert.equal(calls.enqueued.length, 0);
  });

  it('already-known fp lands as already-known, no gate row written', async () => {
    const { deps, calls } = makeDeps({ getContactByFingerprint: async () => ({}) as any });
    const l = createConnectAddLogic(deps);
    const r = await l.landInGate('owner', CARD);
    assert.equal(r.kind, 'already-known');
    assert.equal(calls.enqueued.length, 0);
  });

  it('refuses an unbindable card — nothing written', async () => {
    const { deps, calls } = makeDeps();
    const l = createConnectAddLogic(deps);
    const r = await l.landInGate('owner', { ...CARD, fingerprint: '' });
    assert.equal(r.kind, 'refused');
    assert.equal(calls.enqueued.length, 0);
  });
});

describe('promoteToKnown — invariant 5: only ever an explicit call', () => {
  it('delegates to admitGateArrival with owner opts', async () => {
    const { deps, calls } = makeDeps();
    const l = createConnectAddLogic(deps);
    const arrival = { fingerprint: FP } as any;
    await l.promoteToKnown('owner', arrival, { name: 'Ada', tags: ['t'] });
    assert.equal(calls.admitted.length, 1);
    assert.equal(calls.admitted[0], arrival);
  });
});
