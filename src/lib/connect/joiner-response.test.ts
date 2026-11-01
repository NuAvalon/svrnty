// src/lib/connect/joiner-response.test.ts
// Anchors for the R1 return-channel deposit (connect-ux wiring, svrnty#365).
// The deposit is SHARED by JoinerCeremony + ConnectSheet — every dependency
// is injected so the contract pins here, not against a live store.
/* eslint-disable @typescript-eslint/no-explicit-any */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { depositJoinerResponse } from './joiner-response';

const OWNER = 'a'.repeat(64);
const PEER = {
  fingerprint: 'b'.repeat(64),
  publicKeyArmored: 'PEER_PUB',
  pqKemPublicKey: 'PEER_KEM',
};

function makeDeps(over: Record<string, any> = {}) {
  const calls = { sent: [] as any[] };
  const deps = {
    loadKey: async () => ({ privateKey: 'PRIV', passphrase: 'pp' }),
    loadIdentity: async () => ({
      identity: { public_key: 'OWN_PUB', display_name: 'Me' },
      post_quantum: { kem_public_key: 'K1', sig_public_key: 'S1' },
    }),
    sendJoinerResponse: async (joiner: any, giver: any) => {
      calls.sent.push({ joiner, giver });
      return { ok: true, status: 200 };
    },
    ...over,
  };
  return { deps, calls };
}

describe('depositJoinerResponse', () => {
  it('fires sendJoinerResponse bound to owner fp + peer card + code', async () => {
    const { deps, calls } = makeDeps();
    await depositJoinerResponse(OWNER, PEER, 'CODE123', deps);
    assert.equal(calls.sent.length, 1);
    const { joiner, giver } = calls.sent[0];
    assert.equal(joiner.fingerprint, OWNER);
    assert.equal(joiner.publicKeyArmored, 'OWN_PUB');
    assert.equal(joiner.privateKeyArmored, 'PRIV');
    assert.equal(joiner.kemPublicKeyB64, 'K1');
    assert.equal(joiner.sigPublicKeyB64, 'S1');
    assert.equal(giver.fingerprint, PEER.fingerprint);
    assert.equal(giver.publicKeyArmored, 'PEER_PUB');
    assert.equal(giver.giverPqKemPublicKey, 'PEER_KEM');
    assert.equal(giver.inviteNonce, 'CODE123');
  });

  it('classical identity omits the canonical-fp PQ fields', async () => {
    const { deps, calls } = makeDeps({
      loadIdentity: async () => ({ identity: { public_key: 'OWN_PUB', name: 'Me' } }),
    });
    await depositJoinerResponse(OWNER, PEER, 'C', deps);
    assert.equal('kemPublicKeyB64' in calls.sent[0].joiner, false);
  });

  it('locked identity: no send, resolves quietly — book entry stands', async () => {
    const { deps, calls } = makeDeps({ loadKey: async () => null });
    await assert.doesNotReject(() => depositJoinerResponse(OWNER, PEER, 'C', deps));
    assert.equal(calls.sent.length, 0);
  });

  it('missing own public key: no send, resolves quietly', async () => {
    const { deps, calls } = makeDeps({ loadIdentity: async () => null });
    await assert.doesNotReject(() => depositJoinerResponse(OWNER, PEER, 'C', deps));
    assert.equal(calls.sent.length, 0);
  });

  it('deposit transport failure: fail-soft — never throws', async () => {
    const { deps } = makeDeps({ sendJoinerResponse: async () => ({ ok: false, status: 502 }) });
    await assert.doesNotReject(() => depositJoinerResponse(OWNER, PEER, 'C', deps));
  });

  it('deposit throw: fail-soft — never throws', async () => {
    const { deps } = makeDeps({ sendJoinerResponse: async () => { throw new Error('relay down'); } });
    await assert.doesNotReject(() => depositJoinerResponse(OWNER, PEER, 'C', deps));
  });

  it('unbindable peer fields: early return, no send', async () => {
    const { deps, calls } = makeDeps();
    await depositJoinerResponse(OWNER, { fingerprint: '', publicKeyArmored: 'X' }, 'C', deps);
    await depositJoinerResponse(OWNER, { fingerprint: 'f', publicKeyArmored: '' }, 'C', deps);
    await depositJoinerResponse(OWNER, PEER, '', deps);
    assert.equal(calls.sent.length, 0);
  });
});
