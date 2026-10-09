import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  pqPubStringsFromIdentity,
  publicKeyFromIdentity,
  redeemBetaAccessKey,
} from './beta-redeem';

describe('redeemBetaAccessKey — thin claim wrapper', () => {
  it('refuses an empty token without calling fetch (not an admit oracle)', async () => {
    let fetchCalls = 0;
    const r = await redeemBetaAccessKey({
      token: '   ',
      fingerprint: 'aa'.repeat(32),
      publicKeyArmored: 'PUB',
      privateKeyArmored: 'PRIV',
      passphrase: 'pw',
      fetchImpl: async () => {
        fetchCalls += 1;
        return new Response('{}');
      },
      signClaim: async () => ({ 'x-svrnty-owner-auth': 'nope' }),
      mailboxIdOf: () => 'mbx_test',
    });
    assert.equal(r.ok, false);
    assert.equal(fetchCalls, 0);
  });

  it('treats a non-claimed HTTP body as uniform failure', async () => {
    const r = await redeemBetaAccessKey({
      token: 'wire-token',
      fingerprint: 'aa'.repeat(32),
      publicKeyArmored: 'PUB',
      privateKeyArmored: 'PRIV',
      passphrase: 'pw',
      fetchImpl: async () => new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401 }),
      signClaim: async () => ({ 'x-svrnty-owner-auth': 'bundle' }),
      mailboxIdOf: (fp) => 'mbx_' + fp.slice(0, 4),
    });
    assert.equal(r.ok, false);
  });

  it('returns ok only on { status: claimed }', async () => {
    let posted: { url: string; token?: string } = { url: '' };
    const r = await redeemBetaAccessKey({
      token: '  wire-token  ',
      fingerprint: 'bb'.repeat(32),
      publicKeyArmored: 'PUB',
      privateKeyArmored: 'PRIV',
      passphrase: 'pw',
      kemPublicKey: 'kem',
      sigPublicKey: 'sig',
      fetchImpl: async (url, init) => {
        posted = { url: String(url), token: JSON.parse(String(init?.body)).token };
        return new Response(JSON.stringify({ status: 'claimed', idempotent: false }), { status: 200 });
      },
      signClaim: async (args) => {
        assert.equal(args.mailboxId, 'mbx_from_fp');
        assert.equal(args.kemPublicKey, 'kem');
        return { 'x-svrnty-owner-auth': 'bundle' };
      },
      mailboxIdOf: () => 'mbx_from_fp',
    });
    assert.equal(r.ok, true);
    assert.equal(posted.url, '/api/relay/claim');
    assert.equal(posted.token, 'wire-token');
  });
});

describe('identity field reads (no crypto)', () => {
  it('reads public_key and PQ pubs from the genesis wrapper', () => {
    const id = {
      identity: { fingerprint: 'f', public_key: 'BEGIN PGP' },
      post_quantum: { kem_public_key: 'kemB64', sig_public_key: 'sigB64' },
    };
    assert.equal(publicKeyFromIdentity(id), 'BEGIN PGP');
    assert.deepEqual(pqPubStringsFromIdentity(id), {
      kemPublicKey: 'kemB64',
      sigPublicKey: 'sigB64',
    });
  });

  it('fails closed on missing pubs', () => {
    assert.equal(publicKeyFromIdentity(null), '');
    assert.deepEqual(pqPubStringsFromIdentity({}), {
      kemPublicKey: undefined,
      sigPublicKey: undefined,
    });
  });
});
