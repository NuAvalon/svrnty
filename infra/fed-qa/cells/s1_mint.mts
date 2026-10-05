// infra/fed-qa/cells/s1_mint.mts
//
// fed-qa scenario S1 — "Mint K identities (headless mintHeadlessAgent, proven path)".
// Asserts the REAL, source-grounded contract (per Athena's F2 discipline + Hypatia's acceptance-honesty
// layer: assert the DEPLOYED contract verified vs source, never an assumed/intuitive one):
//
//   A. CARDS SIGN + Invariant-1 (fp ≡ H(pubkey)) — verifySignedIdentityCard(card) enforces BOTH:
//      (1) fingerprintMatchesKey(fp, pubkey, {kem,sig})  = the fp↔key binding (Invariant-1)
//      (2) the envelope signature over the canonical card = "card signs"
//   B. ★ FULL 64-hex, exact — NOT a prefix. canonicalClaimMatches() (fingerprint.ts:91) deliberately
//      accepts a PREFIX (derived.startsWith(claimed) for claimed.len>=16), so verifySignedIdentityCard
//      alone would pass a TRUNCATED fp. S1's Invariant-1 must be the full durable_id, so we additionally
//      INDEPENDENTLY recompute the canonical fp from the minted keys and assert strict equality.
//   C. subject_type === 'agent' — the headless path is silicon-only, fail-closed (no human self-attest).
//   D. all K durable_ids are distinct (no fingerprint collision across the batch).
//
// This cell is CLIENT-BEHAVIOUR (in-process mint + assertion) — it needs NO satellite image, so it runs
// pre-CONVERGE (like S0/S3). It does NOT graduate a G-gate on its own (Hypatia: stub/client-only ≠ gate-green).
//
// Run (from repo root):  npx tsx infra/fed-qa/cells/s1_mint.mts        (K via S1_K env, default 10)
// Bonus: emits the K durable_ids as JSON on the last line → feeds the glyph-distribution QA (Peter #160422).

import { mintHeadlessAgent } from '../../../src/lib/identity/headless-mint';
import { verifySignedIdentityCard } from '../../../src/lib/identity/identity-card-sign';
import { mintCanonicalFingerprint } from '../../../src/lib/identity/fingerprint';
import * as openpgp from 'openpgp';

const K = Number(process.env.S1_K ?? 10);
const b64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(`S1 FAIL: ${msg}`);
}

async function main() {
  const seen = new Set<string>();
  const durableIds: string[] = [];

  for (let i = 0; i < K; i++) {
    const art = await mintHeadlessAgent({ throwaway: true });
    const { durableId, subjectType, card } = art.introduction;

    // C — silicon-only
    assert(subjectType === 'agent', `#${i} subject_type must be 'agent', got ${subjectType}`);

    // A — card signs + Invariant-1 binding (the import-path verification)
    assert(await verifySignedIdentityCard(card), `#${i} verifySignedIdentityCard must pass (sig + fp↔key binding)`);

    // B — full 64-hex exact; then INDEPENDENT strict recompute (defeats the prefix-leniency)
    assert(/^[0-9a-f]{64}$/.test(durableId), `#${i} durable_id must be full 64 lowercase-hex, got "${durableId}"`);
    const pk = await openpgp.readPrivateKey({ armoredKey: art.secret_material.classicalPrivateKey });
    const decrypted = await openpgp.decryptKey({ privateKey: pk, passphrase: art.secret_material.classicalKpass });
    const { fingerprint } = await mintCanonicalFingerprint({
      decryptedIdentityKey: decrypted,
      kemPublicKey: b64(card.identity.pq_kem_public_key as string),
      sigPublicKey: b64(card.identity.pq_sig_public_key as string),
    });
    assert(fingerprint === durableId,
      `#${i} Invariant-1: independently-derived fp !== durable_id\n  derived=${fingerprint}\n  claimed=${durableId}`);

    // D — distinctness
    assert(!seen.has(durableId), `#${i} duplicate durable_id ${durableId}`);
    seen.add(durableId);
    durableIds.push(durableId);
  }

  assert(seen.size === K, `expected ${K} distinct durable_ids, got ${seen.size}`);
  console.log(`S1 PASS — ${K}/${K} identities: cards verify (sig + Invariant-1 binding), full-64-hex fp, independent fp-recompute exact, subject_type=agent, all distinct.`);
  // last line = machine-readable payload for the glyph-distribution QA
  console.log(JSON.stringify({ scenario: 'S1', k: K, durable_ids: durableIds }));
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
