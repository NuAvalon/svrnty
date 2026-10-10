// src/lib/headless/custody-owner.ts
//
// Custody → HeadlessOwner adapter (custody ①, Peter #168173; Athena's custody lane).
//
// A headless agent has NO browser IndexedDB — so (unlike the FE path, where buildConsumeDeps sources
// the ML-KEM secret from loadPQKeys) the agent's own secret must ride ON the OwnerIdentity it hands to
// buildHeadlessConsumeDeps. This adapter maps the custody-store wire shape (SerializedMintArtifact,
// serializeMintArtifact in headless-mint.ts — what agent_custody.py stores + load_secret_material returns)
// into an OwnerIdentity carrying owner.kemSecretKey, so deriveOwnerHybridSecrets can build the hybrid
// open-material and the agent can OPEN inbound PQ-hybrid mail (else classical-only → the headless
// silent-loss gate). Pure + node-safe: type-only import of the artifact shape, no crypto/openpgp pulled in.
//
// Contract (Apollo #168442, co-confirmed): owner.kemSecretKey === private.mlkem1024_sec ===
// uint8ToBase64(MintSecret.mlkem1024Sec) — already clean B64 out of serializeMintArtifact.

import type { OwnerIdentity } from '@/lib/sync/consume-mailbox';
import type { SerializedMintArtifact } from '@/lib/identity/headless-mint';

/**
 * Build a headless agent's OwnerIdentity from its unlocked custody artifact.
 *
 * FAIL-CLOSED on the classical key material (public_key + private armored key): without it the owner
 * cannot sign poll/ack requests (owner-auth) at all, so a missing classical key is a hard error — never
 * a silently half-built owner. The PQ fields are OPTIONAL by design: a classical-only identity (no
 * ML-KEM) yields kemPublicKey/kemSecretKey = undefined → deriveOwnerHybridSecrets returns undefined →
 * classical-only openers (correct, not a loss). A kem-ADVERTISING owner whose secret is absent is the
 * loud-not-silent case the consume gate (③) surfaces — this adapter just threads what custody holds.
 */
export function custodyToHeadlessOwner(artifact: SerializedMintArtifact): OwnerIdentity {
  const pub = artifact?.public;
  const priv = artifact?.private;
  const id = pub?.card?.identity;
  if (!id?.public_key || !priv?.classical_private_key) {
    throw new Error(
      'custodyToHeadlessOwner: missing classical key material (card.identity.public_key / private.classical_private_key) — cannot build a signing owner',
    );
  }
  return {
    // durable_id IS the canonical fingerprint (= card.identity.fingerprint = H(public_key)); use the
    // top-level durable_id so a (hypothetical) card/intro mismatch surfaces as an auth failure, not silently.
    fingerprint: pub.durable_id,
    publicKeyArmored: id.public_key,
    privateKeyArmored: priv.classical_private_key,
    passphrase: priv.classical_kpass,
    // PQ pubs (B64) — absent ⇒ classical identity. '' coerces to undefined to match OwnerIdentity optionals.
    kemPublicKey: id.pq_kem_public_key || undefined,
    sigPublicKey: id.pq_sig_public_key || undefined,
    // ★ custody ①: the owner's ML-KEM-1024 SECRET (B64). The receive counterpart of kemPublicKey.
    kemSecretKey: priv.mlkem1024_sec || undefined,
  };
}
