// src/lib/trust/mailbox-pointer-transport.ts
/**
 * Mailbox-pointer transport — sovereign publish/resolve of "here is my mailbox" over the blind rendezvous
 * (KB#90104 item 4 + KB#90108 seal-model). A thin specialization of the trust-beacon transport
 * (trust-rendezvous.ts): the SAME rendezvous R_e + deposit/poll relay, carrying the SIGNED POINTER blob
 * (mailbox-pointer.ts) instead of a trust assertion.
 *
 * SEAL-MODEL (Flint, KB#90108) — transport UNIFORM, only the seal TARGET varies:
 *   • bootstrap (pointerEpoch 0): seal to the peer's IDENTITY ENC keys (x25519 enc[32] + ML-KEM-1024
 *     enc[1568] from the genesis card, held after VERIFY) — same {x25519,mlkem1024} shape as a mailbox, so
 *     sealToMailbox generalizes. This is how the FIRST mailbox is conveyed (the genesis card has NO mailbox
 *     slot by design — the first pointer is beacon-conveyed, not embedded).
 *   • rotation (pointerEpoch >= 1): seal to the peer's CURRENT mailbox pubkeys.
 * NO sPair-derived symmetric seal — reuse the #129 envelope exactly (minimal crypto surface, consistent
 * with the random-per-pair keypair choice). The relay stays blind: the blob is #129-sealed, R_e is opaque,
 * and the identity-enc key is only an E2E seal TARGET (never leaked to the relay).
 *
 * The publisher signs the pointer with its identity key; the resolver authenticates WHO published via that
 * signature (verifyMailboxPointer) and enforces the anti-substitution MUST (fp == SHA256(pubkeys)) REGARDLESS
 * of seal target. selectLatestValidPointer takes the highest-epoch valid pointer → monotonic rotation.
 *
 * EDGE (KB#90108): simultaneous rotation — each peer seals to the other's OLD mailbox; the caller must keep
 * the old decap key valid through an overlap window until the new pointer is confirmed-received.
 */
import { deriveRendezvousTag, type TrustRelay } from './trust-rendezvous.js';
import { deriveSharedSecret, currentEpochWeek } from '../crypto/mutual-trust.js';
import {
  sealToMailbox,
  openMailboxEnvelope,
  type MailboxPublicKeys,
  type MailboxSecretKeys,
  type MailboxEnvelopePackage,
} from '../crypto/mailbox-envelope.js';
import {
  buildSignedMailboxPointer,
  selectLatestValidPointer,
  type MailboxPointer,
} from '../crypto/mailbox-pointer.js';
import { uint8ToBase64 } from '../crypto/pq.js';

/**
 * PUBLISH my mailbox pointer to a peer: sign it with my identity, #129-seal it to `sealTarget`, deposit at
 * the pair's rendezvous R_e. The caller supplies the seal target per the seal-model: the peer's IDENTITY
 * ENC keys for bootstrap (pointerEpoch 0), or the peer's CURRENT mailbox for rotation (pointerEpoch >= 1).
 */
export async function publishMailboxPointer(args: {
  relay: TrustRelay;
  myEdPriv: Uint8Array; // my identity seed — signs the pointer AND derives S_pair
  myDid: string;
  peerEdPub: Uint8Array; // peer identity pubkey — derives S_pair (R_e)
  peerDid: string;
  sealTarget: MailboxPublicKeys; // WHERE the peer opens it (identity-enc keys | current mailbox)
  sealTargetFp: string; // the recipient content-address = deriveMailboxFp(sealTarget)
  myMailboxX25519Pub: Uint8Array; // MY mailbox pubkeys being advertised (go INSIDE the signed pointer)
  myMailboxMlkemEk: Uint8Array;
  pointerEpoch: number; // mailbox rotation counter: 0 = bootstrap, >= 1 = rotation
  rendezvousEpoch?: number; // R_e week epoch (default currentEpochWeek)
}): Promise<{ deposited: boolean; rTagB64: string; pointerEpoch: number }> {
  const wkEpoch = args.rendezvousEpoch ?? currentEpochWeek();
  const sPair = deriveSharedSecret(args.myEdPriv, args.peerEdPub);
  const rTagB64 = uint8ToBase64(deriveRendezvousTag(sPair, args.myDid, args.peerDid, wkEpoch));

  const signedPtr = buildSignedMailboxPointer(
    args.pointerEpoch,
    args.myMailboxX25519Pub,
    args.myMailboxMlkemEk,
    args.myEdPriv,
  );
  const sealed = await sealToMailbox(signedPtr, args.sealTarget, args.sealTargetFp);
  const deposited = await args.relay.deposit(rTagB64, JSON.stringify(sealed));
  return { deposited, rTagB64, pointerEpoch: args.pointerEpoch };
}

/** A key set the resolver may hold: identity-enc secrets (bootstrap) or mailbox secrets (rotation). */
export interface PointerOpenCandidate {
  secrets: MailboxSecretKeys;
  fp: string; // the matching mailbox_fp = deriveMailboxFp(the corresponding pubkeys)
}

/**
 * RESOLVE a peer's current mailbox pointer: poll the rendezvous across {current, current-1} week epochs,
 * open each blob with whichever candidate key set it was sealed to (identity-enc for a bootstrap pointer,
 * mailbox for a rotation pointer — the envelope's wrong-recipient→null is the discriminator), then verify
 * + take the HIGHEST-epoch valid pointer. Returns null if no authentic pointer from `peerEdPub` is present.
 * Never throws on relay/attacker input.
 */
export async function resolveMailboxPointer(args: {
  relay: TrustRelay;
  myEdPriv: Uint8Array;
  myDid: string;
  peerEdPub: Uint8Array; // the publisher (peer) identity pubkey — verifies the pointer signature
  peerDid: string;
  openWith: PointerOpenCandidate[]; // e.g. [my identity-enc secrets, my mailbox secrets]
  now?: number;
}): Promise<MailboxPointer | null> {
  const currentEpoch = args.now ?? currentEpochWeek();
  const sPair = deriveSharedSecret(args.myEdPriv, args.peerEdPub);
  const opened: Uint8Array[] = [];

  for (const wkEpoch of [currentEpoch, currentEpoch - 1]) {
    const rTagB64 = uint8ToBase64(deriveRendezvousTag(sPair, args.myDid, args.peerDid, wkEpoch));
    const blobs = await args.relay.poll(rTagB64);
    for (const blob of blobs) {
      let pkg: MailboxEnvelopePackage;
      try {
        pkg = JSON.parse(blob) as MailboxEnvelopePackage;
      } catch {
        continue;
      }
      for (const cand of args.openWith) {
        const pt = await openMailboxEnvelope(pkg, cand.secrets, cand.fp);
        if (pt) {
          opened.push(pt); // opened by this candidate; the wrong-recipient blobs returned null
          break;
        }
      }
    }
  }

  // verify (identity sig + anti-substitution) + highest-epoch-wins; forged / tampered / lower-epoch dropped
  return selectLatestValidPointer(opened, args.peerEdPub);
}
