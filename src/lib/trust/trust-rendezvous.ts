// src/lib/trust/trust-rendezvous.ts
/**
 * Sovereign trust-rendezvous (TR) — the relay-blind trust-edge listener (Track C).
 *
 * Closes Charter §8.5: reciprocity becomes SOVEREIGN (the relay never learns who trusts whom), which
 * SUPERSEDES the dead trust-commit oracle (mutual-trust.ts computeCommitment/submitCommitment — saltless,
 * O(N)-reversible; REMOVED, never re-activated).
 *
 * How it works (Flint's contract §7 + #136666, Apollo design §54-73):
 *   1. Two VERIFY'd peers share S_pair = deriveSharedSecret(myEdPriv, theirEdPub) — X25519 DH, symmetric,
 *      the relay CANNOT compute it (no privkeys). So the rendezvous tag R is NOT dictionary-reversible.
 *   2. R = HKDF-SHA256( sort(DID_A,DID_B) ‖ S_pair ‖ epoch, info="svrnty-tr-rendezvous-v1" ). DID = the
 *      DURABLE genesis fingerprint (survives key rotation). epoch = currentEpochWeek() → R rotates weekly
 *      (cross-epoch relay-unlinkability); poll {epoch, epoch-1} for week-boundary skew.
 *   3. The trust beacon is Ed25519-SIGNED over the assertion (anti-forgery — encryption≠authentication;
 *      both peers can deposit at R, so presence alone proves nothing; only the depositor's identity sig
 *      proves "A trusts B"), then SEALED via the PQ-hybrid mailbox envelope (Track A) to the peer's
 *      mailbox, and deposited at R.
 *   4. The recipient polls R, opens the blob sealed to THEM (the envelope's wrong-recipient→null is the
 *      natural filter between the two beacons that collide at the symmetric R), verifies the sig vs the
 *      peer's identity pubkey from the book, checks from/to/epoch → accepts authentic "peer trusts me".
 *
 * ⚠ CRYPTO CO-VERIFY (Flint): §7 gives the R formula but NOT a byte-exact preimage layout (no §5-style
 * vector). The R + beacon preimage SERIALIZATIONS below are my explicit injective choice — FLAGGED for
 * Flint to pin/co-verify. Do not treat as final until he greens the bytes.
 *
 * SCOPE (minimal 24h slice, Archie/Flint): R-derive (epoch IN, per Flint #136628) + signed-beacon
 * seal/deposit + poll/open/verify → mutual-on-match + idempotent rehydrate (Peter's migrate req, §46).
 * DEFERRED (post-event): forward-revocation ratchet, unlinkability mixing, full both-decide state machine.
 */
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { deriveSharedSecret, currentEpochWeek } from '../crypto/mutual-trust.js';
import { uint8ToBase64, base64ToUint8 } from '../crypto/pq.js';
import {
  sealToMailbox,
  openMailboxEnvelope,
  type MailboxPublicKeys,
  type MailboxSecretKeys,
  type MailboxEnvelopePackage,
} from '../crypto/mailbox-envelope.js';

const TR_RENDEZVOUS_INFO = 'svrnty-tr-rendezvous-v1';
const TR_BEACON_SIG_PREFIX = 'svrnty-trust-beacon-v1:';
const TR_ASSERTION = 'trust';
const BEACON_V = 1;

/** Signed trust assertion. Sig proves the DEPOSITOR's identity — the anti-forgery core (Flint #136666). */
export interface TrustBeacon {
  v: number;
  from_did: string;
  to_did: string;
  epoch: number;
  assertion: 'trust';
  /** Ed25519(depositor_identity_priv, TR_BEACON_SIG_PREFIX + from|to|epoch|assertion), hex. */
  sig: string;
}

export type EdSignFn = (message: Uint8Array, privateKey: Uint8Array) => Uint8Array;
export type EdVerifyFn = (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => boolean;

/** Relay deposit/poll namespace for beacons-at-R. Injected — Athena's relay implements the server side. */
export interface TrustRelay {
  /** Append a sealed beacon blob at rendezvous tag R (base64). Multiple blobs may collide at one R. */
  deposit(rTagB64: string, blob: string): Promise<boolean>;
  /** Return all sealed beacon blobs currently at R (base64). */
  poll(rTagB64: string): Promise<string[]>;
}

/**
 * Concrete TrustRelay over the satellite's rendezvous endpoints (Athena #137166, /trust/rendezvous/*):
 *   POST {satelliteUrl}/trust/rendezvous/deposit  {r, blob} → {deposited: boolean}
 *   POST {satelliteUrl}/trust/rendezvous/poll     {r}       → {blobs: string[]}
 * Both are POST (R rides the JSON body, never the URL/access-log) and UNAUTHENTICATED BY DESIGN —
 * blindness comes from R-secrecy (only the pair derives R from S_pair) + the sealed+signed beacon,
 * NOT from endpoint auth (authing would deanonymize the pair → defeats §8.5 sovereignty). Fail-soft:
 * a non-2xx/throw deposit → false; a failed poll → [] (the caller re-polls next epoch/tick).
 */
export function httpTrustRelay(satelliteUrl: string, fetchImpl: typeof fetch = fetch): TrustRelay {
  const base = satelliteUrl.replace(/\/$/, '');
  return {
    async deposit(rTagB64, blob) {
      try {
        const res = await fetchImpl(`${base}/trust/rendezvous/deposit`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ r: rTagB64, blob }),
        });
        if (!res.ok) return false;
        const j = (await res.json()) as { deposited?: boolean };
        return j?.deposited === true;
      } catch {
        return false;
      }
    },
    async poll(rTagB64) {
      try {
        const res = await fetchImpl(`${base}/trust/rendezvous/poll`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ r: rTagB64 }),
        });
        if (!res.ok) return [];
        const j = (await res.json()) as { blobs?: unknown };
        return Array.isArray(j.blobs) ? (j.blobs as unknown[]).filter((b): b is string => typeof b === 'string') : [];
      } catch {
        return [];
      }
    },
  };
}

function sortDids(didA: string, didB: string): [string, string] {
  return didA < didB ? [didA, didB] : [didB, didA];
}

/**
 * R = HKDF-SHA256( preimage, info="svrnty-tr-rendezvous-v1" ) → 32 bytes.
 * preimage (injective, domain-separated — FLAGGED for Flint's pin):
 *   utf8(`${didLow}|${didHigh}|`) ‖ S_pair(32) ‖ utf8(`|${epoch}`)
 * DIDs are hex (no '|'); S_pair is raw bytes between delimited text; epoch is a decimal integer.
 * Symmetric: both peers sort DIDs identically + derive the same S_pair → the same R.
 */
export function deriveRendezvousTag(sPair: Uint8Array, didA: string, didB: string, epoch: number): Uint8Array {
  const [didLow, didHigh] = sortDids(didA, didB);
  const preimage = concatBytes(utf8ToBytes(`${didLow}|${didHigh}|`), sPair, utf8ToBytes(`|${epoch}`));
  return hkdf(sha256, preimage, undefined, utf8ToBytes(TR_RENDEZVOUS_INFO), 32);
}

/** Convenience: derive R straight from the Ed25519 keypair + DIDs (derives S_pair internally). */
export function rendezvousTagFor(
  myEdPriv: Uint8Array,
  theirEdPub: Uint8Array,
  myDid: string,
  theirDid: string,
  epoch: number,
): Uint8Array {
  const sPair = deriveSharedSecret(myEdPriv, theirEdPub);
  return deriveRendezvousTag(sPair, myDid, theirDid, epoch);
}

/** The exact bytes the beacon signature covers (injective, domain-separated — FLAGGED for Flint's pin). */
export function beaconSigPreimage(fromDid: string, toDid: string, epoch: number): Uint8Array {
  return utf8ToBytes(`${TR_BEACON_SIG_PREFIX}${fromDid}|${toDid}|${epoch}|${TR_ASSERTION}`);
}

/** Build a trust beacon signed by the depositor's identity key. */
export function buildSignedBeacon(
  fromDid: string,
  toDid: string,
  epoch: number,
  myEdPriv: Uint8Array,
  signFn: EdSignFn,
): TrustBeacon {
  const sig = signFn(beaconSigPreimage(fromDid, toDid, epoch), myEdPriv);
  return { v: BEACON_V, from_did: fromDid, to_did: toDid, epoch, assertion: TR_ASSERTION, sig: bytesToHex(sig) };
}

/**
 * Verify a beacon is an authentic trust assertion FROM the expected peer TO me, for an accepted epoch.
 * Rejects: wrong shape/assertion, from/to mismatch, epoch outside {current, current-1}, bad signature.
 */
export function verifyBeacon(
  beacon: TrustBeacon,
  expectedFromDid: string,
  myDid: string,
  peerEdPub: Uint8Array,
  verifyFn: EdVerifyFn,
  currentEpoch: number = currentEpochWeek(),
): boolean {
  if (!beacon || beacon.v !== BEACON_V || beacon.assertion !== TR_ASSERTION) return false;
  if (beacon.from_did !== expectedFromDid || beacon.to_did !== myDid) return false;
  if (beacon.epoch !== currentEpoch && beacon.epoch !== currentEpoch - 1) return false; // week-skew window
  let sig: Uint8Array;
  try {
    sig = hexToBytesStrict(beacon.sig);
  } catch {
    return false;
  }
  return verifyFn(sig, beaconSigPreimage(beacon.from_did, beacon.to_did, beacon.epoch), peerEdPub);
}

function hexToBytesStrict(hex: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error('bad hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Deposit a signed+sealed trust beacon at the rendezvous for (me → peer) at the current epoch.
 * Seals the beacon via the PQ-hybrid envelope to the PEER's mailbox (only they can open it).
 */
export async function depositTrustBeacon(args: {
  relay: TrustRelay;
  myEdPriv: Uint8Array;
  myDid: string;
  peerEdPub: Uint8Array;
  peerDid: string;
  peerMailbox: MailboxPublicKeys;
  peerMailboxFp: string;
  signFn: EdSignFn;
  epoch?: number;
}): Promise<{ deposited: boolean; rTagB64: string }> {
  const epoch = args.epoch ?? currentEpochWeek();
  const sPair = deriveSharedSecret(args.myEdPriv, args.peerEdPub);
  const rTag = deriveRendezvousTag(sPair, args.myDid, args.peerDid, epoch);
  const rTagB64 = uint8ToBase64(rTag);

  const beacon = buildSignedBeacon(args.myDid, args.peerDid, epoch, args.myEdPriv, args.signFn);
  const sealed = await sealToMailbox(utf8ToBytes(JSON.stringify(beacon)), args.peerMailbox, args.peerMailboxFp);
  const deposited = await args.relay.deposit(rTagB64, JSON.stringify(sealed));
  return { deposited, rTagB64 };
}

/**
 * Poll the rendezvous for (me ↔ peer) across {current, current-1} epochs, open the beacon sealed to me,
 * and verify it. Returns true iff an authentic "peer trusts me" beacon is present (my side of mutual).
 */
export async function pollForPeerTrust(args: {
  relay: TrustRelay;
  myEdPriv: Uint8Array;
  myDid: string;
  myMailbox: MailboxSecretKeys;
  myMailboxFp: string;
  peerEdPub: Uint8Array;
  peerDid: string;
  verifyFn: EdVerifyFn;
  now?: number;
}): Promise<boolean> {
  const currentEpoch = args.now ?? currentEpochWeek();
  const sPair = deriveSharedSecret(args.myEdPriv, args.peerEdPub);
  for (const epoch of [currentEpoch, currentEpoch - 1]) {
    const rTag = deriveRendezvousTag(sPair, args.myDid, args.peerDid, epoch);
    const blobs = await args.relay.poll(uint8ToBase64(rTag));
    for (const blob of blobs) {
      let pkg: MailboxEnvelopePackage;
      try {
        pkg = JSON.parse(blob) as MailboxEnvelopePackage;
      } catch {
        continue;
      }
      const opened = await openMailboxEnvelope(pkg, args.myMailbox, args.myMailboxFp);
      if (!opened) continue; // not sealed to me (the collision filter) or tampered
      let beacon: TrustBeacon;
      try {
        beacon = JSON.parse(new TextDecoder().decode(opened)) as TrustBeacon;
      } catch {
        continue;
      }
      if (verifyBeacon(beacon, args.peerDid, args.myDid, args.peerEdPub, args.verifyFn, currentEpoch)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Rehydrate (Peter's migrate/rehydrate req, §46 "the book makes the mailbox"): re-derive R for every
 * trusted peer on the (possibly new) relay and re-deposit the signed+sealed beacon. Idempotent — the same
 * (R, beacon) overwrites/no-ops. This is what makes migration lossless: point at a new relay + rehydrate
 * from the book; the sovereign trust edges rebuild with zero relay-side directory call.
 */
export async function rehydrateTrustBeacons(args: {
  relay: TrustRelay;
  myEdPriv: Uint8Array;
  myDid: string;
  signFn: EdSignFn;
  peers: Array<{ edPub: Uint8Array; did: string; mailbox: MailboxPublicKeys; mailboxFp: string }>;
  epoch?: number;
}): Promise<{ peerDid: string; deposited: boolean }[]> {
  const out: { peerDid: string; deposited: boolean }[] = [];
  for (const peer of args.peers) {
    const { deposited } = await depositTrustBeacon({
      relay: args.relay,
      myEdPriv: args.myEdPriv,
      myDid: args.myDid,
      peerEdPub: peer.edPub,
      peerDid: peer.did,
      peerMailbox: peer.mailbox,
      peerMailboxFp: peer.mailboxFp,
      signFn: args.signFn,
      epoch: args.epoch,
    });
    out.push({ peerDid: peer.did, deposited });
  }
  return out;
}
