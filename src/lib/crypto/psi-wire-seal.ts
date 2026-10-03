// src/lib/crypto/psi-wire-seal.ts
/**
 * PSI wire-seal — ML-KEM-wrap the PSI blinded-set exchanges so they ride the wire PQ-protected.
 *
 * WHY (Peter's deploy gate #155212): "don't deploy PSI if blinders are not pq encapsulated... IF blinders
 * are wrapped in mailbox pq over wire then fine." Today the PSI protocol (mutual-trust-sync.ts) sends
 * classical X25519-blinded points as PLAIN JSON to /trust/psi/* — harvest-now-decrypt-later exposed. This
 * module wraps each PSI body in the ML-KEM mailbox envelope so a network harvester sees only ciphertext.
 *
 * ★★ TWO DISTINCT PROTECTIONS — keep them separate or the claim lies (Archie #155275; Flint seals BOTH):
 *   1. ML-KEM shell (THIS module): protects the WIRE against HNDL. The body is sealed to the SATELLITE's
 *      mailbox key; a network harvester gets only ML-KEM-1024 + X25519 hybrid ciphertext.
 *   2. X25519 point-blinding (mutual-trust-sync.ts, NOT here): keeps the satellite from DE-BLINDING. The
 *      satellite DOES read the blinded points after it decaps — it IS the PSI relay, that's its job — it
 *      simply cannot de-blind them (no ephemeral scalar).
 *   ⟹ HONEST CLAIM: "mutual discovery, PQ-protected on the wire + blinded from the relay."
 *      NEVER "quantum-proof PSI". NEVER "the satellite can't see the blinded points" (it can; it relays them).
 *
 * SHELL CHOICE: SINGLE-shell seal-TO-satellite (sealToMailbox), NOT the two-shell onion. The satellite is
 * the PSI relay endpoint that reads the blinded set, not a blind router passing an opaque inner to a device.
 * (The two-shell onion — inner→device, outer→satellite — is the 1:1 dead-drop, a separate unit.)
 *
 * COVERS all 4 PSI wire exchanges (mutual-trust-sync.ts §protocol): initiate POST, fetch-pending GET,
 * respond POST, fetch-result GET — every body carrying blinded_set / reblinded_initiator_set.
 *   Request  (client → satellite): sealPsiToSatellite(body, satelliteKeys) → opaque envelope → decap → relay.
 *   Response (satellite → client): the satellite seals the result to the CLIENT's mailbox key → openPsiFromSatellite.
 *
 * ★ JOINT BUILD (Apollo client-half HERE; Athena satellite-half = /trust/psi decap+reseal, infra/satellite.py).
 *   Byte-exact co-verify like K0/S1. NOT wired or flipped until the round-trip seals on the DEPLOYED edge
 *   (verify-then-flip, Archie's apex gate) — isPSIDiscoveryLive stays FALSE until then.
 *
 * DEPENDS on the client holding the satellite's mailbox PUBKEY, fetched + anti-swap-verified (GET /satellite/key,
 * Athena). That fetch/verify is a separate concern (networking + the key-pinning contract) — this module is the
 * pure, testable, co-verifiable crypto only. NO new crypto: reuses sealToMailbox / openMailboxEnvelope as-is.
 */
import {
  sealToMailbox,
  openMailboxEnvelope,
  deriveMailboxFp,
  type MailboxEnvelopePackage,
  type MailboxPublicKeys,
  type MailboxSecretKeys,
} from './mailbox-envelope';
import {
  generateMailboxKeypair,
  toPublicKeys,
  toSecretKeys,
  mailboxFpOf,
  type MailboxKeypair,
} from './mailbox-keys';

const enc = new TextEncoder();
const dec = new TextDecoder();

const X25519_LEN = 32;
const KEM_PUB_LEN = 1568;

/**
 * Seal a PSI request body (the blinded set + session fields) to the satellite's mailbox key. The result is
 * an opaque ML-KEM+X25519 hybrid envelope that rides the wire HNDL-safe; only the satellite (holding the
 * matching secret) decaps it to read the blinded points for relay.
 */
export async function sealPsiToSatellite(
  body: unknown,
  satelliteKeys: MailboxPublicKeys,
): Promise<MailboxEnvelopePackage> {
  const plaintext = enc.encode(JSON.stringify(body));
  return sealToMailbox(plaintext, satelliteKeys);
}

/**
 * Open a satellite-sealed PSI response with the client's own mailbox secrets. Returns the parsed body, or
 * NULL on ANY rejection (wrong recipient mailbox_fp, malformed field, AEAD tag failure, or non-JSON payload) —
 * never throws on attacker-controlled input (mirrors openMailboxEnvelope's null-not-throw contract).
 *
 * `clientMailboxFpHex` = deriveMailboxFp(clientX25519Pub, clientMlkem1024Pub) — the fp the satellite sealed to.
 */
export async function openPsiFromSatellite(
  pkg: MailboxEnvelopePackage,
  clientSecrets: MailboxSecretKeys,
  clientMailboxFpHex: string,
): Promise<unknown | null> {
  const pt = await openMailboxEnvelope(pkg, clientSecrets, clientMailboxFpHex);
  if (pt === null) return null;
  try {
    return JSON.parse(dec.decode(pt));
  } catch {
    return null;
  }
}

// ── Ephemeral per-session response key (Athena Q2 / #155354) ──────────────────────────────────────
// The satellite seals its GET responses back to the client. Rather than the client's long-term registered
// mailbox key, each PSI session mints a FRESH ephemeral keypair: forward-secrecy (a session key compromise
// doesn't reach past/other sessions or the long-term mailbox), blast-radius isolation, AND it decouples PSI
// from mailbox registration (a user can run discovery without a registered mailbox). The pubkeys ride INSIDE
// the sealed initiate/respond body so the satellite binds them (a relay can't swap them — they're under the
// device→satellite seal). The secret stays on the client to open responses; discard after the session.

/** A client's per-PSI-session ephemeral response key. */
export interface PsiSessionKey {
  /** The ephemeral keypair. The SECRET never leaves the device; discard after the session. */
  keypair: MailboxKeypair;
  /** Embed this in the sealed initiate/respond body so the satellite can seal its responses back to us. */
  responsePub: { x25519_pub_b64: string; mlkem1024_pub_b64: string; mailbox_fp: string };
}

const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64');

/** Mint a fresh ephemeral response key for one PSI session. */
export function newPsiSessionKey(): PsiSessionKey {
  const keypair = generateMailboxKeypair();
  return {
    keypair,
    responsePub: {
      x25519_pub_b64: b64(keypair.x25519Pub),
      mlkem1024_pub_b64: b64(keypair.mlkem1024Pub),
      mailbox_fp: mailboxFpOf(keypair),
    },
  };
}

/** Open a satellite GET-response that was sealed to this session's ephemeral key. Null on any rejection. */
export async function openPsiSessionResponse(
  pkg: MailboxEnvelopePackage,
  session: PsiSessionKey,
): Promise<unknown | null> {
  return openPsiFromSatellite(pkg, toSecretKeys(session.keypair), mailboxFpOf(session.keypair));
}

// ── S4: anti-swap satellite key (Flint seal S4 / Athena Q1 / #155354) ─────────────────────────────
// GET /satellite/key returns {x25519_pk, mlkem1024_pk, mailbox_fp} with NO signature, and mailbox_fp is just
// SHA256(x25519‖mlkem) — so a SWAPPED key is self-consistent; the endpoint alone can't prove authenticity
// (the satellite holds only a routing keypair, no long-term signing identity). Without this check a malicious
// relay hands a swapped onion key → the client seals the blinders to the ATTACKER → the whole PQ-wrap is
// bypassed at the key fetch. DEV/tonight: the client PINS the satellite mailbox_fp and REJECTS any key whose
// DERIVED fp != the pin. (PROD/self-host fast-follow: a satellite Ed25519 identity signs the key response;
// replace the pin check with a signature check then.)

/** The pinned dev satellite mailbox_fp (GET /satellite/key, dev-outpost-satellite). A fetched key whose
 *  derived fp differs from this is REJECTED. Replace with a signed-identity check for prod/self-host. */
export const PINNED_SATELLITE_MAILBOX_FP_DEV =
  '746ba505b57221e7f149125b3f41f081a1d3befdbdeee49030219f06ed43a03c';

/**
 * Verify fetched satellite key bytes against the pin and bind them. Returns the MailboxPublicKeys to seal to,
 * or NULL (REJECT) if lengths are wrong or the derived fp != pinnedFp. This is the S4 gate: a swapped key
 * fails here, so the client never seals the blinders to an attacker. Format-agnostic — the caller decodes the
 * GET /satellite/key response (hex on dev) into bytes before calling.
 */
export function verifySatelliteKey(
  x25519Pub: Uint8Array,
  mlkem1024Pub: Uint8Array,
  pinnedFp: string = PINNED_SATELLITE_MAILBOX_FP_DEV,
): MailboxPublicKeys | null {
  if (x25519Pub.length !== X25519_LEN || mlkem1024Pub.length !== KEM_PUB_LEN) return null;
  const derived = deriveMailboxFp(x25519Pub, mlkem1024Pub);
  if (derived !== pinnedFp) return null; // S4: reject a swapped / unpinned key
  return { x25519Pub, mlkem1024Pub };
}
