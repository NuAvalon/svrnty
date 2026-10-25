// src/lib/compose/compose-sign.ts
// The SIGNER for a portal sign-request (spec v0.7 §1/§8; Flint #996 Q2/Q4/Q6). Runs only when the person has seen the card and pressed Approve.
//
// RE-VALIDATES at approval time with a FRESH clock: a card shown before expires_at must never be signed after it ("never sign late"), and the
// app signs only what the strict validator re-accepts, computed into JCS by THIS module, never a string the sender supplied.
//
// Returns {object, sig_packet_b64}: the detached ~252-char signature packet EXTRACTED from the attached message signWithEnvelope produces (the
// attached form is ~4.8 KB and too big for a URL fragment; receivers rebuild the literal from the object and keep only the packet, V1). Before
// returning it SELF-VERIFIES the packet detached against the bytes this module rebuilt. ANY failure returns nothing: there is no unsigned fallback
// (S6) and no partial result. v1 is Ed25519 only (the PQ leg becomes required before compose carries authority beyond posting text).
//
// SHOWN = SIGNED (Flint G1): the signer takes the object the card DISPLAYED and refuses unless the re-validated request has the identical canonical
// form. With a queue of cards (one shown, more waiting) any slip in which raw reaches Approve (queue advance, a state race, a re-render that swaps the
// reference) would otherwise sign a DIFFERENT valid request than the one the person looked at, and validation alone cannot catch that.
//
// SCOPE (Flint N2): the task kind is Peter CREATING a task in lane:orch on an Ed25519-only signature. Land it as proposed / normal priority. No approve,
// assign-with-authority or state-change verbs until the PQ leg is required.
import { createMessage, decryptKey, enums, readKey, readMessage, readPrivateKey, readSignature, verify } from 'openpgp';
import { signWithEnvelope } from '../crypto/sign-envelope';
import { COMPOSE_DOMAIN, composeSignedBytes, jcs, type ComposeKind } from './compose-rules';
import { validateComposeRequest, type Refusal } from './compose-request';

export interface SignedCompose {
  kind: ComposeKind;
  /** The exact object that was signed (a fresh copy). */
  object: Record<string, string>;
  suite: 'ed25519';
  /** Detached OpenPGP signature packet, base64 (standard alphabet). */
  sig_packet_b64: string;
}

export type SignFailure =
  | { ok: false; reason: 'refused'; refusal: Refusal }
  | { ok: false; reason: 'shown-mismatch' | 'sign-failed' | 'literal-mismatch' | 'extract-failed' | 'self-verify-failed' };
export type SignResult = { ok: true; signed: SignedCompose } | SignFailure;

/** Test seam: the real signer by default. Nothing in production passes this. */
export interface SignDeps {
  sign?: typeof signWithEnvelope;
  /** Lets a test prove the self-verify guard is load-bearing (it must fail closed when this says false). */
  verifyDetached?: typeof selfCheckComposePacket;
}

const SUITE = 'ed25519' as const;
const toB64 = (u8: Uint8Array): string => {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
};
const fromB64 = (b64: string): Uint8Array => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

/**
 * Detached SELF-CHECK of `sigB64` over `bytes` against `pub`. Never throws.
 *
 * NOT a receiver verifier (Flint N1): it only says "this key made a signature over these bytes". It does NOT enforce one signature packet, type 1,
 * SHA-256+, the issuer fingerprint, the nonce, or the expiry. Nothing may reuse it as the V1-V4 verifier; the portal's verifier is the full V1-V4
 * against Peter's PINNED card and never trusts a key that rides in the hand-back.
 */
export async function selfCheckComposePacket(pub: Awaited<ReturnType<typeof readKey>>, sigB64: string, bytes: string): Promise<boolean> {
  try {
    const r = await verify({
      message: await createMessage({ text: bytes }),
      signature: await readSignature({ binarySignature: fromB64(sigB64) }),
      verificationKeys: pub,
    });
    await r.signatures[0].verified;
    return true;
  } catch {
    return false;
  }
}

export async function signComposeRequest(
  raw: unknown,
  /** The object the card DISPLAYED (the validated request's `object` at display time). The signature is refused unless `raw` re-validates to exactly this. */
  shown: Readonly<Record<string, string>>,
  now: Date,
  identity: { privateKeyArmored: string; passphrase: string },
  deps: SignDeps = {},
): Promise<SignResult> {
  // 1. Re-validate NOW (never trust the validation that produced the card).
  const v = validateComposeRequest(raw, now);
  if (!v.ok) return { ok: false, reason: 'refused', refusal: v.refusal };
  const { kind, object } = v.request;
  // 1b. SHOWN = SIGNED: the canonical form of what was displayed must equal the canonical form of what we are about to sign. jcs() throws on anything
  // that is not a flat object of strings with printable-ASCII keys, and that is a mismatch too.
  let same = false;
  try {
    same = shown !== null && typeof shown === 'object' && !Array.isArray(shown) && jcs(shown as Record<string, string>) === jcs(object);
  } catch {
    same = false;
  }
  if (!same) return { ok: false, reason: 'shown-mismatch' };
  const domain = COMPOSE_DOMAIN[kind];
  const canonical = jcs(object); // computed HERE from the validated fields
  const signedBytes = composeSignedBytes(kind, SUITE, object);

  // 2. Sign (attached message, as the app does for every other domain). A wrong passphrase / bad key throws; reveal nothing about why.
  let attached: string;
  try {
    attached = (await (deps.sign ?? signWithEnvelope)(domain, canonical, identity.privateKeyArmored, identity.passphrase)).classical;
  } catch {
    return { ok: false, reason: 'sign-failed' };
  }

  // 3. Extract the packet, enforcing V1 (one one-pass-sig + one literal + one signature, literal == the bytes WE rebuilt).
  let pub: Awaited<ReturnType<typeof readKey>>;
  let sigB64: string;
  try {
    pub = (await decryptKey({ privateKey: await readPrivateKey({ armoredKey: identity.privateKeyArmored }), passphrase: identity.passphrase })).toPublic();
    const msg = await readMessage({ armoredMessage: attached });
    const tags = msg.packets.map((p) => (p.constructor as unknown as { tag: number }).tag);
    // openpgp.js lists a one-pass-signed message as [one-pass-sig, literal]: the trailing signature packet is read separately and surfaces as
    // `signatures` (Athena's fixture records the same [4, 11] for every vector). So V1 = exactly those two packets AND exactly one signature.
    if (tags.length !== 2 || tags[0] !== enums.packet.onePassSignature || tags[1] !== enums.packet.literalData) {
      return { ok: false, reason: 'extract-failed' };
    }
    const res = await verify({ message: msg, verificationKeys: pub, expectSigned: true });
    if (res.signatures.length !== 1) return { ok: false, reason: 'extract-failed' };
    if (res.data !== signedBytes) return { ok: false, reason: 'literal-mismatch' };
    const sig = await res.signatures[0].signature;
    const pkt = sig.packets[0] as unknown as { signatureType: number; hashAlgorithm: number; issuerFingerprint?: Uint8Array };
    const hashOk = [enums.hash.sha256, enums.hash.sha384, enums.hash.sha512].includes(pkt.hashAlgorithm);
    const issuer = Array.from(pkt.issuerFingerprint ?? [], (b) => b.toString(16).padStart(2, '0')).join('');
    // V2 on our own output: text signature (type 1), SHA-256 or stronger, issued by the key we hold.
    if (pkt.signatureType !== enums.signature.text || !hashOk || issuer !== pub.getFingerprint()) return { ok: false, reason: 'extract-failed' };
    sigB64 = toB64(sig.write());
  } catch {
    return { ok: false, reason: 'extract-failed' };
  }

  // 4. SELF-VERIFY the extracted packet detached against our own rebuilt bytes. Fail closed.
  if (!(await (deps.verifyDetached ?? selfCheckComposePacket)(pub, sigB64, signedBytes))) return { ok: false, reason: 'self-verify-failed' };

  return { ok: true, signed: { kind, object: { ...object }, suite: SUITE, sig_packet_b64: sigB64 } };
}
