// src/lib/crypto/message-ratchet.ts
/**
 * Hybrid triple ratchet — Phase 3.3 candidate for 1:1 notes. UNWIRED.
 *
 * WHAT IT IS: a Signal-style message ratchet with a third leg, so a break of
 * either X25519 or ML-KEM-1024 is not enough to follow a session. Three ratchets:
 *
 *   1. Symmetric chain, every message. Forward secrecy by DELETION of the
 *      message key and the previous chain key (HKDF is one-way).
 *   2. X25519 DH, on every direction change. Classical post-compromise security:
 *      fresh ephemeral entropy the previous snapshot does not hold.
 *   3. ML-KEM-1024, on the same direction change, mixed into the SAME root KDF
 *      as the DH (`ssDh ‖ ssKem`). There is no classical-only branch to strip.
 *
 * This is not the K1 route-id hash chain (route-ratchet.ts) and not the one-shot
 * mailbox seal (mailbox-envelope.ts). The one-shot seal opens every past envelope
 * with the recipient's long-term keys. A ratchet deletes the keys that opened
 * past messages.
 *
 * HANDSHAKE (no one-time prekeys — identity keys act as signed prekeys):
 *   ssStatic = X25519(our identity sk, their identity pk)   // binds the peer
 *   ssEph    = X25519(our ephemeral sk, their identity pk)  // initiator's eph
 *   ssKem    = ML-KEM-1024 to their identity pk
 *   root ‖ send-chain = HKDF(ssStatic ‖ ssEph ‖ ssKem) with two domain labels
 * Identity secrets and the IKM are not stored on the session. The header carries
 * the ephemeral X25519 pub, the ephemeral KEM pub, and the KEM ciphertext.
 *
 * DIRECTION CHANGE: fresh X25519 keypair + fresh ML-KEM keypair. Encapsulate to
 * the peer's current KEM pub, DH against the peer's current X25519 pub, then
 *   newRoot ‖ chain = HKDF(ssDh ‖ ssKem, salt = oldRoot)
 * with two labels, so the chain is not a function of the retained root. Used
 * ephemeral secrets are wiped after the step (JS `fill(0)` is best-effort).
 *
 * SAME DIRECTION: symmetric ratchet only. The header repeats dh / kemPk / kemCt
 * and increments n.
 *
 * CLAIM BOUNDARY (honest):
 *   - Not wired into sealNoteTo, the notes store, or the Encrypt tab.
 *     `isPQEncapLive()` stays false. Do not call the product "messaging".
 *   - No one-time prekey pool. The recipient's long-term X25519 + ML-KEM secrets
 *     re-open the INITIAL sending chain (the handshake). Forward secrecy against
 *     that seizure starts at the first reply ratchet, whose ephemeral secrets are
 *     not retained and cannot be recomputed from identity keys.
 *   - PCS heals when the compromised party SENDS a new ratchet. A snapshot of a
 *     receiver still opens the next inbound ratchet addressed to keys that
 *     snapshot already holds. A snapshot does not open messages created after the
 *     peer has ratcheted to fresh publics the snapshot never generated.
 *   - Ongoing device access is not a snapshot. PCS does not help while the
 *     attacker still lives on the device.
 *   - Sender authentication is the existing note signature, not this module.
 *     Static-static X25519 only stops a stranger's init from opening as the
 *     expected peer.
 *   - Skipped keys are bounded (MAX_SKIP per gap, MAX_SKIP_KEYS stored). Over
 *     the cap we fail closed (null), we do not allocate without limit.
 *   - AEAD failure commits nothing. A forged header cannot desynchronize state.
 *   - Concurrent first-messages from both sides need a prekey pool later. Two
 *     initiate() calls are two sessions, not one merged thread.
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { encapsulate, decapsulate, generateKEMKeypair, uint8ToBase64, base64ToUint8 } from './pq.js';
import { aesGcmEncrypt, aesGcmDecrypt, randomBytes } from './kdf.js';

/** Header version. Bump when the canonical header or the KDF labels change. */
export const TRIPLE_RATCHET_VERSION = 1;

const X25519_LEN = 32;
const KEM_PUB_LEN = 1568;
const KEM_CT_LEN = 1568;
const KEM_SS_LEN = 32;
const KEM_SK_LEN = 3168;
const NONCE_LEN = 12;
const KEY_LEN = 32;

/** Max chain steps we will skip to reach one message. */
export const MAX_SKIP = 64;
/** Max message keys retained for out-of-order delivery. */
export const MAX_SKIP_KEYS = 128;

// Versioned domain separators. Never reuse a label across derivations.
const LABEL_INIT = 'svrnty-tr-init-v1';
const LABEL_INIT_SEND = 'svrnty-tr-init-send-v1';
const LABEL_ROOT = 'svrnty-tr-root-v1';
const LABEL_CHAIN = 'svrnty-tr-chain-v1';
const LABEL_CK = 'svrnty-tr-ck-v1';
const LABEL_MK = 'svrnty-tr-mk-v1';

/** Identity secrets. Used only inside initiate / acceptFirst. Never a session field. */
export interface RatchetIdentity {
  x25519Sec: Uint8Array;
  x25519Pub: Uint8Array;
  mlkem1024Sec: Uint8Array;
  mlkem1024Pub: Uint8Array;
}

/** The peer's identity pubs (the person we believe we are talking to). */
export interface RatchetPeer {
  x25519Pub: Uint8Array;
  mlkem1024Pub: Uint8Array;
}

export interface RatchetHeader {
  v: 1;
  dh: string; // base64, 32B X25519 pub for this sending epoch
  kemPk: string; // base64, 1568B ML-KEM-1024 pub for this sending epoch
  kemCt: string; // base64, 1568B ML-KEM ciphertext that established this epoch
  pn: number; // messages sent in the previous sending chain
  n: number; // index in the current sending chain
}

export interface RatchetPacket {
  header: RatchetHeader;
  nonce: string; // base64, 12B AES-GCM nonce
  ct: string; // base64, ciphertext || 16B tag
}

interface ParsedPacket {
  header: RatchetHeader;
  dh: Uint8Array;
  kemPk: Uint8Array;
  kemCt: Uint8Array;
  nonce: Uint8Array;
  ct: Uint8Array;
}

interface ChainStep {
  ck: Uint8Array;
  mk: Uint8Array;
}

function wipe(b: Uint8Array | null | undefined): void {
  if (b) b.fill(0);
}

function copyBytes(b: Uint8Array): Uint8Array {
  return new Uint8Array(b);
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

function isCount(n: unknown): n is number {
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
}

function assertIdentity(self: RatchetIdentity, peer: RatchetPeer): void {
  if (self.x25519Sec.length !== X25519_LEN || self.x25519Pub.length !== X25519_LEN) {
    throw new Error('triple-ratchet: identity X25519 keys must be 32 bytes');
  }
  if (self.mlkem1024Sec.length !== KEM_SK_LEN || self.mlkem1024Pub.length !== KEM_PUB_LEN) {
    throw new Error('triple-ratchet: identity ML-KEM-1024 key length mismatch');
  }
  if (peer.x25519Pub.length !== X25519_LEN || peer.mlkem1024Pub.length !== KEM_PUB_LEN) {
    throw new Error('triple-ratchet: peer public key length mismatch');
  }
}

/**
 * Initial split. Two HKDF calls over the same IKM so the retained root does not
 * recompute the sending chain (different info, IKM deleted by the caller).
 * Flipping ssStatic, ssEph, or ssKem changes both outputs — the hybrid and the
 * identity binding live in this mix, not in a side check.
 */
export function mixInitialHandshake(
  ssStatic: Uint8Array,
  ssEph: Uint8Array,
  ssKem: Uint8Array,
): { root: Uint8Array; chain: Uint8Array } {
  if (ssStatic.length !== X25519_LEN || ssEph.length !== X25519_LEN || ssKem.length !== KEM_SS_LEN) {
    throw new Error('triple-ratchet: initial shared secrets must be 32 bytes');
  }
  const ikm = concatBytes(ssStatic, ssEph, ssKem);
  const root = hkdf(sha256, ikm, undefined, utf8ToBytes(LABEL_INIT), KEY_LEN);
  const chain = hkdf(sha256, ikm, undefined, utf8ToBytes(LABEL_INIT_SEND), KEY_LEN);
  wipe(ikm);
  return { root, chain };
}

/**
 * Direction-change mix. IKM is `ssDh ‖ ssKem` (both required), salt is the
 * previous root. Root and chain are sibling outputs: the chain is not
 * HKDF(newRoot), so a later root leak does not recompute this chain.
 */
export function mixRatchetStep(
  root: Uint8Array,
  ssDh: Uint8Array,
  ssKem: Uint8Array,
): { root: Uint8Array; chain: Uint8Array } {
  if (root.length !== KEY_LEN || ssDh.length !== X25519_LEN || ssKem.length !== KEM_SS_LEN) {
    throw new Error('triple-ratchet: ratchet step inputs must be 32 bytes');
  }
  const ikm = concatBytes(ssDh, ssKem);
  const newRoot = hkdf(sha256, ikm, root, utf8ToBytes(LABEL_ROOT), KEY_LEN);
  const chain = hkdf(sha256, ikm, root, utf8ToBytes(LABEL_CHAIN), KEY_LEN);
  wipe(ikm);
  return { root: newRoot, chain };
}

/** One symmetric step. next chain key and message key are independent HKDF outputs. */
export function symmetricRatchet(ck: Uint8Array): ChainStep {
  if (ck.length !== KEY_LEN) throw new Error('triple-ratchet: chain key must be 32 bytes');
  const next = hkdf(sha256, ck, undefined, utf8ToBytes(LABEL_CK), KEY_LEN);
  const mk = hkdf(sha256, ck, undefined, utf8ToBytes(LABEL_MK), KEY_LEN);
  return { ck: next, mk };
}

/** Canonical header bytes. Key order is fixed; this is the AEAD AAD. */
export function headerAad(h: RatchetHeader): Uint8Array {
  const canon =
    `{"v":1,"dh":${JSON.stringify(h.dh)},"kemPk":${JSON.stringify(h.kemPk)},` +
    `"kemCt":${JSON.stringify(h.kemCt)},"pn":${h.pn},"n":${h.n}}`;
  return utf8ToBytes(canon);
}

function skipKey(dhB64: string, n: number): string {
  return `${dhB64}|${n}`;
}

function parsePacket(packet: RatchetPacket | null): ParsedPacket | null {
  if (packet === null || typeof packet !== 'object') return null;
  const h = packet.header;
  if (!h || typeof h !== 'object') return null;
  if (h.v !== TRIPLE_RATCHET_VERSION) return null;
  if (typeof h.dh !== 'string' || typeof h.kemPk !== 'string' || typeof h.kemCt !== 'string') return null;
  if (!isCount(h.pn) || !isCount(h.n)) return null;
  if (typeof packet.nonce !== 'string' || typeof packet.ct !== 'string') return null;
  try {
    const dh = base64ToUint8(h.dh);
    const kemPk = base64ToUint8(h.kemPk);
    const kemCt = base64ToUint8(h.kemCt);
    const nonce = base64ToUint8(packet.nonce);
    const ct = base64ToUint8(packet.ct);
    if (dh.length !== X25519_LEN || kemPk.length !== KEM_PUB_LEN || kemCt.length !== KEM_CT_LEN) return null;
    if (nonce.length !== NONCE_LEN || ct.length < 16) return null;
    return {
      header: { v: 1, dh: h.dh, kemPk: h.kemPk, kemCt: h.kemCt, pn: h.pn, n: h.n },
      dh,
      kemPk,
      kemCt,
      nonce,
      ct,
    };
  } catch {
    return null;
  }
}

async function openWith(mk: Uint8Array, parsed: ParsedPacket): Promise<string | null> {
  try {
    const pt = await aesGcmDecrypt(mk, parsed.nonce, parsed.ct, headerAad(parsed.header));
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}

interface StagedSkip {
  id: string;
  mk: Uint8Array;
}

/**
 * Walk `ck` from `from` inclusive to `until` exclusive, staging message keys.
 * Returns the chain key positioned AT `until` (not yet stepped for that index).
 * Null when the gap exceeds MAX_SKIP. Does not touch session state.
 */
function stageSkip(
  ck: Uint8Array,
  from: number,
  until: number,
  dhB64: string,
): { ck: Uint8Array; staged: StagedSkip[] } | null {
  if (until < from) return null;
  if (until - from > MAX_SKIP) return null;
  const staged: StagedSkip[] = [];
  let cur = ck;
  for (let i = from; i < until; i++) {
    const step = symmetricRatchet(cur);
    if (cur !== ck) wipe(cur);
    staged.push({ id: skipKey(dhB64, i), mk: step.mk });
    cur = step.ck;
  }
  return { ck: cur, staged };
}

function discardStaged(staged: StagedSkip[], ck: Uint8Array | null): void {
  for (const s of staged) wipe(s.mk);
  wipe(ck);
}

/**
 * 1:1 hybrid triple-ratchet session.
 *
 * Holds the current root, the live send/recv chain keys, the current ratchet
 * keypairs, and a bounded skipped-key map. Does not hold identity secrets, the
 * handshake IKM, or any message key that has already been used.
 */
export class TripleRatchet {
  private root: Uint8Array;
  private sendCk: Uint8Array | null;
  private recvCk: Uint8Array | null;
  private ns: number;
  private nr: number;
  private pn: number;
  private myDhSk: Uint8Array | null;
  private myDhPk: Uint8Array | null;
  private myKemSk: Uint8Array | null;
  private myKemPk: Uint8Array | null;
  private theirDh: Uint8Array | null;
  private theirKem: Uint8Array | null;
  private sendKemCt: Uint8Array | null;
  private pendingSendRatchet: boolean;
  private skipped: Map<string, Uint8Array>;

  private constructor(init: {
    root: Uint8Array;
    sendCk: Uint8Array | null;
    recvCk: Uint8Array | null;
    theirDh: Uint8Array;
    theirKem: Uint8Array;
    myDhSk: Uint8Array | null;
    myDhPk: Uint8Array | null;
    myKemSk: Uint8Array | null;
    myKemPk: Uint8Array | null;
    sendKemCt: Uint8Array | null;
    pendingSendRatchet: boolean;
  }) {
    this.root = init.root;
    this.sendCk = init.sendCk;
    this.recvCk = init.recvCk;
    this.ns = 0;
    this.nr = 0;
    this.pn = 0;
    this.myDhSk = init.myDhSk;
    this.myDhPk = init.myDhPk;
    this.myKemSk = init.myKemSk;
    this.myKemPk = init.myKemPk;
    this.theirDh = init.theirDh;
    this.theirKem = init.theirKem;
    this.sendKemCt = init.sendKemCt;
    this.pendingSendRatchet = init.pendingSendRatchet;
    this.skipped = new Map();
  }

  /**
   * Alice → Bob. Builds the initial hybrid root against Bob's identity pubs and
   * a fresh ephemeral X25519 + ML-KEM keypair. Ready to send. Does not retain
   * `self`'s identity secrets.
   */
  static initiate(self: RatchetIdentity, peer: RatchetPeer): TripleRatchet {
    assertIdentity(self, peer);
    const ephSk = x25519.utils.randomSecretKey();
    const ephPk = x25519.getPublicKey(ephSk);
    const kem = encapsulate(peer.mlkem1024Pub);
    const ephKem = freshKem();
    const ssStatic = x25519.getSharedSecret(self.x25519Sec, peer.x25519Pub);
    const ssEph = x25519.getSharedSecret(ephSk, peer.x25519Pub);
    const split = mixInitialHandshake(ssStatic, ssEph, kem.sharedSecret);
    wipe(ssStatic);
    wipe(ssEph);
    wipe(kem.sharedSecret);
    return new TripleRatchet({
      root: split.root,
      sendCk: split.chain,
      recvCk: null,
      theirDh: copyBytes(peer.x25519Pub),
      theirKem: copyBytes(peer.mlkem1024Pub),
      myDhSk: ephSk,
      myDhPk: ephPk,
      myKemSk: ephKem.sk,
      myKemPk: ephKem.pk,
      sendKemCt: kem.ciphertext,
      pendingSendRatchet: false,
    });
  }

  /**
   * Bob opens Alice's first flight with his identity secrets and the peer pubs
   * he expects. Returns null on tamper, the wrong peer, a gap over MAX_SKIP, or
   * any AEAD failure. Identity secrets are not copied onto the session.
   */
  static async acceptFirst(
    self: RatchetIdentity,
    peer: RatchetPeer,
    packet: RatchetPacket,
  ): Promise<{ session: TripleRatchet; plaintext: string } | null> {
    assertIdentity(self, peer);
    const parsed = parsePacket(packet);
    if (!parsed) return null;

    let ssStatic: Uint8Array;
    let ssEph: Uint8Array;
    let ssKem: Uint8Array;
    try {
      ssStatic = x25519.getSharedSecret(self.x25519Sec, peer.x25519Pub);
      ssEph = x25519.getSharedSecret(self.x25519Sec, parsed.dh);
      ssKem = decapsulate(parsed.kemCt, self.mlkem1024Sec);
    } catch {
      return null;
    }
    if (ssKem.length !== KEM_SS_LEN) {
      wipe(ssStatic);
      wipe(ssEph);
      wipe(ssKem);
      return null;
    }
    const split = mixInitialHandshake(ssStatic, ssEph, ssKem);
    wipe(ssStatic);
    wipe(ssEph);
    wipe(ssKem);

    const session = new TripleRatchet({
      root: split.root,
      sendCk: null,
      recvCk: split.chain,
      theirDh: copyBytes(parsed.dh),
      theirKem: copyBytes(parsed.kemPk),
      myDhSk: null,
      myDhPk: null,
      myKemSk: null,
      myKemPk: null,
      sendKemCt: null,
      pendingSendRatchet: true,
    });
    // The initial flight is already the epoch theirDh names. Decrypt on that
    // chain (honoring n, including a bounded skip) and only then keep the session.
    const pt = await session.receive(packet);
    if (pt === null) return null;
    return { session, plaintext: pt };
  }

  /** Deep copy. A later wipe on this session does not reach the clone. */
  clone(): TripleRatchet {
    const c = new TripleRatchet({
      root: copyBytes(this.root),
      sendCk: this.sendCk ? copyBytes(this.sendCk) : null,
      recvCk: this.recvCk ? copyBytes(this.recvCk) : null,
      theirDh: copyBytes(this.theirDh!),
      theirKem: copyBytes(this.theirKem!),
      myDhSk: this.myDhSk ? copyBytes(this.myDhSk) : null,
      myDhPk: this.myDhPk ? copyBytes(this.myDhPk) : null,
      myKemSk: this.myKemSk ? copyBytes(this.myKemSk) : null,
      myKemPk: this.myKemPk ? copyBytes(this.myKemPk) : null,
      sendKemCt: this.sendKemCt ? copyBytes(this.sendKemCt) : null,
      pendingSendRatchet: this.pendingSendRatchet,
    });
    c.ns = this.ns;
    c.nr = this.nr;
    c.pn = this.pn;
    for (const [k, v] of this.skipped) c.skipped.set(k, copyBytes(v));
    return c;
  }

  /**
   * True when `secret` appears as a contiguous byte run inside retained session
   * material. The adversarial tests use this to refute "the session still holds
   * the identity secret / a used message key".
   */
  holdsContiguous(secret: Uint8Array): boolean {
    if (secret.length === 0) return false;
    const parts: Uint8Array[] = [this.root];
    for (const b of [
      this.sendCk,
      this.recvCk,
      this.myDhSk,
      this.myDhPk,
      this.myKemSk,
      this.myKemPk,
      this.theirDh,
      this.theirKem,
      this.sendKemCt,
    ]) {
      if (b) parts.push(b);
    }
    for (const mk of this.skipped.values()) parts.push(mk);
    const hay = concatBytes(...parts);
    const found = indexOfBytes(hay, secret);
    wipe(hay);
    return found;
  }

  async send(plaintext: string): Promise<RatchetPacket> {
    if (this.pendingSendRatchet || this.sendCk === null) {
      this.sendRatchet();
    }
    if (!this.sendCk || !this.myDhPk || !this.myKemPk || !this.sendKemCt) {
      throw new Error('triple-ratchet: send chain is not initialized');
    }
    const step = symmetricRatchet(this.sendCk);
    wipe(this.sendCk);
    this.sendCk = step.ck;
    const n = this.ns;
    this.ns += 1;
    const header: RatchetHeader = {
      v: 1,
      dh: uint8ToBase64(this.myDhPk),
      kemPk: uint8ToBase64(this.myKemPk),
      kemCt: uint8ToBase64(this.sendKemCt),
      pn: this.pn,
      n,
    };
    const nonce = randomBytes(NONCE_LEN);
    const pt = new TextEncoder().encode(plaintext);
    const ct = await aesGcmEncrypt(step.mk, nonce, pt, headerAad(header));
    wipe(pt);
    wipe(step.mk);
    return { header, nonce: uint8ToBase64(nonce), ct: uint8ToBase64(ct) };
  }

  /**
   * Open one packet. Null on tamper, over-skip, unknown epoch, or tag failure.
   * State changes only after the AEAD tag verifies.
   */
  async receive(packet: RatchetPacket): Promise<string | null> {
    const parsed = parsePacket(packet);
    if (!parsed || !this.theirDh || !this.theirKem) return null;

    const early = this.skipped.get(skipKey(parsed.header.dh, parsed.header.n));
    if (early) {
      const pt = await openWith(early, parsed);
      if (pt === null) return null;
      this.skipped.delete(skipKey(parsed.header.dh, parsed.header.n));
      wipe(early);
      return pt;
    }

    if (bytesEq(parsed.dh, this.theirDh)) {
      return this.receiveSameEpoch(parsed);
    }
    return this.receiveNewEpoch(parsed);
  }

  private async receiveSameEpoch(parsed: ParsedPacket): Promise<string | null> {
    if (!this.recvCk) return null;
    if (parsed.header.n < this.nr) return null;
    const gap = parsed.header.n - this.nr;
    if (gap > MAX_SKIP) return null;
    if (this.skipped.size + gap > MAX_SKIP_KEYS) return null;

    const walked = stageSkip(this.recvCk, this.nr, parsed.header.n, parsed.header.dh);
    if (!walked) return null;
    const step = symmetricRatchet(walked.ck);
    if (walked.ck !== this.recvCk) wipe(walked.ck);
    const pt = await openWith(step.mk, parsed);
    wipe(step.mk);
    if (pt === null) {
      discardStaged(walked.staged, null);
      wipe(step.ck);
      return null;
    }
    for (const s of walked.staged) this.skipped.set(s.id, s.mk);
    wipe(this.recvCk);
    this.recvCk = step.ck;
    this.nr = parsed.header.n + 1;
    return pt;
  }

  private async receiveNewEpoch(parsed: ParsedPacket): Promise<string | null> {
    if (!this.myDhSk || !this.myKemSk || !this.theirDh) return null;
    if (parsed.header.pn < this.nr) return null;
    if (!this.recvCk && parsed.header.pn !== this.nr) return null;

    const oldGap = parsed.header.pn - this.nr;
    if (oldGap > MAX_SKIP) return null;
    if (parsed.header.n > MAX_SKIP) return null;
    if (this.skipped.size + oldGap + parsed.header.n > MAX_SKIP_KEYS) return null;

    const oldDhB64 = uint8ToBase64(this.theirDh);
    let oldStaged: StagedSkip[] = [];
    if (oldGap > 0) {
      if (!this.recvCk) return null;
      const walked = stageSkip(this.recvCk, this.nr, parsed.header.pn, oldDhB64);
      if (!walked) return null;
      oldStaged = walked.staged;
      // The chain key at pn is unused (the old epoch ends at pn). Drop it.
      if (walked.ck !== this.recvCk) wipe(walked.ck);
    }

    let ssDh: Uint8Array;
    let ssKem: Uint8Array;
    try {
      ssDh = x25519.getSharedSecret(this.myDhSk, parsed.dh);
      ssKem = decapsulate(parsed.kemCt, this.myKemSk);
    } catch {
      discardStaged(oldStaged, null);
      return null;
    }
    if (ssKem.length !== KEM_SS_LEN) {
      wipe(ssDh);
      wipe(ssKem);
      discardStaged(oldStaged, null);
      return null;
    }
    const mixed = mixRatchetStep(this.root, ssDh, ssKem);
    wipe(ssDh);
    wipe(ssKem);

    const newDhB64 = parsed.header.dh;
    const walkedNew = stageSkip(mixed.chain, 0, parsed.header.n, newDhB64);
    if (!walkedNew) {
      wipe(mixed.root);
      wipe(mixed.chain);
      discardStaged(oldStaged, null);
      return null;
    }
    const step = symmetricRatchet(walkedNew.ck);
    // Position-0 chain key is not the retained recv chain. Wipe it even when the
    // walk stepped forward (those bytes would otherwise stay reachable).
    if (walkedNew.ck !== mixed.chain) wipe(walkedNew.ck);
    wipe(mixed.chain);
    const pt = await openWith(step.mk, parsed);
    wipe(step.mk);
    if (pt === null) {
      wipe(mixed.root);
      wipe(step.ck);
      discardStaged(oldStaged, null);
      discardStaged(walkedNew.staged, null);
      return null;
    }

    for (const s of oldStaged) this.skipped.set(s.id, s.mk);
    for (const s of walkedNew.staged) this.skipped.set(s.id, s.mk);
    wipe(this.root);
    this.root = mixed.root;
    wipe(this.recvCk);
    this.recvCk = step.ck;
    wipe(this.sendCk);
    this.sendCk = null;
    wipe(this.myDhSk);
    wipe(this.myKemSk);
    this.myDhSk = null;
    this.myDhPk = null;
    this.myKemSk = null;
    this.myKemPk = null;
    wipe(this.sendKemCt);
    this.sendKemCt = null;
    this.theirDh = copyBytes(parsed.dh);
    this.theirKem = copyBytes(parsed.kemPk);
    this.pendingSendRatchet = true;
    this.nr = parsed.header.n + 1;
    return pt;
  }

  /** Fresh X25519 + ML-KEM mixed into the root. Replaces the send chain. */
  private sendRatchet(): void {
    if (!this.theirDh || !this.theirKem) {
      throw new Error('triple-ratchet: cannot send before the peer ratchet key is known');
    }
    const dhSk = x25519.utils.randomSecretKey();
    const dhPk = x25519.getPublicKey(dhSk);
    const kem = freshKem();
    const enc = encapsulate(this.theirKem);
    const ssDh = x25519.getSharedSecret(dhSk, this.theirDh);
    const mixed = mixRatchetStep(this.root, ssDh, enc.sharedSecret);
    wipe(ssDh);
    wipe(enc.sharedSecret);
    wipe(this.root);
    this.root = mixed.root;
    wipe(this.sendCk);
    this.sendCk = mixed.chain;
    wipe(this.myDhSk);
    wipe(this.myKemSk);
    this.myDhSk = dhSk;
    this.myDhPk = dhPk;
    this.myKemSk = kem.sk;
    this.myKemPk = kem.pk;
    wipe(this.sendKemCt);
    this.sendKemCt = enc.ciphertext;
    this.pn = this.ns;
    this.ns = 0;
    this.pendingSendRatchet = false;
  }
}

function freshKem(): { sk: Uint8Array; pk: Uint8Array } {
  const kp = generateKEMKeypair();
  return { sk: kp.secretKey, pk: kp.publicKey };
}

function indexOfBytes(hay: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length > hay.length) return false;
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}
