// src/lib/identity/headless-mint.ts
//
// HEADLESS agent identity mint (Peter #152949). A non-browser (Node/service) agent mints its OWN genesis
// identity: a 4-key OPERATIONAL bundle (ed25519 sign + x25519 enc + ML-KEM-1024 + ML-DSA-87) whose canonical
// fingerprint IS its durable_id, a self-signed genesis DID-Doc with subject_type='agent' bound IMMUTABLY, plus
// a cold-seed RECOVERY authority (KERI two-tier).
//
// SILICON-ONLY, FAIL-CLOSED: this path can ONLY mint 'agent' — subject_type is hardcoded, there is no parameter
// to self-attest 'human'/'org'. A bot cannot forge organic embodiment.
//
// NO new crypto: reuses the SAME primitives as the human mint (OpenPGP ecc/ed25519 → extractRawSign/extractRawEnc,
// + pq keygen), so the emitted card carries an OpenPGP-armored `public_key` and is importable by the existing
// contact path (encrypt/decrypt roundtrip holds — proven in the test). Emits an opaque-secret MintArtifact for
// Athena's per-agent custody store (agent_custody.py); this module NEVER persists, logs, or prints a secret.

import * as openpgp from 'openpgp';
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js';
import { generateKEMKeypair, generateSigningKeypair, uint8ToBase64 } from '../crypto/pq';
import { extractRawSign, extractRawEnc } from './raw-sign';
import { buildAgentIntroduction, deriveGenesisAuthorityCommitment } from './introduce-shell';
import { buildSignedIdentityCard, type SignedIdentityCard } from './identity-card-sign';
import type { DidDocument } from './did-peer';

/** SILICON-ONLY: the headless path mints exactly this subject_type. Not a parameter — a constant. */
const AGENT_SUBJECT_TYPE = 'agent' as const;

/** The public introduction — durable_id + signed genesis DID-Doc + card. For OOB fp-verify + import. */
export interface MintPublic {
  durableId: string;
  did: string;
  subjectType: typeof AGENT_SUBJECT_TYPE;
  signedDidDoc: DidDocument;
  card: SignedIdentityCard; // self-signed, entity_type='agent' — importable via the SAME path as humans
}

/**
 * The operational SECRET bundle — OPAQUE to custody (encrypted at rest, per-agent). NEVER logged/persisted here.
 * Carries the non-secret enc/kem PUBLIC keys too, so the serve can reconstruct SenderKeys/MyKeys without parsing
 * the armored card or re-deriving anything.
 */
export interface MintSecret {
  ed25519Seed: Uint8Array; // 32B raw ed25519 seed (genesis operational signing)
  x25519Sec: Uint8Array; // 32B raw x25519 enc secret
  x25519Pub: Uint8Array; // 32B (not secret — bundled for the serve's convenience)
  mlkem1024Sec: Uint8Array; // ML-KEM-1024 secret
  mlkem1024Pub: Uint8Array; // 1568B (not secret)
  mldsa87Secret: Uint8Array; // ML-DSA-87 secret
}

/** Full mint artifact handed to the custody store: public introduction + opaque secret + cold-seed recovery authority. */
export interface MintArtifact {
  introduction: MintPublic;
  secret_material: MintSecret; // OPAQUE to custody
  cold_seed: Uint8Array; // 32B RECOVERY authority — handled per recovery_mode (M-of-N / throwaway), NOT operational
  recoveryMode: string | null; // 'm-of-n' | ... ; a REAL mint requires a non-null §0-clean mode (enforced by the custody store)
  throwaway: boolean; // true = dev/test key (custody store won't apply real-mint gates); false = real mint
}

/**
 * Mint a fresh headless agent identity. Defaults to a THROWAWAY mint (dev/test); a real mint passes
 * `throwaway:false` + a §0-clean `recoveryMode` (e.g. 'm-of-n') — the real-mint gate is ENFORCED by the custody
 * store, not here. `coldSeed` may be supplied for deterministic tests; otherwise a fresh 32B random seed is used.
 */
export async function mintHeadlessAgent(
  opts: { recoveryMode?: string | null; throwaway?: boolean; coldSeed?: Uint8Array } = {},
): Promise<MintArtifact> {
  const throwaway = opts.throwaway ?? true;
  const recoveryMode = opts.recoveryMode ?? null;
  // A caller-supplied coldSeed is ONLY for deterministic THROWAWAY tests. A REAL mint (throwaway:false) MUST use
  // a freshly-generated, full-entropy cold seed — the recovery authority must never be caller-known or low-entropy
  // (an attacker-known cold seed = forgeable recovery). (Codex P1, #153190.)
  if (opts.coldSeed !== undefined && !throwaway)
    throw new Error(
      'mintHeadlessAgent: caller-supplied coldSeed is only allowed for throwaway mints; a real mint must use a freshly generated cold seed',
    );
  const cold_seed = opts.coldSeed ?? randomBytes(32);
  if (cold_seed.length !== 32) throw new Error('mintHeadlessAgent: coldSeed must be exactly 32 bytes');

  // Classical (ed25519 sign + x25519 enc) via OpenPGP → raw, so the emitted card is import-compatible.
  // Generate WITH a throwaway in-process passphrase: extractRaw* needs a DECRYPTED key (we decrypt a copy),
  // and buildSignedIdentityCard's signer decrypts an ENCRYPTED armored key with the passphrase (openpgp refuses
  // to "decrypt" an already-decrypted key). The passphrase is random, used ONLY in-process, NEVER emitted; the
  // armored private key is discarded after signing.
  const kpass = bytesToHex(randomBytes(16));
  const { privateKey: encPrivateKey, publicKey } = (await openpgp.generateKey({
    type: 'ecc',
    curve: 'ed25519',
    userIDs: [{ name: 'agent' }],
    format: 'object',
    passphrase: kpass,
  } as any)) as any;
  const decryptedPrivateKey = await openpgp.decryptKey({ privateKey: encPrivateKey, passphrase: kpass });
  const { seed: ed25519Seed, signPub } = extractRawSign(decryptedPrivateKey);
  const { encSec: x25519Sec, encPub: x25519Pub } = await extractRawEnc(decryptedPrivateKey);

  // Post-quantum bundle.
  const kem = generateKEMKeypair(); // { publicKey, secretKey } ML-KEM-1024
  const sig = generateSigningKeypair(); // { publicKey, secretKey } ML-DSA-87

  // Genesis introduction: durable_id + operationally self-signed DID-Doc, subject_type='agent' bound immutably.
  const authorityCommitment = deriveGenesisAuthorityCommitment(cold_seed);
  const intro = buildAgentIntroduction({
    keys: { deviceSlug: 'genesis', signPub, encPub: x25519Pub, kemPub: kem.publicKey, sigPub: sig.publicKey },
    signer: { signSeed: ed25519Seed, sigSecret: sig.secretKey },
    authorityCommitment,
    subjectType: AGENT_SUBJECT_TYPE, // silicon-only, fail-closed
  });

  // A SELF-SIGNED, TYPED IdentityCard so the agent imports via the SAME path as humans
  // (buildSignedIdentityCard → verifySignedIdentityCard). entity_type='agent' is bound IN the signed card
  // (immutable, G-attest). Signed IN-PROCESS with the transient armored key, which is then discarded — only
  // the signed PUBLIC card is emitted; NO armored private key ever leaves this function.
  const card = await buildSignedIdentityCard(
    {
      fingerprint: intro.durableId,
      public_key: publicKey.armor(),
      display_name: 'agent',
      email: '',
      post_quantum: { sig_public_key: uint8ToBase64(sig.publicKey), kem_public_key: uint8ToBase64(kem.publicKey) },
      next_authority_commitment: authorityCommitment,
    },
    encPrivateKey.armor(),
    kpass,
    AGENT_SUBJECT_TYPE,
  );

  return {
    introduction: {
      durableId: intro.durableId,
      did: intro.did,
      subjectType: AGENT_SUBJECT_TYPE,
      signedDidDoc: intro.signedDidDoc,
      card,
    },
    secret_material: {
      ed25519Seed,
      x25519Sec,
      x25519Pub,
      mlkem1024Sec: kem.secretKey,
      mlkem1024Pub: kem.publicKey,
      mldsa87Secret: sig.secretKey,
    },
    cold_seed,
    recoveryMode,
    throwaway,
  };
}

/**
 * JSON-safe wire form for the cross-language handoff to the (Python) custody store (agent_custody.py).
 * SHAPE is Athena's confirmed contract (#153088): snake_case, top-level `public`/`private`, ALL secrets (incl.
 * cold_seed) inside `private` (opaque to custody — encrypted wholesale). `signed_did_doc` keeps its own signed
 * field names (do NOT rename — under the signature); only the wrapper keys are snake_case.
 */
export interface SerializedMintArtifact {
  public: {
    durable_id: string;
    did: string;
    subject_type: typeof AGENT_SUBJECT_TYPE;
    signed_did_doc: DidDocument;
    card: SignedIdentityCard; // the self-signed, entity_type='agent' identity card — REQUIRED for import
  };
  private: {
    // OPAQUE to custody — all secrets (base64) + the non-secret enc/kem pubs so the serve can rebuild keys.
    cold_seed: string;
    ed25519_seed: string;
    x25519_sec: string;
    x25519_pub: string;
    mlkem1024_sec: string;
    mlkem1024_pub: string;
    mldsa87_secret: string;
  };
  recovery_mode: string | null; // non-null REQUIRED for a real mint; null for throwaway
  throwaway: boolean;
}

/** Serialize a MintArtifact to the custody-store wire shape (#153088). Custody treats `private` as an opaque blob. */
export function serializeMintArtifact(a: MintArtifact): SerializedMintArtifact {
  const s = a.secret_material;
  const p = a.introduction;
  return {
    public: {
      durable_id: p.durableId,
      did: p.did,
      subject_type: p.subjectType,
      signed_did_doc: p.signedDidDoc,
      card: p.card,
    },
    private: {
      cold_seed: uint8ToBase64(a.cold_seed),
      ed25519_seed: uint8ToBase64(s.ed25519Seed),
      x25519_sec: uint8ToBase64(s.x25519Sec),
      x25519_pub: uint8ToBase64(s.x25519Pub),
      mlkem1024_sec: uint8ToBase64(s.mlkem1024Sec),
      mlkem1024_pub: uint8ToBase64(s.mlkem1024Pub),
      mldsa87_secret: uint8ToBase64(s.mldsa87Secret),
    },
    recovery_mode: a.recoveryMode,
    throwaway: a.throwaway,
  };
}
