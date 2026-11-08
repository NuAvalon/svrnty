// src/lib/trust/psi-epoch-element.ts
/**
 * Per-epoch PSI element: the value a friend can form for a contact only if they were handed that contact's
 * epoch secret. Library only: nothing calls this yet, and PSI still builds its points from the bare fingerprint
 * (hashFingerprintToPoint in mutual-trust-sync.ts).
 *
 *   element_A^L(e) = HKDF-SHA256(ikm  = LP('svrnty/psi-elem/v2') || LP(fp_A) || LP(L) || u64be(e) || E_A^L(e),
 *                                salt = 'svrnty-psi-v2', info = 'svrnty-psi-elem-point-v2', 32 bytes)
 *
 * L is 'know' or 'trust'. A holds TWO independent 32-byte secrets per epoch, one per layer, and the layer is also
 * in the key material, so either alone would stop a know-layer friend from forming a trust-layer element.
 * LP is the shared lp-tlv.ts framing (uint32 big-endian length prefix); the fingerprint is the canonical lowercase
 * 64-hex string. The salt and info differ from the bare-fingerprint point's, so the two derivations cannot collide.
 *
 * The 32 output bytes are used as an x25519 u-coordinate exactly where hashFingerprintToPoint(fp) is used today.
 * The known-answer vectors in psi-epoch-element.test.ts come from scripts/psi-epoch-element-kat.py, which shares
 * no code with this file.
 */
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { lpStr, u64be } from '../crypto/lp-tlv';

export const PSI_LAYERS = ['know', 'trust'] as const;
export type PsiLayer = (typeof PSI_LAYERS)[number];

export const EPOCH_SECRET_LEN = 32;

const ELEM_IKM_TAG = 'svrnty/psi-elem/v2';
const ELEM_SALT = 'svrnty-psi-v2';
const ELEM_INFO = 'svrnty-psi-elem-point-v2';
const CANONICAL_FP = /^[0-9a-f]{64}$/;

export type PsiElementErrorCode = 'bad-fingerprint' | 'bad-layer' | 'bad-epoch' | 'bad-secret' | 'secrets-not-independent';

export class PsiElementError extends Error {
  constructor(readonly code: PsiElementErrorCode, detail: string) {
    super(`psi-epoch-element: ${code}: ${detail}`);
    this.name = 'PsiElementError';
  }
}

export interface EpochSecrets {
  know: Uint8Array;
  trust: Uint8Array;
}

function checkSecret(s: unknown): Uint8Array {
  if (!(s instanceof Uint8Array) || s.length !== EPOCH_SECRET_LEN) {
    throw new PsiElementError('bad-secret', `must be exactly ${EPOCH_SECRET_LEN} bytes`);
  }
  return s;
}

/**
 * One epoch's two secrets, drawn independently (no relation, no PRF between them). A source that hands back the
 * same bytes twice is refused: it would make the layers one secret.
 */
export function mintEpochSecrets(rand: (n: number) => Uint8Array = randomBytes): EpochSecrets {
  const know = checkSecret(rand(EPOCH_SECRET_LEN)).slice();
  const trust = checkSecret(rand(EPOCH_SECRET_LEN)).slice();
  let same = true;
  for (let i = 0; i < EPOCH_SECRET_LEN; i++) if (know[i] !== trust[i]) same = false;
  if (same) throw new PsiElementError('secrets-not-independent', 'the two layer secrets came out identical');
  return { know, trust };
}

/** element_A^L(e). Throws PsiElementError on anything but a canonical fingerprint, a known layer, a safe epoch and a 32-byte secret. */
export function psiElement(fpA: string, layer: PsiLayer, epoch: number, secret: Uint8Array): Uint8Array {
  if (typeof fpA !== 'string' || !CANONICAL_FP.test(fpA)) {
    throw new PsiElementError('bad-fingerprint', 'not canonical (lowercase 64-hex)');
  }
  if (!PSI_LAYERS.includes(layer)) throw new PsiElementError('bad-layer', 'must be "know" or "trust"');
  if (!Number.isSafeInteger(epoch) || epoch < 0) throw new PsiElementError('bad-epoch', 'must be a non-negative safe integer');
  checkSecret(secret);
  const ikm = concatBytes(lpStr(ELEM_IKM_TAG), lpStr(fpA), lpStr(layer), u64be(epoch), secret);
  return hkdf(sha256, ikm, utf8ToBytes(ELEM_SALT), utf8ToBytes(ELEM_INFO), 32);
}
