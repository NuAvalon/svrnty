// src/lib/crypto/beacon-artifacts.ts
// #588 piece F (DARK; nothing imports it): load the proving files ONLY if they are byte-for-byte the pinned ones. Fail closed: the zkey pin is null until
// the ceremony's output exists (H7), and until then the prover must not run on ANY zkey (the prototype/throwaway keys are simply "a hash that is not
// the pin"). Cheap refusals (malformed pin, no pin) happen before any download; size caps happen before hashing. Messages are fixed strings.

export interface ArtifactPins {
  /** sha256 (lowercase hex) of slotbind.wasm as built by the pinned circom (circuits/588-slotbind/pins.json wasm_sha256["2.2.3"]). */
  wasmSha256: string;
  /** sha256 of the FINAL phase-2 zkey. null until the ceremony has run: the loader refuses while it is null. */
  zkeySha256: string | null;
}

export const PINS: ArtifactPins = {
  wasmSha256: '3f603c198ba712cb8fb3e34f59bbf75c445ddd8cf3596a305ea57c31000083be',
  zkeySha256: null, // set by H7 (the ceremony), and only then
};

export type ArtifactReason = 'pin-format' | 'zkey-unpinned' | 'fetch' | 'size' | 'wasm-hash' | 'zkey-hash';
export class ArtifactRefused extends Error {
  readonly reason: ArtifactReason;
  constructor(reason: ArtifactReason) {
    super(`refused: ${reason}`);
    this.name = 'ArtifactRefused';
    this.reason = reason;
  }
}

const MAX_WASM_BYTES = 8 * 1024 * 1024;   // slotbind.wasm is ~2 MB; a generous cap
const MAX_ZKEY_BYTES = 96 * 1024 * 1024;  // the final zkey for 6,574 constraints is a few MB; a generous cap
const HEX64 = /^[0-9a-f]{64}$/;

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- globalThis has no typed crypto on every target
  const subtle: SubtleCrypto | undefined = (globalThis as any).crypto?.subtle;
  if (!subtle) throw new Error('no WebCrypto available');
  const d = new Uint8Array(await subtle.digest('SHA-256', bytes));
  return Array.from(d, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Fetch both files with the injected `fetchBytes` and return them only if they equal the pins. Throws ArtifactRefused (a fixed reason) otherwise. */
export async function loadProvingFiles(
  fetchBytes: (url: string) => Promise<Uint8Array>,
  urls: { wasm: string; zkey: string },
  pins: ArtifactPins = PINS,
): Promise<{ wasm: Uint8Array; zkey: Uint8Array }> {
  if (typeof pins.wasmSha256 !== 'string' || !HEX64.test(pins.wasmSha256)) throw new ArtifactRefused('pin-format');
  if (pins.zkeySha256 === null) throw new ArtifactRefused('zkey-unpinned');
  if (typeof pins.zkeySha256 !== 'string' || !HEX64.test(pins.zkeySha256)) throw new ArtifactRefused('pin-format');

  const get = async (url: string, cap: number): Promise<Uint8Array> => {
    let b: unknown;
    try { b = await fetchBytes(url); } catch { throw new ArtifactRefused('fetch'); }
    if (!(b instanceof Uint8Array)) throw new ArtifactRefused('fetch');
    if (b.length > cap) throw new ArtifactRefused('size');
    return b;
  };
  const wasm = await get(urls.wasm, MAX_WASM_BYTES);
  if ((await sha256Hex(wasm)) !== pins.wasmSha256) throw new ArtifactRefused('wasm-hash');
  const zkey = await get(urls.zkey, MAX_ZKEY_BYTES);
  if ((await sha256Hex(zkey)) !== pins.zkeySha256) throw new ArtifactRefused('zkey-hash');
  return { wasm, zkey };
}
