# 588-slotbind: slot-binding circuit (WORKING DRAFT, not reviewed)

Status: built against Flint's R1-R3 spec v2 (8eb488c0). **R5 independent review has NOT happened.** Do not describe this circuit as independently verified or audited.

Build: `npm ci && CIRCOM=/path/to/circom ./build.sh`. It refuses an unpinned circom binary, an r1cs whose sha256 differs from `pins.json`, any unconstrained public wire (R2-c), and any KAT witness that is rejected. Command line (explicit `--O2`; the optimisation level changes the r1cs): see `pins.json`.

## Known-answer vector (`kat.json`)
- Reference implementation = circomlibjs, **the same project family as circomlib**. The KAT shows *circuit == reference*, not two independent implementations. The Weft's own implementation matching it is the independent check.
- Domain tags: big-endian integer of the ASCII bytes of `svrnty:588:slot:v1`, `svrnty:588:null:v1`, `svrnty:588:k:v1` (each < 31 bytes, so injective).
- **Byte order trap:** `K = Poseidon[DS_K, pk_lo, pk_hi]` where the 32-byte key is read as ONE **big-endian** 256-bit integer; `pk_lo` = low 128 bits, `pk_hi` = high 128 bits. Ed25519 keys are conventionally little-endian, so a second implementation will get this wrong unless it follows the KAT.
- Point order of (P, Y): lexicographic on the FULL field element (x, then y), not the low 252 bits.
- Wire spelling of public inputs: 64 lowercase hex, value < p (R1; `src/lib/crypto/beacon-public-inputs.ts`).
- Secrets in the KAT are SHA-256 of fixed labels. They are test values; never reuse them.

## Limits
- The full-width comparator is unit-tested at template level (`cmp_test.cjs`); real curve points with equal low-252 x cannot be constructed.
- Proving/setup artefacts made here are throwaway (single-party). The ceremony output is a separate step.
- Phone proving time is unmeasured.
