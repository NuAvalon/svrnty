# pair-slot fixtures: THROWAWAY test material

Used only by `infra/svrnty/test_beacon_pair_slot.py`. Nothing here is a release key and nothing here may become one.

- `vkey.json`: the verification key of a single-party setup made for these tests (sha256 starts `4e350988b5db2ef6`). The setup's secret was never kept, and a setup run by one party is not a ceremony. It differs from any key the satellite pins for release.
- `proof_X.json` / `public_X.json`: Groth16 proofs and their public signals (epoch, slot, nullifier, poll key), all verifying under `vkey.json`.
  - **A**, **B**: the two parties of one pair (same slot, different nullifiers).
  - **C**: a third party proving against B with its own secret (a slot of its own).
  - **H**: a third party that was handed the counterpart key that makes its shared secret equal the pair's (checked when the fixtures were generated, not by the test); the slot also covers the two public points, so it is still a slot of its own.
- Every secret is the SHA-256 of a fixed label; they are test values and must not be reused.
- Made from the slot-binding circuit (r1cs sha256 starts `4f334609c93f39cc`, 6,574 constraints, 4 public signals), compiled with circom 2.2.3 and set up and proved with snarkjs 0.7.6, from the PSE powers-of-tau file the circuit's pins name. Check any proof with: `snarkjs groth16 verify vkey.json public_X.json proof_X.json`.
