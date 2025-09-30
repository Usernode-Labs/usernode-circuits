# Noir Circuits

This folder hosts Noir circuits compiled and proven using the Aztec/Barretenberg toolchain.

Current status:
- `utxo_spend` (transparent INS=1, OUTS=2):
  - Inputs (temporarily private while wiring ACVM): sender/recipient keys, input note fields, transfer token/amount, output note fields, and signature.
  - Enforces transfer semantics and conservation for a single token per call.
  - Computes output commitments committing `recipient_pk_x` directly (no pk-hash preimage) and returns them as public outputs.
  - Computes a canonical transaction digest inside the circuit and verifies Schnorr over it.
- `utxo_merge` (transparent INS=2, OUTS=1):
  - Inputs: sender key, two input notes, one output note, and signature.
  - Enforces per-slot equality of tokens across inputs and sums their amounts into the output.
  - Computes output commitment committing `recipient_pk_x` (sender_pk_x) directly and returns it as a public output.
  - Computes canonical merge digest in-circuit and verifies Schnorr.

Notes on hashing compatibility:
- Commitments commit `recipient_pk_x` directly alongside assets and salt (no pk-hash preimage).
- Canonical digests include a small numeric tag as the first field (e.g., 1=spend, 2=merge) to separate message layouts without string domains.

Dependencies:
- Noir toolchain v1.0.0-beta.11.
- Stdlib is sourced from the Noir monorepo; do not depend on the legacy `noir_stdlib` repo.
- Schnorr is an external Noir crate (`noir-lang/schnorr`), pinned in each circuit’s `Nargo.toml` when needed.

Build locally (requires `nargo`):
- `cd circuits/utxo_spend && nargo build`
- `cd circuits/utxo_merge && nargo build`
- `cd circuits/poseidon2_compat && nargo build`

Tips:
- Ensure `nargo` is discoverable. Set `NARGO_BIN=/home/you/.nargo/bin/nargo` or add it to PATH.
- Cargo builds/tests will invoke `nargo build` automatically via `crates/usernode/build.rs`. Artifacts are written to `circuits/*/target/*.json` and are consumed by tests/examples through `usernode::prover::init_circuit_from_artifacts`.
- Non-interactive builds: the build script sets `GIT_TERMINAL_PROMPT=0` to avoid credential prompts when fetching Noir dependencies.

Next steps:
- Add INS=2 variant for merging (OUTS=1), reusing the same transparent pattern.
- Keep Merkle inclusion and nullifiers out of this circuit (handled elsewhere).
