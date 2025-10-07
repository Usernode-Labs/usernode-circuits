# Usernode Circuits

Embedded Noir circuit artifacts and proving helpers extracted from the historic `circuits` branch of `usernode`.

> **Status:** spend and merge circuits ship with real ACIR/ABI/VK blobs generated from Noir `v1.0.0-beta.11` and Barretenberg `bb-v1.1.3`; CI keeps the embedded catalog in sync.

## Repository Layout
- `Cargo.toml` – single `usernode_circuits` library crate.
- `src/` – merged Barretenberg wrappers (`bn254`, `poseidon2`), circuit catalog, and proving APIs.
- `artifacts/` – committed circuit blobs (`*.acir`, `*.vk`, `*.abi.json`) reused at runtime via `include_bytes!`/`include_str!`.
- `noir/` – Noir sources copied from the original repository (`utxo_spend`, `utxo_merge`).
- `tests/` – end-to-end proving/verification suites (positive + negative coverage) exercising the embedded blobs.
- `scripts/` – developer helpers (e.g. `nargo_to_artifacts.py`, `regen_artifacts.sh`).
- `docs/DEVELOPMENT.md` – end-to-end setup instructions for Linux/macOS.

## Tooling Expectations
- Runtime callers import `usernode_circuits` and call `init_default_circuits()` (or `init_embedded_catalog()`) to hydrate the catalog from embedded artifacts.
- No `build.rs` tasks run `nargo`; default builds only touch the checked-in blobs.
- The Barretenberg dependencies pin `Usernode-Labs/aztec-packages` release `bb-v1.1.3`.

## Regenerating Artifacts
Both CI and local developers follow the same workflow when the Noir circuits change:
1. Install Noir `v1.0.0-beta.11` and the Barretenberg toolchain (`Usernode-Labs/aztec-packages@bb-v1.1.3`).
2. Run `scripts/regen_artifacts.sh` from the repository root. The script compiles Noir sources, converts the JSON outputs into `.acir` / `.abi.json`, produces `.vk` blobs via `cargo run --bin write_vk`, and refreshes `artifacts/manifest.json` hashes.
3. Commit the regenerated blobs alongside the code change. CI re-runs the script and fails if any diffs are missing.

## Proving & Aggregation APIs
- Initialise the embedded catalog with `init_default_circuits()` (or hydrate it manually via `init_circuit_from_artifacts`); the helper is now idempotent and thread-safe, so repeated calls across threads reuse the cached Barretenberg compilation result.
- Generate single proofs by encoding the Noir ABI (`encode_*` helpers) and calling `prove`/`prove_with_*`. Verification is available through `verify` or raw Barretenberg entry points.
- Aggregate two spend/merge proofs into a MegaHonK batch node with `merge_batch_h2(left_proof, left_vk, right_proof, right_vk)`. The helper wraps Barretenberg’s C++ batching primitive and returns the merged proof plus its verification key as raw bytes.
- Use `merge_batch_h2_by_name` when you only have proof bytes; it fetches (or regenerates) the verification keys from the catalog before delegating to the batching primitive. See `tests/batch_merge.rs:1` for a full walk-through of the binding block layout the merged proof exposes.
