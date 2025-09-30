# Usernode Circuits

Embedded Noir circuit artifacts and proving helpers extracted from the historic `circuits` branch of `usernode`.

> **Status:** early extraction prototype. The committed artifacts are placeholders until we wire in the real ACIR/ABI/VK blobs from `nargo build`.

## Repository Layout
- `Cargo.toml` – single `usernode_circuits` library crate.
- `src/` – merged Barretenberg wrappers (`bn254`, `poseidon2`), circuit catalog, and proving APIs.
- `artifacts/` – committed circuit blobs (`*.acir`, `*.vk`, `*.abi.json`) reused at runtime via `include_bytes!`/`include_str!`.
- `noir/` – Noir sources copied from the original repository (`utxo_spend`, `utxo_merge`).
- `tests/` – crate-level checks (full proving tests migrate here once real artifacts land).
- `scripts/` – developer helpers (e.g. `nargo_to_artifacts.py`, `regen_artifacts.sh`).
- `docs/DEVELOPMENT.md` – end-to-end setup instructions for Linux/macOS.

## Tooling Expectations
- Runtime callers import `usernode_circuits` and call `init_default_circuits()` (or `init_embedded_catalog()`) to hydrate the catalog from embedded artifacts.
- No `build.rs` tasks run `nargo`; default builds only touch the checked-in blobs.
- The Barretenberg dependencies pin `Usernode-Labs/aztec-packages` release `bb-v0.1.2`.

## Refreshing Artifacts
A maintainer-only flow will live in CI:
1. Install the Noir toolchain and Barretenberg runtime via `aztec-package` (currently `0.1.2`, tag `bb-v0.1.2`).
2. Run `nargo build` inside each circuit under `noir/` to produce fresh ACIR/ABI outputs.
3. Convert the outputs into raw `.acir`, `.abi.json`, and `.vk` files (see `scripts/nargo_to_artifacts.py` and `cargo run --bin write_vk`).
4. Regenerate `artifacts/manifest.json` (TBD) describing hashes for downstream consumers.
5. Commit the regenerated artifacts and push a tag. GitHub Actions will publish the crate and attach the raw artifacts to the release.

Until the automation exists, developers can update the artifacts manually and run `cargo test`. The placeholder binaries checked in right now allow the crate to compile but will not yield valid proofs.

## Next Steps
- Replace the placeholder artifacts with real Noir outputs once build tooling is wired.
- Port the existing prover integration tests from `usernode` into this repository (guarded or updated to use the embedded blobs).
- Add an `xtask`/CLI helper to regenerate artifacts locally (e.g. `cargo xtask embed-circuits --nargo <path>`).
- Author GitHub Actions workflows for linting, artifact regeneration, diffing, and release packaging.
