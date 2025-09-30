# Development Guide

This document collects everything needed to work on `usernode-circuits` from a
fresh Linux checkout without referring back to the legacy `usernode` repo.

## 1. Prerequisites

### Toolchain
- **Rust**: Stable (1.79+). Install with `rustup` and run `rustup default stable`.
- **Cargo components**: `cargo fmt`/`cargo clippy` if you plan to run format/lints.
- **System packages** (Ubuntu/Debian example):
  ```bash
  sudo apt-get update && sudo apt-get install -y \
      build-essential clang cmake git ninja-build pkg-config python3 python3-venv \
      libssl-dev libomp-dev zstd
  ```
  These are needed by the Barretenberg crates.
- **Aztec package toolchain**: Install
  `Usernode-Labs/aztec-packages@bb-v0.1.2`. That release pulls the Barretenberg
  binaries used by `aztec-barretenberg-rs`.
- **Noir/Nargo**: Use `v1.0.0-beta.11` to match the Noir sources in `noir/`.
  Install on Linux with `curl -fsSL https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash`
  and then `noirup -v v1.0.0-beta.11`.

### Environment
- (Optional) Set `BB_CRS_DIR` to reuse a pre-downloaded Barretenberg CRS
  (defaults to `~/.bb-crs`). The first proving run will fetch it if missing.
- Ensure `~/.nargo/bin` and `~/.cargo/bin` are on `PATH` before invoking the
  helper scripts below.

## 2. Repository Layout Recap
- `artifacts/`: ACIR, ABI JSON, and verifying key (`*.vk`) blobs embedded at
  compile time. Regenerate them with `nargo_to_artifacts.py` and `write_vk`
  when the Noir sources change.
- `noir/`: Noir circuit sources (`utxo_spend`, `utxo_merge`).
- `scripts/nargo_to_artifacts.py`: Helper to convert the JSON emitted by `nargo`
  into the raw files expected under `artifacts/`.
- `src/`: Rust crate with merged BN254 field arithmetic, Poseidon2 helpers,
  catalog, and proving APIs.
- `src/bin/write_vk.rs`: CLI to derive a verifying key from a freshly generated
  ACIR+ABI using Barretenberg.
- `tests/`: Rust tests (currently only a catalog smoke test).

## 3. Bootstrapping on Linux
1. Clone or copy this repository onto the target machine.
2. Run `cargo fetch` to download the git dependencies (`aztec-barretenberg-rs`,
   `binprot`, etc.). Network access is required for this step.
3. Run `cargo test` to ensure the crate builds. With placeholder artifacts the
   proving APIs will panic when invoked, but the catalog smoke test will pass.

## 4. Generating Real Artifacts with Nargo
The goal is to replace every placeholder under `artifacts/` with data produced
from `nargo compile` and Barretenberg.

### 4.1 Compile the Noir circuits
```
# UTXO spend circuit
cd noir/utxo_spend
nargo compile utxo_spend --workspace-root ../..
# Output -> ./target/utxo_spend.json

# UTXO merge circuit
cd ../utxo_merge
nargo compile utxo_merge --workspace-root ../..
# Output -> ./target/utxo_merge.json
```
Adjust paths if your Nargo version produces a different layout; the important
part is capturing the JSON artifact that contains `bytecode` and `abi`.

### 4.2 Convert JSON into embedded files
Use the bundled helper script from the repository root:
```
./scripts/nargo_to_artifacts.py \
    --name utxo_spend \
    --artifact noir/utxo_spend/target/utxo_spend.json \
    --out-dir artifacts \
    --manifest artifacts/manifest.json

./scripts/nargo_to_artifacts.py \
    --name utxo_merge \
    --artifact noir/utxo_merge/target/utxo_merge.json \
    --out-dir artifacts \
    --manifest artifacts/manifest.json
```
This writes `utxo_*.acir` and `utxo_*.abi.json`, updating the manifest and
preserving SHA256 hashes for traceability. If you already have a verifying key
on disk, pass `--vk /path/to/file` so the manifest references the correct name.

### 4.3 Derive verifying keys with Barretenberg
Once the ACIR/ABI files exist, generate the MegaHonK verifying keys via the
provided binary:
```
cargo run --bin write_vk -- \
    utxo_spend artifacts/utxo_spend.acir artifacts/utxo_spend.abi.json artifacts/utxo_spend.vk

cargo run --bin write_vk -- \
    utxo_merge artifacts/utxo_merge.acir artifacts/utxo_merge.abi.json artifacts/utxo_merge.vk
```
Set `BB_CRS_DIR` beforehand if you have a custom CRS location. The command
updates the catalog cache in-memory only; it writes the VK directly to the path
supplied on the command line.

> Tip: run `./scripts/regen_artifacts.sh` from the repository root to execute
> all of the steps above (compile, convert, and write verifying keys) in one
> go. The script ensures `nargo` is on `PATH` and defaults `BB_CRS_DIR` to
> `.bb-crs/` inside the workspace if none is provided.

### 4.4 Verify everything compiles
Re-run `cargo test` to ensure the crate still builds with the new artifacts. At
this point the proving APIs can be exercised by higher-level integration tests
once they are ported into this repository.

## 5. Running Tests and Examples
- `cargo test` – builds the crate and runs unit/integration tests.
- `cargo test -- --nocapture` – useful when debugging catalog initialization.
- (Future) Integration tests from the old `usernode` repo will live here; ensure
  they pass before releasing new artifacts.

## 6. Release & Automation Checklist
When preparing a tagged release:
1. Install the pinned Noir toolchain (`nargo v1.0.0-beta.11`) and
   `aztec-package` (`0.1.2`, tag `bb-v0.1.2`).
2. Rebuild circuits and regenerate artifacts using the steps above.
3. Run `cargo fmt`, `cargo clippy`, and `cargo test`.
4. Diff the updated `artifacts/` contents to confirm only expected changes.
5. Commit the new blobs, bump the crate version, and push a tag.
6. CI (to be added) should publish the crate and upload the raw artifacts as
   release assets for non-Rust consumers.

## 7. Copying Between Machines
To move work from macOS to Linux:
- Copy the entire `usernode-circuits` directory (including `.git/` if you want
  history). All repository dependencies are either vendored (Noir sources) or
  fetched via Cargo.
- On the Linux VM, run through the bootstrapping and artifact-generation steps
  above. No other external repositories are required.
- If you regenerate artifacts on Linux, remember to commit the updated files so
  future macOS sessions can pick up the same state.

With this guide, you should be able to resume development from any environment
without referring back to the original `usernode` workspace.
