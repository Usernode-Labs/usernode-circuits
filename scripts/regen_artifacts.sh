#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export PATH="$HOME/.nargo/bin:$PATH"

if ! command -v nargo >/dev/null 2>&1; then
  echo "error: nargo not found on PATH. Install via noirup (see docs/DEVELOPMENT.md)." >&2
  exit 1
fi

BB_CRS_DIR="${BB_CRS_DIR:-$ROOT_DIR/.bb-crs}"
mkdir -p "$BB_CRS_DIR"
export BB_CRS_DIR

echo "==> Compiling Noir circuits"
(
  cd "$ROOT_DIR/noir/utxo_spend"
  nargo compile
)
(
  cd "$ROOT_DIR/noir/utxo_merge"
  nargo compile
)

echo "==> Converting Nargo outputs into embedded artifacts"
python3 "$ROOT_DIR/scripts/nargo_to_artifacts.py" \
  --name utxo_spend \
  --artifact "$ROOT_DIR/noir/utxo_spend/target/utxo_spend.json" \
  --out-dir "$ROOT_DIR/artifacts" \
  --manifest "$ROOT_DIR/artifacts/manifest.json"

python3 "$ROOT_DIR/scripts/nargo_to_artifacts.py" \
  --name utxo_merge \
  --artifact "$ROOT_DIR/noir/utxo_merge/target/utxo_merge.json" \
  --out-dir "$ROOT_DIR/artifacts" \
  --manifest "$ROOT_DIR/artifacts/manifest.json"

echo "==> Deriving verifying keys with Barretenberg"
cargo run --quiet --bin write_vk -- \
  utxo_spend \
  "$ROOT_DIR/artifacts/utxo_spend.acir" \
  "$ROOT_DIR/artifacts/utxo_spend.abi.json" \
  "$ROOT_DIR/artifacts/utxo_spend.vk"

cargo run --quiet --bin write_vk -- \
  utxo_merge \
  "$ROOT_DIR/artifacts/utxo_merge.acir" \
  "$ROOT_DIR/artifacts/utxo_merge.abi.json" \
  "$ROOT_DIR/artifacts/utxo_merge.vk"

echo "==> Done"
