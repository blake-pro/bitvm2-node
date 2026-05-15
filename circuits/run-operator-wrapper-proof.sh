#!/bin/bash
set -euo pipefail

source ~/.zkm-toolchain/env
set -a
source .env
set +a

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "Missing required environment variable: $name" >&2
    exit 1
  fi
}

require_file() {
  local path="$1"
  if [ ! -f "$path" ]; then
    echo "Missing required file: $path" >&2
    exit 1
  fi
}

operator_input_proof="${1:-}"
output="${2:-}"
if [ -z "$operator_input_proof" ] || [ -z "$output" ]; then
  echo "Usage: bash run-operator-wrapper-proof.sh <operator_input_proof> <output_path>" >&2
  exit 1
fi

require_env "GRAPH_ID"
require_env "GENESIS_SEQUENCER_COMMIT_TXID"

require_file "$operator_input_proof"
require_file "${operator_input_proof}.public_inputs.bin"
require_file "${operator_input_proof}.vk_hash.bin"
require_file "${operator_input_proof}.zkm_version.bin"

mkdir -p "$(dirname "$output")"

graph_id_hex="${GRAPH_ID//-/}"

cargo build -r --bin operator-wrapper-proof --package operator-wrapper-proof
CMD="../target/release/operator-wrapper-proof"

RUST_LOG=info "$CMD" \
  --operator-input-proof "$operator_input_proof" \
  --graph-id "$graph_id_hex" \
  --genesis-sequencer-commit-txid "$GENESIS_SEQUENCER_COMMIT_TXID" \
  --output "$output"
