#!/bin/bash

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "[!] Testing hunt..."

cargo run -- hunt ${SCRIPT_DIR}/../evtx_attack_samples --mapping ${SCRIPT_DIR}/../mapping_files/sigma-mapping.yml --rules ${SCRIPT_DIR}/../sigma_rules -j > /tmp/chainsaw.json 2>/dev/null
diff /tmp/chainsaw.json ${SCRIPT_DIR}/hunt_expected.json
rm /tmp/chainsaw.json

echo "[+] Success..."

echo "[!] Testing search..."
cargo run -- search ${SCRIPT_DIR}/../evtx_attack_samples -i -s bypass > /tmp/chainsaw.yml 2>/dev/null
diff /tmp/chainsaw.yml ${SCRIPT_DIR}/search_expected.yml
rm /tmp/chainsaw.yml

echo "[+] Success..."
