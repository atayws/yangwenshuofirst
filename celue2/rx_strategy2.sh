#!/usr/bin/env bash
set -euo pipefail
DPORT="${1:-50202}"
EXPECTED_PACKETS="${2:-192}"
EXPECTED_BYTES="${3:-64}"
CASE_NAME="${4:-smoke}"
TIMEOUT_S="${TIMEOUT_S:-30}"
OUT_DIR="celue2/results/${CASE_NAME}"
mkdir -p "${OUT_DIR}"
exec python3 experiments/live_receive_strategy.py   --strategy 2   --iface h2-eth0   --dport "${DPORT}"   --expected-packets "${EXPECTED_PACKETS}"   --expected-bytes "${EXPECTED_BYTES}"   --timeout "${TIMEOUT_S}"   --output "${OUT_DIR}/decoded_output.bin"   --summary "${OUT_DIR}/receive_summary.json"
