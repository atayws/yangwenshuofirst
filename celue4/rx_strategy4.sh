#!/usr/bin/env bash
set -euo pipefail
DPORT="${1:-50240}"
EXPECTED_PACKETS="${2:-256}"
EXPECTED_BYTES="${3:-23}"
CASE_NAME="${4:-smoke}"
TIMEOUT_S="${TIMEOUT_S:-15}"
STRATEGY4_K="${STRATEGY4_K:-4}"
STRATEGY4_NUM_OUTPUT="${STRATEGY4_NUM_OUTPUT:-16}"
PATH_WEIGHTS="${PATH_WEIGHTS:-1,1,1}"
SECRET_KEY="${SECRET_KEY:-low-altitude-ipid-fountain-v1}"
BUSINESS_PAYLOAD_LEN="${BUSINESS_PAYLOAD_LEN:-32}"
OUT_DIR="celue4/results/${CASE_NAME}"
mkdir -p "${OUT_DIR}"
exec python3 experiments/live_receive_strategy.py \
  --strategy 4 \
  --iface h2-eth0 \
  --dport "${DPORT}" \
  --expected-packets "${EXPECTED_PACKETS}" \
  --expected-bytes "${EXPECTED_BYTES}" \
  --timeout "${TIMEOUT_S}" \
  --strategy4-k "${STRATEGY4_K}" \
  --strategy4-num-output "${STRATEGY4_NUM_OUTPUT}" \
  --path-weights "${PATH_WEIGHTS}" \
  --secret-key "${SECRET_KEY}" \
  --business-payload-len "${BUSINESS_PAYLOAD_LEN}" \
  --output "${OUT_DIR}/decoded_output.bin" \
  --summary "${OUT_DIR}/receive_summary.json"