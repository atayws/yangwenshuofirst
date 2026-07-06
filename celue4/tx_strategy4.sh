#!/usr/bin/env bash
set -euo pipefail
DPORT="${1:-50240}"
CASE_NAME="${2:-smoke}"
INPUT_FILE="${INPUT_FILE:-celue4/input_payload.bin}"
PACE_MS="${PACE_MS:-1}"
STRATEGY4_K="${STRATEGY4_K:-4}"
STRATEGY4_NUM_OUTPUT="${STRATEGY4_NUM_OUTPUT:-16}"
PATH_WEIGHTS="${PATH_WEIGHTS:-1,1,1}"
SECRET_KEY="${SECRET_KEY:-low-altitude-ipid-fountain-v1}"
BUSINESS_PAYLOAD_LEN="${BUSINESS_PAYLOAD_LEN:-32}"
OUT_DIR="celue4/results/${CASE_NAME}"
mkdir -p "${OUT_DIR}"
exec python3 experiments/live_send_strategy.py \
  --strategy 4 \
  --input "${INPUT_FILE}" \
  --dst-ip 10.0.2.2 \
  --src-ip 10.0.1.2 \
  --iface h1-eth0 \
  --dst-mac 00:00:00:00:01:01 \
  --send-mode scapy-l2 \
  --dport "${DPORT}" \
  --pace-ms "${PACE_MS}" \
  --strategy4-k "${STRATEGY4_K}" \
  --strategy4-num-output "${STRATEGY4_NUM_OUTPUT}" \
  --path-weights "${PATH_WEIGHTS}" \
  --secret-key "${SECRET_KEY}" \
  --business-payload-len "${BUSINESS_PAYLOAD_LEN}"