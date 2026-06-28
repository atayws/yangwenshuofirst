#!/usr/bin/env bash
set -euo pipefail
DPORT="${1:-50202}"
CASE_NAME="${2:-smoke}"
INPUT_FILE="${INPUT_FILE:-celue2/input_payload.bin}"
PACE_MS="${PACE_MS:-1}"
OUT_DIR="celue2/results/${CASE_NAME}"
mkdir -p "${OUT_DIR}"
exec python3 experiments/live_send_strategy.py   --strategy 2   --input "${INPUT_FILE}"   --dst-ip 10.0.1.2   --src-ip 10.0.1.1   --iface h1-eth0   --dst-mac 00:00:00:00:00:02   --send-mode scapy-l2   --dport "${DPORT}"   --pace-ms "${PACE_MS}"
