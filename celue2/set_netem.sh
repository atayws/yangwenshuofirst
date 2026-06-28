#!/usr/bin/env bash
set -euo pipefail
IFACE="${1:?iface}"
DELAY_MS="${2:-5}"
LOSS_PCT="${3:-0}"
tc qdisc replace dev "${IFACE}" root netem delay "${DELAY_MS}ms" loss "${LOSS_PCT}%"
