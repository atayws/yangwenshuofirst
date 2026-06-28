#!/usr/bin/env bash
set -euo pipefail
IFACE="${1:?iface}"
tc qdisc del dev "${IFACE}" root 2>/dev/null || true
