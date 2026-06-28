#!/usr/bin/env bash
set -euo pipefail

# 一键启动阶段验证拓扑：
#   h1 -- s1 == 三条并行链路 == s2 -- h2
# 两台交换机运行同一个 P4 程序，流表分别从 p4/s1_commands.txt 和 p4/s2_commands.txt 下发。

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
P4_FILE="${ROOT_DIR}/p4/covert_int_switch.p4"
P4_DIR="${ROOT_DIR}/p4"
LOG_DIR="${ROOT_DIR}/logs/mininet"
JSON_FILE="${P4_DIR}/covert_int_switch.json"
RUNTIME_PY="${ROOT_DIR}/experiments/mininet_runtime.py"
S1_CLI_FILE="${ROOT_DIR}/p4/s1_commands.txt"
S2_CLI_FILE="${ROOT_DIR}/p4/s2_commands.txt"

P4C_BIN="${P4C_BIN:-p4c}"
SIMPLE_SWITCH_BIN="${SIMPLE_SWITCH_BIN:-simple_switch}"
SIMPLE_SWITCH_CLI_BIN="${SIMPLE_SWITCH_CLI_BIN:-simple_switch_CLI}"
HOST_MTU="${HOST_MTU:-1500}"
TRUNK_MTU="${TRUNK_MTU:-1600}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "[run.sh] Mininet/BMv2 需要 root 权限，正在用 sudo 重新启动..."
    exec sudo -E bash "$0" "$@"
fi

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "[run.sh] 找不到命令：$1"
        exit 1
    fi
}

need_file() {
    if [[ ! -f "$1" ]]; then
        echo "[run.sh] 找不到文件：$1"
        exit 1
    fi
}

need_cmd "${P4C_BIN}"
need_cmd "${SIMPLE_SWITCH_BIN}"
need_cmd "${SIMPLE_SWITCH_CLI_BIN}"
need_cmd python3
need_cmd ethtool
need_file "${P4_FILE}"
need_file "${RUNTIME_PY}"
need_file "${S1_CLI_FILE}"
need_file "${S2_CLI_FILE}"

mkdir -p "${LOG_DIR}"

echo "[run.sh] 清理旧 Mininet 状态..."
mn -c >/dev/null 2>&1 || true

echo "[run.sh] 编译 P4 -> ${JSON_FILE}"
rm -rf "${JSON_FILE}"
"${P4C_BIN}" --target bmv2 --arch v1model \
    --output "${P4_DIR}" \
    "${P4_FILE}"

if [[ ! -f "${JSON_FILE}" ]]; then
    echo "[run.sh] 编译后没有找到 BMv2 JSON：${JSON_FILE}"
    echo "[run.sh] 当前 p4 目录内容："
    find "${P4_DIR}" -maxdepth 1 -type f -print
    exit 1
fi

if ! head -c 1 "${JSON_FILE}" | grep -q "{"; then
    echo "[run.sh] ${JSON_FILE} 不是合法 BMv2 JSON 文件"
    head -5 "${JSON_FILE}" || true
    exit 1
fi

echo "[run.sh] 启动 Mininet 拓扑..."
SIMPLE_SWITCH_BIN="${SIMPLE_SWITCH_BIN}" \
SIMPLE_SWITCH_CLI_BIN="${SIMPLE_SWITCH_CLI_BIN}" \
python3 "${RUNTIME_PY}" \
    --json "${JSON_FILE}" \
    --log-dir "${LOG_DIR}" \
    --s1-cli "${S1_CLI_FILE}" \
    --s2-cli "${S2_CLI_FILE}" \
    --host-mtu "${HOST_MTU}" \
    --trunk-mtu "${TRUNK_MTU}"
