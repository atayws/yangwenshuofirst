#!/usr/bin/env python3
"""
策略2 live 矩阵测试。

脚本自动启动 h1-s1-(三链路)-s2-h2 拓扑，固定使用链路0验证策略2，
按多个时延/丢包梯度发送同一份隐蔽数据，并把结果写入 celue2/results。
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
P4_JSON = ROOT / "p4" / "covert_int_switch.json"
LOG_DIR = ROOT / "logs" / "celue2_matrix"
S1_CLI = ROOT / "p4" / "s1_commands.txt"
S2_CLI = ROOT / "p4" / "s2_commands.txt"
RUNTIME_PY = ROOT / "p4" / "build" / "mininet_runtime.py"
INPUT_FILE = ROOT / "celue2" / "input_payload.bin"
RESULTS_DIR = ROOT / "celue2" / "results"

CASES = [
    {"name": "delay5_loss0", "delay_ms": 5, "loss_pct": 0},
    {"name": "delay20_loss0", "delay_ms": 20, "loss_pct": 0},
    {"name": "delay50_loss0", "delay_ms": 50, "loss_pct": 0},
    {"name": "delay5_loss5", "delay_ms": 5, "loss_pct": 5},
    {"name": "delay5_loss10", "delay_ms": 5, "loss_pct": 10},
    {"name": "delay5_loss20", "delay_ms": 5, "loss_pct": 20},
    {"name": "delay5_loss30", "delay_ms": 5, "loss_pct": 30},
]


def load_runtime():
    spec = importlib.util.spec_from_file_location("celue2_mininet_runtime", RUNTIME_PY)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法加载 Mininet 运行时：{RUNTIME_PY}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ensure_p4_json() -> None:
    if P4_JSON.exists():
        return
    subprocess.check_call([
        "p4c",
        "--target", "bmv2",
        "--arch", "v1model",
        "--output", str(ROOT / "p4"),
        str(ROOT / "p4" / "covert_int_switch.p4"),
    ])


def expected_packets() -> int:
    sys.path.insert(0, str(ROOT))
    from python.covert_strategies.base import StrategyID
    from python.covert_strategies.strategy_registry import get_strategy

    data = INPUT_FILE.read_bytes()
    strategy = get_strategy(StrategyID.PROTOCOL_HIGH_RELIABILITY)
    return len(strategy.encode(data, path_id=0, seq_num=1))


def file_md5(path: Path) -> str:
    if not path.exists():
        return ""
    return hashlib.md5(path.read_bytes()).hexdigest()


def run_case(h1, h2, s1, case, expected_count: int, expected_bytes: int, timeout_s: int, port: int) -> dict:
    out_dir = RESULTS_DIR / case["name"]
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    s1.cmd(f"cd {ROOT} && bash celue2/set_netem.sh s1-eth2 {case['delay_ms']} {case['loss_pct']}")
    rx_cmd = (
        f"cd {ROOT} && TIMEOUT_S={timeout_s} "
        f"bash celue2/rx_strategy2.sh {port} {expected_count} {expected_bytes} {case['name']} "
        f"> {out_dir}/receive_stdout.txt 2>&1 & echo $!"
    )
    rx_pid = h2.cmd(rx_cmd).strip().splitlines()[-1]
    time.sleep(0.5)

    tx_cmd = (
        f"cd {ROOT} && PACE_MS=1 "
        f"bash celue2/tx_strategy2.sh {port} {case['name']} "
        f"> {out_dir}/send_stdout.txt 2>&1"
    )
    send_stdout = h1.cmd(tx_cmd)
    (out_dir / "send_cmd_stdout.txt").write_text(send_stdout, encoding="utf-8")

    time.sleep(timeout_s + 1)
    if rx_pid.isdigit():
        h2.cmd(f"kill {rx_pid} >/dev/null 2>&1 || true")

    summary_path = out_dir / "receive_summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    else:
        summary = {"success": False, "error": "没有生成接收摘要"}

    decoded_path = out_dir / "decoded_output.bin"
    input_md5 = file_md5(INPUT_FILE)
    decoded_md5 = file_md5(decoded_path)
    hidden_match = bool(decoded_md5 and decoded_md5 == input_md5)
    packets_received = int(summary.get("packets_received", 0))
    packet_loss_est = 1.0 - (packets_received / expected_count) if expected_count else 0.0

    result = {
        "case": case["name"],
        "configured_delay_ms": case["delay_ms"],
        "configured_loss_pct": case["loss_pct"],
        "port": port,
        "expected_packets": expected_count,
        "packets_received": packets_received,
        "estimated_packet_loss_pct": round(packet_loss_est * 100, 2),
        "decoded_bytes": summary.get("decoded_bytes", 0),
        "success": bool(summary.get("success")),
        "hidden_match": hidden_match,
        "input_md5": input_md5,
        "decoded_md5": decoded_md5,
        "decode_info": summary.get("decode_info", {}),
    }
    (out_dir / "case_result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="策略2 live 矩阵测试")
    parser.add_argument("--timeout", type=int, default=25)
    parser.add_argument("--start-port", type=int, default=50220)
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("请使用 sudo 运行该脚本。", file=sys.stderr)
        return 2

    ensure_p4_json()
    runtime = load_runtime()
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    expected_count = expected_packets()
    expected_bytes = len(INPUT_FILE.read_bytes())

    runtime_args = SimpleNamespace(
        json=str(P4_JSON),
        log_dir=str(LOG_DIR),
        s1_cli=str(S1_CLI),
        s2_cli=str(S2_CLI),
        host_mtu=1500,
        trunk_mtu=1600,
    )

    net = runtime.build_net(runtime_args)
    results = []
    try:
        print("[celue2] 启动 Mininet/BMv2")
        net.start()
        runtime.configure_mtu(net, runtime_args.host_mtu, runtime_args.trunk_mtu)
        runtime.disable_offload(net)
        h1, h2, s1, s2 = net.get("h1", "h2", "s1", "s2")
        h1.setARP("10.0.1.2", "00:00:00:00:00:02")
        h2.setARP("10.0.1.1", "00:00:00:00:00:01")
        runtime.wait_for_thrift(9090)
        runtime.wait_for_thrift(9091)
        runtime.run_cli_file(9090, "s1", str(S1_CLI), str(LOG_DIR))
        runtime.run_cli_file(9091, "s2", str(S2_CLI), str(LOG_DIR))

        ping_out = h1.cmd("ping -c 2 10.0.1.2")
        (RESULTS_DIR / "matrix_ping.txt").write_text(ping_out, encoding="utf-8")
        print("[celue2] ping 检查完成")

        for index, case in enumerate(CASES):
            port = args.start_port + index
            print(f"[celue2] 运行 {case['name']} port={port}")
            results.append(run_case(h1, h2, s1, case, expected_count, expected_bytes, args.timeout, port))
            print(
                f"[celue2] {case['name']} success={results[-1]['success']} "
                f"match={results[-1]['hidden_match']} recv={results[-1]['packets_received']}/{expected_count}"
            )
    finally:
        print("[celue2] 清理 Mininet")
        net.stop()

    summary = {
        "input_file": str(INPUT_FILE),
        "input_bytes": expected_bytes,
        "expected_packets": expected_count,
        "cases": results,
    }
    (RESULTS_DIR / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    csv_lines = [
        "case,delay_ms,loss_pct,expected_packets,packets_received,estimated_loss_pct,success,hidden_match,decoded_bytes"
    ]
    for item in results:
        csv_lines.append(
            f"{item['case']},{item['configured_delay_ms']},{item['configured_loss_pct']},"
            f"{item['expected_packets']},{item['packets_received']},{item['estimated_packet_loss_pct']},"
            f"{item['success']},{item['hidden_match']},{item['decoded_bytes']}"
        )
    (RESULTS_DIR / "summary.csv").write_text("\n".join(csv_lines) + "\n", encoding="utf-8")
    print(f"[celue2] 完成，结果见 {RESULTS_DIR}/summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
