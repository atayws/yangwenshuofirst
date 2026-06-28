#!/usr/bin/env python3
"""
中期演示用交互式闭环脚本。

功能目标：
1. 一键启动 h1-s1-(三条链路)-s2-h2 P4/Mininet 拓扑。
2. 后台持续运行 h2->h1 UDP iperf，触发反向 INT，h1 周期性解析三条链路状态。
3. 用户在终端输入任意长度隐蔽数据。
4. 脚本根据最新 INT 状态生成规则策略计划。
5. h1 把隐蔽数据切成全局 chunk，短数据走一条最优链路，长数据按策略计划分块多路发送。
6. h2 抓包、统一分发解码并按 chunk_id 重组，实时打印恢复出的隐蔽数据。

该脚本暂不做 PPO 动态切换；它完成“INT -> 规则选策略 -> 发送 -> 接收分发 -> 按序重组”的
中期审核闭环。后续 PPO 只需要输出同样格式的策略计划即可替换规则选择器。
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace
from typing import Iterable, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments import mininet_runtime
from experiments.run_manual_policy_live import (
    configure_s1_for_entry,
    configure_s2_for_reverse_int,
    ensure_p4_json,
    parse_iperf_ok,
    wait_background,
    write_manifest_csv,
)
from experiments.verify_manual_policy_session import PolicyEntry, write_policy_plan
from experiments.live_manual_policy_sender import build_chunk_packets
from python.control_plane.rule_policy_selector import RuleBasedPolicySelector


P4_JSON = PROJECT_ROOT / "p4" / "covert_int_switch.json"
P4_FILE = PROJECT_ROOT / "p4" / "covert_int_switch.p4"
S1_CLI = PROJECT_ROOT / "p4" / "s1_commands.txt"
S2_CLI = PROJECT_ROOT / "p4" / "s2_commands.txt"
RESULTS_DIR = PROJECT_ROOT / "experiments" / "results" / "interactive_closed_loop"
LOG_DIR = PROJECT_ROOT / "logs" / "interactive_closed_loop"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="交互式 INT+策略闭环演示")
    parser.add_argument("--timeout", type=int, default=75, help="单次输入的接收超时时间")
    parser.add_argument("--chunk-size", type=int, default=7, help="隐蔽数据全局 chunk 大小")
    parser.add_argument("--base-dport", type=int, default=51200)
    parser.add_argument("--session-id-start", type=int, default=40)
    parser.add_argument("--pace-ms", type=float, default=1.0)
    parser.add_argument("--chunk-gap-ms", type=float, default=100.0)
    parser.add_argument("--iperf-rate", default="700K")
    parser.add_argument("--clean-results", action="store_true")
    parser.add_argument("--demo-once", default=None, help="非交互模式：发送一条指定字符串后退出")
    return parser.parse_args()


def run_cli(thrift_port: int, commands: Iterable[str]) -> None:
    """向 simple_switch_CLI 写入一组命令。"""
    proc = subprocess.run(
        ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
        input="\n".join(commands) + "\n",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"simple_switch_CLI {thrift_port} 失败:\n{proc.stdout}")


def configure_s1_round_robin_for_business() -> None:
    """让普通 h1->h2 业务流默认按三路径轮询。"""
    run_cli(
        9090,
        [
            "register_write reg_path_mode 0 2",
            "register_write reg_rr_burst_size 0 12",
            "register_write reg_rr_counter 0 0",
            "register_write reg_rr_current_path 0 0",
            "register_write reg_int_enabled 0 0",
        ],
    )


def stop_background(host, pid: str) -> None:
    """停止 Mininet 主机中的后台进程。"""
    if pid and pid.isdigit():
        host.cmd(f"kill {pid} >/dev/null 2>&1 || true")


def start_background_services(h1, h2, args: argparse.Namespace) -> dict:
    """启动反向业务流和 INT 解析器。"""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    int_output = RESULTS_DIR / "latest_int_summary.json"
    int_pid = h1.cmd(
        f"cd {PROJECT_ROOT} && python3 experiments/reverse_probe_receiver.py "
        f"--timeout 86400 --window-ms 60000 --write-interval 1 "
        f"--output {int_output} "
        f"> {RESULTS_DIR}/int_receiver.log 2>&1 & echo $!"
    ).strip().splitlines()[-1]
    iperf_server_pid = h1.cmd(
        f"iperf -s -u -i 5 > {RESULTS_DIR}/reverse_iperf_server_h1.log 2>&1 & echo $!"
    ).strip().splitlines()[-1]
    time.sleep(0.5)
    iperf_client_pid = h2.cmd(
        f"iperf -u -c 10.0.1.1 -b {args.iperf_rate} -t 86400 -i 5 "
        f"> {RESULTS_DIR}/reverse_iperf_client_h2.log 2>&1 & echo $!"
    ).strip().splitlines()[-1]
    return {
        "int_pid": int_pid,
        "iperf_server_pid": iperf_server_pid,
        "iperf_client_pid": iperf_client_pid,
        "int_output": int_output,
    }


def read_latest_int_state(int_output: Path) -> dict:
    """读取 h1 已解析出的最新 INT 链路状态。"""
    if not int_output.exists():
        return {}
    try:
        summary = json.loads(int_output.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return summary.get("path_states", {}) or {}


def path_sort_key(item: tuple[int, object]) -> tuple[float, float, float]:
    """根据 INT 状态对路径排序，越小越好。"""
    _path_id, state = item
    if isinstance(state, dict):
        return (
            float(state.get("loss_rate", 0.0)),
            float(state.get("jitter_ms", 0.0)),
            float(state.get("delay_ms", 0.0)),
        )
    return (
        float(getattr(state, "loss_rate", 0.0)),
        float(getattr(state, "jitter_ms", 0.0)),
        float(getattr(state, "delay_ms", 0.0)),
    )


def build_demo_plan(secret: bytes, path_states: dict, chunk_size: int) -> List[PolicyEntry]:
    """根据隐蔽数据长度和最新链路状态生成中期演示策略计划。"""
    if len(secret) <= chunk_size:
        if path_states:
            best_path = sorted(
                ((int(path_id), state) for path_id, state in path_states.items()),
                key=path_sort_key,
            )[0][0]
        else:
            best_path = 0
        return [PolicyEntry(f"short_best_path{best_path}_s3", 3, (best_path,), 1)]

    selector = RuleBasedPolicySelector()
    plan = selector.select({int(path_id): state for path_id, state in path_states.items()})
    if plan:
        return plan
    return [
        PolicyEntry("fallback_path0_s2", 2, (0,), 1),
        PolicyEntry("fallback_path1_s3", 3, (1,), 1),
        PolicyEntry("fallback_path012_s4", 4, (0, 1, 2), 1),
    ]


def write_input_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def build_session_manifest(
    input_file: Path,
    chunk_size: int,
    session_id: int,
    base_dport: int,
    plan_file: Path,
) -> list[dict]:
    """生成本次输入对应的 chunk 发送清单，不写入其他结果目录。"""
    ns = SimpleNamespace(
        input=str(input_file),
        dst_ip="10.0.1.2",
        src_ip="10.0.1.1",
        iface="h1-eth0",
        src_mac=None,
        dst_mac="00:00:00:00:00:02",
        sport=41000,
        base_dport=base_dport,
        chunk_size=chunk_size,
        session_id=session_id,
        chunk_id=None,
        plan_file=str(plan_file),
        pace_ms=1.0,
        send_mode="scapy-l2",
        summary=None,
        dry_run=True,
    )
    _secret, _chunks, selected, _plan = build_chunk_packets(ns)
    return [
        {
            "chunk_id": item["chunk"].chunk_id,
            "strategy_id": item["entry"].strategy_id,
            "paths": list(item["entry"].paths),
            "dport": item["dport"],
            "sequence_num": item["sequence_num"],
            "packets": len(item["packets"]),
            "encoded_bytes": item["encoded_bytes"],
        }
        for item in selected
    ]


def send_one_session(
    h1,
    h2,
    args: argparse.Namespace,
    secret: bytes,
    session_id: int,
    sequence_index: int,
    path_states: dict,
) -> dict:
    """发送并接收一条用户输入的隐蔽数据。"""
    session_dir = RESULTS_DIR / f"session_{session_id:03d}"
    session_dir.mkdir(parents=True, exist_ok=True)
    input_file = session_dir / "input_secret.bin"
    output_file = session_dir / "decoded_secret.bin"
    plan_file = session_dir / "rule_plan.json"
    summary_file = session_dir / "summary.json"
    write_input_file(input_file, secret)

    plan = build_demo_plan(secret, path_states, args.chunk_size)
    write_policy_plan(
        plan_file,
        plan,
        extra={
            "source": "interactive_closed_loop",
            "input_path_states": path_states,
            "sequence_index": sequence_index,
            "secret_bytes": len(secret),
        },
    )

    manifest = build_session_manifest(
        input_file=input_file,
        chunk_size=args.chunk_size,
        session_id=session_id,
        base_dport=args.base_dport,
        plan_file=plan_file,
    )
    write_manifest_csv(session_dir / "send_manifest.csv", manifest)
    expected_packets = sum(int(row["packets"]) for row in manifest)
    receive_timeout = max(args.timeout, int(expected_packets * 0.04) + 20)

    receiver_pid = h2.cmd(
        f"cd {PROJECT_ROOT} && python3 experiments/live_manual_policy_receiver.py "
        f"--iface h2-eth0 --base-dport {args.base_dport} --chunk-count {len(manifest)} "
        f"--chunk-size {args.chunk_size} --session-id {session_id} "
        f"--plan-file {plan_file} --secret-bytes {len(secret)} "
        f"--expected-packets {expected_packets} --timeout {receive_timeout} "
        f"--output {output_file} --summary {session_dir}/receiver_summary.json "
        f"> {session_dir}/receiver_stdout.log 2>&1 & echo $!"
    ).strip().splitlines()[-1]
    time.sleep(0.8)

    for row in manifest:
        configure_s1_for_entry(int(row["strategy_id"]), row["paths"])
        chunk_id = int(row["chunk_id"])
        h1.cmd(
            f"cd {PROJECT_ROOT} && python3 experiments/live_manual_policy_sender.py "
            f"--input {input_file} --dst-ip 10.0.1.2 --src-ip 10.0.1.1 "
            f"--iface h1-eth0 --dst-mac 00:00:00:00:00:02 "
            f"--base-dport {args.base_dport} --chunk-size {args.chunk_size} "
            f"--session-id {session_id} --plan-file {plan_file} "
            f"--chunk-id {chunk_id} --pace-ms {args.pace_ms} --send-mode scapy-l2 "
            f"--summary {session_dir}/sender_chunk_{chunk_id}.json "
            f"> {session_dir}/sender_chunk_{chunk_id}.log 2>&1"
        )
        time.sleep(args.chunk_gap_ms / 1000.0)

    wait_background(h2, receiver_pid, receive_timeout + 5)
    stop_background(h2, receiver_pid)
    configure_s1_round_robin_for_business()

    receiver_summary_path = session_dir / "receiver_summary.json"
    receiver_summary = (
        json.loads(receiver_summary_path.read_text(encoding="utf-8"))
        if receiver_summary_path.exists()
        else {"success": False}
    )
    decoded = output_file.read_bytes() if output_file.exists() else b""
    hidden_match = decoded == secret
    result = {
        "success": bool(receiver_summary.get("success")) and hidden_match,
        "hidden_match": hidden_match,
        "session_id": session_id,
        "sequence_index": sequence_index,
        "input_text": secret.decode("utf-8", errors="replace"),
        "decoded_text": decoded.decode("utf-8", errors="replace"),
        "input_bytes": len(secret),
        "decoded_bytes": len(decoded),
        "expected_packets": expected_packets,
        "plan": [entry.to_dict() for entry in plan],
        "manifest": manifest,
        "path_states_used": path_states,
        "receiver_summary": receiver_summary,
        "session_dir": str(session_dir),
    }
    summary_file.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    append_history(result)
    return result


def append_history(result: dict) -> None:
    """把每次交互发送的摘要追加到历史 CSV。"""
    history_path = RESULTS_DIR / "history.csv"
    is_new = not history_path.exists()
    with history_path.open("a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "session_id",
                "sequence_index",
                "success",
                "hidden_match",
                "input_bytes",
                "decoded_bytes",
                "input_text",
                "decoded_text",
                "session_dir",
            ],
        )
        if is_new:
            writer.writeheader()
        writer.writerow(
            {
                key: result.get(key)
                for key in writer.fieldnames
            }
        )


def print_result(result: dict) -> None:
    """在交互终端打印一次解码结果。"""
    print("\n[闭环结果]")
    print(f"  session_id: {result['session_id']}")
    print(f"  成功: {result['success']}  比对一致: {result['hidden_match']}")
    print(f"  输入: {result['input_text']}")
    print(f"  解码: {result['decoded_text']}")
    print("  策略计划:")
    for entry in result["plan"]:
        print(
            f"    - {entry['name']}: strategy={entry['strategy_id']} "
            f"paths={entry['paths']} weight={entry['weight']}"
        )
    print(f"  结果目录: {result['session_dir']}\n")


def write_overall_summary(service_info: dict, sent_results: list[dict]) -> None:
    """写出本次交互运行的总摘要。"""
    iperf_client = RESULTS_DIR / "reverse_iperf_client_h2.log"
    iperf_text = iperf_client.read_text(encoding="utf-8", errors="ignore") if iperf_client.exists() else ""
    int_summary = {}
    int_output = service_info.get("int_output")
    if isinstance(int_output, Path) and int_output.exists():
        try:
            int_summary = json.loads(int_output.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            int_summary = {}
    summary = {
        "success": all(item.get("success") for item in sent_results) if sent_results else False,
        "sessions": [
            {
                "session_id": item["session_id"],
                "success": item["success"],
                "hidden_match": item["hidden_match"],
                "input_bytes": item["input_bytes"],
                "decoded_bytes": item["decoded_bytes"],
                "session_dir": item["session_dir"],
            }
            for item in sent_results
        ],
        "iperf_ok": parse_iperf_ok(iperf_text),
        "iperf_client_tail": "\n".join(iperf_text.strip().splitlines()[-8:]),
        "int_success": bool(int_summary.get("success")),
        "int_parsed_reports": int_summary.get("parsed_int_reports", 0),
        "int_path_states": int_summary.get("path_states", {}),
    }
    (RESULTS_DIR / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def interactive_loop(h1, h2, args: argparse.Namespace, service_info: dict) -> list[dict]:
    """读取用户输入并逐条发送。"""
    sent_results: list[dict] = []
    session_id = args.session_id_start
    print("\n[交互闭环已启动]")
    print("输入要隐蔽传输的文本，回车后立即发送；输入 /quit 退出。")
    print("短文本走最优单路径，长文本自动分块并按 INT 状态生成规则策略计划。\n")

    pending_inputs: List[str]
    if args.demo_once is not None:
        pending_inputs = [args.demo_once]
    else:
        pending_inputs = []

    sequence_index = 0
    while True:
        if pending_inputs:
            text = pending_inputs.pop(0)
            print(f"> {text}")
        else:
            try:
                text = input("> ")
            except EOFError:
                break
        if text.strip() in {"/quit", "/exit"}:
            break
        if not text:
            continue

        path_states = read_latest_int_state(service_info["int_output"])
        result = send_one_session(
            h1=h1,
            h2=h2,
            args=args,
            secret=text.encode("utf-8"),
            session_id=session_id,
            sequence_index=sequence_index,
            path_states=path_states,
        )
        sent_results.append(result)
        print_result(result)
        session_id += 1
        sequence_index += 1
        if args.demo_once is not None:
            break
    return sent_results


def main() -> int:
    args = parse_args()
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("请使用 sudo 运行该脚本。", file=sys.stderr)
        return 2

    ensure_p4_json()
    if args.clean_results and RESULTS_DIR.exists():
        shutil.rmtree(RESULTS_DIR)
    if args.clean_results and LOG_DIR.exists():
        shutil.rmtree(LOG_DIR)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    runtime_args = SimpleNamespace(
        json=str(P4_JSON),
        log_dir=str(LOG_DIR),
        s1_cli=str(S1_CLI),
        s2_cli=str(S2_CLI),
        host_mtu=1500,
        trunk_mtu=1600,
    )

    net = None
    service_info: dict = {}
    sent_results: list[dict] = []
    try:
        print("[interactive] 启动 Mininet/BMv2 拓扑...")
        net = mininet_runtime.start_configured_net(runtime_args)
        h1, h2 = net.get("h1", "h2")
        configure_s2_for_reverse_int()
        configure_s1_round_robin_for_business()
        ping_out = h1.cmd("ping -c 2 10.0.1.2")
        (RESULTS_DIR / "ping.txt").write_text(ping_out, encoding="utf-8")
        print("[interactive] 启动 h2->h1 UDP iperf 和 h1 INT 解析器...")
        service_info = start_background_services(h1, h2, args)
        time.sleep(2.0)
        sent_results = interactive_loop(h1, h2, args, service_info)
        return 0 if sent_results and all(item.get("success") for item in sent_results) else 1
    finally:
        if net is not None:
            try:
                h1, h2 = net.get("h1", "h2")
                stop_background(h1, service_info.get("int_pid", ""))
                stop_background(h1, service_info.get("iperf_server_pid", ""))
                stop_background(h2, service_info.get("iperf_client_pid", ""))
                write_overall_summary(service_info, sent_results)
            finally:
                print("[interactive] 清理 Mininet/BMv2 拓扑...")
                net.stop()
                print(f"[interactive] 结果目录：{RESULTS_DIR}")


if __name__ == "__main__":
    raise SystemExit(main())
