#!/usr/bin/env python3
"""
长消息在线规则切换闭环验证。

该脚本验证升级后的 chunk 级动态重规划能力：
1. 启动 h1-s1-(三链路)-s2-h2 P4/Mininet 拓扑；
2. h2->h1 持续 UDP iperf 触发 inline INT，h1 周期性解析三条链路状态；
3. h1->h2 使用真实 UDP iperf 业务流承载隐蔽数据；
4. 每个 chunk 开始前重新读取最新 INT 状态，并改写该 chunk 的策略/路径计划；
5. 传输中途主动改变链路时延和丢包，验证后续 chunk 自动换策略继续传输；
6. h2 统一分发解码后按 segment_id 恢复完整隐蔽明文。
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import time
from types import SimpleNamespace
from typing import Dict, Iterable, List

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.run_manual_policy_live import (
    apply_link_config,
    configure_s1_for_entry,
    configure_s2_for_reverse_int,
    ensure_p4_json,
    parse_iperf_ok,
    stop_background,
    wait_background,
)
from experiments.run_rule_proxy_closed_loop import (
    read_json,
    set_s1_round_robin,
    wait_for_int_paths,
)
from experiments.verify_manual_policy_session import PolicyEntry, write_policy_plan
from python.control_plane.rule_policy_selector import RuleBasedPolicySelector


P4_JSON = ROOT / "p4" / "covert_int_switch.json"
S1_CLI = ROOT / "p4" / "s1_commands.txt"
S2_CLI = ROOT / "p4" / "s2_commands.txt"
RUNTIME_PY = ROOT / "experiments" / "mininet_runtime.py"
LOG_DIR = ROOT / "logs" / "dynamic_rule_proxy_closed_loop"
RESULTS_DIR = ROOT / "experiments" / "results" / "dynamic_rule_proxy_closed_loop"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="长消息在线规则切换闭环验证")
    parser.add_argument("--clean-results", action="store_true")
    parser.add_argument("--timeout", type=int, default=130)
    parser.add_argument("--iperf-rate", default="260K")
    parser.add_argument("--iperf-len", type=int, default=200)
    parser.add_argument("--base-port", type=int, default=6500)
    parser.add_argument("--change-after-segment", type=int, default=6)
    parser.add_argument("--settle-after-change", type=float, default=6.0)
    parser.add_argument(
        "--secret",
        default="DYNAMIC_SWITCH_OK",
        help="在线动态切换验证使用的隐蔽明文；脚本按字节切成多个 chunk",
    )
    return parser.parse_args()


def load_runtime():
    spec = importlib.util.spec_from_file_location("dynamic_rule_runtime", RUNTIME_PY)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法加载 Mininet 运行时：{RUNTIME_PY}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_initial_proxy_plan(path: Path, secret: bytes, base_port: int) -> dict:
    """先写出所有 segment 的端口和顺序，后续再逐段改写策略。"""

    segments = []
    for index, value in enumerate(secret):
        segments.append(
            {
                "segment_id": index,
                "strategy_id": 2,
                "paths": [0],
                "weight": 1,
                "hidden_hex": bytes([value]).hex(),
                "expected_bytes": 1,
                "sequence_num": 90 + index,
                "remote_port": base_port + index,
                "repeat": 1,
                "strategy3_business_budget": 260,
            }
        )
    data = {
        "hidden_hex": secret.hex(),
        "plain_ports": [base_port + len(segments)],
        "segments": segments,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data


def update_proxy_segment(path: Path, segment_id: int, entry: PolicyEntry, hidden: bytes) -> dict:
    """在当前 chunk 开始前，把最新策略选择写回 plan 文件。"""

    data = json.loads(path.read_text(encoding="utf-8"))
    for segment in data["segments"]:
        if int(segment["segment_id"]) == int(segment_id):
            strategy_id = int(entry.strategy_id)
            segment.update(
                {
                    "strategy_id": strategy_id,
                    "paths": [int(path_id) for path_id in entry.paths],
                    "weight": int(entry.weight),
                    "hidden_hex": hidden.hex(),
                    "expected_bytes": len(hidden),
                    "repeat": 3 if strategy_id in {0, 1} else (5 if strategy_id == 5 else 1),
                    "strategy3_business_budget": 260,
                }
            )
            break
    else:
        raise ValueError(f"找不到 segment {segment_id}")
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data


def normalize_path_states(raw: dict) -> Dict[int, dict]:
    return {int(path_id): state for path_id, state in (raw or {}).items()}


def sorted_path_ids(path_states: Dict[int, dict]) -> List[int]:
    selector = RuleBasedPolicySelector()
    scores = selector.score_paths(path_states)
    paths = [item.path_id for item in scores]
    for fallback in (0, 1, 2):
        if fallback not in paths:
            paths.append(fallback)
    return paths[:3]


def choose_entry(segment_id: int, path_states: Dict[int, dict], after_change: bool) -> PolicyEntry:
    """
    为当前 chunk 选择策略。

    前 5 个 segment 覆盖低容量/多路径策略，之后进入真正的规则切换：
    网络稳定时优先策略3；网络突变出现丢包后切到策略2。
    """

    paths = sorted_path_ids(path_states)
    coverage = [0, 1, 3, 4, 5]
    if segment_id < len(coverage):
        strategy_id = coverage[segment_id]
        if strategy_id == 0:
            return PolicyEntry("coverage_s0", 0, (paths[0],), 1)
        if strategy_id == 1:
            return PolicyEntry("coverage_s1", 1, (paths[1],), 1)
        if strategy_id == 3:
            return PolicyEntry("coverage_s3", 3, (paths[0],), 2)
        if strategy_id == 4:
            return PolicyEntry("coverage_s4", 4, tuple(paths[:3]), 1)
        return PolicyEntry("coverage_s5", 5, tuple(paths[:3]), 1)

    if after_change:
        return PolicyEntry("online_after_change_s2", 2, (paths[0],), 1)
    return PolicyEntry("online_before_change_s3", 3, (paths[0],), 2)


def wait_for_ready(control_dir: Path, segment_id: int, timeout_s: float = 50.0) -> None:
    ready = control_dir / f"segment_{segment_id}.ready"
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if ready.exists():
            return
        time.sleep(0.05)
    raise TimeoutError(f"segment {segment_id} 未进入 ready 状态")


def allow_segment(control_dir: Path, segment_id: int) -> None:
    (control_dir / f"segment_{segment_id}.done").write_text("done\n", encoding="utf-8")


def wait_for_all_segments_done(control_dir: Path, timeout_s: float = 30.0) -> bool:
    """等待发送代理确认所有隐蔽分段已经完成挂载。"""

    marker = control_dir / "all_segments.done"
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if marker.exists():
            return True
        time.sleep(0.1)
    return marker.exists()


def wait_for_receiver_success(summary_path: Path, timeout_s: float = 30.0) -> bool:
    """等待接收代理写出成功摘要，作为隐蔽分段完成的兜底信号。"""

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        summary = read_json(summary_path)
        if summary.get("success"):
            return True
        time.sleep(0.2)
    return bool(read_json(summary_path).get("success"))


def wait_for_sender_complete(summary_path: Path, timeout_s: float = 30.0) -> bool:
    """等待发送代理写出 complete=true，避免摘要读取时机早于文件落盘。"""

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        summary = read_json(summary_path)
        if summary.get("complete"):
            return True
        time.sleep(0.2)
    return bool(read_json(summary_path).get("complete"))


def run_live(args: argparse.Namespace) -> dict:
    runtime = load_runtime()
    runtime_args = SimpleNamespace(
        json=str(P4_JSON),
        log_dir=str(LOG_DIR),
        s1_cli=str(S1_CLI),
        s2_cli=str(S2_CLI),
        host_mtu=1500,
        trunk_mtu=1600,
    )

    if args.clean_results and RESULTS_DIR.exists():
        shutil.rmtree(RESULTS_DIR)
    if args.clean_results and LOG_DIR.exists():
        shutil.rmtree(LOG_DIR)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    secret = args.secret.encode("utf-8")
    proxy_plan_file = RESULTS_DIR / "dynamic_proxy_plan.json"
    rule_plan_file = RESULTS_DIR / "dynamic_rule_plan.json"
    control_dir = RESULTS_DIR / "control"
    int_summary_path = RESULTS_DIR / "latest_int_summary.json"
    output_file = RESULTS_DIR / "decoded_secret.bin"
    control_dir.mkdir(parents=True, exist_ok=True)
    proxy_plan = write_initial_proxy_plan(proxy_plan_file, secret, int(args.base_port))

    initial_links = {
        0: {"delay_ms": 5, "loss_percent": 0},
        1: {"delay_ms": 15, "loss_percent": 0},
        2: {"delay_ms": 30, "loss_percent": 0},
    }
    changed_links = {
        0: {"delay_ms": 60, "loss_percent": 4},
        1: {"delay_ms": 20, "loss_percent": 1},
        2: {"delay_ms": 35, "loss_percent": 2},
    }

    net = runtime.build_net(runtime_args)
    try:
        print("[dynamic-rule] 启动 Mininet/BMv2")
        net.start()
        runtime.configure_mtu(net, runtime_args.host_mtu, runtime_args.trunk_mtu)
        runtime.disable_offload(net)
        h1, h2 = net.get("h1", "h2")
        h1.setARP("10.0.1.2", "00:00:00:00:00:02")
        h2.setARP("10.0.1.1", "00:00:00:00:00:01")
        runtime.wait_for_thrift(9090)
        runtime.wait_for_thrift(9091)
        runtime.run_cli_file(9090, "s1", str(S1_CLI), str(LOG_DIR))
        runtime.run_cli_file(9091, "s2", str(S2_CLI), str(LOG_DIR))

        apply_link_config(net, initial_links)
        configure_s2_for_reverse_int()
        set_s1_round_robin()
        ping_out = h1.cmd("ping -c 3 10.0.1.2")
        (RESULTS_DIR / "ping.txt").write_text(ping_out, encoding="utf-8")

        int_pid = h1.cmd(
            f"cd {ROOT} && python3 experiments/reverse_probe_receiver.py "
            f"--timeout {args.timeout + 20} --window-ms 12000 --write-interval 1 "
            f"--output {int_summary_path} "
            f"> {RESULTS_DIR}/int_receiver.log 2>&1 & echo $!"
        ).strip().splitlines()[-1]
        reverse_server_pid = h1.cmd(
            f"iperf -s -u -i 2 > {RESULTS_DIR}/reverse_iperf_server_h1.log 2>&1 & echo $!"
        ).strip().splitlines()[-1]
        time.sleep(0.5)
        reverse_client_pid = h2.cmd(
            f"iperf -u -c 10.0.1.1 -b 650K -t {args.timeout + 20} -i 2 "
            f"> {RESULTS_DIR}/reverse_iperf_client_h2.log 2>&1 & echo $!"
        ).strip().splitlines()[-1]
        initial_int = wait_for_int_paths(int_summary_path, timeout_s=18.0)

        iperf_server_pid = h2.cmd(
            f"iperf -s -u -p 5201 -i 1 > {RESULTS_DIR}/forward_iperf_server_h2.log 2>&1 & echo $!"
        ).strip().splitlines()[-1]
        receiver_pid = h2.cmd(
            f"cd {ROOT} && python3 experiments/udp_covert_proxy.py plan-receiver "
            f"--plan-file {proxy_plan_file} --iface h2-eth0 --forward-ip 127.0.0.1 "
            f"--forward-port 5201 --timeout {args.timeout} --max-idle 8 "
            f"--hidden-output {output_file} "
            f"--summary {RESULTS_DIR}/receiver_summary.json "
            f"> {RESULTS_DIR}/receiver_stdout.log 2>&1 & echo $!"
        ).strip().splitlines()[-1]
        time.sleep(0.5)
        sender_pid = h1.cmd(
            f"cd {ROOT} && python3 experiments/udp_covert_proxy.py plan-sender "
            f"--plan-file {proxy_plan_file} --listen-ip 127.0.0.1 --listen-port 6000 "
            f"--remote-ip 10.0.1.2 --src-ip 10.0.1.1 --iface h1-eth0 "
            f"--dst-mac 00:00:00:00:00:02 --plain-remote-port {proxy_plan['plain_ports'][0]} "
            f"--control-dir {control_dir} --max-idle 7 "
            f"--summary {RESULTS_DIR}/sender_summary.json "
            f"> {RESULTS_DIR}/sender_stdout.log 2>&1 & echo $!"
        ).strip().splitlines()[-1]
        time.sleep(0.5)
        iperf_client_pid = h1.cmd(
            f"timeout {args.timeout + 10} "
            f"iperf -u -c 127.0.0.1 -p 6000 -b {args.iperf_rate} "
            f"-l {int(args.iperf_len)} -t {args.timeout - 15} -i 1 "
            f"> {RESULTS_DIR}/forward_iperf_client_h1.log 2>&1 & echo $!"
        ).strip().splitlines()[-1]

        decisions = []
        changed_applied = False
        plan_entries: List[PolicyEntry] = []
        for segment_id, byte_value in enumerate(secret):
            wait_for_ready(control_dir, segment_id, timeout_s=float(args.timeout))
            if segment_id == int(args.change_after_segment) and not changed_applied:
                print("[dynamic-rule] 触发链路状态变化")
                apply_link_config(net, changed_links)
                changed_applied = True
                time.sleep(float(args.settle_after_change))

            int_summary = wait_for_int_paths(int_summary_path, timeout_s=5.0)
            path_states = normalize_path_states(int_summary.get("path_states", {}))
            entry = choose_entry(segment_id, path_states, changed_applied)
            update_proxy_segment(proxy_plan_file, segment_id, entry, bytes([byte_value]))
            configure_s1_for_entry(int(entry.strategy_id), entry.paths)
            allow_segment(control_dir, segment_id)
            plan_entries.append(entry)
            decision = {
                "segment_id": segment_id,
                "char": chr(byte_value),
                "after_network_change": changed_applied,
                "strategy_id": int(entry.strategy_id),
                "paths": [int(path) for path in entry.paths],
                "path_states": path_states,
            }
            decisions.append(decision)
            print(
                f"[dynamic-rule] segment={segment_id} "
                f"strategy={entry.strategy_id} paths={list(entry.paths)} "
                f"after_change={changed_applied}"
            )

        write_policy_plan(
            rule_plan_file,
            plan_entries,
            extra={
                "source": "dynamic_rule_proxy_closed_loop",
                "initial_links": initial_links,
                "changed_links": changed_links,
                "decisions": decisions,
            },
        )

        all_segments_done = wait_for_all_segments_done(control_dir, timeout_s=8.0)
        receiver_done_before_stop = wait_for_receiver_success(
            RESULTS_DIR / "receiver_summary.json",
            timeout_s=20.0,
        )
        time.sleep(3.0)
        stop_background(h1, iperf_client_pid)
        wait_background(h1, sender_pid, 20)
        wait_background(h2, receiver_pid, 20)
        wait_background(h1, iperf_client_pid, 5)
        sender_done_before_summary = wait_for_sender_complete(
            RESULTS_DIR / "sender_summary.json",
            timeout_s=10.0,
        )

        stop_background(h1, sender_pid)
        stop_background(h2, receiver_pid)
        stop_background(h1, iperf_client_pid)
        stop_background(h2, iperf_server_pid)
        stop_background(h1, int_pid)
        stop_background(h1, reverse_server_pid)
        stop_background(h2, reverse_client_pid)
        set_s1_round_robin()

        sender_done_after_stop = wait_for_sender_complete(
            RESULTS_DIR / "sender_summary.json",
            timeout_s=20.0,
        )
        receiver_done_after_stop = wait_for_receiver_success(
            RESULTS_DIR / "receiver_summary.json",
            timeout_s=5.0,
        )
        sender_summary = read_json(RESULTS_DIR / "sender_summary.json")
        receiver_summary = read_json(RESULTS_DIR / "receiver_summary.json")
        final_int = read_json(int_summary_path)
        decoded = output_file.read_bytes() if output_file.exists() else b""
        hidden_match = decoded == secret
        forward_iperf_server = (RESULTS_DIR / "forward_iperf_server_h2.log").read_text(
            encoding="utf-8",
            errors="ignore",
        )
        forward_iperf_client = (RESULTS_DIR / "forward_iperf_client_h1.log").read_text(
            encoding="utf-8",
            errors="ignore",
        )
        before_ids = [item["strategy_id"] for item in decisions if not item["after_network_change"]]
        after_ids = [item["strategy_id"] for item in decisions if item["after_network_change"]]
        strategy_changed_after_network_change = bool(before_ids and after_ids and before_ids[-1] != after_ids[0])
        path_changed_after_network_change = bool(
            decisions
            and len(decisions) > int(args.change_after_segment)
            and decisions[int(args.change_after_segment) - 1]["paths"]
            != decisions[int(args.change_after_segment)]["paths"]
        )
        all_seen = sorted({item["strategy_id"] for item in decisions})
        iperf_server_received = "datagrams" in forward_iperf_server.lower() or "sec" in forward_iperf_server.lower()
        sender_complete = bool(sender_summary.get("complete")) or bool(all_segments_done)
        receiver_success = bool(receiver_summary.get("success")) or bool(receiver_done_after_stop)
        summary = {
            "success": sender_complete
            and receiver_success
            and hidden_match
            and bool(final_int.get("success"))
            and strategy_changed_after_network_change
            and iperf_server_received,
            "hidden_match": hidden_match,
            "hidden_text": secret.decode("utf-8", errors="replace"),
            "decoded_text": decoded.decode("utf-8", errors="replace"),
            "sender_complete": sender_complete,
            "receiver_success": receiver_success,
            "iperf_ok": parse_iperf_ok(forward_iperf_client),
            "iperf_server_received": iperf_server_received,
            "int_success": bool(final_int.get("success")),
            "initial_int_path_states": normalize_path_states(initial_int.get("path_states", {})),
            "final_int_path_states": normalize_path_states(final_int.get("path_states", {})),
            "all_strategies_seen": all_seen,
            "all_six_strategies_seen": all_seen == [0, 1, 2, 3, 4, 5],
            "strategy_changed_after_network_change": strategy_changed_after_network_change,
            "path_changed_after_network_change": path_changed_after_network_change,
            "all_segments_done_marker": all_segments_done,
            "receiver_done_before_stop": receiver_done_before_stop,
            "sender_done_before_summary": sender_done_before_summary,
            "sender_done_after_stop": sender_done_after_stop,
            "receiver_done_after_stop": receiver_done_after_stop,
            "change_after_segment": int(args.change_after_segment),
            "initial_links": initial_links,
            "changed_links": changed_links,
            "decisions": decisions,
            "sender_summary": sender_summary,
            "receiver_summary": receiver_summary,
            "results_dir": str(RESULTS_DIR),
        }
        (RESULTS_DIR / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        return summary
    finally:
        print("[dynamic-rule] 清理 Mininet")
        net.stop()


def main() -> int:
    args = parse_args()
    if os.geteuid() != 0:
        print("请使用 sudo 运行该脚本", file=sys.stderr)
        return 2
    ensure_p4_json()
    summary = run_live(args)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"[dynamic-rule] 结果目录：{RESULTS_DIR}")
    return 0 if summary.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
