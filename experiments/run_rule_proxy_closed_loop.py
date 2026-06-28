#!/usr/bin/env python3
"""
规则策略真实业务流闭环验证。

这个脚本用于中期阶段验证除 PPO 之外的完整链路：
1. 启动 h1-s1-(三链路)-s2-h2 P4/Mininet 拓扑；
2. h2->h1 持续 UDP iperf 触发 inline INT；
3. 按场景动态修改三条链路 delay/loss；
4. h1 读取 INT 状态，用规则选择器生成策略计划；
5. h1 的 UDP iperf 业务流进入 plan-sender 代理，隐蔽数据挂载在真实业务包上；
6. h2 的 plan-receiver 自动识别策略0-5，解码后继续把业务 payload 转发给 iperf server；
7. 输出隐蔽数据正确性、业务流是否不中断、INT 是否正常、策略是否随网络状态变化。
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace
from typing import Iterable, List

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.run_manual_policy_live import (
    apply_link_config,
    configure_s1_for_entry,
    configure_s2_for_reverse_int,
    ensure_p4_json,
    parse_iperf_ok,
    run_cli,
    stop_background,
    wait_background,
)
from experiments.verify_manual_policy_session import PolicyEntry, write_policy_plan
from python.control_plane.rule_policy_selector import RuleBasedPolicySelector


P4_JSON = ROOT / "p4" / "covert_int_switch.json"
S1_CLI = ROOT / "p4" / "s1_commands.txt"
S2_CLI = ROOT / "p4" / "s2_commands.txt"
RUNTIME_PY = ROOT / "experiments" / "mininet_runtime.py"
LOG_DIR = ROOT / "logs" / "rule_proxy_closed_loop"
RESULTS_DIR = ROOT / "experiments" / "results" / "rule_proxy_closed_loop"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="规则策略真实业务流闭环验证")
    parser.add_argument("--clean-results", action="store_true")
    parser.add_argument("--timeout", type=int, default=95)
    parser.add_argument("--iperf-rate", default="220K")
    parser.add_argument("--iperf-len", type=int, default=200)
    parser.add_argument("--chunk-size", type=int, default=4)
    parser.add_argument(
        "--secret",
        default="RULE_PROXY_CLOSED_LOOP_OK_0123456789",
        help="要验证的隐蔽明文",
    )
    return parser.parse_args()


def load_runtime():
    spec = importlib.util.spec_from_file_location("rule_proxy_runtime", RUNTIME_PY)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法加载 Mininet 运行时：{RUNTIME_PY}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def set_s1_round_robin() -> None:
    """没有隐蔽数据时，h1->h2 普通业务流按三路径轮询。"""

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


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def wait_for_int_paths(path: Path, timeout_s: float = 20.0) -> dict:
    """等待 h1 解析出三条路径的 INT 状态。"""

    deadline = time.time() + timeout_s
    latest = {}
    while time.time() < deadline:
        latest = read_json(path)
        states = latest.get("path_states", {}) or {}
        if len(states) >= 3:
            return latest
        time.sleep(0.5)
    return latest


def normalize_path_states(raw: dict) -> dict[int, dict]:
    return {int(path_id): state for path_id, state in (raw or {}).items()}


def scenario_plan(path_states: dict[int, dict]) -> List[PolicyEntry]:
    """根据 INT 状态生成演示计划，并确保六个策略都能在闭环里出现。"""

    selector = RuleBasedPolicySelector()
    base = selector.select(path_states)
    paths = sorted(path_states.keys()) or [0, 1, 2]
    while len(paths) < 3:
        paths.append(len(paths))

    plan: List[PolicyEntry] = [
        PolicyEntry("timing_probe_s0", 0, (paths[0],), 1),
        PolicyEntry("timing_probe_s1", 1, (paths[1],), 1),
    ]
    seen = {0, 1}
    for entry in base:
        if entry.strategy_id == 4 and len(entry.paths) < 2:
            continue
        if entry.strategy_id not in seen:
            plan.append(entry)
            seen.add(entry.strategy_id)
    if 2 not in seen:
        plan.append(PolicyEntry("fallback_reliable_s2", 2, (paths[0],), 1))
    if 3 not in seen:
        plan.append(PolicyEntry("fallback_length_s3", 3, (paths[1],), 1))
    if 4 not in seen:
        plan.append(PolicyEntry("fallback_fountain_s4", 4, tuple(paths[:2]), 1))
    if 5 not in seen:
        plan.append(PolicyEntry("fallback_path_sequence_s5", 5, tuple(paths[:3]), 1))
    return plan


def split_secret_for_plan(secret: bytes, plan: List[PolicyEntry], chunk_size: int) -> list[bytes]:
    """按策略能力切分隐蔽数据，低容量策略只承担短段。"""

    chunks = [b"" for _ in plan]
    offset = 0
    capacities = {0: 1, 1: 1, 2: max(8, chunk_size * 6), 3: max(6, chunk_size * 3), 4: 4, 5: 1}

    for index, entry in enumerate(plan):
        if offset >= len(secret):
            break
        capacity = capacities.get(int(entry.strategy_id), chunk_size)
        take = min(capacity, len(secret) - offset)
        chunks[index] = secret[offset : offset + take]
        offset += take

    if offset < len(secret):
        # 剩余数据优先追加给可靠 IP-ID 和包长策略，避免策略5承担过长消息导致验证耗时过大。
        preferred = [
            index for index, entry in enumerate(plan)
            if int(entry.strategy_id) in {2, 3}
        ] or [
            index for index, entry in enumerate(plan)
            if int(entry.strategy_id) not in {0, 1, 5}
        ] or [len(plan) - 1]
        target = preferred[0]
        chunks[target] += secret[offset:]

    return chunks


def split_secret_for_ordered_plan(secret: bytes, plan: List[PolicyEntry], chunk_size: int) -> tuple[list[bytes], List[PolicyEntry]]:
    """按全局顺序切分隐蔽数据，剩余数据只追加到计划末尾，避免接收端重组错位。"""

    chunks: list[bytes] = []
    expanded_plan: List[PolicyEntry] = []
    offset = 0
    capacities = {0: 1, 1: 1, 2: max(8, chunk_size * 6), 3: max(6, chunk_size * 3), 4: 4, 5: 1}

    for entry in plan:
        capacity = capacities.get(int(entry.strategy_id), chunk_size)
        take = min(capacity, len(secret) - offset)
        chunks.append(secret[offset : offset + take])
        expanded_plan.append(entry)
        offset += take

    if offset < len(secret):
        tail_paths = next(
            (tuple(entry.paths) for entry in plan if int(entry.strategy_id) == 2 and entry.paths),
            next((tuple(entry.paths) for entry in plan if entry.paths), (0,)),
        )
        tail_capacity = capacities[2]
        tail_index = 0
        while offset < len(secret):
            take = min(tail_capacity, len(secret) - offset)
            expanded_plan.append(
                PolicyEntry(
                    name=f"tail_reliable_s2_{tail_index}",
                    strategy_id=2,
                    paths=(int(tail_paths[0]),),
                    weight=1,
                )
            )
            chunks.append(secret[offset : offset + take])
            offset += take
            tail_index += 1

    return chunks, expanded_plan


def write_proxy_plan(path: Path, secret: bytes, plan: List[PolicyEntry], base_port: int, chunk_size: int) -> dict:
    """写出 plan-sender/plan-receiver 共用的代理计划。"""

    chunks, expanded_plan = split_secret_for_ordered_plan(secret, plan, chunk_size)
    segments = []
    for index, (entry, chunk) in enumerate(zip(expanded_plan, chunks)):
        segments.append(
            {
                "segment_id": index,
                "strategy_id": int(entry.strategy_id),
                "paths": [int(path_id) for path_id in entry.paths],
                "weight": int(entry.weight),
                "hidden_hex": chunk.hex(),
                "expected_bytes": len(chunk),
                "sequence_num": 30 + index,
                "remote_port": base_port + index,
                "repeat": 3 if entry.strategy_id in {0, 1} else (5 if entry.strategy_id == 5 else 1),
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


def wait_for_segment_ready(control_dir: Path, segment_id: int, timeout_s: float = 40.0) -> None:
    """等待 plan-sender 准备发送某个分段。"""

    ready = control_dir / f"segment_{segment_id}.ready"
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if ready.exists():
            return
        time.sleep(0.05)
    raise TimeoutError(f"segment {segment_id} 未进入 ready 状态")


def allow_segment(control_dir: Path, segment_id: int) -> None:
    """通知 plan-sender 当前分段的路径模式已经配置完成。"""

    (control_dir / f"segment_{segment_id}.done").write_text("done\n", encoding="utf-8")


def run_one_scenario(h1, h2, net, args: argparse.Namespace, scenario: dict, index: int) -> dict:
    """运行一个链路状态场景。"""

    case_dir = RESULTS_DIR / f"scenario_{index}_{scenario['name']}"
    case_dir.mkdir(parents=True, exist_ok=True)
    apply_link_config(net, scenario["links"])
    configure_s2_for_reverse_int()
    set_s1_round_robin()
    time.sleep(float(scenario.get("settle_s", 4.0)))

    int_summary_path = case_dir / "int_summary.json"
    int_pid = h1.cmd(
        f"cd {ROOT} && python3 experiments/reverse_probe_receiver.py "
        f"--timeout 18 --window-ms 18000 --write-interval 1 "
        f"--output {int_summary_path} "
        f"> {case_dir}/int_receiver.log 2>&1 & echo $!"
    ).strip().splitlines()[-1]
    int_iperf_server_pid = h1.cmd(
        f"iperf -s -u -i 1 > {case_dir}/int_iperf_server_h1.log 2>&1 & echo $!"
    ).strip().splitlines()[-1]
    time.sleep(0.4)
    int_iperf_client_pid = h2.cmd(
        f"iperf -u -c 10.0.1.1 -b 500K -t 16 -i 1 "
        f"> {case_dir}/int_iperf_client_h2.log 2>&1 & echo $!"
    ).strip().splitlines()[-1]
    wait_background(h1, int_pid, 22)
    wait_background(h2, int_iperf_client_pid, 22)
    stop_background(h1, int_pid)
    stop_background(h2, int_iperf_client_pid)
    stop_background(h1, int_iperf_server_pid)
    int_summary = wait_for_int_paths(int_summary_path, 1.0)
    path_states = normalize_path_states(int_summary.get("path_states", {}))

    plan = scenario_plan(path_states)
    plan_file = case_dir / "proxy_plan.json"
    secret = f"{args.secret}|{scenario['name']}".encode("utf-8")
    proxy_plan = write_proxy_plan(plan_file, secret, plan, 6300 + index * 20, args.chunk_size)
    write_policy_plan(
        case_dir / "rule_plan.json",
        plan,
        extra={"input_path_states": path_states, "source": "rule_proxy_closed_loop"},
    )
    control_dir = case_dir / "control"
    control_dir.mkdir(parents=True, exist_ok=True)

    iperf_server_pid = h2.cmd(
        f"iperf -s -u -p 5201 -i 1 > {case_dir}/iperf_server_h2.log 2>&1 & echo $!"
    ).strip().splitlines()[-1]
    receiver_pid = h2.cmd(
        f"cd {ROOT} && python3 experiments/udp_covert_proxy.py plan-receiver "
        f"--plan-file {plan_file} --iface h2-eth0 --forward-ip 127.0.0.1 "
        f"--forward-port 5201 --timeout {args.timeout} --max-idle 6 "
        f"--hidden-output {case_dir}/decoded_secret.bin "
        f"--summary {case_dir}/receiver_summary.json "
        f"> {case_dir}/receiver_stdout.log 2>&1 & echo $!"
    ).strip().splitlines()[-1]
    time.sleep(0.5)
    sender_pid = h1.cmd(
        f"cd {ROOT} && python3 experiments/udp_covert_proxy.py plan-sender "
        f"--plan-file {plan_file} --listen-ip 127.0.0.1 --listen-port 6000 "
        f"--remote-ip 10.0.1.2 --src-ip 10.0.1.1 --iface h1-eth0 "
        f"--dst-mac 00:00:00:00:00:02 --plain-remote-port {proxy_plan['plain_ports'][0]} "
        f"--control-dir {control_dir} --max-idle 5 "
        f"--summary {case_dir}/sender_summary.json "
        f"> {case_dir}/sender_stdout.log 2>&1 & echo $!"
    ).strip().splitlines()[-1]
    time.sleep(0.5)
    iperf_client_pid = h1.cmd(
        f"timeout {args.timeout + 10} "
        f"iperf -u -c 127.0.0.1 -p 6000 -b {args.iperf_rate} "
        f"-l {args.iperf_len} -t {max(12, args.timeout - 20)} -i 1 "
        f"> {case_dir}/iperf_client_h1.log 2>&1 & echo $!"
    ).strip().splitlines()[-1]

    for segment in proxy_plan["segments"]:
        segment_id = int(segment["segment_id"])
        wait_for_segment_ready(control_dir, segment_id)
        configure_s1_for_entry(int(segment["strategy_id"]), segment["paths"])
        allow_segment(control_dir, segment_id)

    wait_background(h1, sender_pid, args.timeout + 15)
    wait_background(h2, receiver_pid, args.timeout + 15)
    wait_background(h1, iperf_client_pid, args.timeout + 15)
    stop_background(h1, sender_pid)
    stop_background(h2, receiver_pid)
    stop_background(h1, iperf_client_pid)
    time.sleep(0.5)
    stop_background(h2, iperf_server_pid)
    set_s1_round_robin()

    sender_summary = read_json(case_dir / "sender_summary.json")
    receiver_summary = read_json(case_dir / "receiver_summary.json")
    decoded = (case_dir / "decoded_secret.bin").read_bytes() if (case_dir / "decoded_secret.bin").exists() else b""
    iperf_client = (case_dir / "iperf_client_h1.log").read_text(encoding="utf-8", errors="ignore")
    iperf_server = (case_dir / "iperf_server_h2.log").read_text(encoding="utf-8", errors="ignore")
    hidden_match = decoded == secret
    iperf_server_received = "datagrams" in iperf_server.lower() or "sec" in iperf_server.lower()
    strategy_ids = [int(segment["strategy_id"]) for segment in proxy_plan["segments"]]
    result = {
        "name": scenario["name"],
        "success": bool(sender_summary.get("complete"))
        and bool(receiver_summary.get("success"))
        and hidden_match
        and iperf_server_received
        and bool(int_summary.get("success")),
        "hidden_match": hidden_match,
        "sender_complete": bool(sender_summary.get("complete")),
        "receiver_success": bool(receiver_summary.get("success")),
        "iperf_ok": parse_iperf_ok(iperf_client),
        "iperf_server_received": iperf_server_received,
        "int_success": bool(int_summary.get("success")),
        "int_path_states": path_states,
        "strategy_ids": strategy_ids,
        "strategy_changed": len(set(strategy_ids)) > 1,
        "link_config": scenario["links"],
        "plan": [entry.to_dict() for entry in plan],
        "proxy_plan": proxy_plan,
        "sender_summary": sender_summary,
        "receiver_summary": receiver_summary,
        "case_dir": str(case_dir),
    }
    (case_dir / "case_summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


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
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    scenarios = [
        {
            "name": "baseline",
            "links": {
                0: {"delay_ms": 5, "loss_percent": 0},
                1: {"delay_ms": 15, "loss_percent": 0},
                2: {"delay_ms": 30, "loss_percent": 0},
            },
        },
        {
            "name": "path0_degraded",
            "links": {
                0: {"delay_ms": 55, "loss_percent": 8},
                1: {"delay_ms": 10, "loss_percent": 0},
                2: {"delay_ms": 25, "loss_percent": 2},
            },
        },
    ]

    net = runtime.build_net(runtime_args)
    try:
        print("[rule-proxy] 启动 Mininet/BMv2")
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

        ping_out = h1.cmd("ping -c 3 10.0.1.2")
        (RESULTS_DIR / "ping.txt").write_text(ping_out, encoding="utf-8")

        results = []
        for index, scenario in enumerate(scenarios):
            print(f"[rule-proxy] 场景 {scenario['name']}")
            results.append(run_one_scenario(h1, h2, net, args, scenario, index))

        all_strategies = sorted({sid for item in results for sid in item.get("strategy_ids", [])})
        plan_signatures = [
            json.dumps(item.get("proxy_plan", {}).get("segments", []), sort_keys=True)
            for item in results
        ]
        summary = {
            "success": all(item.get("success") for item in results),
            "scenario_count": len(results),
            "all_strategies_seen": all_strategies,
            "all_six_strategies_seen": all_strategies == [0, 1, 2, 3, 4, 5],
            "strategy_plan_changed_between_scenarios": len(set(plan_signatures)) > 1,
            "cases": results,
        }
        (RESULTS_DIR / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        return summary
    finally:
        print("[rule-proxy] 清理 Mininet")
        net.stop()


def main() -> int:
    args = parse_args()
    if os.geteuid() != 0:
        print("请使用 sudo 运行该脚本。", file=sys.stderr)
        return 2
    ensure_p4_json()
    summary = run_live(args)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"[rule-proxy] 结果目录：{RESULTS_DIR}")
    return 0 if summary.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
