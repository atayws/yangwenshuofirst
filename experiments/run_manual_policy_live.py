#!/usr/bin/env python3
"""
手动策略计划 live 闭环验证。

该脚本用于中期演示前的自动验证：
1. 启动 h1-s1-(三链路)-s2-h2 拓扑；
2. h2->h1 运行 UDP iperf，持续触发 INT；
3. h1->h2 按全局 chunk 手动切换路径/策略发送隐蔽数据；
4. h2 统一接收分发并按 chunk_id 重组；
5. 输出业务、INT、隐蔽数据三部分结果。
"""

from __future__ import annotations

import argparse
import csv
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
P4_FILE = ROOT / "p4" / "covert_int_switch.p4"
RUNTIME_PY = ROOT / "experiments" / "mininet_runtime.py"
S1_CLI = ROOT / "p4" / "s1_commands.txt"
S2_CLI = ROOT / "p4" / "s2_commands.txt"
LOG_DIR = ROOT / "logs" / "manual_policy_live"
RESULTS_DIR = ROOT / "experiments" / "results" / "manual_policy_live"
INPUT_FILE = RESULTS_DIR / "input_secret.bin"

DEFAULT_SECRET = b"LIVE_MANUAL_POLICY_STAGE1_OK"


def load_runtime():
    spec = importlib.util.spec_from_file_location("manual_policy_runtime", RUNTIME_PY)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法加载 Mininet 运行时：{RUNTIME_PY}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ensure_p4_json() -> None:
    if P4_JSON.exists() and P4_JSON.read_text(encoding="utf-8", errors="ignore")[:1] == "{":
        return
    subprocess.check_call([
        "p4c",
        "--target",
        "bmv2",
        "--arch",
        "v1model",
        "--output",
        str(ROOT / "p4"),
        str(P4_FILE),
    ])


def run_cli(thrift_port: int, commands) -> None:
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


def configure_s1_for_entry(strategy_id: int, paths) -> None:
    """根据当前 chunk 的策略切换 s1 路径模式。"""
    if strategy_id == 5:
        run_cli(9090, [
            "register_write reg_path_mode 0 5",
            "register_write reg_int_enabled 0 0",
        ])
        return

    if strategy_id == 4:
        weights = [0, 0, 0]
        for path in paths:
            weights[int(path)] = 1
        if sum(1 for value in weights if value > 0) < 2:
            raise ValueError("策略4必须至少使用两条路径")
        run_cli(9090, [
            "register_write reg_path_mode 0 4",
            f"register_write reg_wrr_weight0 0 {weights[0]}",
            f"register_write reg_wrr_weight1 0 {weights[1]}",
            f"register_write reg_wrr_weight2 0 {weights[2]}",
            "register_write reg_wrr_counter 0 0",
            "register_write reg_int_enabled 0 0",
        ])
        return

    path = int(paths[0])
    run_cli(9090, [
        "register_write reg_path_mode 0 1",
        f"register_write reg_fixed_path 0 {path}",
        "register_write reg_int_enabled 0 0",
    ])


def configure_s2_for_reverse_int() -> None:
    """s2 负责反向业务流轮询和 INT 探测。"""
    run_cli(9091, [
        "register_write reg_path_mode 0 2",
        "register_write reg_rr_burst_size 0 12",
        "register_write reg_rr_counter 0 0",
        "register_write reg_rr_current_path 0 0",
        "register_write reg_int_probe_mode 0 0",
        "register_write reg_int_interval_us 0 500000",
        "register_write reg_next_sample_time 0 0",
        "register_write reg_int_enabled 0 1",
    ])


def stop_background(host, pid: str) -> None:
    if pid and pid.isdigit():
        host.cmd(f"kill {pid} >/dev/null 2>&1 || true")


def wait_background(host, pid: str, timeout_s: float) -> None:
    if not pid or not pid.isdigit():
        return
    host.cmd(
        "python3 - <<'PY'\n"
        "import os, time\n"
        f"pid = {int(pid)}\n"
        f"deadline = time.time() + {float(timeout_s)}\n"
        "while time.time() < deadline:\n"
        "    try:\n"
        "        os.kill(pid, 0)\n"
        "    except OSError:\n"
        "        break\n"
        "    time.sleep(0.2)\n"
        "PY"
    )


def build_manifest(
    secret: bytes,
    chunk_size: int,
    session_id: int,
    base_dport: int,
    plan_file: str | None = None,
) -> list[dict]:
    """通过发送端 dry-run 生成 chunk 发送清单。"""
    INPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    INPUT_FILE.write_bytes(secret)
    proc = subprocess.run(
        [
            "python3",
            "experiments/live_manual_policy_sender.py",
            "--input",
            str(INPUT_FILE),
            "--dst-ip",
            "10.0.2.2",
            "--src-ip",
            "10.0.1.2",
            "--iface",
            "h1-eth0",
            "--base-dport",
            str(base_dport),
            "--chunk-size",
            str(chunk_size),
            "--session-id",
            str(session_id),
            "--dry-run",
        ]
        + (["--plan-file", str(plan_file)] if plan_file else []),
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    summary = json.loads(proc.stdout)
    return summary["chunks"]


def write_manifest_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["chunk_id", "strategy_id", "paths", "dport", "sequence_num", "packets", "encoded_bytes"]
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            clean = dict(row)
            clean["paths"] = ",".join(str(item) for item in row["paths"])
            writer.writerow(clean)


def parse_iperf_ok(text: str) -> bool:
    lower = text.lower()
    return (
        "connect failed" not in lower
        and "failed" not in lower
        and ("datagrams" in lower or "sec" in lower)
    )


def parse_link_config(raw_items: list[str]) -> dict[int, dict]:
    """解析 path:delay_ms:loss_percent 形式的链路配置。"""

    config: dict[int, dict] = {}
    for raw in raw_items:
        parts = str(raw).split(":")
        if len(parts) != 3:
            raise ValueError("--link 必须使用 path:delay_ms:loss_percent，例如 1:20:5")
        path_id = int(parts[0])
        if path_id in {1, 2, 3}:
            path_id -= 1
        if path_id not in {0, 1, 2}:
            raise ValueError("path 只能是 0/1/2 或 1/2/3")
        delay_ms = float(parts[1])
        loss_percent = float(parts[2])
        if delay_ms < 0 or loss_percent < 0 or loss_percent > 100:
            raise ValueError("delay 必须 >=0，loss 必须在 0~100 之间")
        config[path_id] = {"delay_ms": delay_ms, "loss_percent": loss_percent}
    return config


def apply_link_config(net, link_config: dict[int, dict]) -> None:
    """用 tc netem 设置三条交换机间链路的时延和丢包。"""

    for path_id, item in sorted(link_config.items()):
        port = int(path_id) + 2
        delay_ms = float(item["delay_ms"])
        loss_percent = float(item["loss_percent"])
        for node_name in ("s1", "s2"):
            node = net.get(node_name)
            intf = f"{node_name}-eth{port}"
            node.cmd(
                f"tc qdisc replace dev {intf} root netem "
                f"delay {delay_ms}ms loss {loss_percent}% >/dev/null 2>&1"
            )


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
    net = runtime.build_net(runtime_args)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if args.clean_results and RESULTS_DIR.exists():
        shutil.rmtree(RESULTS_DIR)
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    INPUT_FILE.write_bytes(DEFAULT_SECRET)
    manifest = build_manifest(
        DEFAULT_SECRET,
        args.chunk_size,
        args.session_id,
        args.base_dport,
        args.plan_file,
    )
    write_manifest_csv(RESULTS_DIR / "send_manifest.csv", manifest)

    result = {}
    try:
        print("[manual-live] 启动 Mininet/BMv2")
        net.start()
        runtime.configure_mtu(net, runtime_args.host_mtu, runtime_args.trunk_mtu)
        runtime.disable_offload(net)
        h1, h2, _s1, _s2 = net.get("h1", "h2", "s1", "s2")
        runtime.configure_host_routing(h1, h2)
        runtime.wait_for_thrift(9090)
        runtime.wait_for_thrift(9091)
        runtime.run_cli_file(9090, "s1", str(S1_CLI), str(LOG_DIR))
        runtime.run_cli_file(9091, "s2", str(S2_CLI), str(LOG_DIR))
        link_config = parse_link_config(args.link)
        if link_config:
            apply_link_config(net, link_config)
        configure_s2_for_reverse_int()

        ping_out = h1.cmd("ping -c 2 10.0.2.2")
        (RESULTS_DIR / "ping.txt").write_text(ping_out, encoding="utf-8")

        expected_packets = sum(int(row["packets"]) for row in manifest)
        int_output = RESULTS_DIR / "int_summary.json"
        receive_timeout = max(args.timeout, int(expected_packets * 0.04) + 30)
        int_pid = h1.cmd(
            f"cd {ROOT} && python3 experiments/reverse_probe_receiver.py "
            f"--timeout {receive_timeout} --window-ms {receive_timeout * 1000} "
            f"--output {int_output} > {RESULTS_DIR}/int_receiver.log 2>&1 & echo $!"
        ).strip().splitlines()[-1]

        iperf_server_pid = h1.cmd(
            f"iperf -s -u -i 1 > {RESULTS_DIR}/reverse_iperf_server_h1.log 2>&1 & echo $!"
        ).strip().splitlines()[-1]
        time.sleep(0.5)
        iperf_client_pid = h2.cmd(
            f"iperf -u -c 10.0.1.2 -b 700K -t {max(6, receive_timeout - 3)} -i 1 "
            f"> {RESULTS_DIR}/reverse_iperf_client_h2.log 2>&1 & echo $!"
        ).strip().splitlines()[-1]

        receiver_pid = h2.cmd(
            f"cd {ROOT} && python3 experiments/live_manual_policy_receiver.py "
            f"--iface h2-eth0 --base-dport {args.base_dport} --chunk-count {len(manifest)} "
            f"--chunk-size {args.chunk_size} --session-id {args.session_id} "
            f"{('--plan-file ' + str(args.plan_file)) if args.plan_file else ''} "
            f"--secret-bytes {len(DEFAULT_SECRET)} --expected-packets {expected_packets} "
            f"--timeout {receive_timeout} --output {RESULTS_DIR}/decoded_secret.bin "
            f"--summary {RESULTS_DIR}/receiver_summary.json "
            f"> {RESULTS_DIR}/receiver_stdout.log 2>&1 & echo $!"
        ).strip().splitlines()[-1]
        time.sleep(1.0)

        for row in manifest:
            configure_s1_for_entry(int(row["strategy_id"]), row["paths"])
            chunk_id = int(row["chunk_id"])
            print(f"[manual-live] 发送 chunk={chunk_id} strategy={row['strategy_id']} paths={row['paths']}")
            h1.cmd(
                f"cd {ROOT} && python3 experiments/live_manual_policy_sender.py "
                f"--input {INPUT_FILE} --dst-ip 10.0.2.2 --src-ip 10.0.1.2 "
                f"--iface h1-eth0 --dst-mac 00:00:00:00:01:01 --base-dport {args.base_dport} "
                f"--chunk-size {args.chunk_size} --session-id {args.session_id} "
                f"{('--plan-file ' + str(args.plan_file)) if args.plan_file else ''} "
                f"--chunk-id {chunk_id} --pace-ms {args.pace_ms} --send-mode scapy-l2 "
                f"--summary {RESULTS_DIR}/sender_chunk_{chunk_id}.json "
                f"> {RESULTS_DIR}/sender_chunk_{chunk_id}.log 2>&1"
            )
            time.sleep(args.chunk_gap_ms / 1000.0)

        wait_background(h2, receiver_pid, receive_timeout + 5)
        wait_background(h2, iperf_client_pid, receive_timeout + 5)
        wait_background(h1, int_pid, receive_timeout + 5)
        stop_background(h2, receiver_pid)
        stop_background(h1, int_pid)
        stop_background(h1, iperf_server_pid)

        receiver_summary_path = RESULTS_DIR / "receiver_summary.json"
        receiver_summary = json.loads(receiver_summary_path.read_text(encoding="utf-8")) if receiver_summary_path.exists() else {"success": False}
        decoded_path = RESULTS_DIR / "decoded_secret.bin"
        decoded = decoded_path.read_bytes() if decoded_path.exists() else b""
        hidden_match = decoded == DEFAULT_SECRET
        iperf_text = (RESULTS_DIR / "reverse_iperf_client_h2.log").read_text(encoding="utf-8", errors="ignore")
        int_summary = json.loads(int_output.read_text(encoding="utf-8")) if int_output.exists() else {"success": False}
        result = {
            "success": bool(receiver_summary.get("success")) and hidden_match and parse_iperf_ok(iperf_text) and bool(int_summary.get("success")),
            "hidden_match": hidden_match,
            "secret_bytes": len(DEFAULT_SECRET),
            "decoded_bytes": len(decoded),
            "expected_packets": expected_packets,
            "receiver_success": bool(receiver_summary.get("success")),
            "receiver_summary": receiver_summary,
            "iperf_ok": parse_iperf_ok(iperf_text),
            "iperf_client_tail": "\n".join(iperf_text.strip().splitlines()[-8:]),
            "int_success": bool(int_summary.get("success")),
            "int_parsed_reports": int_summary.get("parsed_int_reports", 0),
            "int_metric_sample_counts": int_summary.get("metric_sample_counts", {}),
            "int_path_states": int_summary.get("path_states", {}),
            "link_config": link_config,
            "manifest": manifest,
        }
        (RESULTS_DIR / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        return result
    finally:
        print("[manual-live] 清理 Mininet")
        net.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description="手动策略计划 live 闭环验证")
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--base-dport", type=int, default=51200)
    parser.add_argument("--chunk-size", type=int, default=7)
    parser.add_argument("--session-id", type=int, default=8)
    parser.add_argument("--plan-file", default=None)
    parser.add_argument("--pace-ms", type=float, default=1.0)
    parser.add_argument("--chunk-gap-ms", type=float, default=100.0)
    parser.add_argument(
        "--link",
        action="append",
        default=[],
        help="设置链路状态，格式 path:delay_ms:loss_percent，可重复，例如 --link 1:20:5",
    )
    parser.add_argument("--clean-results", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("请使用 sudo 运行该脚本。", file=sys.stderr)
        return 2
    ensure_p4_json()
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    result = run_live(args)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"[manual-live] 结果目录：{RESULTS_DIR}")
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
