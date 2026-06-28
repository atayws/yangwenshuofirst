#!/usr/bin/env python3
"""
验证六个隐蔽策略是否真正挂载在 UDP 业务流上。

验证逻辑：
1. 启动 h1-s1-(三链路)-s2-h2 拓扑；
2. h1 上用 iperf -u 向本机代理发真实业务流；
3. 发送端代理把策略0~5的隐蔽字段叠加到这些业务包上，再发往 h2；
4. h2 代理抓包、解码隐蔽数据、剥离代理层字段，并把原始 iperf payload 交给 h2 iperf server；
5. 输出每个策略的业务流转发结果和隐蔽数据解码结果。

这个脚本只验证“真实 UDP 业务流挂载”。TCP 透明挂载需要 TUN/iptables 或 NFQUEUE，
中期阶段先用 UDP iperf 作为业务流模拟。
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
P4_JSON = ROOT / "p4" / "covert_int_switch.json"
P4_FILE = ROOT / "p4" / "covert_int_switch.p4"
RUNTIME_PY = ROOT / "experiments" / "mininet_runtime.py"
S1_CLI = ROOT / "p4" / "s1_commands.txt"
S2_CLI = ROOT / "p4" / "s2_commands.txt"
LOG_DIR = ROOT / "logs" / "udp_proxy_real_flow"
RESULTS_DIR = ROOT / "experiments" / "results" / "udp_proxy_real_flow"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="验证六策略真实 UDP 业务流挂载")
    parser.add_argument("--strategies", default="0,1,2,3,4,5", help="要验证的策略编号，例如 0,2,4")
    parser.add_argument("--iperf-rate", default="350K")
    parser.add_argument("--iperf-len", type=int, default=200)
    parser.add_argument("--iperf-time", type=int, default=12)
    parser.add_argument("--case-timeout", type=int, default=25)
    parser.add_argument("--clean-results", action="store_true")
    return parser.parse_args()


def load_runtime():
    spec = importlib.util.spec_from_file_location("udp_proxy_runtime", RUNTIME_PY)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法加载 Mininet 运行时：{RUNTIME_PY}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ensure_p4_json() -> None:
    """如果 P4 JSON 不存在或不是 JSON，就重新编译。"""

    if P4_JSON.exists() and P4_JSON.read_text(encoding="utf-8", errors="ignore")[:1] == "{":
        return
    subprocess.check_call(
        [
            "p4c",
            "--target",
            "bmv2",
            "--arch",
            "v1model",
            "--output",
            str(ROOT / "p4"),
            str(P4_FILE),
        ]
    )


def run_cli(thrift_port: int, commands: Iterable[str]) -> None:
    """向 simple_switch_CLI 下发运行期命令。"""

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


def configure_s1_for_strategy(strategy_id: int) -> None:
    """按策略特点配置 h1->h2 方向路径模式。"""

    if strategy_id == 4:
        run_cli(
            9090,
            [
                "register_write reg_path_mode 0 4",
                "register_write reg_wrr_weight0 0 1",
                "register_write reg_wrr_weight1 0 1",
                "register_write reg_wrr_weight2 0 1",
                "register_write reg_wrr_counter 0 0",
                "register_write reg_int_enabled 0 0",
            ],
        )
        return

    if strategy_id == 5:
        run_cli(
            9090,
            [
                "register_write reg_path_mode 0 5",
                "register_write reg_int_enabled 0 0",
            ],
        )
        return

    run_cli(
        9090,
        [
            "register_write reg_path_mode 0 1",
            "register_write reg_fixed_path 0 0",
            "register_write reg_int_enabled 0 0",
        ],
    )


def configure_s2_reverse_int() -> None:
    """保持反向 h2->h1 业务流可触发 inline INT，不干扰当前 h1->h2 策略验证。"""

    run_cli(
        9091,
        [
            "register_write reg_path_mode 0 2",
            "register_write reg_rr_burst_size 0 12",
            "register_write reg_rr_counter 0 0",
            "register_write reg_rr_current_path 0 0",
            "register_write reg_int_interval_us 0 10000",
            "register_write reg_next_sample_time 0 0",
            "register_write reg_int_enabled 0 1",
        ],
    )


def wait_background(host, pid: str, timeout_s: float) -> None:
    """等待 Mininet 主机中的后台进程退出。"""

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


def stop_background(host, pid: str) -> None:
    """停止 Mininet 主机中的后台进程。"""

    if pid and pid.isdigit():
        host.cmd(f"kill {pid} >/dev/null 2>&1 || true")


def parse_strategy_list(raw: str) -> List[int]:
    values = []
    for item in str(raw).split(","):
        item = item.strip()
        if not item:
            continue
        strategy_id = int(item)
        if strategy_id < 0 or strategy_id > 5:
            raise ValueError("策略编号只能是 0~5")
        values.append(strategy_id)
    return values or [0, 1, 2, 3, 4, 5]


def iperf_server_received(log_text: str) -> bool:
    """粗略判断 h2 iperf server 是否收到业务包。"""

    lower = log_text.lower()
    if "server listening" in lower and ("datagrams" in lower or "sec" in lower):
        return True
    return "0.0- " in lower or "0.0-" in lower


def run_case(h1, h2, args: argparse.Namespace, strategy_id: int) -> dict:
    """运行一个策略的真实业务流挂载验证。"""

    case_dir = RESULTS_DIR / f"strategy_{strategy_id}"
    case_dir.mkdir(parents=True, exist_ok=True)
    hidden = f"S{strategy_id}-OK".encode("ascii")
    if strategy_id == 0:
        # 时序策略容量低、对丢包敏感，中期验证先用短消息证明真实业务流挂载机制。
        hidden = b"A"
    elif strategy_id == 1:
        hidden = b"B"
    input_file = case_dir / "hidden_input.bin"
    hidden_output = case_dir / "hidden_output.bin"
    sender_summary = case_dir / "sender_summary.json"
    receiver_summary = case_dir / "receiver_summary.json"
    input_file.write_bytes(hidden)

    configure_s1_for_strategy(strategy_id)
    h1.cmd("pkill -f 'udp_covert_proxy.py sender' >/dev/null 2>&1 || true")
    h2.cmd("pkill -f 'udp_covert_proxy.py receiver' >/dev/null 2>&1 || true")
    h1.cmd("pkill -f 'iperf.*6000' >/dev/null 2>&1 || true")
    h2.cmd("pkill -f 'iperf.*5201' >/dev/null 2>&1 || true")

    server_pid = h2.cmd(
        f"iperf -s -u -p 5201 -i 1 > {case_dir}/iperf_server_h2.log 2>&1 & echo $!"
    ).strip().splitlines()[-1]
    time.sleep(0.4)
    rate = "90K" if strategy_id in {0, 1} else args.iperf_rate
    iperf_time = max(args.iperf_time, 8) if strategy_id in {0, 1} else args.iperf_time
    receiver_pid = h2.cmd(
        f"cd {ROOT} && python3 experiments/udp_covert_proxy.py receiver "
        f"--strategy {strategy_id} --receive-mode sniff --iface h2-eth0 "
        f"--listen-ip 0.0.0.0 --listen-port 6100 "
        f"--forward-ip 127.0.0.1 --forward-port 5201 "
        f"--expected-bytes {len(hidden)} --seq-num 1 "
        f"--timeout {args.case_timeout} --max-idle 4 "
        f"--business-payload-len 32 --strategy3-business-budget {args.iperf_len + 32} "
        f"--timing-repeat {5 if strategy_id == 1 else 4} "
        f"--path-sequence-repeat 3 "
        f"--hidden-output {hidden_output} --summary {receiver_summary} "
        f"> {case_dir}/receiver_stdout.log 2>&1 & echo $!"
    ).strip().splitlines()[-1]
    time.sleep(0.5)
    sender_pid = h1.cmd(
        f"cd {ROOT} && python3 experiments/udp_covert_proxy.py sender "
        f"--strategy {strategy_id} --hidden-input {input_file} "
        f"--listen-ip 127.0.0.1 --listen-port 6000 "
        f"--remote-ip 10.0.1.2 --remote-port 6100 "
        f"--src-ip 10.0.1.1 --iface h1-eth0 --dst-mac 00:00:00:00:00:02 "
        f"--send-mode auto --path-id 0 --path-weights 1,1,1 --seq-num 1 "
        f"--business-payload-len 32 --strategy3-business-budget {args.iperf_len + 32} "
        f"--timing-repeat {5 if strategy_id == 1 else 4} "
        f"--path-sequence-repeat 3 "
        f"--max-idle 4 --summary {sender_summary} "
        f"> {case_dir}/sender_stdout.log 2>&1 & echo $!"
    ).strip().splitlines()[-1]
    time.sleep(0.5)
    h1.cmd(
        f"timeout {iperf_time + 8} "
        f"iperf -u -c 127.0.0.1 -p 6000 -b {rate} "
        f"-l {args.iperf_len} -t {iperf_time} -i 1 "
        f"> {case_dir}/iperf_client_h1.log 2>&1"
    )

    wait_background(h1, sender_pid, args.case_timeout)
    wait_background(h2, receiver_pid, args.case_timeout)
    stop_background(h1, sender_pid)
    stop_background(h2, receiver_pid)
    time.sleep(0.4)
    stop_background(h2, server_pid)

    sender = json.loads(sender_summary.read_text(encoding="utf-8")) if sender_summary.exists() else {}
    receiver = json.loads(receiver_summary.read_text(encoding="utf-8")) if receiver_summary.exists() else {}
    decoded = hidden_output.read_bytes() if hidden_output.exists() else b""
    server_log = (case_dir / "iperf_server_h2.log").read_text(encoding="utf-8", errors="ignore")
    client_log = (case_dir / "iperf_client_h1.log").read_text(encoding="utf-8", errors="ignore")

    result = {
        "strategy_id": strategy_id,
        "hidden_input": hidden.decode("ascii"),
        "hidden_output": decoded.decode("ascii", errors="replace"),
        "hidden_match": decoded == hidden,
        "sender_complete": bool(sender.get("complete")),
        "receiver_success": bool(receiver.get("success")),
        "business_forwarded_packets": int(receiver.get("forwarded_business_packets", 0)),
        "iperf_server_received": iperf_server_received(server_log),
        "sender_summary": sender,
        "receiver_summary": receiver,
        "iperf_client_tail": "\n".join(client_log.strip().splitlines()[-6:]),
        "iperf_server_tail": "\n".join(server_log.strip().splitlines()[-8:]),
        "case_dir": str(case_dir),
    }
    result["success"] = (
        result["hidden_match"]
        and result["sender_complete"]
        and result["receiver_success"]
        and result["business_forwarded_packets"] > 0
    )
    (case_dir / "case_summary.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
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
    net = runtime.build_net(runtime_args)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if args.clean_results and RESULTS_DIR.exists():
        shutil.rmtree(RESULTS_DIR)
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        print("[udp-proxy-real-flow] 启动 Mininet/BMv2")
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
        configure_s2_reverse_int()

        ping_out = h1.cmd("ping -c 2 10.0.1.2")
        (RESULTS_DIR / "ping.txt").write_text(ping_out, encoding="utf-8")

        results = []
        for strategy_id in parse_strategy_list(args.strategies):
            print(f"[udp-proxy-real-flow] 验证策略 {strategy_id}")
            results.append(run_case(h1, h2, args, strategy_id))

        summary = {
            "success": all(item.get("success") for item in results),
            "strategies": parse_strategy_list(args.strategies),
            "iperf_rate": args.iperf_rate,
            "iperf_len": args.iperf_len,
            "cases": results,
        }
        (RESULTS_DIR / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return summary
    finally:
        print("[udp-proxy-real-flow] 清理 Mininet")
        net.stop()


def main() -> int:
    args = parse_args()
    if os.geteuid() != 0:
        print("请使用 sudo 运行该脚本。", file=sys.stderr)
        return 2
    ensure_p4_json()
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    result = run_live(args)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"[udp-proxy-real-flow] 结果目录：{RESULTS_DIR}")
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
