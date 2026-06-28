#!/usr/bin/env python3
"""
策略4 live 矩阵测试。

脚本自动启动 h1-s1-(三链路)-s2-h2 拓扑，使用 P4 加权轮询把策略4承载包分发到两条或三条链路，
同时用 h2->h1 的低速 UDP iperf 触发 INT，验证业务流、INT 和 IP-ID 喷泉码解码能同时工作。
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
P4_FILE = ROOT / "p4" / "covert_int_switch.p4"
LOG_DIR = ROOT / "logs" / "celue4_matrix"
S1_CLI = ROOT / "p4" / "s1_commands.txt"
S2_CLI = ROOT / "p4" / "s2_commands.txt"
RUNTIME_PY = ROOT / "p4" / "build" / "mininet_runtime.py"
INPUT_FILE = ROOT / "celue4" / "input_payload.bin"
RESULTS_DIR = ROOT / "celue4" / "results"

STRATEGY4_K = 4
STRATEGY4_NUM_OUTPUT = 16
SECRET_KEY = "low-altitude-ipid-fountain-v1"
BUSINESS_PAYLOAD_LEN = 32

CASES = [
    {"name": "three_equal_clean", "weights": [1, 1, 1], "delays_ms": [5, 15, 30], "loss_pct": [0, 0, 0], "note": "三路径等权，无额外丢包"},
    {"name": "three_p2_loss20_equal", "weights": [1, 1, 1], "delays_ms": [5, 15, 30], "loss_pct": [0, 0, 20], "note": "三路径等权，path2 20%丢包"},
    {"name": "three_p2_loss20_weighted", "weights": [2, 2, 1], "delays_ms": [5, 15, 30], "loss_pct": [0, 0, 20], "note": "三路径加权，降低较差 path2 使用比例"},
    {"name": "two_path_clean", "weights": [1, 1, 0], "delays_ms": [5, 15, 30], "loss_pct": [0, 0, 0], "note": "只使用 path0/path1，path2 权重为0"},
    {"name": "two_path_p1_loss30", "weights": [1, 1, 0], "delays_ms": [5, 15, 30], "loss_pct": [0, 30, 0], "note": "两路径协同，path1 30%丢包"},
    {"name": "three_all_loss10", "weights": [1, 1, 1], "delays_ms": [5, 15, 30], "loss_pct": [10, 10, 10], "note": "三条链路均有10%随机丢包"},
]


def load_runtime():
    spec = importlib.util.spec_from_file_location("celue4_mininet_runtime", RUNTIME_PY)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法加载 Mininet 运行时：{RUNTIME_PY}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ensure_p4_json() -> None:
    if P4_JSON.exists() and P4_JSON.read_text(encoding="utf-8", errors="ignore")[:1] == "{":
        return
    subprocess.check_call([
        "p4c", "--target", "bmv2", "--arch", "v1model",
        "--output", str(ROOT / "p4"), str(P4_FILE),
    ])


def strategy4_packets() -> int:
    sys.path.insert(0, str(ROOT))
    from python.covert_strategies.base import StrategyID
    from python.covert_strategies.strategy_registry import get_strategy

    data = INPUT_FILE.read_bytes()
    strategy = get_strategy(
        StrategyID.FULL_PATH_REDUNDANCY,
        config={
            "k": STRATEGY4_K,
            "num_output": STRATEGY4_NUM_OUTPUT,
            "secret_key": SECRET_KEY,
            "business_payload_len": BUSINESS_PAYLOAD_LEN,
        },
    )
    return len(strategy.encode(data, path_id=0, seq_num=1))


def file_md5(path: Path) -> str:
    if not path.exists():
        return ""
    return hashlib.md5(path.read_bytes()).hexdigest()


def weights_to_text(weights) -> str:
    return ",".join(str(int(item)) for item in weights)


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


def configure_switches_for_case(case) -> None:
    w0, w1, w2 = case["weights"]
    run_cli(9090, [
        "register_write reg_path_mode 0 4",
        f"register_write reg_wrr_weight0 0 {w0}",
        f"register_write reg_wrr_weight1 0 {w1}",
        f"register_write reg_wrr_weight2 0 {w2}",
        "register_write reg_wrr_counter 0 0",
        "register_write reg_int_enabled 0 0",
    ])
    run_cli(9091, [
        "register_write reg_path_mode 0 2",
        "register_write reg_rr_burst_size 0 12",
        "register_write reg_rr_counter 0 0",
        "register_write reg_rr_current_path 0 0",
        "register_write reg_int_probe_mode 0 0",
        "register_write reg_int_interval_us 0 10000",
        "register_write reg_next_sample_time 0 0",
        "register_write reg_int_enabled 0 1",
    ])


def apply_netem(s1, s2, case) -> None:
    for idx, port in enumerate((2, 3, 4)):
        delay = int(case["delays_ms"][idx])
        loss = float(case["loss_pct"][idx])
        s1.cmd(f"tc qdisc replace dev s1-eth{port} root netem delay {delay}ms loss {loss}%")
        s2.cmd(f"tc qdisc replace dev s2-eth{port} root netem delay {delay}ms loss {loss}%")


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


def run_case(h1, h2, s1, s2, case, expected_count: int, expected_bytes: int, timeout_s: int, port: int) -> dict:
    out_dir = RESULTS_DIR / case["name"]
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    configure_switches_for_case(case)
    apply_netem(s1, s2, case)

    int_output = out_dir / "int_summary.json"
    int_stdout = out_dir / "int_stdout.txt"
    int_pid = h1.cmd(
        f"cd {ROOT} && python3 experiments/reverse_probe_receiver.py "
        f"--timeout {max(8, timeout_s)} --window-ms {max(8000, timeout_s * 1000)} "
        f"--output {int_output} > {int_stdout} 2>&1 & echo $!"
    ).strip().splitlines()[-1]

    iperf_server_pid = h1.cmd(f"iperf -s -u -i 1 > {out_dir}/iperf_server.txt 2>&1 & echo $!").strip().splitlines()[-1]
    time.sleep(0.5)
    iperf_client_pid = h2.cmd(
        f"iperf -u -c 10.0.1.1 -b 1M -t {max(6, timeout_s - 2)} -i 1 "
        f"> {out_dir}/iperf_client.txt 2>&1 & echo $!"
    ).strip().splitlines()[-1]

    weights_text = weights_to_text(case["weights"])
    rx_pid = h2.cmd(
        f"cd {ROOT} && TIMEOUT_S={timeout_s} STRATEGY4_K={STRATEGY4_K} "
        f"STRATEGY4_NUM_OUTPUT={STRATEGY4_NUM_OUTPUT} PATH_WEIGHTS={weights_text} "
        f"SECRET_KEY={SECRET_KEY} BUSINESS_PAYLOAD_LEN={BUSINESS_PAYLOAD_LEN} "
        f"bash celue4/rx_strategy4.sh {port} {expected_count} {expected_bytes} {case['name']} "
        f"> {out_dir}/receive_stdout.txt 2>&1 & echo $!"
    ).strip().splitlines()[-1]
    time.sleep(0.5)

    h1.cmd(
        f"cd {ROOT} && PACE_MS=1 STRATEGY4_K={STRATEGY4_K} "
        f"STRATEGY4_NUM_OUTPUT={STRATEGY4_NUM_OUTPUT} PATH_WEIGHTS={weights_text} "
        f"SECRET_KEY={SECRET_KEY} BUSINESS_PAYLOAD_LEN={BUSINESS_PAYLOAD_LEN} "
        f"bash celue4/tx_strategy4.sh {port} {case['name']} "
        f"> {out_dir}/send_stdout.txt 2>&1"
    )

    wait_background(h2, iperf_client_pid, timeout_s + 5)
    wait_background(h2, rx_pid, timeout_s + 3)
    wait_background(h1, int_pid, timeout_s + 3)
    stop_background(h2, rx_pid)
    stop_background(h1, int_pid)
    stop_background(h1, iperf_server_pid)

    summary_path = out_dir / "receive_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {"success": False, "error": "没有生成接收摘要"}
    input_md5 = file_md5(INPUT_FILE)
    decoded_path = out_dir / "decoded_output.bin"
    decoded_md5 = file_md5(decoded_path)
    hidden_match = bool(decoded_md5 and decoded_md5 == input_md5)
    packets_received = int(summary.get("packets_received", 0))
    packet_loss_est = 1.0 - (packets_received / expected_count) if expected_count else 0.0

    iperf_client_text = (out_dir / "iperf_client.txt").read_text(encoding="utf-8", errors="ignore") if (out_dir / "iperf_client.txt").exists() else ""
    iperf_ok = (
        "connect failed" not in iperf_client_text.lower()
        and "failed" not in iperf_client_text.lower()
        and ("datagrams" in iperf_client_text.lower() or "sec" in iperf_client_text.lower())
    )
    int_summary = json.loads(int_output.read_text(encoding="utf-8")) if int_output.exists() else {"success": False, "error": "没有生成 INT 摘要"}

    result = {
        "case": case["name"],
        "note": case["note"],
        "weights": case["weights"],
        "delays_ms": case["delays_ms"],
        "loss_pct": case["loss_pct"],
        "port": port,
        "strategy4_k": STRATEGY4_K,
        "strategy4_num_output": STRATEGY4_NUM_OUTPUT,
        "expected_packets": expected_count,
        "packets_received": packets_received,
        "estimated_packet_loss_pct": round(packet_loss_est * 100, 2),
        "decoded_bytes": summary.get("decoded_bytes", 0),
        "success": bool(summary.get("success")),
        "hidden_match": hidden_match,
        "input_md5": input_md5,
        "decoded_md5": decoded_md5,
        "decode_info": summary.get("decode_info", {}),
        "ip_id_sample_hex": summary.get("ip_id_sample_hex", []),
        "iperf_ok": iperf_ok,
        "iperf_client_tail": "\n".join(iperf_client_text.strip().splitlines()[-8:]),
        "int_success": bool(int_summary.get("success")),
        "int_parsed_reports": int_summary.get("parsed_int_reports", 0),
        "int_metric_sample_counts": int_summary.get("metric_sample_counts", {}),
        "int_path_states": int_summary.get("path_states", {}),
    }
    (out_dir / "case_result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def write_summary(results, expected_count: int, expected_bytes: int) -> None:
    summary = {
        "scheme": "strategy4-ipid-fountain-weighted-rr-live",
        "input_file": str(INPUT_FILE),
        "input_bytes": expected_bytes,
        "expected_packets": expected_count,
        "ip_id_layout": "flag(1)+strategy_id(3)+frame_id(4)+symbol_id(4)+encrypted_coded_nibble(4)",
        "strategy4_k": STRATEGY4_K,
        "strategy4_num_output": STRATEGY4_NUM_OUTPUT,
        "cases": results,
    }
    (RESULTS_DIR / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    csv_lines = ["case,weights,delay_ms,loss_pct,expected_packets,packets_received,estimated_loss_pct,success,hidden_match,iperf_ok,int_success,int_reports,decoded_bytes"]
    for item in results:
        csv_lines.append(
            f"{item['case']},{'-'.join(map(str, item['weights']))},{'-'.join(map(str, item['delays_ms']))},"
            f"{'-'.join(map(str, item['loss_pct']))},{item['expected_packets']},{item['packets_received']},"
            f"{item['estimated_packet_loss_pct']},{item['success']},{item['hidden_match']},"
            f"{item['iperf_ok']},{item['int_success']},{item['int_parsed_reports']},{item['decoded_bytes']}"
        )
    (RESULTS_DIR / "summary.csv").write_text("\n".join(csv_lines) + "\n", encoding="utf-8")
    report_lines = [
        "# 策略4测试报告", "", "## 1. 测试目标", "",
        "验证策略4在真实 Mininet/BMv2 拓扑中是否能够通过 IPv4 ID 字段承载喷泉码符号，并由 P4 加权轮询分发到两条或三条链路。测试过程中同时运行 h2->h1 的低速 UDP iperf 业务流触发 INT，观察业务流、INT 和隐蔽解码是否能同时成立。",
        "", "## 2. 当前字段设计", "", "```text",
        "bit15       flag = 1", "bits14-12   strategy_id = 4", "bits11-8    frame_id", "bits7-4     symbol_id", "bits3-0     encrypted coded_nibble", "```", "",
        f"本轮测试 `k={STRATEGY4_K}`，每个 frame 生成 `{STRATEGY4_NUM_OUTPUT}` 个喷泉符号；每个包只在 IP-ID 中携带 4 bit 加密后的编码半字节。",
        "", "## 3. 测试结果", "",
        "| Case | WRR权重 | 时延(ms) | 丢包设置 | 收到包数 | 估计实际丢包 | 解码成功 | 数据一致 | iperf不中断 | INT成功 | INT报告数 |",
        "|---|---|---|---|---:|---:|---|---|---|---|---:|",
    ]
    for item in results:
        report_lines.append(
            f"| {item['case']} | {item['weights']} | {item['delays_ms']} | {item['loss_pct']} | "
            f"{item['packets_received']}/{item['expected_packets']} | {item['estimated_packet_loss_pct']}% | "
            f"{str(item['success']).lower()} | {str(item['hidden_match']).lower()} | {str(item['iperf_ok']).lower()} | "
            f"{str(item['int_success']).lower()} | {item['int_parsed_reports']} |"
        )
    report_lines.extend([
        "", "## 4. 结论", "",
        f"- 隐蔽数据一致性：{sum(1 for item in results if item['hidden_match'])}/{len(results)} 个 case 成功恢复。",
        f"- 业务连续性：{sum(1 for item in results if item['iperf_ok'])}/{len(results)} 个 case 中 UDP iperf 正常完成。",
        f"- INT 可观测性：{sum(1 for item in results if item['int_success'])}/{len(results)} 个 case 解析到三条路径状态。",
        "- P4 只根据寄存器执行加权轮询，策略4包内没有使用 UDP 端口、DSCP、TTL 等明显字段标记路径。",
        "- 接收端只解析 IP-ID 中的策略号、frame_id、symbol_id 和加密半字节；乱序和部分丢包由喷泉码矩阵解码处理。",
        "", "## 5. 原始结果", "", "```text", "celue4/results/summary.json", "celue4/results/summary.csv", "celue4/results/<case>/case_result.json", "celue4/results/<case>/receive_summary.json", "celue4/results/<case>/int_summary.json", "celue4/results/<case>/iperf_client.txt", "```",
    ])
    (ROOT / "celue4" / "测试报告.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")


def write_operation_doc() -> None:
    text = f"""# 策略4验证操作文档

## 1. 功能目标

策略4用于验证“IP-ID 喷泉码多路径协同隐蔽传输”。发送端 h1 生成喷泉码符号，把 `flag + strategy_id + frame_id + symbol_id + encrypted coded_nibble` 写入 IPv4 Identification 字段；P4 交换机不解析隐蔽内容，只通过寄存器控制的加权轮询把包分发到 path0/path1/path2；接收端 h2 抓包读取 IP-ID，按 frame 收集足够多 symbol 后解码。

## 2. 字段格式

```text
bit15       flag = 1
bits14-12   strategy_id = 4
bits11-8    frame_id
bits7-4     symbol_id
bits3-0     encrypted coded_nibble
```

当前 live 测试参数：`k={STRATEGY4_K}`，`num_output={STRATEGY4_NUM_OUTPUT}`。

## 3. 一键测试

```bash
cd /home/p4/yws-covert
sudo python3 celue4/run_strategy4_matrix.py --timeout 15
```

脚本会自动启动拓扑、下发流表、设置 s1 的加权轮询、运行 h2->h1 UDP iperf 触发 INT、发送 h1->h2 策略4隐蔽包并解码，最后清理 Mininet。

## 4. 手动配置加权轮询

三路径等权：

```text
register_write reg_path_mode 0 4
register_write reg_wrr_weight0 0 1
register_write reg_wrr_weight1 0 1
register_write reg_wrr_weight2 0 1
register_write reg_wrr_counter 0 0
```

只使用 path0/path1：

```text
register_write reg_path_mode 0 4
register_write reg_wrr_weight0 0 1
register_write reg_wrr_weight1 0 1
register_write reg_wrr_weight2 0 0
register_write reg_wrr_counter 0 0
```

降低 path2 使用比例：

```text
register_write reg_path_mode 0 4
register_write reg_wrr_weight0 0 2
register_write reg_wrr_weight1 0 2
register_write reg_wrr_weight2 0 1
register_write reg_wrr_counter 0 0
```

## 5. 手动收发策略4

```bash
h2 bash celue4/rx_strategy4.sh 50240 256 23 smoke &
h1 bash celue4/tx_strategy4.sh 50240 smoke
h2 cat celue4/results/smoke/receive_summary.json
h2 md5sum celue4/input_payload.bin
h2 md5sum celue4/results/smoke/decoded_output.bin
```

两个 MD5 一致说明隐蔽数据恢复成功。

## 6. 结果文件

```text
celue4/input_payload.bin
celue4/input_bits.txt
celue4/results/summary.json
celue4/results/summary.csv
celue4/results/<case>/case_result.json
celue4/results/<case>/decoded_output.bin
celue4/results/<case>/int_summary.json
celue4/测试报告.md
```
"""
    (ROOT / "celue4" / "操作文档.md").write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="策略4 live 矩阵测试")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--start-port", type=int, default=50240)
    parser.add_argument("--cases", nargs="*", default=None, help="只运行指定 case 名称")
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("请使用 sudo 运行该脚本。", file=sys.stderr)
        return 2
    ensure_p4_json()
    runtime = load_runtime()
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    write_operation_doc()
    expected_count = strategy4_packets()
    expected_bytes = len(INPUT_FILE.read_bytes())
    wanted = set(args.cases) if args.cases else None
    selected_cases = [case for case in CASES if wanted is None or case["name"] in wanted]
    runtime_args = SimpleNamespace(json=str(P4_JSON), log_dir=str(LOG_DIR), s1_cli=str(S1_CLI), s2_cli=str(S2_CLI), host_mtu=1500, trunk_mtu=1600)
    net = runtime.build_net(runtime_args)
    results = []
    try:
        print("[celue4] 启动 Mininet/BMv2")
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
        (RESULTS_DIR / "matrix_ping.txt").write_text(h1.cmd("ping -c 2 10.0.1.2"), encoding="utf-8")
        print("[celue4] ping 检查完成")
        for index, case in enumerate(selected_cases):
            port = args.start_port + index
            print(f"[celue4] 运行 {case['name']} port={port} weights={case['weights']} loss={case['loss_pct']}")
            result = run_case(h1, h2, s1, s2, case, expected_count, expected_bytes, args.timeout, port)
            results.append(result)
            print(f"[celue4] {case['name']} success={result['success']} match={result['hidden_match']} iperf={result['iperf_ok']} int={result['int_success']} recv={result['packets_received']}/{expected_count}")
    finally:
        print("[celue4] 清理 Mininet")
        net.stop()
    write_summary(results, expected_count, expected_bytes)
    print(f"[celue4] 完成，结果见 {RESULTS_DIR}/summary.json")
    return 0 if all(item["hidden_match"] and item["iperf_ok"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())