#!/usr/bin/env python3
"""
用户演示拓扑服务。

该服务是五窗口演示系统的核心：它用 sudo 持有 Mininet/BMv2 拓扑，
后台启动 h2->h1 UDP iperf 和 h1 INT 解析器，并向其他窗口提供本地
JSON 命令接口。

其他窗口不要直接启动 Mininet，只需要连接 127.0.0.1:38765。
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
import shutil
import socketserver
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments import mininet_runtime
from experiments.run_manual_policy_live import (
    configure_s1_for_entry,
    configure_s2_for_reverse_int,
    ensure_p4_json,
    parse_iperf_ok,
    wait_background,
)
from experiments.run_rule_proxy_closed_loop import (
    allow_segment,
    scenario_plan,
    wait_for_segment_ready,
    write_proxy_plan,
)
from experiments.verify_manual_policy_session import PolicyEntry, write_policy_plan
from experiments.user_demo.demo_client import DEFAULT_HOST, DEFAULT_PORT, short_plan
from python.control_plane.rule_policy_selector import RuleBasedPolicySelector


P4_JSON = PROJECT_ROOT / "p4" / "covert_int_switch.json"
S1_CLI = PROJECT_ROOT / "p4" / "s1_commands.txt"
S2_CLI = PROJECT_ROOT / "p4" / "s2_commands.txt"
RESULTS_DIR = PROJECT_ROOT / "experiments" / "results" / "user_demo"
LOG_DIR = PROJECT_ROOT / "logs" / "user_demo"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="启动用户演示拓扑服务")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--chunk-size", type=int, default=7)
    parser.add_argument("--base-dport", type=int, default=51200)
    parser.add_argument("--session-id-start", type=int, default=100)
    parser.add_argument("--pace-ms", type=float, default=1.0)
    parser.add_argument("--chunk-gap-ms", type=float, default=100.0)
    parser.add_argument("--timeout", type=int, default=75)
    parser.add_argument("--iperf-rate", default="700K")
    parser.add_argument("--forward-iperf-rate", default="220K")
    parser.add_argument("--forward-iperf-len", type=int, default=200)
    parser.add_argument("--clean-results", action="store_true")
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
    """让 h1->h2 普通业务流默认三路径轮询。"""

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

    if pid and str(pid).isdigit():
        host.cmd(f"kill {pid} >/dev/null 2>&1 || true")


def path_sort_key(item: tuple[int, object]) -> tuple[float, float, float]:
    """根据 INT 状态排序路径，越小越适合轻量隐蔽策略。"""

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


class DemoService:
    """持有拓扑和演示状态的服务对象。"""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.net = None
        self.h1 = None
        self.h2 = None
        self.lock = threading.Lock()
        self.session_id = int(args.session_id_start)
        self.sequence_index = 0
        self.services: Dict[str, Any] = {}
        self.latest_results: List[dict] = []
        self.link_config: Dict[int, dict] = {
            0: {"delay_ms": 5.0, "loss_percent": 0.0},
            1: {"delay_ms": 15.0, "loss_percent": 0.0},
            2: {"delay_ms": 30.0, "loss_percent": 0.0},
        }
        self.current_strategy: Dict[str, Any] = {
            "active": False,
            "stage": "idle",
            "message": "当前没有隐蔽数据发送，普通业务流按三路径轮询运行",
            "session_id": None,
            "chunk_id": None,
            "strategy_id": None,
            "strategy_name": "",
            "paths": [],
            "packets": 0,
            "plan_text": "",
            "updated_at": time.time(),
        }
        self.last_strategy: Dict[str, Any] = {}

    @property
    def int_output(self) -> Path:
        return RESULTS_DIR / "latest_int_summary.json"

    def start(self) -> None:
        """启动拓扑、业务流和 INT 解析器。"""

        if os.geteuid() != 0:
            raise RuntimeError("topology_service.py 必须用 sudo 运行")

        ensure_p4_json()
        if self.args.clean_results and RESULTS_DIR.exists():
            shutil.rmtree(RESULTS_DIR)
        if self.args.clean_results and LOG_DIR.exists():
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

        print("[topology] 启动 Mininet/BMv2 拓扑...")
        self.net = mininet_runtime.start_configured_net(runtime_args)
        self.h1, self.h2 = self.net.get("h1", "h2")
        configure_s2_for_reverse_int()
        configure_s1_round_robin_for_business()
        ping_out = self.h1.cmd("ping -c 2 10.0.1.2")
        (RESULTS_DIR / "ping.txt").write_text(ping_out, encoding="utf-8")
        self.start_background_services()
        self.write_state_file()

    def stop(self) -> None:
        """停止后台进程并清理拓扑。"""

        if self.net is not None:
            try:
                stop_background(self.h1, self.services.get("int_pid", ""))
                stop_background(self.h1, self.services.get("iperf_server_pid", ""))
                stop_background(self.h2, self.services.get("iperf_client_pid", ""))
                self.write_overall_summary()
            finally:
                print("[topology] 停止 Mininet/BMv2 拓扑...")
                self.net.stop()
                self.net = None

    def start_background_services(self) -> None:
        """启动 h2->h1 UDP iperf 和 h1 INT 接收器。"""

        int_pid = self.h1.cmd(
            f"cd {PROJECT_ROOT} && python3 experiments/reverse_probe_receiver.py "
            f"--timeout 86400 --window-ms 60000 --write-interval 1 "
            f"--output {self.int_output} "
            f"> {RESULTS_DIR}/int_receiver.log 2>&1 & echo $!"
        ).strip().splitlines()[-1]
        iperf_server_pid = self.h1.cmd(
            f"iperf -s -u -i 5 > {RESULTS_DIR}/reverse_iperf_server_h1.log 2>&1 & echo $!"
        ).strip().splitlines()[-1]
        time.sleep(0.5)
        iperf_client_pid = self.h2.cmd(
            f"iperf -u -c 10.0.1.1 -b {self.args.iperf_rate} -t 86400 -i 5 "
            f"> {RESULTS_DIR}/reverse_iperf_client_h2.log 2>&1 & echo $!"
        ).strip().splitlines()[-1]
        self.services = {
            "int_pid": int_pid,
            "iperf_server_pid": iperf_server_pid,
            "iperf_client_pid": iperf_client_pid,
        }
        print("[topology] 后台业务流和 INT 解析器已启动。")

    def read_latest_int_summary(self) -> dict:
        """读取最新 INT 解析结果。"""

        if not self.int_output.exists():
            return {}
        try:
            return json.loads(self.int_output.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def read_latest_int_state(self) -> dict:
        """读取最新 path_states。"""

        return self.read_latest_int_summary().get("path_states", {}) or {}

    def build_demo_plan(self, secret: bytes, path_states: dict) -> List[PolicyEntry]:
        """根据数据长度和链路状态生成演示策略计划。"""

        if len(secret) <= self.args.chunk_size:
            if path_states:
                best_path = sorted(
                    ((int(path_id), state) for path_id, state in path_states.items()),
                    key=path_sort_key,
                )[0][0]
            else:
                best_path = 0
            return [PolicyEntry(f"short_best_path{best_path}_s3", 3, (best_path,), 1)]

        normalized_states = {int(path_id): state for path_id, state in path_states.items()}
        if len(secret) >= max(self.args.chunk_size * 2, 12):
            return scenario_plan(normalized_states)

        selector = RuleBasedPolicySelector()
        plan = selector.select(normalized_states)
        if plan:
            return plan
        return [
            PolicyEntry("fallback_path0_s2", 2, (0,), 1),
            PolicyEntry("fallback_path1_s3", 3, (1,), 1),
            PolicyEntry("fallback_path012_s4", 4, (0, 1, 2), 1),
        ]

    def set_current_strategy(self, **updates: Any) -> None:
        """更新当前正在执行的隐蔽传输策略状态。"""

        state = dict(self.current_strategy)
        state.update(updates)
        state["updated_at"] = time.time()
        self.current_strategy = state
        self.write_state_file()

    def mark_strategy_idle(self, message: Any = None) -> None:
        """把实时策略状态恢复为普通业务轮询。"""

        self.set_current_strategy(
            active=False,
            stage="idle",
            message=message or "当前没有隐蔽数据发送，普通业务流按三路径轮询运行",
            session_id=None,
            chunk_id=None,
            strategy_id=None,
            strategy_name="",
            paths=[],
            packets=0,
            plan_text="",
        )

    def send_secret_proxy(self, text: str) -> dict:
        """通过真实 UDP iperf 业务流代理发送隐蔽文本。"""

        with self.lock:
            session_id = self.session_id
            sequence_index = self.sequence_index
            self.session_id += 1
            self.sequence_index += 1

            secret = text.encode("utf-8")
            session_dir = RESULTS_DIR / f"session_{session_id:03d}"
            session_dir.mkdir(parents=True, exist_ok=True)
            input_file = session_dir / "input_secret.bin"
            output_file = session_dir / "decoded_secret.bin"
            rule_plan_file = session_dir / "rule_plan.json"
            proxy_plan_file = session_dir / "proxy_plan.json"
            summary_file = session_dir / "summary.json"
            control_dir = session_dir / "control"
            control_dir.mkdir(parents=True, exist_ok=True)
            input_file.write_bytes(secret)

            path_states = self.read_latest_int_state()
            plan = self.build_demo_plan(secret, path_states)
            proxy_plan = write_proxy_plan(
                proxy_plan_file,
                secret,
                plan,
                int(self.args.base_dport) + sequence_index * 32,
                int(self.args.chunk_size),
            )
            write_policy_plan(
                rule_plan_file,
                plan,
                extra={
                    "source": "user_demo_topology_service_proxy",
                    "input_path_states": path_states,
                    "sequence_index": sequence_index,
                    "secret_bytes": len(secret),
                    "proxy_plan_file": str(proxy_plan_file),
                },
            )

            plan_dicts = [entry.to_dict() for entry in plan]
            proxy_segments = list(proxy_plan["segments"])
            proxy_plan_text = short_plan(
                [
                    {
                        "strategy_id": int(segment["strategy_id"]),
                        "paths": [int(path) for path in segment.get("paths", [])],
                        "weight": int(segment.get("weight", 1)),
                    }
                    for segment in proxy_segments
                ]
            )
            receive_timeout = max(int(self.args.timeout), 45 + len(proxy_segments) * 8)

            self.set_current_strategy(
                active=True,
                stage="proxy_receiver_ready",
                message=f"session {session_id} 接收端代理已启动，等待真实 UDP 业务流承载隐蔽数据",
                session_id=session_id,
                chunk_id=None,
                strategy_id=None,
                strategy_name="",
                paths=[],
                packets=0,
                input_bytes=len(secret),
                expected_packets=0,
                plan=plan_dicts,
                plan_text=proxy_plan_text,
                session_dir=str(session_dir),
            )

            iperf_server_pid = ""
            receiver_pid = ""
            sender_pid = ""
            iperf_client_pid = ""
            try:
                iperf_server_pid = self.h2.cmd(
                    f"iperf -s -u -p 5201 -i 1 > {session_dir}/iperf_server_h2.log 2>&1 & echo $!"
                ).strip().splitlines()[-1]
                receiver_pid = self.h2.cmd(
                    f"cd {PROJECT_ROOT} && python3 experiments/udp_covert_proxy.py plan-receiver "
                    f"--plan-file {proxy_plan_file} --iface h2-eth0 --forward-ip 127.0.0.1 "
                    f"--forward-port 5201 --timeout {receive_timeout} --max-idle 6 "
                    f"--hidden-output {output_file} "
                    f"--summary {session_dir}/receiver_summary.json "
                    f"> {session_dir}/receiver_stdout.log 2>&1 & echo $!"
                ).strip().splitlines()[-1]
                time.sleep(0.5)
                sender_pid = self.h1.cmd(
                    f"cd {PROJECT_ROOT} && python3 experiments/udp_covert_proxy.py plan-sender "
                    f"--plan-file {proxy_plan_file} --listen-ip 127.0.0.1 --listen-port 6000 "
                    f"--remote-ip 10.0.1.2 --src-ip 10.0.1.1 --iface h1-eth0 "
                    f"--dst-mac 00:00:00:00:00:02 --plain-remote-port {proxy_plan['plain_ports'][0]} "
                    f"--control-dir {control_dir} --max-idle 5 "
                    f"--summary {session_dir}/sender_summary.json "
                    f"> {session_dir}/sender_stdout.log 2>&1 & echo $!"
                ).strip().splitlines()[-1]
                time.sleep(0.5)
                iperf_client_pid = self.h1.cmd(
                    f"timeout {receive_timeout + 10} "
                    f"iperf -u -c 127.0.0.1 -p 6000 -b {self.args.forward_iperf_rate} "
                    f"-l {int(self.args.forward_iperf_len)} -t {receive_timeout} -i 1 "
                    f"> {session_dir}/iperf_client_h1.log 2>&1 & echo $!"
                ).strip().splitlines()[-1]

                for segment in proxy_segments:
                    segment_id = int(segment["segment_id"])
                    strategy_id = int(segment["strategy_id"])
                    paths = [int(path) for path in segment.get("paths", [])]
                    self.set_current_strategy(
                        active=True,
                        stage="proxy_sending_segment",
                        message=(
                            f"session {session_id} segment {segment_id} 正在真实 UDP 业务流上"
                            f"挂载策略{strategy_id}，路径={paths}"
                        ),
                        session_id=session_id,
                        chunk_id=segment_id,
                        strategy_id=strategy_id,
                        strategy_name=f"proxy_segment_{segment_id}",
                        paths=paths,
                        packets=0,
                        encoded_bytes=int(segment.get("expected_bytes", 0)),
                        dport=int(segment.get("remote_port", 0)),
                        sequence_num=int(segment.get("sequence_num", 0)),
                        plan=plan_dicts,
                        plan_text=proxy_plan_text,
                        session_dir=str(session_dir),
                    )
                    wait_for_segment_ready(control_dir, segment_id, timeout_s=float(receive_timeout))
                    configure_s1_for_entry(strategy_id, paths)
                    allow_segment(control_dir, segment_id)

                self.set_current_strategy(
                    active=True,
                    stage="proxy_waiting_receiver",
                    message=f"session {session_id} 已完成发送，正在等待 h2 代理解码",
                    session_id=session_id,
                    chunk_id=None,
                    strategy_id=None,
                    strategy_name="",
                    paths=[],
                    packets=0,
                    plan=plan_dicts,
                    plan_text=proxy_plan_text,
                    session_dir=str(session_dir),
                )
                wait_background(self.h1, sender_pid, receive_timeout + 15)
                wait_background(self.h2, receiver_pid, receive_timeout + 15)
                wait_background(self.h1, iperf_client_pid, receive_timeout + 15)
            finally:
                stop_background(self.h1, sender_pid)
                stop_background(self.h2, receiver_pid)
                stop_background(self.h1, iperf_client_pid)
                time.sleep(0.3)
                stop_background(self.h2, iperf_server_pid)
                configure_s1_round_robin_for_business()

            sender_summary_path = session_dir / "sender_summary.json"
            receiver_summary_path = session_dir / "receiver_summary.json"
            sender_summary = (
                json.loads(sender_summary_path.read_text(encoding="utf-8"))
                if sender_summary_path.exists()
                else {"complete": False}
            )
            receiver_summary = (
                json.loads(receiver_summary_path.read_text(encoding="utf-8"))
                if receiver_summary_path.exists()
                else {"success": False}
            )
            decoded = output_file.read_bytes() if output_file.exists() else b""
            hidden_match = decoded == secret
            iperf_server_log = session_dir / "iperf_server_h2.log"
            iperf_text = iperf_server_log.read_text(encoding="utf-8", errors="ignore") if iperf_server_log.exists() else ""
            iperf_server_received = "datagrams" in iperf_text.lower() or "sec" in iperf_text.lower()
            result = {
                "success": bool(sender_summary.get("complete"))
                and bool(receiver_summary.get("success"))
                and hidden_match
                and iperf_server_received,
                "hidden_match": hidden_match,
                "session_id": session_id,
                "sequence_index": sequence_index,
                "input_text": text,
                "decoded_text": decoded.decode("utf-8", errors="replace"),
                "input_bytes": len(secret),
                "decoded_bytes": len(decoded),
                "expected_packets": sum(int(item.get("covert_business_packets", 0)) for item in sender_summary.get("segments", [])),
                "plan": plan_dicts,
                "plan_text": proxy_plan_text,
                "proxy_plan": proxy_plan,
                "path_states_used": path_states,
                "sender_summary": sender_summary,
                "receiver_summary": receiver_summary,
                "iperf_server_received": iperf_server_received,
                "session_dir": str(session_dir),
                "timestamp": time.time(),
            }
            summary_file.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            self.latest_results.append(result)
            self.latest_results = self.latest_results[-100:]
            self.append_history(result)
            self.last_strategy = {
                "session_id": session_id,
                "sequence_index": sequence_index,
                "success": result["success"],
                "hidden_match": hidden_match,
                "decoded_text": result["decoded_text"],
                "input_bytes": len(secret),
                "decoded_bytes": len(decoded),
                "expected_packets": result["expected_packets"],
                "plan": plan_dicts,
                "plan_text": proxy_plan_text,
                "session_dir": str(session_dir),
                "timestamp": time.time(),
            }
            self.mark_strategy_idle(f"最近 session {session_id} 已完成，普通业务流恢复三路径轮询")
            self.write_state_file()
            return result

    def append_history(self, result: dict) -> None:
        """把发送历史追加到 CSV，供接收显示窗口读取。"""

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
                    "plan_text",
                    "session_dir",
                ],
            )
            if is_new:
                writer.writeheader()
            writer.writerow({key: result.get(key) for key in writer.fieldnames})

    def get_status(self) -> dict:
        """返回链路状态、建议策略和最近解码结果。"""

        int_summary = self.read_latest_int_summary()
        path_states = int_summary.get("path_states", {}) or {}
        selector = RuleBasedPolicySelector()
        try:
            plan = selector.select({int(path_id): state for path_id, state in path_states.items()})
            plan_dicts = [entry.to_dict() for entry in plan]
        except Exception:
            plan_dicts = []
        iperf_client = RESULTS_DIR / "reverse_iperf_client_h2.log"
        iperf_text = iperf_client.read_text(encoding="utf-8", errors="ignore") if iperf_client.exists() else ""
        return {
            "ok": True,
            "running": self.net is not None,
            "results_dir": str(RESULTS_DIR),
            "int_success": bool(int_summary.get("success")),
            "int_parsed_reports": int_summary.get("parsed_int_reports", 0),
            "path_states": path_states,
            "metric_sample_counts": int_summary.get("metric_sample_counts", {}),
            "suggested_plan": plan_dicts,
            "suggested_plan_text": short_plan(plan_dicts),
            "link_config": self.link_config,
            "latest_results": self.latest_results[-20:],
            "current_strategy": self.current_strategy,
            "last_strategy": self.last_strategy,
            "iperf_ok": parse_iperf_ok(iperf_text),
        }

    def set_links(self, links: list[dict]) -> dict:
        """设置三条交换机间链路的 delay/loss。"""

        if self.net is None:
            raise RuntimeError("拓扑尚未启动")
        applied = []
        for item in links:
            raw_path = int(item["path"])
            path_id = raw_path - 1 if raw_path in {1, 2, 3} else raw_path
            if path_id not in {0, 1, 2}:
                raise ValueError("链路编号只能是 0/1/2 或 1/2/3")
            delay_ms = float(item.get("delay_ms", item.get("delay", 0.0)))
            loss_percent = float(item.get("loss_percent", item.get("loss", 0.0)))
            if delay_ms < 0 or loss_percent < 0 or loss_percent > 100:
                raise ValueError("delay 必须 >=0，loss 必须在 0~100 之间")

            port = path_id + 2
            for node_name in ("s1", "s2"):
                node = self.net.get(node_name)
                intf = f"{node_name}-eth{port}"
                node.cmd(
                    f"tc qdisc replace dev {intf} root netem "
                    f"delay {delay_ms}ms loss {loss_percent}% >/dev/null 2>&1"
                )
            self.link_config[path_id] = {
                "delay_ms": delay_ms,
                "loss_percent": loss_percent,
            }
            applied.append({"path": path_id, "delay_ms": delay_ms, "loss_percent": loss_percent})
        self.write_state_file()
        return {"ok": True, "applied": applied, "link_config": self.link_config}

    def write_state_file(self) -> None:
        """写出服务状态快照，便于不连 API 时查看。"""

        state_path = RESULTS_DIR / "service_state.json"
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "timestamp": time.time(),
            "service_port": self.args.port,
            "link_config": self.link_config,
            "latest_results_count": len(self.latest_results),
            "current_strategy": self.current_strategy,
            "last_strategy": self.last_strategy,
        }
        state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

    def write_overall_summary(self) -> None:
        """退出前写出汇总。"""

        status = self.get_status()
        status.pop("ok", None)
        (RESULTS_DIR / "summary.json").write_text(
            json.dumps(status, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


class RequestHandler(socketserver.StreamRequestHandler):
    """一行 JSON 请求处理器。"""

    def handle(self) -> None:
        raw = self.rfile.readline().decode("utf-8").strip()
        try:
            request = json.loads(raw)
            response = self.dispatch(request)
        except Exception as exc:
            response = {"ok": False, "error": str(exc)}
        self.wfile.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))

    def dispatch(self, request: Dict[str, Any]) -> Dict[str, Any]:
        service: DemoService = self.server.service  # type: ignore[attr-defined]
        action = request.get("action")
        if action == "status":
            return service.get_status()
        if action == "send":
            text = str(request.get("text", ""))
            if not text:
                raise ValueError("text 不能为空")
            try:
                result = service.send_secret_proxy(text)
            except Exception as exc:
                try:
                    configure_s1_round_robin_for_business()
                except Exception:
                    pass
                service.last_strategy = {
                    "success": False,
                    "hidden_match": False,
                    "error": str(exc),
                    "timestamp": time.time(),
                    "plan_text": service.current_strategy.get("plan_text", ""),
                    "session_id": service.current_strategy.get("session_id"),
                }
                service.set_current_strategy(
                    active=False,
                    stage="error",
                    message=f"最近一次隐蔽发送失败：{exc}",
                    chunk_id=None,
                    strategy_id=None,
                    strategy_name="",
                    paths=[],
                    packets=0,
                )
                raise
            return {"ok": True, "result": result}
        if action == "results":
            return {"ok": True, "results": service.latest_results[-50:]}
        if action == "set_links":
            links = request.get("links", [])
            if not isinstance(links, list):
                raise ValueError("links 必须是列表")
            return service.set_links(links)
        if action == "shutdown":
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return {"ok": True, "message": "服务正在退出"}
        raise ValueError(f"未知 action: {action}")


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def main() -> int:
    args = parse_args()
    service = DemoService(args)
    server = None
    try:
        service.start()
        server = ThreadedServer((args.host, args.port), RequestHandler)
        server.service = service  # type: ignore[attr-defined]
        print(f"[topology] 用户演示服务已启动：{args.host}:{args.port}")
        print("[topology] 其他窗口现在可以运行 sender_window.py / receiver_window.py / link_status_window.py")
        server.serve_forever()
        return 0
    finally:
        if server is not None:
            server.server_close()
        service.stop()
        print(f"[topology] 结果目录：{RESULTS_DIR}")


if __name__ == "__main__":
    raise SystemExit(main())
