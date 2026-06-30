#!/usr/bin/env python3
"""
链路状态与建议策略窗口。

周期显示 h1 解析出的 INT 链路状态，以及规则选择器建议的策略计划。
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.user_demo.demo_client import DEFAULT_HOST, DEFAULT_PORT, request


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="链路状态与建议策略窗口")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--no-clear", action="store_true")
    return parser.parse_args()


def fmt_percent(value: object) -> str:
    try:
        return f"{float(value) * 100:.2f}%"
    except (TypeError, ValueError):
        return "-"


def fmt_float(value: object, digits: int = 2) -> str:
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return "-"


def fmt_paths(paths: object) -> str:
    if not isinstance(paths, list) or not paths:
        return "-"
    return ",".join(f"链路{int(path) + 1}" for path in paths)


def fmt_strategy(strategy_id: object, strategy_name: object = "") -> str:
    if strategy_id is None:
        return "-"
    labels = {
        0: "策略0 相对时序",
        1: "策略1 排序时序",
        2: "策略2 IP-ID可靠",
        3: "策略3 包长统计",
        4: "策略4 喷泉多路径",
        5: "策略5 路径序列",
    }
    try:
        return labels.get(int(strategy_id), f"策略{strategy_id}")
    except (TypeError, ValueError):
        return f"策略{strategy_id}"


def draw_running_strategy(status: dict) -> None:
    current = status.get("current_strategy", {}) or {}
    last = status.get("last_strategy", {}) or {}
    print("实时运行策略:")
    if current.get("active"):
        print(
            f"session={current.get('session_id')}  "
            f"segment={current.get('chunk_id')}  "
            f"{fmt_strategy(current.get('strategy_id'), current.get('strategy_name'))}  "
            f"路径={fmt_paths(current.get('paths'))}"
        )
        config = current.get("strategy_config") or {}
        if config:
            if int(current.get("strategy_id") or -1) == 0:
                print(
                    "  自适应时序: "
                    f"短间隔={fmt_float(config.get('short_gap_ms'), 1)}ms  "
                    f"长间隔={fmt_float(config.get('long_gap_ms'), 1)}ms"
                )
            elif int(current.get("strategy_id") or -1) == 1:
                gaps = config.get("rank_gaps_ms") or []
                if gaps:
                    print(
                        "  自适应时序: 排序间隔="
                        + "/".join(f"{fmt_float(item, 1)}ms" for item in gaps)
                    )
        print(f"  说明: {current.get('message', '-')}")
        return

    print(f"  当前: {current.get('message') or '当前没有隐蔽数据发送，普通业务流按三路径轮询运行'}")
    if last:
        print(
            f"  最近完成: session={last.get('session_id')}  "
            f"success={last.get('success')}  "
            f"hidden_match={last.get('hidden_match')}  "
            f"误码率={float(last.get('bit_error_rate', 1.0)):.4%}"
        )


def draw_link_strategies(status: dict) -> None:
    print("当前建议策略:")
    items = status.get("per_link_strategy", []) or []
    if not items:
        print("  暂无 INT 状态，默认优先策略2。")
        return
    for item in items:
        path = int(item.get("path", 0)) + 1
        print(
            f"  链路{path}: {item.get('strategy_label', '-')}"
            f"  ({item.get('reason', '-')})"
        )


def draw(status: dict, no_clear: bool) -> None:
    if not no_clear:
        os.system("clear")
    print("[链路状态窗口] Ctrl+C 退出")
    print(f"业务流状态 iperf_ok: {status.get('iperf_ok')}  INT成功: {status.get('int_success')}  INT报告数: {status.get('int_parsed_reports')}")
    print(f"结果目录: {status.get('results_dir')}")
    print()
    print("路径  设置delay/loss        最新delay 最新loss   窗口delay 窗口loss   窗口收/发包     bw利用率   样本")
    print("-" * 104)
    states = status.get("path_states", {}) or {}
    raw_metrics = status.get("raw_metrics", {}) or {}
    counts = status.get("metric_sample_counts", {}) or {}
    configs = status.get("link_config", {}) or {}
    for path_id in range(3):
        state = states.get(str(path_id), {}) or states.get(path_id, {}) or {}
        raw = raw_metrics.get(str(path_id), {}) or raw_metrics.get(path_id, {}) or {}
        config = configs.get(str(path_id), {}) or configs.get(path_id, {}) or {}
        print(
            f"链路{path_id + 1} "
            f"{fmt_float(config.get('delay_ms'), 1):>6}ms/{fmt_float(config.get('loss_percent'), 1):>5}% "
            f"{fmt_float(float(raw.get('delay_us', 0.0)) / 1000.0 if raw else None):>9} "
            f"{fmt_percent(raw.get('loss_rate') if raw else None):>8} "
            f"{fmt_float(state.get('delay_ms')):>9} "
            f"{fmt_percent(state.get('loss_rate')):>8} "
            f"{int(state.get('loss_recv_delta', 0) or 0):>5}/{int(state.get('loss_sent_delta', 0) or 0):<5} "
            f"{fmt_percent(state.get('bw_utilization')):>10} "
            f"{counts.get(str(path_id), counts.get(path_id, 0)):>6}"
        )
    print()
    draw_link_strategies(status)
    print()
    draw_running_strategy(status)


def main() -> int:
    args = parse_args()
    try:
        while True:
            try:
                status = request("status", host=args.host, port=args.port, timeout=5.0)
                draw(status, args.no_clear)
            except Exception as exc:
                if not args.no_clear:
                    os.system("clear")
                print(f"[等待拓扑服务] {exc}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[链路状态窗口] 已退出。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
