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
    parser.add_argument("--interval", type=float, default=2.0)
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
    return ",".join(f"path{path}" for path in paths)


def fmt_strategy(strategy_id: object, strategy_name: object = "") -> str:
    if strategy_id is None:
        return "-"
    name = str(strategy_name or "").strip()
    if name:
        return f"策略{strategy_id}({name})"
    return f"策略{strategy_id}"


def draw_running_strategy(status: dict) -> None:
    current = status.get("current_strategy", {}) or {}
    last = status.get("last_strategy", {}) or {}
    print("实时运行策略:")
    if current.get("active"):
        print(
            f"  状态: {current.get('stage')}  "
            f"session={current.get('session_id')}  "
            f"chunk={current.get('chunk_id')}  "
            f"{fmt_strategy(current.get('strategy_id'), current.get('strategy_name'))}  "
            f"paths={fmt_paths(current.get('paths'))}  "
            f"packets={current.get('packets', '-')}"
        )
        print(f"  说明: {current.get('message', '-')}")
        print(f"  本轮计划: {current.get('plan_text') or '-'}")
        return

    print(f"  当前: {current.get('message') or '当前没有隐蔽数据发送，普通业务流按三路径轮询运行'}")
    if last:
        print(
            f"  最近完成: session={last.get('session_id')}  "
            f"success={last.get('success')}  "
            f"hidden_match={last.get('hidden_match')}  "
            f"计划={last.get('plan_text') or '-'}"
        )


def draw(status: dict, no_clear: bool) -> None:
    if not no_clear:
        os.system("clear")
    print("[链路状态窗口] Ctrl+C 退出")
    print(f"业务流状态 iperf_ok: {status.get('iperf_ok')}  INT成功: {status.get('int_success')}  INT报告数: {status.get('int_parsed_reports')}")
    print(f"结果目录: {status.get('results_dir')}")
    print()
    print("路径  设置delay/loss        INT delay   jitter    loss       bw利用率   qdepth   样本")
    print("-" * 86)
    states = status.get("path_states", {}) or {}
    counts = status.get("metric_sample_counts", {}) or {}
    configs = status.get("link_config", {}) or {}
    for path_id in range(3):
        state = states.get(str(path_id), {}) or states.get(path_id, {}) or {}
        config = configs.get(str(path_id), {}) or configs.get(path_id, {}) or {}
        print(
            f"path{path_id} "
            f"{fmt_float(config.get('delay_ms'), 1):>6}ms/{fmt_float(config.get('loss_percent'), 1):>5}% "
            f"{fmt_float(state.get('delay_ms')):>10} "
            f"{fmt_float(state.get('jitter_ms')):>8} "
            f"{fmt_percent(state.get('loss_rate')):>9} "
            f"{fmt_percent(state.get('bw_utilization')):>10} "
            f"{fmt_float(state.get('qdepth_avg'), 1):>8} "
            f"{counts.get(str(path_id), counts.get(path_id, 0)):>6}"
        )
    print()
    draw_running_strategy(status)
    print()
    print("建议策略计划:")
    print(f"  {status.get('suggested_plan_text')}")
    for entry in status.get("suggested_plan", []):
        print(
            f"  - {entry.get('name')}: strategy={entry.get('strategy_id')} "
            f"paths={entry.get('paths')} weight={entry.get('weight')}"
        )


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
