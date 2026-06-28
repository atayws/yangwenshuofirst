#!/usr/bin/env python3
"""
链路状态设置工具。

支持两种用法：
1. 一次性设置：
   python3 experiments/user_demo/link_config_tool.py 1 20 10 2 10 20 3 30 30
   表示 path0 delay=20ms loss=10%，path1 delay=10ms loss=20%，path2 delay=30ms loss=30%。

2. 交互设置：
   python3 experiments/user_demo/link_config_tool.py
   然后输入同样的三元组，输入 /quit 退出。
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.user_demo.demo_client import DEFAULT_HOST, DEFAULT_PORT, request


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="设置三条链路的时延和丢包率")
    parser.add_argument("values", nargs="*", help="三元组：链路编号 delay_ms loss_percent")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    return parser.parse_args()


def parse_values(values: list[str]) -> list[dict]:
    """把三元组参数转换成服务可识别的 links 列表。"""

    if len(values) % 3 != 0 or not values:
        raise ValueError("请输入三元组：链路编号 delay_ms loss_percent，例如：1 20 10 2 10 20 3 30 30")
    links = []
    for index in range(0, len(values), 3):
        raw_path = int(values[index])
        delay_ms = float(values[index + 1])
        loss_percent = float(values[index + 2])
        links.append({
            "path": raw_path,
            "delay_ms": delay_ms,
            "loss_percent": loss_percent,
        })
    return links


def apply_links(args: argparse.Namespace, links: list[dict]) -> None:
    response = request(
        "set_links",
        {"links": links},
        host=args.host,
        port=args.port,
        timeout=20.0,
    )
    print("[链路设置完成]")
    for item in response.get("applied", []):
        print(
            f"path{item['path']}: delay={item['delay_ms']}ms "
            f"loss={item['loss_percent']}%"
        )


def main() -> int:
    args = parse_args()
    if args.values:
        apply_links(args, parse_values(args.values))
        return 0

    print("[链路设置窗口] 输入：链路编号 delay_ms loss_percent，可一次设置多条。")
    print("例子：1 20 10 2 10 20 3 30 30；输入 /quit 退出。")
    while True:
        try:
            line = input("> ")
        except EOFError:
            break
        if line.strip() in {"/quit", "/exit"}:
            break
        if not line.strip():
            continue
        try:
            apply_links(args, parse_values(line.split()))
        except Exception as exc:
            print(f"[设置失败] {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
