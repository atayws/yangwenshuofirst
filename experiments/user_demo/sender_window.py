#!/usr/bin/env python3
"""
发送端窗口。

启动后输入任意隐蔽文本，回车后交给拓扑服务发送；输入 /quit 退出。
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
    parser = argparse.ArgumentParser(description="隐蔽数据发送端窗口")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--text", default=None, help="非交互模式：发送一条文本后退出")
    return parser.parse_args()


def print_result(result: dict) -> None:
    print(
        f"[发送完成] session={result.get('session_id')} "
        f"成功={result.get('success')}  误码率={float(result.get('bit_error_rate', 1.0)):.4%}"
    )


def send_text(args: argparse.Namespace, text: str) -> None:
    response = request(
        "send",
        {"text": text},
        host=args.host,
        port=args.port,
        timeout=300.0,
    )
    print_result(response["result"])


def main() -> int:
    args = parse_args()
    print("[发送端窗口] 输入隐蔽数据后回车发送，输入 /quit 退出。")
    print("提示：只输入 0/1 时会按真正 bit 串发送，例如 101 就是 3 bit。")
    if args.text is not None:
        send_text(args, args.text)
        return 0

    while True:
        try:
            text = input("> ")
        except EOFError:
            break
        if text.strip() in {"/quit", "/exit"}:
            break
        if not text:
            continue
        try:
            send_text(args, text)
        except Exception as exc:
            print(f"[发送失败] {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
