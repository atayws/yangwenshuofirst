#!/usr/bin/env python3
"""
接收端实时显示窗口。

该窗口轮询拓扑服务的解码历史，只显示新的 session 解码结果。
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.user_demo.demo_client import DEFAULT_HOST, DEFAULT_PORT, request


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="隐蔽数据接收端实时显示窗口")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--interval", type=float, default=1.0)
    return parser.parse_args()


def print_result(result: dict) -> None:
    print("\n[接收端解码结果]")
    print(f"session_id: {result.get('session_id')}")
    print(f"成功: {result.get('success')}  比对一致: {result.get('hidden_match')}")
    print(f"误码率: {float(result.get('bit_error_rate', 1.0)):.4%}  "
          f"错误bit: {result.get('bit_errors', '-')} / {result.get('total_bits', '-')}")
    print(f"解码文本: {result.get('decoded_text')}")


def main() -> int:
    args = parse_args()
    seen = set()
    print("[接收端窗口] 等待 h2 解码结果，Ctrl+C 退出。")
    try:
        while True:
            try:
                response = request("results", host=args.host, port=args.port, timeout=5.0)
                for result in response.get("results", []):
                    session_id = result.get("session_id")
                    if session_id in seen:
                        continue
                    seen.add(session_id)
                    print_result(result)
            except Exception as exc:
                print(f"[等待服务] {exc}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[接收端窗口] 已退出。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
