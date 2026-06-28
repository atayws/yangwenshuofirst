"""
用户演示程序的公共客户端。

拓扑服务在本机 127.0.0.1 上提供一行 JSON 请求/响应接口。
其他窗口脚本只通过这个客户端发送命令，避免每个窗口都直接操作 Mininet。
"""

from __future__ import annotations

import json
import socket
from typing import Any, Dict


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 38765


def request(
    action: str,
    payload: Dict[str, Any] | None = None,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    timeout: float = 180.0,
) -> Dict[str, Any]:
    """向拓扑服务发送一个 JSON 命令并读取响应。"""

    message = {"action": action}
    if payload:
        message.update(payload)

    data = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
    with socket.create_connection((host, int(port)), timeout=timeout) as sock:
        sock.sendall(data)
        sock_file = sock.makefile("rb")
        line = sock_file.readline()
    if not line:
        raise RuntimeError("拓扑服务没有返回响应")
    response = json.loads(line.decode("utf-8"))
    if not response.get("ok", False):
        raise RuntimeError(str(response.get("error", "未知错误")))
    return response


def short_plan(plan: list[dict]) -> str:
    """把策略计划压缩成一行便于窗口显示。"""

    if not plan:
        return "(暂无策略计划)"
    parts = []
    for entry in plan:
        paths = ",".join(str(path) for path in entry.get("paths", []))
        parts.append(f"S{entry.get('strategy_id')}@[{paths}]x{entry.get('weight', 1)}")
    return " | ".join(parts)
