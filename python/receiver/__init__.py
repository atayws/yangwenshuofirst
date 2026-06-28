"""
接收端模块。

目前主要包含统一策略接收分发器，用于把抓包得到的业务包按策略编号分流，
再调用策略库完成解码。
"""

from .strategy_router import RouterDecodeResult, RoutedPacket, StrategyReceiverRouter

__all__ = [
    "RouterDecodeResult",
    "RoutedPacket",
    "StrategyReceiverRouter",
]
