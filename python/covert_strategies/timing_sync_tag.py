"""
策略0/1共用的两字节同步标签。

标签只用于接收端重同步和分组，不承载真正的隐蔽数据；隐蔽数据仍然由包间隔关系承载。
"""

from dataclasses import dataclass
from typing import Optional


ANCHOR_PHASE = 3


@dataclass(frozen=True)
class TimingSyncTag:
    """两字节同步标签解析结果。"""

    frame_id: int
    strategy_id: int
    phase: int
    symbol_index: int


def _mask0(sync_key: int) -> int:
    return ((sync_key & 0xFF) * 31 + 0x5A) & 0xFF


def _mask1(sync_key: int, clear_byte0: int) -> int:
    return (((sync_key >> 8) & 0xFF) + clear_byte0 * 29 + 0xC3) & 0xFF


def build_timing_tag(
    frame_id: int,
    strategy_id: int,
    phase: int,
    symbol_index: int,
    sync_key: int = 0x5A17,
) -> bytes:
    """
    生成方案B的两字节标签。

    明文字段布局：
    byte0 = frame_id(4 bit) + strategy_id(2 bit) + phase(2 bit)
    byte1 = symbol_index(8 bit)
    发送前做轻量异或混淆，避免抓包时直接出现连续明文字段。
    """
    clear0 = ((frame_id & 0x0F) << 4) | ((strategy_id & 0x03) << 2) | (phase & 0x03)
    clear1 = symbol_index & 0xFF
    return bytes((clear0 ^ _mask0(sync_key), clear1 ^ _mask1(sync_key, clear0)))


def parse_timing_tag(
    payload: bytes,
    expected_strategy_id: int,
    sync_key: int = 0x5A17,
) -> Optional[TimingSyncTag]:
    """从UDP业务载荷前两个字节解析同步标签。"""
    if len(payload) < 2:
        return None

    clear0 = payload[0] ^ _mask0(sync_key)
    clear1 = payload[1] ^ _mask1(sync_key, clear0)
    strategy_id = (clear0 >> 2) & 0x03
    if strategy_id != (expected_strategy_id & 0x03):
        return None

    return TimingSyncTag(
        frame_id=(clear0 >> 4) & 0x0F,
        strategy_id=strategy_id,
        phase=clear0 & 0x03,
        symbol_index=clear1,
    )
