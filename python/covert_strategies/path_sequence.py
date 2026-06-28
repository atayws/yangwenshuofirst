"""
策略5：多路径路径序列隐蔽信道。

该策略的真实隐蔽数据由路径排列承载。IP-ID 只写入轻量自描述信息：策略号、路径号和
片段低 8 位，帮助接收端识别策略5承载包并解决窗口顺序问题。
"""

import hashlib
import zlib
from typing import Dict, List, Optional, Tuple

from .base import CovertStrategy, PacketSpec, StrategyMetrics, PathState, StrategyID
from .strategy_registry import register_strategy


FRAME_MAGIC = b"P5"
FRAME_HEADER_BYTES = 8
STRATEGY5_VALID_MASK = 0x8000
STRATEGY5_STRATEGY_SHIFT = 12
STRATEGY5_PATH_SHIFT = 10
STRATEGY5_FRAGMENT_MASK = 0x03FF
DEFAULT_SYMBOL_MAP: Dict[int, Tuple[int, int, int]] = {
    0: (0, 1, 2),
    1: (0, 2, 1),
    2: (1, 0, 2),
    3: (1, 2, 0),
}
UNKNOWN_SYMBOL = -1


@register_strategy
class PathSequenceStrategy(CovertStrategy):
    """策略5：通过多路径排列序列承载隐蔽数据。"""

    strategy_id = StrategyID.PATH_SEQUENCE
    name = "path_sequence"
    description = "多路径路径序列信道：一个窗口内三条路径的排列表示2 bit，IP-ID只保存轻量路径/顺序提示。"

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config)
        key = self._config.get("secret_key", b"low-altitude-path-sequence-v1")
        if isinstance(key, str):
            key = key.encode("utf-8")
        self._secret_key = key
        self._payload_len = max(1, int(self._config.get("business_payload_len", 32)))
        self._expected_bytes = self._config.get("expected_bytes")
        self._symbol_map = DEFAULT_SYMBOL_MAP
        self._reverse_map = {value: key for key, value in self._symbol_map.items()}
        self.last_decode_info: Dict[str, object] = {}

    def encode(self, data: bytes, path_id: int = 0, seq_num: int = 0) -> List[PacketSpec]:
        """把隐蔽数据编码为路径排列窗口。"""
        framed = self._build_frame(data)
        symbols = self._bytes_to_2bit_symbols(framed)
        packets: List[PacketSpec] = []
        total_packets = len(symbols) * 3

        fragment_id = 0
        for symbol_index, symbol in enumerate(symbols):
            path_sequence = self._symbol_map[symbol]
            for slot_index, path in enumerate(path_sequence):
                packets.append(
                    PacketSpec(
                        payload=self._build_business_payload(seq_num, symbol_index, slot_index, fragment_id),
                        sequence_num=seq_num,
                        fragment_id=fragment_id,
                        total_fragments=total_packets,
                        path_id=path,
                        ip_id_field=self._pack_ip_id(path, fragment_id),
                        strategy_id=int(self.strategy_id),
                    )
                )
                fragment_id += 1

        self._bytes_encoded += len(data)
        return packets

    def decode(self, packets: List[bytes], metadata: Optional[List[dict]] = None) -> Optional[bytes]:
        """根据每个窗口内的 path_id 排列恢复隐蔽数据。"""
        if metadata is None:
            self.last_decode_info = {"complete": False, "reason": "缺少路径元数据"}
            return None

        windows: Dict[int, Dict[int, Dict[int, int]]] = {}
        inferred_windows = 0
        for index, meta in enumerate(metadata):
            window_id, slot_id = self._window_and_slot(index, meta)
            path = self._metadata_path(meta)
            if path is None:
                continue
            slot_votes = windows.setdefault(window_id, {}).setdefault(slot_id, {})
            slot_votes[path] = slot_votes.get(path, 0) + 1
            inferred_windows = max(inferred_windows, window_id + 1)

        if not windows:
            self.last_decode_info = {"complete": False, "reason": "没有可用路径序列"}
            return None

        symbols: List[int] = []
        unknown_symbols: List[int] = []
        for window_id in range(inferred_windows):
            slot_votes = windows.get(window_id, {})
            if len(slot_votes) != 3:
                symbols.append(UNKNOWN_SYMBOL)
                unknown_symbols.append(window_id)
                continue
            slots = {
                slot_id: sorted(votes.items(), key=lambda item: (-item[1], item[0]))[0][0]
                for slot_id, votes in slot_votes.items()
            }
            sequence = (slots.get(0), slots.get(1), slots.get(2))
            symbol = self._reverse_map.get(sequence)
            if symbol is None:
                symbols.append(UNKNOWN_SYMBOL)
                unknown_symbols.append(window_id)
            else:
                symbols.append(symbol)

        decoded = self._symbols_to_bytes(symbols)
        if len(decoded) < FRAME_HEADER_BYTES:
            self.last_decode_info = self._failure("帧头不足", symbols, unknown_symbols)
            return None
        if decoded[:2] != FRAME_MAGIC:
            self.last_decode_info = self._failure("帧头 magic 错误", symbols, unknown_symbols)
            return None

        original_len = int.from_bytes(decoded[2:4], "big")
        crc_expected = int.from_bytes(decoded[4:8], "big")
        needed_symbols = (FRAME_HEADER_BYTES + original_len) * 4
        complete = len(symbols) >= needed_symbols and not any(
            symbol == UNKNOWN_SYMBOL for symbol in symbols[:needed_symbols]
        )
        if not complete:
            self.last_decode_info = self._failure("可用路径窗口不足或存在未知符号", symbols, unknown_symbols, original_len)
            return decoded[FRAME_HEADER_BYTES:FRAME_HEADER_BYTES + original_len]

        framed = decoded[:FRAME_HEADER_BYTES + original_len]
        payload = framed[FRAME_HEADER_BYTES:]
        crc_actual = zlib.crc32(payload) & 0xFFFFFFFF
        if crc_actual != crc_expected:
            self.last_decode_info = self._failure("CRC 校验失败", symbols, unknown_symbols, original_len)
            return None

        self._bytes_decoded += len(payload)
        self.last_decode_info = {
            "scheme": "strategy5-path-sequence-v1",
            "complete": True,
            "decoded_bytes": len(payload),
            "total_windows": inferred_windows,
            "used_windows": needed_symbols,
            "unknown_symbols": unknown_symbols,
            "bits_per_window": 2,
            "packets_per_window": 3,
        }
        return payload

    def get_metrics(self, network_state: PathState) -> StrategyMetrics:
        """估计路径序列信道在当前链路状态下的性能。"""
        reliability = 0.92
        if network_state.loss_rate > 0.05:
            reliability -= min(0.45, network_state.loss_rate * 2.0)
        if network_state.jitter_ms > 20:
            reliability -= 0.08

        covertness = 0.88
        if network_state.bw_utilization > 0.75:
            covertness = 0.82

        return StrategyMetrics(
            covertness_score=max(0.0, min(1.0, covertness)),
            capacity_bps=120.0,
            reliability_score=max(0.0, min(1.0, reliability)),
            delay_tolerance_ms=250.0,
            loss_tolerance=0.08,
        )

    def _build_frame(self, data: bytes) -> bytes:
        """给隐蔽数据加长度和 CRC，避免路径窗口误判后静默输出错误数据。"""
        if len(data) > 0xFFFF:
            raise ValueError("策略5单次消息暂不支持超过 65535 字节")
        return FRAME_MAGIC + len(data).to_bytes(2, "big") + (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, "big") + data

    def _build_business_payload(self, seq_num: int, symbol_index: int, slot_index: int, fragment_id: int) -> bytes:
        """生成看起来像普通业务载荷的填充内容。"""
        material = (
            self._secret_key
            + b"payload"
            + int(seq_num & 0xFFFF).to_bytes(2, "big")
            + int(symbol_index & 0xFFFFFFFF).to_bytes(4, "big")
            + bytes([slot_index & 0x03, fragment_id & 0xFF])
        )
        output = bytearray()
        counter = 0
        while len(output) < self._payload_len:
            output.extend(hashlib.blake2s(material + counter.to_bytes(2, "big"), digest_size=32).digest())
            counter += 1
        return bytes(output[:self._payload_len])

    @staticmethod
    def _bytes_to_2bit_symbols(data: bytes) -> List[int]:
        symbols: List[int] = []
        for value in data:
            symbols.append((value >> 6) & 0x03)
            symbols.append((value >> 4) & 0x03)
            symbols.append((value >> 2) & 0x03)
            symbols.append(value & 0x03)
        return symbols

    @staticmethod
    def _symbols_to_bytes(symbols: List[int]) -> bytes:
        values = list(symbols)
        while len(values) % 4:
            values.append(0)
        output = bytearray()
        for index in range(0, len(values), 4):
            byte_value = 0
            for symbol in values[index:index + 4]:
                safe_symbol = 0 if symbol == UNKNOWN_SYMBOL else symbol
                byte_value = (byte_value << 2) | (safe_symbol & 0x03)
            output.append(byte_value)
        return bytes(output)

    def parse_ip_id(self, ip_id: int) -> Optional[dict]:
        """解析策略5的 IP-ID 自描述字段。"""
        return self._unpack_ip_id(ip_id)

    def _pack_ip_id(self, path_id: int, fragment_id: int) -> int:
        """把策略号、路径号和加密片段号写入 IP-ID，不直接写真实隐蔽数据。"""
        path_part = int(path_id) & 0x03
        fragment_mod = int(fragment_id) & STRATEGY5_FRAGMENT_MASK
        cipher_fragment = fragment_mod ^ self._fragment_mask(path_part)
        return (
            STRATEGY5_VALID_MASK
            | ((int(self.strategy_id) & 0x07) << STRATEGY5_STRATEGY_SHIFT)
            | (path_part << STRATEGY5_PATH_SHIFT)
            | (cipher_fragment & STRATEGY5_FRAGMENT_MASK)
        )

    def _unpack_ip_id(self, ip_id: int) -> Optional[dict]:
        """从 IP-ID 中恢复策略5自描述信息。"""
        value = int(ip_id) & 0xFFFF
        if (value & STRATEGY5_VALID_MASK) == 0:
            return None
        strategy_id = (value >> STRATEGY5_STRATEGY_SHIFT) & 0x07
        if strategy_id != int(self.strategy_id):
            return None
        path_id = (value >> STRATEGY5_PATH_SHIFT) & 0x03
        if path_id > 2:
            return None
        cipher_fragment = value & STRATEGY5_FRAGMENT_MASK
        fragment_id_mod = cipher_fragment ^ self._fragment_mask(path_id)
        return {
            "strategy_id": strategy_id,
            "path_id": path_id,
            "fragment_id_mod": fragment_id_mod,
            "cipher_fragment": cipher_fragment,
        }

    def _fragment_mask(self, path_id: int) -> int:
        """生成 10 bit 片段号扰动值，避免 IP-ID 低位直接线性递增。"""
        material = self._secret_key + b"ipid-fragment" + bytes([path_id & 0x03, int(self.strategy_id) & 0x07])
        return int.from_bytes(hashlib.blake2s(material, digest_size=2).digest(), "big") & STRATEGY5_FRAGMENT_MASK

    def _metadata_fragment_id(self, meta: dict) -> Optional[int]:
        fragment_id = meta.get("fragment_id")
        if fragment_id is not None:
            return int(fragment_id)
        parsed = self._metadata_ip_id(meta)
        if parsed is not None:
            return int(parsed["fragment_id_mod"])
        return None

    def _window_and_slot(self, index: int, meta: dict) -> Tuple[int, int]:
        fragment_id = self._metadata_fragment_id(meta)
        if fragment_id is None:
            return index // 3, index % 3
        return int(fragment_id) // 3, int(fragment_id) % 3

    def _metadata_path(self, meta: dict) -> Optional[int]:
        for key in ("path_id", "observed_path_id", "link_id"):
            value = meta.get(key)
            if value is not None:
                return int(value)
        parsed = self._metadata_ip_id(meta)
        if parsed is not None:
            return int(parsed["path_id"])
        return None

    def _metadata_ip_id(self, meta: dict) -> Optional[dict]:
        ip_id = meta.get("ip_id")
        if ip_id is None:
            ip_id = meta.get("ip_id_field")
        if ip_id is None:
            return None
        return self._unpack_ip_id(int(ip_id))

    def _failure(self, reason: str, symbols: List[int], unknown_symbols: List[int], original_len: Optional[int] = None) -> dict:
        return {
            "scheme": "strategy5-path-sequence-v1",
            "complete": False,
            "reason": reason,
            "decoded_bytes": 0 if original_len is None else int(original_len),
            "total_windows": len(symbols),
            "unknown_symbols": unknown_symbols,
            "bits_per_window": 2,
            "packets_per_window": 3,
        }
