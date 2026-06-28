"""
策略3：统计分布包长隐蔽信道。

该策略仍然以 UDP/IP 包长作为主要隐蔽载体，但相比早期“一个区间直接表示 2 bit”的方案，
当前版本加入数据白化、帧同步、重复投票、伪随机区间映射和块认证，避免普通丢包或乱序导致整体失步。
"""

import hashlib
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .base import CovertStrategy, PacketSpec, StrategyMetrics, PathState, StrategyID
from .strategy_registry import register_strategy


DEFAULT_LENGTH_BANDS = [
    (96, 160),
    (320, 520),
    (720, 940),
    (1100, 1360),
]

HEADER_LEN = 12
HEADER_MAGIC = b"S3"
HEADER_VERSION = 1
HEADER_FORMAT = "!2sBBHHHBB"


@dataclass(frozen=True)
class FusionTag:
    """策略3同步小头解析结果。"""

    seq_num: int
    symbol_index: int
    total_symbols: int
    total_bits: int
    repeat_index: int


@register_strategy
class StatisticalFusionStrategy(CovertStrategy):
    """基于包长区间分布拟合的隐蔽策略。"""

    strategy_id = StrategyID.STATISTICAL_FUSION
    name = "statistical_fusion"
    description = (
        "统计分布包长编码：数据白化后映射到多个包长区间，"
        "使用加密同步小头、重复投票和伪随机区间映射提高隐蔽性与稳健性。"
    )

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config)
        self._wire_header_overhead = int(self._config.get("header_overhead_bytes", 40))
        self._min_band_gap_bytes = int(self._config.get("min_band_gap_bytes", 24))
        self._classification_margin_bytes = int(
            self._config.get("classification_margin_bytes", 80)
        )
        self._length_bands = self._normalize_bands(
            self._config.get("length_bands", DEFAULT_LENGTH_BANDS)
        )
        self._bits_per_packet = min(2, max(1, (len(self._length_bands) - 1).bit_length()))
        self._symbol_count = 1 << self._bits_per_packet
        self._repeat_count = max(1, int(self._config.get("repeat_count", 3)))
        self._edge_guard_bytes = int(self._config.get("edge_guard_bytes", 12))
        key = self._config.get("secret_key", b"low-altitude-statistical-fusion-v2")
        if isinstance(key, str):
            key = key.encode("utf-8")
        self._secret_key = key
        self.last_decode_info: Dict[str, object] = {}

    def encode(
        self, data: bytes, path_id: int, seq_num: int = 0
    ) -> List[PacketSpec]:
        """将原始数据编码为带同步小头的包长区间序列。"""
        whitened = self._whiten_bytes(data, seq_num)
        bit_string = self._bytes_to_bits(whitened)
        total_bits = len(self._bytes_to_bits(data))
        padding = (-len(bit_string)) % self._bits_per_packet
        if padding:
            bit_string += "0" * padding

        total_symbols = len(bit_string) // self._bits_per_packet
        packets: List[PacketSpec] = []
        fragment_id = 0

        for repeat_index in range(self._repeat_count):
            for symbol_index in range(total_symbols):
                start = symbol_index * self._bits_per_packet
                symbol_bits = bit_string[start : start + self._bits_per_packet]
                plain_symbol = int(symbol_bits, 2)
                band_symbol = self._symbol_to_band(plain_symbol, seq_num)
                target_len = self._pick_length_in_band(
                    band_symbol, seq_num, symbol_index, repeat_index, path_id
                )
                payload = self._build_fusion_payload(
                    seq_num=seq_num,
                    symbol_index=symbol_index,
                    total_symbols=total_symbols,
                    total_bits=total_bits,
                    repeat_index=repeat_index,
                    target_packet_length=target_len,
                )

                packets.append(
                    PacketSpec(
                        payload=payload,
                        sequence_num=seq_num,
                        fragment_id=fragment_id,
                        total_fragments=total_symbols * self._repeat_count,
                        is_redundant=repeat_index > 0,
                        target_packet_length=target_len,
                        path_id=path_id,
                        strategy_id=int(self.strategy_id),
                    )
                )
                fragment_id += 1

        self._bytes_encoded += len(data)
        return packets

    def decode(
        self,
        packets: List[bytes],
        metadata: Optional[List[dict]] = None,
    ) -> Optional[bytes]:
        """根据包长区间投票恢复隐蔽比特。"""
        if not packets:
            self.last_decode_info = {"complete": False, "reason": "没有收到策略3候选包"}
            return None

        votes: Dict[int, Dict[int, float]] = {}
        total_symbols = None
        total_bits = None
        seq_num = None
        tagged_packets = 0
        unclassified_packets = 0

        for index, pkt in enumerate(packets):
            tag = self._parse_tag(pkt[:HEADER_LEN])
            if tag is None:
                continue
            tagged_packets += 1
            pkt_len = self._get_wire_length(pkt, metadata, index)
            band_symbol, confidence = self._classify_packet_length_with_confidence(pkt_len)
            if band_symbol is None:
                unclassified_packets += 1
                continue

            if total_symbols is None:
                total_symbols = tag.total_symbols
                total_bits = tag.total_bits
                seq_num = tag.seq_num
            if tag.total_symbols != total_symbols or tag.total_bits != total_bits:
                continue

            plain_symbol = self._band_to_symbol(band_symbol, tag.seq_num)
            symbol_votes = votes.setdefault(tag.symbol_index, {})
            symbol_votes[plain_symbol] = symbol_votes.get(plain_symbol, 0.0) + confidence

        if total_symbols is None or total_bits is None or seq_num is None:
            self.last_decode_info = {
                "complete": False,
                "reason": "没有解析到有效同步小头",
                "packets_seen": len(packets),
                "tagged_packets": tagged_packets,
            }
            return None

        bits: List[str] = []
        missing_symbols: List[int] = []
        low_confidence_symbols: List[int] = []
        decoded_symbols = 0
        for symbol_index in range(total_symbols):
            symbol_votes = votes.get(symbol_index, {})
            if not symbol_votes:
                bits.append("0" * self._bits_per_packet)
                missing_symbols.append(symbol_index)
                continue
            sorted_votes = sorted(symbol_votes.items(), key=lambda item: item[1], reverse=True)
            best_symbol, best_score = sorted_votes[0]
            second_score = sorted_votes[1][1] if len(sorted_votes) > 1 else 0.0
            if best_score <= second_score:
                low_confidence_symbols.append(symbol_index)
            bits.append(format(best_symbol, f"0{self._bits_per_packet}b"))
            decoded_symbols += 1

        bit_string = "".join(bits)[:total_bits]
        whitened = self._bits_to_bytes(bit_string)
        data = self._whiten_bytes(whitened, seq_num)
        original_len = (total_bits + 7) // 8
        data = data[:original_len]

        self._bytes_decoded += len(data)
        self.last_decode_info = {
            "scheme": "strategy3-statistical-length-v2",
            "complete": len(missing_symbols) == 0,
            "total_symbols": total_symbols,
            "decoded_symbols": decoded_symbols,
            "missing_symbols": missing_symbols,
            "low_confidence_symbols": low_confidence_symbols,
            "packets_seen": len(packets),
            "tagged_packets": tagged_packets,
            "unclassified_packets": unclassified_packets,
            "repeat_count": self._repeat_count,
        }
        return data

    def get_metrics(self, network_state: PathState) -> StrategyMetrics:
        """估计当前网络状态下该策略的性能指标。"""
        avg_packet_len = sum((low + high) / 2 for low, high in self._length_bands) / len(
            self._length_bands
        )
        capacity = 8.0 * self._bits_per_packet * 1000.0 / max(
            1.0, avg_packet_len * self._repeat_count
        )

        if 0.25 <= network_state.bw_utilization <= 0.75:
            covertness = 0.88
        elif network_state.bw_utilization < 0.15 or network_state.bw_utilization > 0.9:
            covertness = 0.60
        else:
            covertness = 0.76

        reliability = 0.94
        if network_state.loss_rate > 0.10:
            reliability = max(0.35, 0.94 - network_state.loss_rate * 3.2)
        elif network_state.loss_rate > 0.03:
            reliability = 0.90 - network_state.loss_rate

        if network_state.jitter_ms > 50:
            covertness = max(0.52, covertness - 0.06)

        return StrategyMetrics(
            covertness_score=covertness,
            capacity_bps=capacity,
            reliability_score=max(0.0, min(1.0, reliability)),
            delay_tolerance_ms=220.0,
            loss_tolerance=0.18,
        )

    @staticmethod
    def _bytes_to_bits(data: bytes) -> str:
        return "".join(format(b, "08b") for b in data)

    @staticmethod
    def _bits_to_bytes(bits: str) -> bytes:
        padded = bits + "0" * ((8 - len(bits) % 8) % 8)
        return bytes(int(padded[i : i + 8], 2) for i in range(0, len(padded), 8))

    def _build_fusion_payload(
        self,
        seq_num: int,
        symbol_index: int,
        total_symbols: int,
        total_bits: int,
        repeat_index: int,
        target_packet_length: int,
    ) -> bytes:
        tag = self._build_tag(seq_num, symbol_index, total_symbols, total_bits, repeat_index)
        payload_size = max(len(tag), target_packet_length - self._wire_header_overhead)
        padding_needed = payload_size - len(tag)
        padding = self._padding_bytes(seq_num, symbol_index, repeat_index, padding_needed)
        return tag + padding

    def _build_tag(
        self,
        seq_num: int,
        symbol_index: int,
        total_symbols: int,
        total_bits: int,
        repeat_index: int,
    ) -> bytes:
        clear_without_auth = struct.pack(
            "!2sBBHHHB",
            HEADER_MAGIC,
            HEADER_VERSION,
            seq_num & 0xFF,
            symbol_index & 0xFFFF,
            total_symbols & 0xFFFF,
            total_bits & 0xFFFF,
            repeat_index & 0xFF,
        )
        auth = self._tag_auth(clear_without_auth)
        clear = clear_without_auth + bytes([auth])
        return self._xor_bytes(clear, self._header_mask())

    def _parse_tag(self, raw: bytes) -> Optional[FusionTag]:
        if len(raw) < HEADER_LEN:
            return None
        clear = self._xor_bytes(raw[:HEADER_LEN], self._header_mask())
        try:
            magic, version, seq_num, symbol_index, total_symbols, total_bits, repeat_index, auth = struct.unpack(
                HEADER_FORMAT, clear
            )
        except struct.error:
            return None
        if magic != HEADER_MAGIC or version != HEADER_VERSION:
            return None
        if self._tag_auth(clear[:-1]) != auth:
            return None
        if total_symbols == 0 or symbol_index >= total_symbols:
            return None
        return FusionTag(
            seq_num=seq_num,
            symbol_index=symbol_index,
            total_symbols=total_symbols,
            total_bits=total_bits,
            repeat_index=repeat_index,
        )

    def _pick_length_in_band(
        self, symbol: int, seq_num: int, symbol_index: int, repeat_index: int, path_id: int
    ) -> int:
        low, high = self._length_bands[symbol]
        guarded_low = min(high, low + self._edge_guard_bytes)
        guarded_high = max(guarded_low, high - self._edge_guard_bytes)
        span = guarded_high - guarded_low + 1
        seed_material = (
            self._secret_key
            + b"len"
            + bytes([seq_num & 0xFF, symbol & 0x03, repeat_index & 0xFF, path_id & 0xFF])
            + int(symbol_index & 0xFFFF).to_bytes(2, "big")
        )
        seed = int.from_bytes(hashlib.blake2s(seed_material, digest_size=4).digest(), "big")
        return guarded_low + (seed % span)

    def _classify_packet_length(self, pkt_len: int) -> Optional[int]:
        symbol, _confidence = self._classify_packet_length_with_confidence(pkt_len)
        return symbol

    def _classify_packet_length_with_confidence(self, pkt_len: int) -> Tuple[Optional[int], float]:
        nearest_symbol = None
        nearest_distance = float("inf")
        nearest_half_width = 1.0

        for symbol, (low, high) in enumerate(self._length_bands[: self._symbol_count]):
            center = (low + high) / 2
            half_width = max(1.0, (high - low) / 2)
            if low <= pkt_len <= high:
                distance = abs(pkt_len - center)
                confidence = max(0.25, 1.0 - distance / (half_width + self._classification_margin_bytes))
                return symbol, confidence
            distance = abs(pkt_len - center)
            if distance < nearest_distance:
                nearest_symbol = symbol
                nearest_distance = distance
                nearest_half_width = half_width

        if nearest_distance <= nearest_half_width + self._classification_margin_bytes:
            confidence = max(0.10, 1.0 - nearest_distance / (nearest_half_width + self._classification_margin_bytes))
            return nearest_symbol, confidence
        return None, 0.0

    def _get_wire_length(
        self, packet: bytes, metadata: Optional[List[dict]], index: int
    ) -> int:
        if metadata and index < len(metadata):
            meta = metadata[index]
            for key in ("packet_length", "wire_length", "target_packet_length"):
                if key in meta and meta[key] is not None:
                    return int(meta[key])
        return len(packet) + self._wire_header_overhead

    def _normalize_bands(self, raw_bands) -> List[tuple]:
        bands = []
        for item in raw_bands:
            if len(item) != 2:
                continue
            low, high = int(item[0]), int(item[1])
            if high <= low:
                continue
            min_packet_len = self._wire_header_overhead + HEADER_LEN
            low = max(low, int(min_packet_len))
            high = max(high, low + self._min_band_gap_bytes)
            bands.append((low, high))

        if len(bands) < 4:
            bands = DEFAULT_LENGTH_BANDS[:]
        bands = sorted(bands)[:4]

        fixed_bands = []
        previous_high = 0
        for low, high in bands:
            if low <= previous_high + self._min_band_gap_bytes:
                low = previous_high + self._min_band_gap_bytes + 1
                high = max(high, low + self._min_band_gap_bytes)
            fixed_bands.append((low, high))
            previous_high = high
        return fixed_bands

    def _symbol_to_band(self, symbol: int, seq_num: int) -> int:
        perm = self._symbol_permutation(seq_num)
        return perm[symbol]

    def _band_to_symbol(self, band_symbol: int, seq_num: int) -> int:
        perm = self._symbol_permutation(seq_num)
        reverse = {band: symbol for symbol, band in enumerate(perm)}
        return reverse[band_symbol]

    def _symbol_permutation(self, seq_num: int) -> List[int]:
        values = list(range(self._symbol_count))
        seed = int.from_bytes(
            hashlib.blake2s(
                self._secret_key + b"perm" + bytes([seq_num & 0xFF]),
                digest_size=4,
            ).digest(),
            "big",
        )
        for idx in range(len(values) - 1, 0, -1):
            seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
            swap_idx = seed % (idx + 1)
            values[idx], values[swap_idx] = values[swap_idx], values[idx]
        return values

    def _whiten_bytes(self, data: bytes, seq_num: int) -> bytes:
        stream = bytearray()
        counter = 0
        while len(stream) < len(data):
            material = (
                self._secret_key
                + b"white"
                + bytes([seq_num & 0xFF])
                + counter.to_bytes(4, "big")
            )
            stream.extend(hashlib.blake2s(material, digest_size=32).digest())
            counter += 1
        return bytes(value ^ stream[index] for index, value in enumerate(data))

    def _padding_bytes(self, seq_num: int, symbol_index: int, repeat_index: int, length: int) -> bytes:
        output = bytearray()
        counter = 0
        while len(output) < length:
            material = (
                self._secret_key
                + b"pad"
                + bytes([seq_num & 0xFF, repeat_index & 0xFF])
                + int(symbol_index & 0xFFFF).to_bytes(2, "big")
                + counter.to_bytes(2, "big")
            )
            output.extend(hashlib.blake2s(material, digest_size=32).digest())
            counter += 1
        return bytes(output[:length])

    def _header_mask(self) -> bytes:
        return hashlib.blake2s(self._secret_key + b"header-mask", digest_size=HEADER_LEN).digest()

    def _tag_auth(self, clear_without_auth: bytes) -> int:
        return hashlib.blake2s(self._secret_key + b"tag-auth" + clear_without_auth, digest_size=1).digest()[0]

    @staticmethod
    def _xor_bytes(data: bytes, mask: bytes) -> bytes:
        return bytes(value ^ mask[index % len(mask)] for index, value in enumerate(data))

    @staticmethod
    def _extract_total_bytes(packets: List[bytes]) -> Optional[int]:
        """兼容旧接口：新版解码从同步小头读取长度，该函数仅保留给外部调用。"""
        return None
