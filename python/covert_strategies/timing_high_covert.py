"""
策略0：高隐蔽相对时序信道。

每个隐蔽比特由两个连续间隔的大小关系表示：
0 = 短间隔后接长间隔，1 = 长间隔后接短间隔。
业务UDP载荷前两个字节使用方案B同步标签，用来在轻微丢包后重新对齐符号索引。
"""

from typing import Dict, List, Optional

from .base import CovertStrategy, PacketSpec, StrategyMetrics, PathState, StrategyID
from .strategy_registry import register_strategy
from .timing_sync_tag import ANCHOR_PHASE, build_timing_tag, parse_timing_tag


@register_strategy
class TimingHighCovertStrategy(CovertStrategy):
    """高隐蔽相对时序策略。"""

    strategy_id = StrategyID.TIMING_HIGH_COVERT
    name = "timing_high_covert"
    description = "用两个连续间隔的相对大小承载1 bit，并用2字节标签避免丢包后整体错位。"

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config)
        self._short_gap_ms = float(
            self._config.get("short_gap_ms", self._config.get("gap_0_ms", 30))
        )
        self._long_gap_ms = float(
            self._config.get("long_gap_ms", self._config.get("gap_1_ms", 90))
        )
        if self._long_gap_ms <= self._short_gap_ms:
            self._long_gap_ms = self._short_gap_ms + 20.0
        self._min_relation_delta_ms = float(
            self._config.get(
                "min_relation_delta_ms",
                max(5.0, (self._long_gap_ms - self._short_gap_ms) * 0.25),
            )
        )
        self._max_jitter_tolerance_ms = float(
            self._config.get("max_jitter_tolerance_ms", 15)
        )
        self._sync_key = int(self._config.get("sync_key", 0x5A17))
        self._business_payload_len = max(2, int(self._config.get("business_payload_len", 32)))
        self._expected_bytes = self._config.get("expected_bytes")
        self.last_decode_info: Dict[str, object] = {}

    def encode(
        self, data: bytes, path_id: int, seq_num: int = 0
    ) -> List[PacketSpec]:
        """将隐蔽数据编码为承载业务流的包序列。"""
        bit_string = self._bytes_to_bits(data)
        total_bits = len(bit_string)
        total_fragments = 1 + total_bits * 2
        packets: List[PacketSpec] = [
            PacketSpec(
                payload=self._build_business_payload(seq_num, ANCHOR_PHASE, 0, 0),
                sequence_num=seq_num,
                fragment_id=0,
                total_fragments=total_fragments,
                send_delay_ms=0.0,
                path_id=path_id,
                strategy_id=int(self.strategy_id),
            )
        ]

        fragment_id = 1
        for bit_index, bit_char in enumerate(bit_string):
            bit = int(bit_char)
            first_delay, second_delay = (
                (self._short_gap_ms, self._long_gap_ms)
                if bit == 0
                else (self._long_gap_ms, self._short_gap_ms)
            )
            for phase, delay_ms in ((0, first_delay), (1, second_delay)):
                packets.append(
                    PacketSpec(
                        payload=self._build_business_payload(seq_num, phase, bit_index, fragment_id),
                        sequence_num=seq_num,
                        fragment_id=fragment_id,
                        total_fragments=total_fragments,
                        send_delay_ms=delay_ms,
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
        """按同步标签重组符号，再根据局部间隔关系恢复比特。"""
        if metadata is None or not packets:
            self.last_decode_info = {"complete": False, "reason": "没有可用的接收时间戳"}
            return None

        symbols: Dict[int, Dict[int, float]] = {}
        anchors: List[float] = []
        tagged_packets = 0
        for payload, meta in zip(packets, metadata):
            tag = parse_timing_tag(payload, int(self.strategy_id), self._sync_key)
            if tag is None:
                continue
            tagged_packets += 1
            arrival = float(meta.get("arrival_time_ms", 0.0))
            if tag.phase == ANCHOR_PHASE:
                anchors.append(arrival)
            else:
                phases = symbols.setdefault(tag.symbol_index, {})
                phases[tag.phase] = min(phases.get(tag.phase, arrival), arrival)

        total_bits = self._expected_total_bits(symbols)
        if total_bits <= 0:
            self.last_decode_info = {
                "complete": False,
                "reason": "没有解析到同步标签",
                "packets_seen": len(packets),
                "tagged_packets": tagged_packets,
            }
            return None

        anchor_time = min(anchors) if anchors else None
        bits: List[str] = []
        unknown_bits: List[int] = []
        decoded_bits: List[int] = []
        for bit_index in range(total_bits):
            phases = symbols.get(bit_index, {})
            previous_time = anchor_time if bit_index == 0 else symbols.get(bit_index - 1, {}).get(1)
            first_time = phases.get(0)
            second_time = phases.get(1)
            if previous_time is None or first_time is None or second_time is None:
                bits.append("0")
                unknown_bits.append(bit_index)
                continue
            first_gap = first_time - previous_time
            second_gap = second_time - first_time
            if first_gap <= 0 or second_gap <= 0:
                bits.append("0")
                unknown_bits.append(bit_index)
                continue
            if abs(first_gap - second_gap) < self._min_relation_delta_ms:
                bits.append("0")
                unknown_bits.append(bit_index)
                continue
            bit = "0" if first_gap < second_gap else "1"
            bits.append(bit)
            decoded_bits.append(bit_index)

        data = self._bits_to_bytes("".join(bits))
        expected_bytes = self._expected_total_bytes(total_bits)
        if expected_bytes is not None:
            data = data[:expected_bytes]

        self.last_decode_info = {
            "scheme": "B-2byte-sync-tag",
            "complete": len(unknown_bits) == 0,
            "total_bits": total_bits,
            "decoded_bits": len(decoded_bits),
            "unknown_bits": unknown_bits,
            "packets_seen": len(packets),
            "tagged_packets": tagged_packets,
        }
        self._bytes_decoded += len(data)
        return data

    def get_metrics(self, network_state: PathState) -> StrategyMetrics:
        """估计当前网络状态下该策略的性能指标。"""
        avg_gap_ms = (self._short_gap_ms + self._long_gap_ms) / 2.0
        capacity = 1000.0 / avg_gap_ms if avg_gap_ms > 0 else 0.0

        if network_state.jitter_ms < 5:
            covertness = 0.96
        elif network_state.jitter_ms < self._max_jitter_tolerance_ms:
            covertness = 0.88
        else:
            covertness = 0.64

        if network_state.jitter_ms <= self._max_jitter_tolerance_ms:
            reliability = 0.95 - (network_state.jitter_ms / self._max_jitter_tolerance_ms) * 0.28
        else:
            reliability = max(
                0.08,
                0.67 - (network_state.jitter_ms - self._max_jitter_tolerance_ms) / 20.0 * 0.5,
            )

        if network_state.loss_rate > 0.01:
            reliability *= 0.55

        return StrategyMetrics(
            covertness_score=covertness,
            capacity_bps=capacity,
            reliability_score=max(0.0, min(1.0, reliability)),
            delay_tolerance_ms=self._max_jitter_tolerance_ms,
            loss_tolerance=0.03,
        )

    def _build_business_payload(
        self, seq_num: int, phase: int, symbol_index: int, fragment_id: int
    ) -> bytes:
        tag = build_timing_tag(
            frame_id=seq_num,
            strategy_id=int(self.strategy_id),
            phase=phase,
            symbol_index=symbol_index,
            sync_key=self._sync_key,
        )
        filler_len = max(0, self._business_payload_len - len(tag))
        filler = bytes(((seq_num * 17 + fragment_id * 31 + i) & 0xFF) for i in range(filler_len))
        return tag + filler

    def _expected_total_bits(self, symbols: Dict[int, Dict[int, float]]) -> int:
        if self._expected_bytes is not None:
            return max(0, int(self._expected_bytes) * 8)
        if not symbols:
            return 0
        return max(symbols.keys()) + 1

    def _expected_total_bytes(self, total_bits: int) -> Optional[int]:
        if self._expected_bytes is not None:
            return int(self._expected_bytes)
        return (total_bits + 7) // 8

    @staticmethod
    def _bytes_to_bits(data: bytes) -> str:
        return "".join(format(b, "08b") for b in data)

    @staticmethod
    def _bits_to_bytes(bits: str) -> bytes:
        padded = bits + "0" * ((8 - len(bits) % 8) % 8)
        return bytes(int(padded[i : i + 8], 2) for i in range(0, len(padded), 8))
