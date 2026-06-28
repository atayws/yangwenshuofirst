"""
策略1：高容量排序时序信道。

每个2 bit符号由三个连续间隔的排序表示。
业务UDP载荷前两个字节使用方案B同步标签，用来在轻微丢包后按符号索引恢复同步。
"""

from typing import Dict, List, Optional, Tuple

from .base import CovertStrategy, PacketSpec, StrategyMetrics, PathState, StrategyID
from .strategy_registry import register_strategy
from .timing_sync_tag import ANCHOR_PHASE, build_timing_tag, parse_timing_tag


DEFAULT_GAPS_MS = [25.0, 60.0, 100.0]
SYMBOL_TO_ORDER = {
    0b00: (0, 1, 2),
    0b01: (0, 2, 1),
    0b10: (1, 0, 2),
    0b11: (2, 0, 1),
}
ORDER_TO_SYMBOL = {order: symbol for symbol, order in SYMBOL_TO_ORDER.items()}


@register_strategy
class TimingHighCapacityStrategy(CovertStrategy):
    """高容量排序时序策略。"""

    strategy_id = StrategyID.TIMING_HIGH_CAPACITY
    name = "timing_high_capacity"
    description = "用三个间隔的排序承载2 bit，并用2字节标签避免丢包后整体错位。"

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config)
        self._gaps_ms = self._normalize_gaps(
            self._config.get("rank_gaps_ms", self._config.get("levels_ms", DEFAULT_GAPS_MS))
        )
        self._min_rank_delta_ms = float(self._config.get("min_rank_delta_ms", 12))
        self._max_jitter_tolerance_ms = float(
            self._config.get("max_jitter_tolerance_ms", 10)
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
        if len(bit_string) % 2 != 0:
            bit_string += "0"

        total_symbols = len(bit_string) // 2
        total_fragments = 1 + total_symbols * 3
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
        for symbol_index in range(total_symbols):
            two_bits = bit_string[symbol_index * 2 : symbol_index * 2 + 2]
            symbol = int(two_bits, 2)
            delays = self._build_ordered_delays(SYMBOL_TO_ORDER[symbol])
            for phase, delay_ms in enumerate(delays):
                packets.append(
                    PacketSpec(
                        payload=self._build_business_payload(seq_num, phase, symbol_index, fragment_id),
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
        """按同步标签重组符号，再根据三个局部间隔的排序恢复2 bit。"""
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

        total_symbols = self._expected_total_symbols(symbols)
        if total_symbols <= 0:
            self.last_decode_info = {
                "complete": False,
                "reason": "没有解析到同步标签",
                "packets_seen": len(packets),
                "tagged_packets": tagged_packets,
            }
            return None

        anchor_time = min(anchors) if anchors else None
        bits: List[str] = []
        unknown_symbols: List[int] = []
        for symbol_index in range(total_symbols):
            phases = symbols.get(symbol_index, {})
            previous_time = anchor_time if symbol_index == 0 else symbols.get(symbol_index - 1, {}).get(2)
            phase0 = phases.get(0)
            phase1 = phases.get(1)
            phase2 = phases.get(2)
            if phase0 is None or phase1 is None or phase2 is None:
                bits.append("00")
                unknown_symbols.append(symbol_index)
                continue

            order: Optional[Tuple[int, int, int]] = None
            if previous_time is not None:
                triple = [phase0 - previous_time, phase1 - phase0, phase2 - phase1]
                if min(triple) > 0 and not self._has_too_small_spacing(triple):
                    order = tuple(sorted(range(3), key=lambda idx: triple[idx]))

            if order is None:
                # 首个anchor或上一符号末包丢失时，仍可用窗口内部两个间隔推断排序。
                order = self._infer_order_from_internal_gaps(phase1 - phase0, phase2 - phase1)

            symbol = ORDER_TO_SYMBOL.get(order) if order is not None else None
            if symbol is None:
                bits.append("00")
                unknown_symbols.append(symbol_index)
                continue
            bits.append(format(symbol, "02b"))

        bit_string = "".join(bits)
        data = self._bits_to_bytes(bit_string)
        expected_bytes = self._expected_total_bytes(total_symbols)
        if expected_bytes is not None:
            data = data[:expected_bytes]

        unknown_bits: List[int] = []
        for symbol_index in unknown_symbols:
            unknown_bits.extend([symbol_index * 2, symbol_index * 2 + 1])

        self.last_decode_info = {
            "scheme": "B-2byte-sync-tag",
            "complete": len(unknown_symbols) == 0,
            "total_symbols": total_symbols,
            "decoded_symbols": total_symbols - len(unknown_symbols),
            "unknown_symbols": unknown_symbols,
            "unknown_bits": unknown_bits,
            "packets_seen": len(packets),
            "tagged_packets": tagged_packets,
        }
        self._bytes_decoded += len(data)
        return data

    def get_metrics(self, network_state: PathState) -> StrategyMetrics:
        """估计当前网络状态下该策略的性能指标。"""
        avg_gap_ms = sum(self._gaps_ms) / len(self._gaps_ms)
        capacity = 2000.0 / avg_gap_ms if avg_gap_ms > 0 else 0.0

        if network_state.jitter_ms < 4:
            covertness = 0.84
        elif network_state.jitter_ms < self._max_jitter_tolerance_ms:
            covertness = 0.72
        else:
            covertness = 0.50

        if network_state.jitter_ms <= self._max_jitter_tolerance_ms:
            span = max(1.0, self._gaps_ms[-1] - self._gaps_ms[0])
            reliability = 0.94 - (network_state.jitter_ms / span) * 0.42
        else:
            reliability = max(
                0.05,
                0.58 - (network_state.jitter_ms - self._max_jitter_tolerance_ms) / 10.0 * 0.5,
            )

        if network_state.loss_rate > 0.01:
            reliability *= 0.5

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
        filler = bytes(((seq_num * 19 + fragment_id * 23 + i) & 0xFF) for i in range(filler_len))
        return tag + filler

    def _expected_total_symbols(self, symbols: Dict[int, Dict[int, float]]) -> int:
        if self._expected_bytes is not None:
            return max(0, int(self._expected_bytes) * 4)
        if not symbols:
            return 0
        return max(symbols.keys()) + 1

    def _expected_total_bytes(self, total_symbols: int) -> Optional[int]:
        if self._expected_bytes is not None:
            return int(self._expected_bytes)
        return (total_symbols * 2 + 7) // 8

    @staticmethod
    def _bytes_to_bits(data: bytes) -> str:
        return "".join(format(b, "08b") for b in data)

    @staticmethod
    def _bits_to_bytes(bits: str) -> bytes:
        padded = bits + "0" * ((8 - len(bits) % 8) % 8)
        return bytes(int(padded[i : i + 8], 2) for i in range(0, len(padded), 8))

    def _normalize_gaps(self, gaps: List[float]) -> List[float]:
        values = [float(g) for g in gaps]
        if len(values) < 3:
            values = DEFAULT_GAPS_MS[:]
        values = sorted(values[:3])
        if values[0] <= 0:
            values[0] = DEFAULT_GAPS_MS[0]
        if values[1] <= values[0]:
            values[1] = values[0] + 20.0
        if values[2] <= values[1]:
            values[2] = values[1] + 20.0
        return values

    def _has_too_small_spacing(self, triple: List[float]) -> bool:
        ordered = sorted(triple)
        return min(ordered[1] - ordered[0], ordered[2] - ordered[1]) < self._min_rank_delta_ms

    def _infer_order_from_internal_gaps(
        self, gap_after_phase0: float, gap_after_phase1: float
    ) -> Optional[Tuple[int, int, int]]:
        """anchor缺失时，根据窗口内部两个间隔反推三档排序。"""
        if gap_after_phase0 <= 0 or gap_after_phase1 <= 0:
            return None

        rank1 = self._nearest_gap_rank(gap_after_phase0)
        rank2 = self._nearest_gap_rank(gap_after_phase1)
        if rank1 is None or rank2 is None or rank1 == rank2:
            return None

        remaining = ({0, 1, 2} - {rank1, rank2}).pop()
        rank_to_position = [0, 0, 0]
        rank_to_position[remaining] = 0
        rank_to_position[rank1] = 1
        rank_to_position[rank2] = 2
        return tuple(rank_to_position)

    def _nearest_gap_rank(self, observed_gap_ms: float) -> Optional[int]:
        """把观测间隔归到最接近的预设档位，偏差太大则认为不可判定。"""
        distances = [abs(observed_gap_ms - gap) for gap in self._gaps_ms]
        rank = min(range(len(distances)), key=lambda idx: distances[idx])
        tolerance = max(self._max_jitter_tolerance_ms * 2.0, self._min_rank_delta_ms)
        if distances[rank] > tolerance:
            return None
        return rank

    def _build_ordered_delays(self, order: Tuple[int, int, int]) -> List[float]:
        delays = [0.0, 0.0, 0.0]
        for rank, packet_position in enumerate(order):
            delays[packet_position] = self._gaps_ms[rank]
        return delays
