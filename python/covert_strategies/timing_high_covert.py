"""
Strategy 0: high-covert sliding second-difference timing channel.

Four consecutive tagged business packets form one window. If their three
inter-packet gaps are d1, d2 and d3, the decision score is:

    S = (d1 - d2) - (d2 - d3) = d1 - 2*d2 + d3

S < -T encodes 0, and S > +T encodes 1. Windows slide by one packet, so
neighboring symbols reuse three packets.
"""

from math import ceil
from typing import Dict, List, Optional

from .base import CovertStrategy, PacketSpec, PathState, StrategyID, StrategyMetrics
from .strategy_registry import register_strategy
from .timing_sync_tag import build_timing_tag, parse_timing_tag


@register_strategy
class TimingHighCovertStrategy(CovertStrategy):
    """High-covertness binary timing strategy based on second differences."""

    strategy_id = StrategyID.TIMING_HIGH_COVERT
    name = "timing_high_covert"
    description = "Use a 4-packet sliding second-difference timing window to carry 1 bit."

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config)
        short_gap = float(self._config.get("short_gap_ms", self._config.get("gap_0_ms", 30.0)))
        long_gap = float(self._config.get("long_gap_ms", self._config.get("gap_1_ms", 90.0)))
        if long_gap <= short_gap:
            long_gap = short_gap + 20.0

        self._base_gap_ms = float(self._config.get("base_gap_ms", (short_gap + long_gap) / 2.0))
        self._decision_threshold_ms = float(
            self._config.get(
                "decision_threshold_ms",
                self._config.get(
                    "min_relation_delta_ms",
                    max(5.0, (long_gap - short_gap) * 0.25),
                ),
            )
        )
        self._second_diff_delta_ms = float(
            self._config.get(
                "second_diff_delta_ms",
                self._config.get(
                    "curvature_delta_ms",
                    max(self._decision_threshold_ms * 2.0, long_gap - short_gap),
                ),
            )
        )
        if self._second_diff_delta_ms <= self._decision_threshold_ms:
            self._second_diff_delta_ms = self._decision_threshold_ms * 1.8

        self._max_jitter_tolerance_ms = float(self._config.get("max_jitter_tolerance_ms", 15.0))
        self._block_symbols = max(1, int(self._config.get("sliding_window_block_symbols", 8)))
        self._min_gap_ms = max(1.0, float(self._config.get("min_gap_ms", 3.0)))
        self._sync_key = int(self._config.get("sync_key", 0x5A17))
        self._business_payload_len = max(2, int(self._config.get("business_payload_len", 32)))
        self._expected_bytes = self._config.get("expected_bytes")
        self.last_decode_info: Dict[str, object] = {}

    def encode(self, data: bytes, path_id: int, seq_num: int = 0) -> List[PacketSpec]:
        bit_string = self._bytes_to_bits(data)
        scores = [
            -self._second_diff_delta_ms if bit_char == "0" else self._second_diff_delta_ms
            for bit_char in bit_string
        ]

        total_fragments = self._packet_count_for_symbols(len(scores))
        packets: List[PacketSpec] = []
        fragment_id = 0

        for block_start in range(0, len(scores), self._block_symbols):
            block_scores = scores[block_start : block_start + self._block_symbols]
            gaps = self._build_gaps_from_scores(block_scores)
            block_packet_count = len(block_scores) + 3
            for offset in range(block_packet_count):
                packet_index = fragment_id
                if not packets:
                    delay_ms = 0.0
                elif offset == 0:
                    delay_ms = self._base_gap_ms
                else:
                    delay_ms = gaps[offset - 1]
                packets.append(
                    PacketSpec(
                        payload=self._build_business_payload(seq_num, packet_index, fragment_id),
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

    def decode(self, packets: List[bytes], metadata: Optional[List[dict]] = None) -> Optional[bytes]:
        if metadata is None or not packets:
            self.last_decode_info = {"complete": False, "reason": "no timing metadata"}
            return None

        packet_times: Dict[int, float] = {}
        tagged_packets = 0
        for payload, meta in zip(packets, metadata):
            tag = parse_timing_tag(payload, int(self.strategy_id), self._sync_key)
            if tag is None:
                continue
            tagged_packets += 1
            packet_index = int(tag.symbol_index)
            if int(tag.phase) != (packet_index & 0x03):
                continue
            arrival = float(meta.get("arrival_time_ms", 0.0))
            packet_times[packet_index] = min(packet_times.get(packet_index, arrival), arrival)

        total_bits = self._expected_total_bits(packet_times)
        if total_bits <= 0:
            self.last_decode_info = {
                "complete": False,
                "reason": "no timing tags",
                "packets_seen": len(packets),
                "tagged_packets": tagged_packets,
            }
            return None

        bits: List[str] = []
        decoded_bits: List[int] = []
        unknown_bits: List[int] = []
        for bit_index in range(total_bits):
            start = self._packet_index_for_symbol(bit_index)
            window = [packet_times.get(start + offset) for offset in range(4)]
            if any(item is None for item in window):
                bits.append("0")
                unknown_bits.append(bit_index)
                continue
            score = self._window_score(window)  # type: ignore[arg-type]
            if score is None:
                bits.append("0")
                unknown_bits.append(bit_index)
            elif score < -self._decision_threshold_ms:
                bits.append("0")
                decoded_bits.append(bit_index)
            elif score > self._decision_threshold_ms:
                bits.append("1")
                decoded_bits.append(bit_index)
            else:
                bits.append("0")
                unknown_bits.append(bit_index)

        data = self._bits_to_bytes("".join(bits))
        expected_bytes = self._expected_total_bytes(total_bits)
        if expected_bytes is not None:
            data = data[:expected_bytes]

        self.last_decode_info = {
            "scheme": "sliding-second-difference",
            "complete": len(unknown_bits) == 0,
            "total_bits": total_bits,
            "decoded_bits": len(decoded_bits),
            "unknown_bits": unknown_bits,
            "threshold_ms": self._decision_threshold_ms,
            "packets_seen": len(packets),
            "tagged_packets": tagged_packets,
        }
        self._bytes_decoded += len(data)
        return data

    def get_metrics(self, network_state: PathState) -> StrategyMetrics:
        packet_per_symbol = 1.0 + 3.0 / max(1.0, float(self._block_symbols))
        capacity = 1000.0 / (self._base_gap_ms * packet_per_symbol) if self._base_gap_ms > 0 else 0.0

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

    def _build_business_payload(self, seq_num: int, packet_index: int, fragment_id: int) -> bytes:
        tag = build_timing_tag(
            frame_id=seq_num,
            strategy_id=int(self.strategy_id),
            phase=packet_index & 0x03,
            symbol_index=packet_index,
            sync_key=self._sync_key,
        )
        filler_len = max(0, self._business_payload_len - len(tag))
        filler = bytes(((seq_num * 17 + fragment_id * 31 + i) & 0xFF) for i in range(filler_len))
        return tag + filler

    def _expected_total_bits(self, packet_times: Dict[int, float]) -> int:
        if self._expected_bytes is not None:
            return max(0, int(self._expected_bytes) * 8)
        if not packet_times:
            return 0
        return self._symbol_count_for_packets(max(packet_times.keys()) + 1)

    def _expected_total_bytes(self, total_bits: int) -> Optional[int]:
        if self._expected_bytes is not None:
            return int(self._expected_bytes)
        return (total_bits + 7) // 8

    def _packet_count_for_symbols(self, total_symbols: int) -> int:
        if total_symbols <= 0:
            return 0
        blocks = ceil(total_symbols / self._block_symbols)
        return total_symbols + 3 * blocks

    def _symbol_count_for_packets(self, total_packets: int) -> int:
        remaining = max(0, total_packets)
        symbols = 0
        while remaining >= 4:
            block_packets = min(remaining, self._block_symbols + 3)
            symbols += max(0, block_packets - 3)
            remaining -= block_packets
        return symbols

    def _packet_index_for_symbol(self, symbol_index: int) -> int:
        block = symbol_index // self._block_symbols
        offset = symbol_index % self._block_symbols
        return block * (self._block_symbols + 3) + offset

    def _build_gaps_from_scores(self, scores: List[float]) -> List[float]:
        raw = [0.0, 0.0]
        for score in scores:
            raw.append(float(score) - raw[-2] + 2.0 * raw[-1])

        count = len(raw)
        if count > 1:
            xs = list(range(count))
            mean_x = sum(xs) / count
            mean_y = sum(raw) / count
            denom = sum((x - mean_x) ** 2 for x in xs) or 1.0
            slope = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, raw)) / denom
            intercept = mean_y - slope * mean_x
            raw = [y - (slope * x + intercept) for x, y in zip(xs, raw)]
            mean_raw = sum(raw) / count
            raw = [item - mean_raw for item in raw]

        gaps = [self._base_gap_ms + item for item in raw]
        min_gap = min(gaps) if gaps else self._base_gap_ms
        if min_gap < self._min_gap_ms:
            shift = self._min_gap_ms - min_gap
            gaps = [item + shift for item in gaps]
        return gaps

    @staticmethod
    def _window_score(window: List[float]) -> Optional[float]:
        d1 = window[1] - window[0]
        d2 = window[2] - window[1]
        d3 = window[3] - window[2]
        if d1 <= 0 or d2 <= 0 or d3 <= 0:
            return None
        return (d1 - d2) - (d2 - d3)

    @staticmethod
    def _bytes_to_bits(data: bytes) -> str:
        return "".join(format(b, "08b") for b in data)

    @staticmethod
    def _bits_to_bytes(bits: str) -> bytes:
        padded = bits + "0" * ((8 - len(bits) % 8) % 8)
        return bytes(int(padded[i : i + 8], 2) for i in range(0, len(padded), 8))
