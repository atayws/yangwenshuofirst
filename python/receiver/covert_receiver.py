"""
隐蔽接收端，负责缓存、解码和反馈。
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ..covert_strategies.base import CovertStrategy, StrategyID
from ..covert_strategies.strategy_registry import get_strategy


@dataclass
class ReceivedPacket:
    """ReceivedPacket 类。"""
    path_id: int
    payload: bytes
    arrival_time_ms: float
    ip_id: Optional[int] = None
    packet_length: Optional[int] = None
    nonce: int = 0
    strategy_id: int = 0
    sequence_num: int = 0


@dataclass
class DecodeResult:
    """DecodeResult 类。"""
    success: bool
    data: Optional[bytes] = None
    bytes_delivered: int = 0
    path_id: int = 0
    strategy_id: int = 0
    packets_used: int = 0


class PacketBuffer:
    """
    PacketBuffer 类。
    """

    def __init__(self, max_age_ms: float = 2000.0, max_packets: int = 500):
        """
        __init__ 函数。
        """
        self._max_age_ms = max_age_ms
        self._max_packets = max_packets

        # 中文注释。
        self._buffer: Dict[int, Dict[int, List[ReceivedPacket]]] = defaultdict(
            lambda: defaultdict(list)
        )

    def add(self, packet: ReceivedPacket):
        """add 函数。"""
        self._buffer[packet.path_id][packet.sequence_num].append(packet)

        # 中文注释。
        self._evict_old()

    def get_packets(self, path_id: int, seq_num: int) -> List[ReceivedPacket]:
        """get_packets 函数。"""
        return self._buffer.get(path_id, {}).get(seq_num, [])

    def get_all_for_sequence(self, seq_num: int) -> Dict[int, List[ReceivedPacket]]:
        """get_all_for_sequence 函数。"""
        result = {}
        for path_id, seq_dict in self._buffer.items():
            if seq_num in seq_dict:
                result[path_id] = seq_dict[seq_num]
        return result

    def clear_sequence(self, seq_num: int):
        """clear_sequence 函数。"""
        for path_id in list(self._buffer.keys()):
            self._buffer[path_id].pop(seq_num, None)

    def _evict_old(self):
        """_evict_old 函数。"""
        now = time.time() * 1000
        for path_id in list(self._buffer.keys()):
            for seq_num in list(self._buffer[path_id].keys()):
                packets = self._buffer[path_id][seq_num]
                # 中文注释。
                self._buffer[path_id][seq_num] = [
                    p for p in packets
                    if now - p.arrival_time_ms < self._max_age_ms
                ]
                if not self._buffer[path_id][seq_num]:
                    del self._buffer[path_id][seq_num]


class CovertReceiver:
    """
    CovertReceiver 类。
    """

    def __init__(self, num_paths: int = 3, buffer_max_age_ms: float = 2000.0):
        """
        __init__ 函数。
        """
        self.num_paths = num_paths
        self._buffer = PacketBuffer(max_age_ms=buffer_max_age_ms)
        self._strategies: Dict[int, CovertStrategy] = {}

        # 中文注释。
        self._packets_received: int = 0
        self._messages_decoded: int = 0
        self._bytes_decoded: int = 0
        self._decode_history: List[DecodeResult] = []

    def receive_packet(
        self,
        path_id: int,
        payload: bytes,
        arrival_time_ms: Optional[float] = None,
        metadata: Optional[dict] = None,
    ):
        """
        receive_packet 函数。
        """
        if arrival_time_ms is None:
            arrival_time_ms = time.time() * 1000

        meta = metadata or {}
        packet = ReceivedPacket(
            path_id=path_id,
            payload=payload,
            arrival_time_ms=arrival_time_ms,
            ip_id=meta.get("ip_id"),
            packet_length=meta.get("packet_length", len(payload)),
            nonce=meta.get("nonce", 0),
            strategy_id=meta.get("strategy_id", 0),
            sequence_num=meta.get("sequence_num", 0),
        )

        self._buffer.add(packet)
        self._packets_received += 1

    def try_decode(self, seq_num: int) -> Optional[DecodeResult]:
        """
        try_decode 函数。
        """
        all_path_packets = self._buffer.get_all_for_sequence(seq_num)

        if not all_path_packets:
            return None

        for path_id, packets in all_path_packets.items():
            if not packets:
                continue

            strategy = self._strategies.get(path_id)
            if strategy is None:
                # 中文注释。
                strat_id = packets[0].strategy_id if packets else 0
                try:
                    strategy = get_strategy(StrategyID(strat_id))
                except Exception:
                    continue

            # 中文注释。
            payloads = [p.payload for p in packets]
            metadata = [
                {
                    "arrival_time_ms": p.arrival_time_ms,
                    "ip_id": p.ip_id,
                    "packet_length": p.packet_length,
                    "nonce": p.nonce,
                }
                for p in packets
            ]

            try:
                decoded = strategy.decode(payloads, metadata)
                if decoded:
                    result = DecodeResult(
                        success=True,
                        data=decoded,
                        bytes_delivered=len(decoded),
                        path_id=path_id,
                        strategy_id=int(strategy.strategy_id),
                        packets_used=len(packets),
                    )
                    self._messages_decoded += 1
                    self._bytes_decoded += len(decoded)
                    self._decode_history.append(result)
                    self._buffer.clear_sequence(seq_num)
                    return result
            except Exception:
                continue

        return None

    def configure_strategy(self, path_id: int, strategy_id: int):
        """configure_strategy 函数。"""
        try:
            self._strategies[path_id] = get_strategy(StrategyID(strategy_id))
        except Exception:
            pass

    def get_feedback(self) -> dict:
        """
        get_feedback 函数。
        """
        total_attempts = max(1, len(self._decode_history))
        recent = self._decode_history[-5:]  # 中文注释。

        success_count = sum(1 for r in recent if r.success)
        bytes_delivered = sum(r.bytes_delivered for r in recent)

        return {
            "success_ratio": success_count / total_attempts,
            "bytes_delivered": bytes_delivered,
            "throughput_bps": bytes_delivered * 8 / 1.0,  # 中文注释。
        }

    @property
    def stats(self) -> dict:
        return {
            "packets_received": self._packets_received,
            "messages_decoded": self._messages_decoded,
            "bytes_decoded": self._bytes_decoded,
            "buffer_size": sum(
                len(packets)
                for seq_dict in self._buffer._buffer.values()
                for packets in seq_dict.values()
            ),
        }
