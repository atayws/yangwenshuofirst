"""
隐蔽发送端，负责编码、调度和路径分发。
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import threading

from ..covert_strategies.base import CovertStrategy, PacketSpec, StrategyID
from ..covert_strategies.strategy_registry import get_strategy
from ..covert_strategies.packet_scheduler import PacketScheduler, ScheduledPacket


@dataclass
class SendResult:
    """SendResult 类。"""
    message_id: int
    bytes_sent: int
    packets_sent: int
    strategies_used: Dict[int, int]  # 中文注释。
    send_time_ms: float
    success: bool = True


class PathDispatcher:
    """
    PathDispatcher 类。
    """

    def __init__(self, num_paths: int = 3):
        self.num_paths = num_paths
        self._send_callbacks: Dict[int, callable] = {}

    def register_path(self, path_id: int, send_func: callable):
        """register_path 函数。"""
        self._send_callbacks[path_id] = send_func

    def dispatch(self, packet_spec: PacketSpec) -> bool:
        """
        dispatch 函数。
        """
        path_id = packet_spec.path_id
        if path_id in self._send_callbacks:
            try:
                self._send_callbacks[path_id](packet_spec)
                return True
            except Exception:
                return False
        return False

    def dispatch_batch(
        self, packets: List[PacketSpec]
    ) -> Dict[int, int]:
        """
        dispatch_batch 函数。
        """
        sent_counts = {}
        for pkt in packets:
            success = self.dispatch(pkt)
            if success:
                sent_counts[pkt.path_id] = sent_counts.get(pkt.path_id, 0) + 1
        return sent_counts


class CovertSender:
    """
    CovertSender 类。
    """

    def __init__(
        self,
        dispatcher: Optional[PathDispatcher] = None,
        default_strategies: Optional[Dict[int, int]] = None,
    ):
        """
        __init__ 函数。
        """
        self._dispatcher = dispatcher or PathDispatcher()
        self._scheduler = PacketScheduler(clock_source="simulated")

        # 中文注释。
        self._strategies: Dict[int, CovertStrategy] = {}
        self._assignments: Dict[int, int] = default_strategies or {}

        # 中文注释。
        for path_id, strat_id in self._assignments.items():
            self._set_strategy(path_id, strat_id)

        # 中文注释。
        self._message_counter: int = 0
        self._total_bytes_sent: int = 0
        self._total_packets_sent: int = 0

    def configure_assignments(self, assignments: Dict[int, int]):
        """
        configure_assignments 函数。
        """
        for path_id, strat_id in assignments.items():
            if path_id not in self._assignments or self._assignments[path_id] != strat_id:
                self._set_strategy(path_id, strat_id)
        self._assignments = assignments.copy()

    def send_message(
        self,
        data: bytes,
        path_ids: Optional[List[int]] = None,
    ) -> SendResult:
        """
        send_message 函数。
        """
        if path_ids is None:
            path_ids = list(self._strategies.keys())

        self._message_counter += 1
        start_time = time.time() * 1000

        all_packets: List[PacketSpec] = []
        strategies_used: Dict[int, int] = {}

        for path_id in path_ids:
            strategy = self._strategies.get(path_id)
            if strategy is None:
                continue

            strat_id = int(strategy.strategy_id)
            strategies_used[path_id] = strat_id

            # 中文注释。
            packets = strategy.encode(
                data, path_id=path_id, seq_num=self._message_counter
            )
            all_packets.extend(packets)

        # 中文注释。
        scheduled = self._scheduler.schedule(all_packets, start_time_ms=start_time)

        # 中文注释。
        for sp in scheduled:
            self._dispatcher.dispatch(sp.packet_spec)

        self._total_bytes_sent += len(data)
        self._total_packets_sent += len(all_packets)

        return SendResult(
            message_id=self._message_counter,
            bytes_sent=len(data),
            packets_sent=len(all_packets),
            strategies_used=strategies_used,
            send_time_ms=time.time() * 1000 - start_time,
        )

    def _set_strategy(self, path_id: int, strategy_id: int):
        """_set_strategy 函数。"""
        try:
            self._strategies[path_id] = get_strategy(StrategyID(strategy_id))
        except (KeyError, ImportError):
            # 中文注释。
            try:
                self._strategies[path_id] = get_strategy(StrategyID.TIMING_HIGH_COVERT)
            except Exception:
                pass

    @property
    def stats(self) -> dict:
        return {
            "messages_sent": self._message_counter,
            "total_bytes_sent": self._total_bytes_sent,
            "total_packets_sent": self._total_packets_sent,
            "active_strategies": self._assignments.copy(),
        }
