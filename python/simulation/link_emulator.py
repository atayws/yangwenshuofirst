"""
三链路统计仿真器，模拟时延、抖动、丢包和带宽。
"""

import time
import random
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional
import numpy as np


@dataclass
class PacketResult:
    """PacketResult 类。"""
    link_id: int
    success: bool
    delay_ms: float              # 中文注释。
    propagation_delay_ms: float = 0.0
    jitter_added_ms: float = 0.0
    queue_delay_ms: float = 0.0
    dropped: bool = False
    timestamp: float = 0.0


@dataclass
class LinkState:
    """LinkState 类。"""
    link_id: int
    delay_ms: float = 5.0
    jitter_ms: float = 2.0
    loss_rate: float = 0.001
    bw_mbps: float = 10.0
    queue_size: int = 100
    queue_occupancy: int = 0


class LinkEmulator:
    """
    LinkEmulator 类。
    """

    def __init__(self, num_links: int = 3, seed: Optional[int] = None):
        self.num_links = num_links

        if seed is not None:
            np.random.seed(seed)
            random.seed(seed)

        self._links: Dict[int, LinkState] = {
            i: LinkState(link_id=i) for i in range(num_links)
        }
        self._queues: Dict[int, deque] = {i: deque() for i in range(num_links)}

        # 中文注释。
        self._sent: Dict[int, int] = {i: 0 for i in range(num_links)}
        self._lost: Dict[int, int] = {i: 0 for i in range(num_links)}
        self._bytes: Dict[int, int] = {i: 0 for i in range(num_links)}

    def set_link(self, link_id: int, **kwargs):
        """set_link 函数。"""
        if link_id in self._links:
            state = self._links[link_id]
            for k, v in kwargs.items():
                if hasattr(state, k):
                    setattr(state, k, v)

    def transmit(self, link_id: int, packet_size_bytes: int) -> PacketResult:
        """transmit 函数。"""
        if link_id not in self._links:
            return PacketResult(link_id=link_id, success=False)

        state = self._links[link_id]
        self._sent[link_id] += 1

        # 中文注释。
        if random.random() < state.loss_rate:
            self._lost[link_id] += 1
            return PacketResult(link_id=link_id, success=False, delay_ms=0.0, dropped=True)

        # 中文注释。
        prop_delay = state.delay_ms
        jitter = np.random.normal(0, state.jitter_ms) if state.jitter_ms > 0 else 0.0
        queue_delay = self._queue_delay(link_id, packet_size_bytes, state)

        total = max(0.1, prop_delay + queue_delay + jitter)
        self._bytes[link_id] += packet_size_bytes

        return PacketResult(
            link_id=link_id, success=True, delay_ms=total,
            propagation_delay_ms=prop_delay, jitter_added_ms=jitter,
            queue_delay_ms=queue_delay,
        )

    def get_link_state(self, link_id: int) -> LinkState:
        return self._links.get(link_id, LinkState(link_id=link_id))

    def get_link_stats(self, link_id: int) -> dict:
        sent = self._sent.get(link_id, 0)
        lost = self._lost.get(link_id, 0)
        state = self._links.get(link_id, LinkState(link_id=link_id))
        return {
            "link_id": link_id,
            "packets_sent": sent,
            "packets_lost": lost,
            "loss_rate": lost / max(sent, 1),
            "bytes_transferred": self._bytes.get(link_id, 0),
            "delay_ms": state.delay_ms,
            "jitter_ms": state.jitter_ms,
            "bw_mbps": state.bw_mbps,
        }

    def reset_stats(self):
        for i in range(self.num_links):
            self._sent[i] = 0
            self._lost[i] = 0
            self._bytes[i] = 0

    def _queue_delay(self, link_id: int, pkt_bytes: int, state: LinkState) -> float:
        q = self._queues[link_id]
        bits_per_us = state.bw_mbps
        tx_time_us = (pkt_bytes * 8) / bits_per_us
        queue_delay_us = len(q) * tx_time_us
        q.append(pkt_bytes)
        # 中文注释。
        for _ in range(min(max(1, int(tx_time_us / 10)), len(q))):
            q.popleft()
        while len(q) > state.queue_size:
            q.popleft()
        state.queue_occupancy = len(q)
        return queue_delay_us / 1000.0
