"""
该模块实现项目中的一个功能组件。
"""

import random
from dataclasses import dataclass
from typing import List, Optional
import numpy as np


@dataclass
class TrafficPacket:
    """TrafficPacket 类。"""
    size_bytes: int
    timestamp_ms: float
    source: str = "background"
    flow_id: int = 0


class TrafficGenerator:
    """
    TrafficGenerator 类。
    """

    PATTERNS = ["cbr", "poisson", "on_off", "periodic"]

    def __init__(
        self,
        pattern: str = "poisson",
        rate_bps: float = 1000.0,
        packet_size_bytes: int = 100,
        burst_size: int = 5,
        burst_probability: float = 0.3,
        idle_probability: float = 0.7,
        num_flows: int = 3,
        seed: Optional[int] = None,
    ):
        """
        __init__ 函数。
        """
        if pattern not in self.PATTERNS:
            raise ValueError(f"Unknown pattern: {pattern}. Use: {self.PATTERNS}")

        self.pattern = pattern
        self.rate_bps = rate_bps
        self.packet_size_bytes = packet_size_bytes
        self.burst_size = burst_size
        self.burst_probability = burst_probability
        self.idle_probability = idle_probability
        self.num_flows = num_flows

        if seed is not None:
            np.random.seed(seed)
            random.seed(seed)

        # 中文注释。
        self._flow_bursting: List[bool] = [False] * num_flows
        self._flow_burst_remaining: List[int] = [0] * num_flows

        # 中文注释。
        self._last_generation_time: float = 0.0

    def generate_interval(
        self, interval_ms: float = 100.0, current_time_ms: Optional[float] = None
    ) -> List[TrafficPacket]:
        """
        generate_interval 函数。
        """
        if current_time_ms is None:
            current_time_ms = self._last_generation_time + interval_ms

        if self.pattern == "cbr":
            packets = self._generate_cbr(interval_ms, current_time_ms)
        elif self.pattern == "poisson":
            packets = self._generate_poisson(interval_ms, current_time_ms)
        elif self.pattern == "on_off":
            packets = self._generate_on_off(interval_ms, current_time_ms)
        elif self.pattern == "periodic":
            packets = self._generate_periodic(interval_ms, current_time_ms)
        else:
            packets = []

        self._last_generation_time = current_time_ms
        return packets

    def _generate_cbr(
        self, interval_ms: float, current_time_ms: float
    ) -> List[TrafficPacket]:
        """_generate_cbr 函数。"""
        bits_per_interval = self.rate_bps * (interval_ms / 1000.0)
        packets_per_interval = max(1, int(bits_per_interval / (self.packet_size_bytes * 8)))

        # 中文注释。
        packets = []
        for i in range(packets_per_interval):
            ts = current_time_ms - interval_ms + (i + 1) * interval_ms / packets_per_interval
            packets.append(TrafficPacket(
                size_bytes=self.packet_size_bytes + random.randint(-20, 20),
                timestamp_ms=ts,
                flow_id=i % self.num_flows,
            ))

        return packets

    def _generate_poisson(
        self, interval_ms: float, current_time_ms: float
    ) -> List[TrafficPacket]:
        """_generate_poisson 函数。"""
        avg_packets_per_interval = (
            self.rate_bps * (interval_ms / 1000.0) / (self.packet_size_bytes * 8)
        )
        num_packets = np.random.poisson(avg_packets_per_interval)

        packets = []
        for i in range(num_packets):
            ts = current_time_ms - interval_ms + random.uniform(0, interval_ms)
            packets.append(TrafficPacket(
                size_bytes=max(40, int(np.random.exponential(self.packet_size_bytes))),
                timestamp_ms=ts,
                flow_id=random.randint(0, self.num_flows - 1),
            ))

        return packets

    def _generate_on_off(
        self, interval_ms: float, current_time_ms: float
    ) -> List[TrafficPacket]:
        """_generate_on_off 函数。"""
        packets = []

        for flow_id in range(self.num_flows):
            if self._flow_burst_remaining[flow_id] > 0:
                # 中文注释。
                packets.append(TrafficPacket(
                    size_bytes=self.packet_size_bytes * random.randint(1, 5),
                    timestamp_ms=current_time_ms - interval_ms / 2,
                    flow_id=flow_id,
                ))
                self._flow_burst_remaining[flow_id] -= 1

                if self._flow_burst_remaining[flow_id] <= 0:
                    if random.random() > self.idle_probability:
                        # 中文注释。
                        self._flow_burst_remaining[flow_id] = self.burst_size
            else:
                # 中文注释。
                if random.random() < self.burst_probability:
                    self._flow_burst_remaining[flow_id] = self.burst_size

        return packets

    def _generate_periodic(
        self, interval_ms: float, current_time_ms: float
    ) -> List[TrafficPacket]:
        """_generate_periodic 函数。"""
        period_ms = 1000.0 / (self.rate_bps / (self.packet_size_bytes * 8 / self.num_flows))

        packets = []
        for flow_id in range(self.num_flows):
            # 中文注释。
            if (current_time_ms / period_ms) % 1 < (interval_ms / period_ms):
                packets.append(TrafficPacket(
                    size_bytes=self.packet_size_bytes,
                    timestamp_ms=current_time_ms,
                    flow_id=flow_id,
                ))

        return packets

    def get_offered_load_bps(self) -> float:
        """get_offered_load_bps 函数。"""
        return self.rate_bps


def create_realistic_background(
    num_flows: int = 5,
) -> TrafficGenerator:
    """
    create_realistic_background 函数。
    """
    # 中文注释。
    # 中文注释。
    return TrafficGenerator(
        pattern="poisson",
        rate_bps=2000.0,
        packet_size_bytes=150,
        num_flows=num_flows,
        burst_probability=0.2,
    )
