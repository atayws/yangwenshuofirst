"""
根据策略中的发送延迟安排数据包发送顺序。
"""

import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple
import random

from .base import PacketSpec


@dataclass
class ScheduledPacket:
    """调度后的单个数据包。"""
    packet_spec: PacketSpec
    scheduled_time_ms: float   # 计划发送时间，单位毫秒。
    delay_from_prev_ms: float  # 与前一个包的计划间隔，单位毫秒。


class PacketScheduler:
    """
    PacketScheduler 类。
    """

    def __init__(
        self,
        clock_source: str = "simulated",
        jitter_ms: float = 0.0,
        jitter_type: str = "gaussian",  # 抖动模型：gaussian 或 uniform。
    ):
        """
        初始化调度器的时钟模式和抖动参数。
        """
        self._clock_source = clock_source
        self._jitter_ms = jitter_ms
        self._jitter_type = jitter_type
        self._simulated_time: float = 0.0

    def schedule(
        self,
        packets: List[PacketSpec],
        start_time_ms: Optional[float] = None,
    ) -> List[ScheduledPacket]:
        """
        根据 PacketSpec 中的发送间隔生成单路径发送计划。
        """
        if not packets:
            return []

        if start_time_ms is None:
            start_time_ms = self._current_time()

        scheduled = []
        current_time = start_time_ms

        for pkt in packets:
            delay = pkt.send_delay_ms

            # 可选加入发送抖动，模拟真实业务流的不稳定间隔。
            if self._jitter_ms > 0:
                delay += self._generate_jitter()

            # 第一个包立即发送，后续包按相对间隔累加。
            if len(scheduled) == 0:
                send_time = current_time
            else:
                send_time = current_time + delay

            scheduled.append(ScheduledPacket(
                packet_spec=pkt,
                scheduled_time_ms=send_time,
                delay_from_prev_ms=delay if len(scheduled) > 0 else 0.0,
            ))

            current_time = send_time

        return scheduled

    def schedule_batch(
        self,
        path_packets: dict,  # path_id 到包列表的映射。
        start_time_ms: Optional[float] = None,
    ) -> dict:
        """
        分别为多条路径生成发送计划。
        """
        if start_time_ms is None:
            start_time_ms = self._current_time()

        result = {}
        for path_id, packets in path_packets.items():
            result[path_id] = self.schedule(packets, start_time_ms)
        return result

    def send_packets(
        self,
        scheduled: List[ScheduledPacket],
        transmit_func: Callable[[PacketSpec], None],
        wait_func: Optional[Callable[[float], None]] = None,
    ):
        """
        按计划等待并调用发送函数。
        """
        if wait_func is None:
            wait_func = self._default_wait

        prev_time = 0.0
        for sp in scheduled:
            wait_time = sp.scheduled_time_ms - prev_time
            if wait_time > 0:
                wait_func(wait_time / 1000.0)  # wait_func 使用秒作为单位。
            transmit_func(sp.packet_spec)
            prev_time = sp.scheduled_time_ms

    @staticmethod
    def interleave_schedules(
        schedules: List[List[ScheduledPacket]],
    ) -> List[ScheduledPacket]:
        """
        将多条路径的计划按发送时间合并。
        """
        all_packets = []
        for schedule in schedules:
            all_packets.extend(schedule)
        all_packets.sort(key=lambda sp: sp.scheduled_time_ms)
        return all_packets

    def _current_time(self) -> float:
        """返回当前调度时间，单位毫秒。"""
        if self._clock_source == "simulated":
            return self._simulated_time
        return time.time() * 1000.0

    def _generate_jitter(self) -> float:
        """按配置生成一个发送抖动值。"""
        if self._jitter_type == "gaussian":
            return random.gauss(0, self._jitter_ms)
        else:
            return random.uniform(-self._jitter_ms, self._jitter_ms)

    @staticmethod
    def _default_wait(seconds: float):
        """默认等待函数，真实发送时使用。"""
        if seconds > 0:
            time.sleep(seconds)
