"""
INT 报告解析与链路指标计算。

P4 交换机发给 h1 的 INT 报告格式为：
IPv4(protocol=0xFD) | compact_int_shim_t | probe_data_t[hop_count] | 原业务负载
解析器只读取 INT shim 和 probe_data，后面的原业务负载会被忽略。
"""

import struct
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

PROBE_DATA_SIZE = 48  # probe_data_t 的固定长度，单位为字节。
INT_SHIM_SIZE = 4     # compact_int_shim_t 的固定长度，单位为字节。


@dataclass
class HopSnapshot:
    """一台交换机写入的一跳遥测快照。"""

    swid: int                 # 写入该快照的交换机编号。
    port_ingress: int         # 数据包进入该交换机的端口。
    port_egress: int          # 数据包离开该交换机的端口。
    byte_ingress: int         # 入端口累计字节数快照。
    byte_egress: int          # 出端口累计字节数快照。
    count_ingress: int        # 入端口累计包数快照。
    count_egress: int         # 出端口累计包数快照。
    last_time_ingress: int    # 上一次 INT 包到达入端口的时间。
    last_time_egress: int     # 上一次 INT 包离开出端口的时间。
    curr_time_ingress: int    # 本次 INT 包到达入端口的时间。
    curr_time_egress: int     # 本次 INT 包离开出端口的时间。
    qdepth: int               # 出端口队列深度。


@dataclass
class IntReport:
    """解析后的 INT 报告。"""

    ver: int
    hop_count: int
    original_protocol: int
    original_total_len: int
    domain_id: int
    flags: int
    trace_id: int
    hops: List[HopSnapshot]
    receive_timestamp: float = 0.0


@dataclass
class LinkMetrics:
    """面向控制平面的单链路状态指标。"""

    link_id: int
    source_swid: int = 0
    sink_swid: int = 0
    source_egress_port: int = 0
    sink_ingress_port: int = 0
    delay_us: float = 0.0
    jitter_us: float = 0.0
    loss_rate: float = 0.0
    bw_bytes_per_s: float = 0.0
    qdepth: int = 0
    interval_us: float = 0.0
    sent_delta: int = 0
    recv_delta: int = 0
    byte_delta: int = 0
    sequence_id: int = 0
    sequence_gap: int = 0
    sample_loss_rate: float = 0.0
    timestamp: float = 0.0


class IntParser:
    """把 INT 原始字节解析为 IntReport。"""

    def __init__(self):
        self._report_count = 0

    def parse(self, raw: bytes) -> Optional[IntReport]:
        if len(raw) < INT_SHIM_SIZE:
            return None

        try:
            shim0, original_proto, trace_id = struct.unpack("!BBH", raw[:INT_SHIM_SIZE])
        except struct.error:
            return None

        ver = (shim0 >> 6) & 0x03
        flags = (shim0 >> 4) & 0x03
        hop_count = shim0 & 0x0F
        hops = []
        offset = INT_SHIM_SIZE
        max_hops = min(hop_count, 4)
        while offset + PROBE_DATA_SIZE <= len(raw) and len(hops) < max_hops:
            hop = self._parse_hop(raw[offset:offset + PROBE_DATA_SIZE])
            if hop:
                hops.append(hop)
            offset += PROBE_DATA_SIZE

        self._report_count += 1
        return IntReport(
            ver=ver,
            hop_count=hop_count,
            original_protocol=original_proto,
            original_total_len=0,
            domain_id=0,
            flags=flags,
            trace_id=trace_id,
            hops=hops,
            receive_timestamp=time.time(),
        )

    def _parse_hop(self, data: bytes) -> Optional[HopSnapshot]:
        if len(data) < PROBE_DATA_SIZE:
            return None
        try:
            swid, port_in, port_out, _pad = struct.unpack("!BBBB", data[:4])
            byte_in, byte_out, cnt_in, cnt_out = struct.unpack("!IIII", data[4:20])
            last_t_in = self._read_u48(data, 20)
            last_t_out = self._read_u48(data, 26)
            curr_t_in = self._read_u48(data, 32)
            curr_t_out = self._read_u48(data, 38)
            qdepth, = struct.unpack("!I", data[44:48])
            return HopSnapshot(
                swid=swid,
                port_ingress=port_in,
                port_egress=port_out,
                byte_ingress=byte_in,
                byte_egress=byte_out,
                count_ingress=cnt_in,
                count_egress=cnt_out,
                last_time_ingress=last_t_in,
                last_time_egress=last_t_out,
                curr_time_ingress=curr_t_in,
                curr_time_egress=curr_t_out,
                qdepth=qdepth,
            )
        except struct.error:
            return None

    @staticmethod
    def _read_u48(data: bytes, offset: int) -> int:
        """读取网络字节序的 48 位无符号整数。"""

        return int.from_bytes(data[offset:offset + 6], byteorder="big", signed=False)


class LinkMetricsCalculator:
    """根据连续 INT 报告估算链路状态。

    阶段1只使用两个观测点：
    1. 源交换机出口快照，例如 s2 的 path 端口 egress。
    2. 宿交换机入口快照，例如 s1 的同 path 端口 ingress。

    这样计算出来的链路状态就是两台交换机之间那一段链路的状态，
    不混入主机侧或终端侧处理时间。
    """

    def __init__(
        self,
        port_to_link: Optional[Dict[int, int]] = None,
        source_swid: int = 1,
        sink_swid: int = 2,
    ):
        self._port_to_link = port_to_link or {}
        self._source_swid = source_swid
        self._sink_swid = sink_swid
        self._prev: Dict[Tuple[int, int], HopSnapshot] = {}
        self._prev_jitter: Dict[int, float] = {}
        self._prev_seq: Dict[int, int] = {}

    @staticmethod
    def _counter_delta(current: int, previous: int, bits: int = 32) -> int:
        """计算 P4 无符号累计计数器的差值，兼容计数器回绕。"""

        if current >= previous:
            return current - previous
        return (1 << bits) - previous + current

    def compute(self, report: IntReport) -> Dict[int, LinkMetrics]:
        """计算当前报告对应的一条链路指标。"""

        metrics = {}

        source_hop = None
        sink_hop = None
        for hop in report.hops:
            if hop.swid == self._source_swid:
                source_hop = hop
            elif hop.swid == self._sink_swid:
                sink_hop = hop

        if source_hop is None or sink_hop is None:
            return metrics

        link_id = self._port_to_link.get(source_hop.port_egress, source_hop.port_egress - 1)
        if link_id < 0:
            link_id = 0

        prev_source = self._prev.get((link_id, self._source_swid))
        prev_sink = self._prev.get((link_id, self._sink_swid))

        lm = LinkMetrics(
            link_id=link_id,
            source_swid=source_hop.swid,
            sink_swid=sink_hop.swid,
            source_egress_port=source_hop.port_egress,
            sink_ingress_port=sink_hop.port_ingress,
            timestamp=report.receive_timestamp,
        )
        lm.sequence_id = report.trace_id

        lm.delay_us = float(sink_hop.curr_time_ingress - source_hop.curr_time_egress)

        prev_delay = self._prev_jitter.get(link_id)
        if prev_delay is not None:
            lm.jitter_us = abs(lm.delay_us - prev_delay)
        self._prev_jitter[link_id] = lm.delay_us

        if prev_source:
            lm.interval_us = float(source_hop.curr_time_egress - prev_source.curr_time_egress)
            if lm.interval_us > 0:
                lm.byte_delta = self._counter_delta(source_hop.byte_egress, prev_source.byte_egress)
                lm.bw_bytes_per_s = lm.byte_delta / (lm.interval_us / 1_000_000.0)
        elif source_hop.curr_time_egress > 0:
            # 第一条样本没有上一条快照，只能用交换机启动以来的累计值做初始估计。
            lm.interval_us = float(source_hop.curr_time_egress)
            lm.byte_delta = source_hop.byte_egress
            lm.bw_bytes_per_s = source_hop.byte_egress / (lm.interval_us / 1_000_000.0)

        prev_seq = self._prev_seq.get(link_id)
        if prev_seq is not None:
            lm.sequence_gap = (report.trace_id - prev_seq) & 0xFFFF
            if lm.sequence_gap == 0:
                lm.sequence_gap = 1
            lm.sample_loss_rate = max(0.0, min(1.0, (lm.sequence_gap - 1) / lm.sequence_gap))

        if prev_source and prev_sink:
            lm.sent_delta = self._counter_delta(source_hop.count_egress, prev_source.count_egress)
            lm.recv_delta = self._counter_delta(sink_hop.count_ingress, prev_sink.count_ingress)
            if lm.sent_delta > 0:
                lm.loss_rate = max(0.0, min(1.0, (lm.sent_delta - lm.recv_delta) / lm.sent_delta))
        else:
            # 第一条样本只建立基准，不用累计端口计数推断丢包。
            lm.sent_delta = 0
            lm.recv_delta = 0
            lm.loss_rate = 0.0

        lm.qdepth = source_hop.qdepth

        self._prev[(link_id, self._sink_swid)] = sink_hop
        self._prev[(link_id, self._source_swid)] = source_hop
        self._prev_seq[link_id] = report.trace_id
        metrics[link_id] = lm
        return metrics
