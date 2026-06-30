"""
统一隐蔽策略接收分发器。

该模块位于接收端 Python 层，负责把抓包得到的业务包按策略自动分流，再调用
策略库中对应的 decode() 方法恢复隐蔽数据。P4 交换机仍只负责转发、路径调度
和 INT，不解析隐蔽数据。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from python.covert_strategies.base import StrategyID
from python.covert_strategies.full_path_redundancy import FullPathRedundancyStrategy
from python.covert_strategies.path_sequence import PathSequenceStrategy
from python.covert_strategies.protocol_high_reliability import (
    ProtocolHighReliabilityStrategy,
)
from python.covert_strategies.statistical_fusion import StatisticalFusionStrategy
from python.covert_strategies.strategy_registry import get_strategy
from python.covert_strategies.timing_sync_tag import (
    parse_timing_tag,
)


RouterKey = Tuple[int, int]


@dataclass
class RoutedPacket:
    """已经被分发器识别并放入某个策略缓冲区的包。"""

    payload: bytes
    metadata: dict
    strategy_id: int
    message_key: int
    confidence: float
    reason: str
    arrival_index: int


@dataclass
class RouterDecodeResult:
    """单个策略缓冲区的解码结果。"""

    strategy_id: int
    message_key: int
    success: bool
    decoded: Optional[bytes]
    packets_used: int
    reason: str
    decode_info: dict = field(default_factory=dict)
    output_file: Optional[str] = None

    def to_dict(self) -> dict:
        """转换为便于写入 JSON 的结构。"""
        return {
            "strategy_id": self.strategy_id,
            "message_key": self.message_key,
            "success": self.success,
            "decoded_bytes": len(self.decoded) if self.decoded is not None else 0,
            "packets_used": self.packets_used,
            "reason": self.reason,
            "decode_info": self.decode_info,
            "output_file": self.output_file,
        }


@dataclass
class DetectionResult:
    """策略识别结果。"""

    strategy_id: int
    message_key: int
    confidence: float
    reason: str
    metadata_updates: dict = field(default_factory=dict)


class StrategyReceiverRouter:
    """
    统一接收分发器。

    典型使用流程：
    1. 抓包程序把每个 UDP/IP 包的 payload、ip_id、packet_length、arrival_time_ms 等
       元数据交给 ingest()；
    2. 分发器根据 IP-ID、时序同步标签或包长统计小头判断策略编号；
    3. decode_all() 对每个策略缓冲区调用对应策略的 decode()。
    """

    def __init__(
        self,
        strategy_configs: Optional[Dict[int, dict]] = None,
        sync_key: int = 0x5A17,
        timing_ports: Optional[Dict[int, int]] = None,
        accept_timing_without_port: bool = True,
    ):
        self.strategy_configs = strategy_configs or {}
        self.sync_key = int(sync_key)
        self.timing_ports = timing_ports or {0: 50000, 1: 50001}
        self.accept_timing_without_port = accept_timing_without_port
        self.buffers: Dict[RouterKey, List[RoutedPacket]] = {}
        self.ignored_packets: List[dict] = []
        self._arrival_index = 0

        # 识别阶段复用这些策略实例，避免每个包都重复初始化。
        self._strategy2_probe = ProtocolHighReliabilityStrategy(
            self.strategy_configs.get(2)
        )
        self._strategy3_probe = StatisticalFusionStrategy(self.strategy_configs.get(3))
        self._strategy4_probe = FullPathRedundancyStrategy(self.strategy_configs.get(4))
        self._strategy5_probe = PathSequenceStrategy(self.strategy_configs.get(5))

    def ingest(self, payload: bytes, metadata: Optional[dict] = None) -> Optional[RoutedPacket]:
        """接收一个包并尝试放入对应策略缓冲区。"""
        self._arrival_index += 1
        packet_meta = dict(metadata or {})
        packet_meta.setdefault("router_arrival_index", self._arrival_index)

        detection = self.detect(payload, packet_meta)
        if detection is None:
            self.ignored_packets.append(
                {
                    "arrival_index": self._arrival_index,
                    "reason": "未识别为隐蔽承载包",
                    "ip_id": packet_meta.get("ip_id"),
                    "dport": packet_meta.get("dport"),
                    "packet_length": packet_meta.get("packet_length"),
                }
            )
            return None

        packet_meta.update(detection.metadata_updates)
        packet_meta["strategy_id"] = detection.strategy_id
        packet_meta["message_key"] = detection.message_key
        packet_meta["route_reason"] = detection.reason
        packet_meta["route_confidence"] = detection.confidence

        routed = RoutedPacket(
            payload=bytes(payload),
            metadata=packet_meta,
            strategy_id=detection.strategy_id,
            message_key=detection.message_key,
            confidence=detection.confidence,
            reason=detection.reason,
            arrival_index=self._arrival_index,
        )
        self.buffers.setdefault((routed.strategy_id, routed.message_key), []).append(routed)
        return routed

    def ingest_many(self, packets: Iterable[Tuple[bytes, dict]]) -> List[RoutedPacket]:
        """批量接收包，返回成功识别出的包。"""
        routed_packets: List[RoutedPacket] = []
        for payload, metadata in packets:
            routed = self.ingest(payload, metadata)
            if routed is not None:
                routed_packets.append(routed)
        return routed_packets

    def detect(self, payload: bytes, metadata: dict) -> Optional[DetectionResult]:
        """按优先级识别当前包属于哪个隐蔽策略。"""
        explicit = self._detect_explicit_hint(metadata)
        if explicit is not None:
            return explicit

        ip_id_result = self._detect_ip_id(metadata)
        if ip_id_result is not None:
            return ip_id_result

        strategy3_result = self._detect_strategy3_tag(payload, metadata)
        if strategy3_result is not None:
            return strategy3_result

        timing_result = self._detect_timing_tag(payload, metadata)
        if timing_result is not None:
            return timing_result

        return None

    def decode_all(self) -> List[RouterDecodeResult]:
        """尝试解码所有已经识别出的策略缓冲区。"""
        results: List[RouterDecodeResult] = []
        for strategy_id, message_key in sorted(self.buffers.keys()):
            results.append(self.decode_group(strategy_id, message_key))
        return results

    def decode_group(self, strategy_id: int, message_key: int = 0) -> RouterDecodeResult:
        """解码一个策略分组。"""
        key = (int(strategy_id), int(message_key))
        routed_packets = self.buffers.get(key, [])
        if not routed_packets:
            return RouterDecodeResult(
                strategy_id=int(strategy_id),
                message_key=int(message_key),
                success=False,
                decoded=None,
                packets_used=0,
                reason="该策略分组没有缓存包",
            )

        strategy = get_strategy(
            StrategyID(int(strategy_id)),
            config=self._config_for_group(int(strategy_id), routed_packets),
        )
        payloads = [item.payload for item in routed_packets]
        metadata = [item.metadata for item in routed_packets]
        decoded = strategy.decode(payloads, metadata)
        decode_info = getattr(strategy, "last_decode_info", {}) or {}
        success = decoded is not None
        reason = "解码成功" if success else decode_info.get("reason", "解码失败")
        return RouterDecodeResult(
            strategy_id=int(strategy_id),
            message_key=int(message_key),
            success=success,
            decoded=decoded,
            packets_used=len(routed_packets),
            reason=reason,
            decode_info=decode_info,
        )

    def summary(self) -> dict:
        """返回当前分发器缓冲状态。"""
        groups = []
        for (strategy_id, message_key), packets in sorted(self.buffers.items()):
            groups.append(
                {
                    "strategy_id": strategy_id,
                    "message_key": message_key,
                    "packets": len(packets),
                    "first_reason": packets[0].reason if packets else "",
                }
            )
        return {
            "groups": groups,
            "routed_packets": sum(len(items) for items in self.buffers.values()),
            "ignored_packets": len(self.ignored_packets),
        }

    def _detect_explicit_hint(self, metadata: dict) -> Optional[DetectionResult]:
        """兼容测试或控制面已经明确标注 strategy_id 的情况。"""
        strategy_id = metadata.get("force_strategy_id")
        if strategy_id is None:
            return None
        strategy_id = int(strategy_id)
        if strategy_id < 0 or strategy_id > 5:
            return None
        message_key = int(metadata.get("message_key", metadata.get("sequence_num", 0)))
        return DetectionResult(
            strategy_id=strategy_id,
            message_key=message_key,
            confidence=1.0,
            reason="控制面显式指定策略",
        )

    def _detect_ip_id(self, metadata: dict) -> Optional[DetectionResult]:
        """根据 IPv4 Identification 字段识别策略2/4/5。"""
        ip_id = metadata.get("ip_id")
        if ip_id is None:
            return None
        ip_id = int(ip_id) & 0xFFFF

        parsed2 = self._strategy2_probe._unpack_ip_id(ip_id)
        if parsed2 is not None:
            updates = {
                "ip_id_info": parsed2,
                "seq_mod": parsed2["seq_mod"],
                "cipher_value": parsed2["cipher_value"],
            }
            message_key = int(metadata.get("message_key", metadata.get("sequence_num", 0)))
            return DetectionResult(
                strategy_id=2,
                message_key=message_key,
                confidence=0.92,
                reason="IP-ID匹配策略2候选头",
                metadata_updates=updates,
            )

        parsed4 = self._strategy4_probe._unpack_ip_id(ip_id)
        if parsed4 is not None:
            updates = {
                "ip_id_info": parsed4,
                "frame_id": parsed4["frame_id"],
                "symbol_id": parsed4["symbol_id"],
            }
            message_key = int(metadata.get("message_key", metadata.get("sequence_num", 0)))
            return DetectionResult(
                strategy_id=4,
                message_key=message_key,
                confidence=0.95,
                reason="IP-ID匹配策略4喷泉码头",
                metadata_updates=updates,
            )

        parsed5 = self._strategy5_probe.parse_ip_id(ip_id)
        if parsed5 is not None:
            updates = {
                "ip_id_info": parsed5,
                "path_id": parsed5["path_id"],
                "fragment_id": parsed5["fragment_id_mod"],
            }
            message_key = int(metadata.get("message_key", metadata.get("sequence_num", 0)))
            return DetectionResult(
                strategy_id=5,
                message_key=message_key,
                confidence=0.95,
                reason="IP-ID匹配策略5路径序列自描述头",
                metadata_updates=updates,
            )

        return None

    def _detect_strategy3_tag(
        self, payload: bytes, metadata: dict
    ) -> Optional[DetectionResult]:
        """根据策略3加密同步小头识别包长统计策略。"""
        tag = self._strategy3_probe._parse_tag(payload)
        if tag is None:
            return None
        updates = {
            "fusion_tag": {
                "seq_num": tag.seq_num,
                "symbol_index": tag.symbol_index,
                "total_symbols": tag.total_symbols,
                "total_bits": tag.total_bits,
                "repeat_index": tag.repeat_index,
            }
        }
        message_key = int(metadata.get("message_key", tag.seq_num))
        return DetectionResult(
            strategy_id=3,
            message_key=message_key,
            confidence=0.96,
            reason="payload匹配策略3加密同步小头",
            metadata_updates=updates,
        )

    def _detect_timing_tag(
        self, payload: bytes, metadata: dict
    ) -> Optional[DetectionResult]:
        """根据策略0/1的两字节同步标签识别时序策略承载包。"""
        for strategy_id in (0, 1):
            if not self._timing_flow_allowed(strategy_id, metadata):
                continue
            tag = parse_timing_tag(payload, strategy_id, self.sync_key)
            if tag is None:
                continue
            updates = {
                "timing_tag": {
                    "frame_id": tag.frame_id,
                    "strategy_id": tag.strategy_id,
                    "phase": tag.phase,
                    "symbol_index": tag.symbol_index,
                    "packet_index": tag.symbol_index,
                }
            }
            return DetectionResult(
                strategy_id=strategy_id,
                message_key=int(metadata.get("message_key", tag.frame_id)),
                confidence=0.80,
                reason="payload匹配策略0/1两字节同步标签",
                metadata_updates=updates,
            )
        return None

    def _timing_flow_allowed(self, strategy_id: int, metadata: dict) -> bool:
        """如果抓包提供了UDP端口，则用端口降低普通业务包误判概率。"""
        dport = metadata.get("dport")
        if dport is None:
            return self.accept_timing_without_port
        expected = self.timing_ports.get(int(strategy_id))
        return expected is None or int(dport) == int(expected)

    def _config_for_group(self, strategy_id: int, packets: List[RoutedPacket]) -> dict:
        """合并全局配置和包级配置，保证发送端/接收端参数一致。"""
        config = dict(self.strategy_configs.get(int(strategy_id), {}))
        if not packets:
            return config

        first_meta = packets[0].metadata
        for key in (
            "sync_key",
            "expected_bytes",
            "business_payload_len",
            "secret_key",
            "k",
            "num_output",
            "path_weights",
            "length_bands",
            "classification_margin_bytes",
            "header_overhead_bytes",
            "bits_per_packet",
            "repeat_count",
            "short_gap_ms",
            "long_gap_ms",
            "rank_gaps_ms",
            "base_gap_ms",
            "decision_threshold_ms",
            "second_diff_delta_ms",
            "threshold1_ms",
            "threshold2_ms",
            "score_step_ms",
            "sliding_window_block_symbols",
            "min_gap_ms",
            "min_relation_delta_ms",
            "min_rank_delta_ms",
        ):
            if key in first_meta and first_meta[key] is not None:
                config[key] = first_meta[key]
        return config
